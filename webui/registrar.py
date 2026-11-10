"""注册 worker：调 auth_flow.run_register，并把日志/状态实时推到队列。

每个注册任务跑在独立线程；通过 `RunLogger` 把 `logging` 记录 + tail 状态推
到队列，前端用 SSE 实时收日志。
"""
from __future__ import annotations

import logging
import base64
import inspect
import json
import queue
import random
import re
import secrets
import sys
import threading
import time
import traceback
import uuid
from contextvars import copy_context
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]  # gpt-outlook-register/
sys.path.insert(0, str(ROOT))

from config import Config  # noqa: E402
from auth_flow import AuthFlow, AuthorizeRateLimitError, PasswordResetProtocolError  # noqa: E402
from mail_providers import (  # noqa: E402
    MailProviderError,
    create_mail_provider,
    get_provider_class,
)
from sms_provider import PhoneCallbackController  # noqa: E402
from safe_diagnostics import (  # noqa: E402
    safe_password_reset_result,
    safe_password_reset_failure_metadata,
    safe_password_reset_diagnostics,
    safe_otp_failure_metadata,
    safe_roxy_rejection_metadata,
    safe_proxy_probe_metadata,
    safe_public_error,
    safe_traceback_summary,
    safe_url,
    sanitize_observable,
    sanitize_text,
)

from . import db  # noqa: E402
from .two_factor import TOTPRecentAuthRequired  # noqa: E402

# run_id -> queue of log strings; sentinel = None 表示流结束
_run_queues: dict[str, queue.Queue] = {}
_run_cancel_events: dict[str, threading.Event] = {}
# run_id -> callback invoked exactly once after the background task exits
_run_finalizers: dict[str, object] = {}
_lock = threading.Lock()


def _run_registration_finalizer(run_id: str) -> None:
    """Release resources owned by a registration after every exit path."""
    with _lock:
        callback = _run_finalizers.pop(run_id, None)
    if callback is None:
        return
    try:
        callback()
    except Exception:
        logging.getLogger("registrar").exception(
            "注册任务收尾回调执行失败: run_id=%s", run_id
        )

# Keep every registration path on the same bounded mailbox wait.  This is
# intentionally server-side so stale browser localStorage cannot restore 180s.
REGISTRATION_OTP_TIMEOUT_SECONDS = 180
REGISTERED_REAUTH_OTP_TIMEOUT_SECONDS = REGISTRATION_OTP_TIMEOUT_SECONDS
REGISTRATION_OTP_TIMEOUT_MIN_SECONDS = 10
REGISTRATION_OTP_TIMEOUT_MAX_SECONDS = 600
REGISTERED_REAUTH_OTP_MAX_SECONDS = REGISTRATION_OTP_TIMEOUT_MAX_SECONDS
# Reuse each Roxy Profile for at most three registrations, then delete it.
ROXY_PROFILE_USE_LIMIT = 3


class Registration2FAError(RuntimeError):
    """Registration obtained authorization but mandatory 2FA binding failed."""

    failure_phase = "bind_2fa"
    exception_type = "Registration2FAError"

    def __init__(self):
        super().__init__("registration 2FA failed")


def normalize_otp_timeout(value=None) -> int:
    """Return an adjustable mailbox OTP wait clamped to the supported range."""
    try:
        timeout = int(value)
    except (TypeError, ValueError):
        timeout = REGISTRATION_OTP_TIMEOUT_SECONDS
    return max(
        REGISTRATION_OTP_TIMEOUT_MIN_SECONDS,
        min(timeout, REGISTRATION_OTP_TIMEOUT_MAX_SECONDS),
    )


def generate_candidate_password() -> str:
    groups = (
        "ABCDEFGHJKLMNPQRSTUVWXYZ",
        "abcdefghjkmnpqrstuvwxyz",
        "23456789",
        "!@#$%^&*?_-+=",
    )
    chars = [secrets.choice(group) for group in groups]
    alphabet = "".join(groups)
    chars.extend(secrets.choice(alphabet) for _ in range(10))
    random.SystemRandom().shuffle(chars)
    return "".join(chars)


def normalize_registration_contract_options(options: dict | None) -> dict:
    """Enforce mandatory password/session/2FA and keep refresh optional."""
    normalized = dict(options or {})
    normalized.update({
        "want_access_token": True,
        "want_session_token": True,
        "want_refresh_token": False,
        "want_2fa": True,
    })
    return normalized



def extend_reauthorization_otp_wait(
    provider,
    initial_timeout: int = REGISTERED_REAUTH_OTP_TIMEOUT_SECONDS,
    total_timeout: int = REGISTERED_REAUTH_OTP_MAX_SECONDS,
    on_extend=None,
):
    """Extend one reauthorization OTP wait once, without resetting the provider."""
    initial = max(0, int(initial_timeout))
    total = max(initial, int(total_timeout))
    extension = total - initial
    if extension <= 0 or not hasattr(provider, "wait_for_otp"):
        return provider

    original_wait_for_otp = provider.wait_for_otp
    extension_used = False

    def wait_for_otp(
        email_addr,
        timeout=120,
        issued_after=None,
        strict_issued_after=False,
        allow_recent_snapshot_fallback=False,
        cancel_event=None,
    ):
        nonlocal extension_used
        otp_kwargs = {
            "timeout": timeout,
            "issued_after": issued_after,
        }
        if strict_issued_after:
            otp_kwargs["strict_issued_after"] = True
        if allow_recent_snapshot_fallback:
            otp_kwargs["allow_recent_snapshot_fallback"] = True
        try:
            parameters = inspect.signature(original_wait_for_otp).parameters.values()
            supports_cancel = any(
                parameter.name == "cancel_event"
                or parameter.kind is inspect.Parameter.VAR_KEYWORD
                for parameter in parameters
            )
        except (TypeError, ValueError):
            supports_cancel = False
        if cancel_event is not None and supports_cancel:
            otp_kwargs["cancel_event"] = cancel_event
        try:
            return original_wait_for_otp(
                email_addr,
                **otp_kwargs,
            )
        except TimeoutError:
            try:
                requested = int(timeout)
            except (TypeError, ValueError):
                raise
            if requested != initial or extension_used:
                raise
            extension_used = True
            if on_extend is not None:
                on_extend(initial, extension, total)
            otp_kwargs["timeout"] = extension
            return original_wait_for_otp(
                email_addr,
                **otp_kwargs,
            )

    provider.wait_for_otp = wait_for_otp
    return provider

class ReauthorizationCancelled(RuntimeError):
    pass


class ReauthorizationMailboxRequired(RuntimeError):
    """The existing-account login unexpectedly required an email OTP."""


class _CredentialOnlyMailProvider:
    """Allow password/TOTP login while refusing unavailable email OTP reads."""

    kind = "credential_only"
    exhausted = True

    def prepare_for_otp(self):
        return None

    def wait_for_otp(self, *args, **kwargs):
        raise ReauthorizationMailboxRequired(
            "账号登录实际要求邮箱验证码，但本地没有对应接码记录"
        )


def log_pending_password_saved(flow, fallback_email: str = "") -> bool:
    """Retry and verify escrow of a server-accepted password after interruption."""
    try:
        if not getattr(flow, "_password_registered_in_run", False):
            return False
        password = (flow.result.password or "").strip()
        if not password:
            return False
        email = (flow.result.email or fallback_email or "").strip().lower()
        if not email:
            return False

        # The normal on_password callback already writes this value. Retrying is
        # intentional and idempotent: it closes the gap when that first write hit
        # a transient SQLite error, then verifies the durable state before logging.
        db.save_password_early(email, password)
        saved = db.get_registered(email, include_pending_password=True) or {}
        extra = saved.get("extra") if isinstance(saved.get("extra"), dict) else {}
        persisted = bool(
            saved.get("password") == password
            and extra.get("pending")
            and str(extra.get("pending_reason") or "")
            == db.PASSWORD_PENDING_REGISTERED
        )
        if persisted:
            logging.getLogger("registrar").error(
                f"[register] {email} 候选密码已保存但尚未确认，注册尚未完成"
            )
            return True
        logging.getLogger("registrar").error(
            f"[register] {email} 候选密码落盘校验失败，注册尚未完成"
        )
        return False
    except Exception:
        logging.getLogger("registrar").error(
            f"[register] {(fallback_email or '').strip().lower()} "
            "候选密码落盘失败，注册尚未完成"
        )
        return False


def retry_2fa_binding(bind_once, max_attempts: int = 2, delay_seconds: float = 2.0):
    """Retry a failed 2FA bind a bounded number of times."""
    attempts = max(1, int(max_attempts))
    last_error = None
    for index in range(attempts):
        try:
            result = bind_once()
            if result and (result.get("secret") or result.get("already_enabled")):
                return result
        except Exception as exc:  # noqa: BLE001 - final failure is handled by caller
            last_error = exc
        if index + 1 < attempts and delay_seconds > 0:
            time.sleep(delay_seconds)
    if last_error is not None:
        raise last_error
    return None


def bind_totp_2fa_durable(
    email: str,
    flow: AuthFlow,
    access_token: str,
    *,
    raise_on_enroll_401: bool = False,
) -> dict | None:
    """Run inline TOTP enrollment with crash-safe one-time secret persistence."""
    from .two_factor import bind_totp_2fa_inline

    normalized = (email or "").strip().lower()
    if not normalized:
        raise ValueError("2FA 绑定缺少邮箱身份")
    pending = db.get_pending_totp_enrollment(normalized)

    def save_pending(info: dict) -> None:
        db.save_pending_totp_enrollment(normalized, info)

    def promote_pending(info: dict) -> None:
        if db.activate_pending_totp_enrollment(normalized):
            return
        current = db.get_registered(normalized, include_pending_password=True) or {}
        if (
            (current.get("totp_secret") or "").strip() == (info.get("secret") or "").strip()
            and (current.get("totp_factor_id") or "").strip()
            == (info.get("factor_id") or "").strip()
        ):
            return
        raise RuntimeError("2FA 已激活，但一次性 TOTP 凭据未能原子落库")

    result = bind_totp_2fa_inline(
        flow,
        access_token,
        pending_enrollment=pending,
        on_enrolled=save_pending,
        on_activated=promote_pending,
        raise_on_enroll_401=raise_on_enroll_401,
    )
    if result and result.get("already_enabled"):
        if not result.get("secret") or not result.get("factor_id"):
            current = db.get_registered(
                normalized,
                include_pending_password=True,
            ) or {}
            secret = str(current.get("totp_secret") or "").strip()
            factor_id = str(current.get("totp_factor_id") or "").strip()
            if secret and factor_id:
                result = {
                    **result,
                    "secret": secret,
                    "factor_id": factor_id,
                }
    return result


def bind_totp_2fa_from_saved_session(
    email: str,
    registered: dict,
    cfg: Config,
    env_overrides: dict | None = None,
    account_callback=None,
) -> dict | None:
    """Bind missing TOTP from an already persisted ChatGPT session.

    This is intentionally narrower than reauthorization: it restores only the
    saved in-memory cookie/session context, then runs the existing durable
    enroll/activate path.  It never submits a password or requests mailbox OTP.
    """
    normalized = (email or "").strip().lower()
    access_token = str((registered or {}).get("access_token") or "").strip()
    session_token = str((registered or {}).get("session_token") or "").strip()
    if not normalized or not access_token or not session_token:
        raise RuntimeError("缺少已保存的 Access/Session，不能复用会话补绑 2FA")

    flow = AuthFlow(
        cfg,
        env_overrides=dict(env_overrides or {}),
        account_callback=account_callback,
    )
    flow.from_existing_credentials(
        session_token,
        access_token,
        str((registered or {}).get("device_id") or "").strip(),
    )
    # ``cookie_header`` comes from the successful ChatGPT session. Restore it
    # only to the in-memory requests jar; it is never logged or written back.
    for pair in str((registered or {}).get("cookie_header") or "").split(";"):
        if "=" not in pair:
            continue
        name, value = pair.strip().split("=", 1)
        if name and value:
            flow.session.cookies.set(name, value, domain=".chatgpt.com")

    effective_access_token = str(
        getattr(flow.result, "access_token", "") or access_token
    ).strip()
    if not effective_access_token:
        raise RuntimeError("已保存会话未能取得可用 Access，不能补绑 2FA")
    return bind_totp_2fa_durable(
        normalized,
        flow,
        effective_access_token,
        raise_on_enroll_401=True,
    )


def verify_registered_password(
    email: str,
    password: str,
    options: dict | None = None,
) -> dict:
    """Verify an externally reset password without touching saved credentials."""
    normalized = (email or "").strip().lower()
    candidate = password if isinstance(password, str) else ""
    if not normalized:
        raise RuntimeError("密码验证缺少邮箱")
    if not candidate or not candidate.strip():
        raise RuntimeError("密码验证缺少密码")

    from config import resolve_proxy

    cfg = Config()
    cfg.proxy = resolve_proxy((options or {}).get("proxy"))
    flow = AuthFlow(
        cfg,
        env_overrides={
            "AUTH_SESSION_TIMEOUT": "60",
            "WEBUI_ALLOW_LOGIN": "1",
            "OAUTH_CODEX_RT_BEFORE_CALLBACK": "0",
            "OAUTH_CODEX_RT_EXCHANGE": "0",
        },
    )
    return flow.verify_existing_password(normalized, candidate)


def verify_password_then_bind_2fa(
    cfg: Config,
    mail_provider,
    email: str,
    password: str,
    env_overrides: dict,
    account_callback=None,
    max_attempts: int = 2,
    retry_delay: float = 2.0,
):
    """Verify the registration password in a fresh session, then bind TOTP 2FA.

    Email OTP is deliberately forbidden here. A result is accepted only when
    run_protocol_login reached the password verification endpoint in this new
    AuthFlow instance and the 2FA enrollment returned a locally storable secret.
    """
    normalized = (email or "").strip().lower()
    registered_password = (password or "").strip()
    if not normalized or not registered_password:
        raise RuntimeError("注册阶段未生成有效密码，拒绝绑定 2FA")

    verify_flow = AuthFlow(
        cfg,
        env_overrides=dict(env_overrides or {}),
        account_callback=account_callback,
    )
    verified = verify_flow.run_protocol_login(
        mail_provider,
        normalized,
        registered_password,
        allow_registration_fallback=False,
        allow_email_otp_after_password=True,
    )
    if not getattr(verify_flow, "_password_verified_in_run", False):
        raise RuntimeError("新会话密码验证未通过，拒绝绑定 2FA")
    if not (verified.access_token or "").strip():
        raise RuntimeError("新会话密码验证后未取得 access_token，拒绝绑定 2FA")

    info = retry_2fa_binding(
        lambda: bind_totp_2fa_durable(normalized, verify_flow, verified.access_token),
        max_attempts=max_attempts,
        delay_seconds=retry_delay,
    )
    if info and info.get("already_enabled") and not info.get("secret"):
        raise RuntimeError("服务端已启用 2FA，但本地没有 TOTP Secret，不能标记成功")
    if not (info and (info.get("secret") or "").strip()):
        raise RuntimeError("2FA 绑定失败或未返回 TOTP Secret，不能标记成功")
    return verified, info


def finalize_password_2fa_registration(
    registration_flow: AuthFlow,
    cfg: Config,
    mail_provider,
    credentials: dict,
    env_overrides: dict,
    account_callback=None,
    max_attempts: int = 2,
    retry_delay: float = 2.0,
) -> dict:
    """Turn a just-created password account into a verified password+2FA result."""
    if not getattr(registration_flow, "_password_registered_in_run", False):
        raise RuntimeError(
            "本轮注册阶段没有成功设置密码；已有账号或邮箱验证码账号不能进入 2FA 成功路径"
        )

    email = (credentials.get("email") or "").strip().lower()
    password = (credentials.get("password") or "").strip()
    verified, info = verify_password_then_bind_2fa(
        cfg,
        mail_provider,
        email,
        password,
        env_overrides,
        account_callback=account_callback,
        max_attempts=max_attempts,
        retry_delay=retry_delay,
    )
    completed = verified.to_dict()
    completed["email"] = email
    completed["password"] = password
    completed["totp_secret"] = info["secret"]
    completed["totp_factor_id"] = info.get("factor_id", "")
    return completed


def _enforce_roxy_password_acceptance_evidence(credentials: dict) -> dict:
    """Fail closed across the worker boundary unless flags carry direct evidence."""
    evidence = str(credentials.get("password_acceptance_evidence") or "").strip()
    password_set = bool(
        credentials.get("password_set")
        and evidence == "signup_password_accepted"
    )
    password_verified = bool(
        credentials.get("password_verified")
        and evidence in {
            "signup_password_accepted",
            "existing_password_accepted",
        }
    )
    credentials["password_set"] = password_set
    credentials["password_verified"] = password_verified
    return credentials


def complete_roxy_browser_credentials(
    browser_credentials: dict,
    mail_provider,
    options: dict,
) -> dict:
    """Finish mandatory repo_0810 acceptance after browser registration.

    Roxy supplies a fresh browser-created password account plus ChatGPT session.
    repo_0810 owns mandatory 2FA enrollment, final credential validation,
    persistence, mailbox state, and the later Plus/status check.
    """
    browser_credentials = _enforce_roxy_password_acceptance_evidence(
        browser_credentials
    )
    email = (browser_credentials.get("email") or "").strip().lower()
    password = (browser_credentials.get("password") or "").strip()
    if not email or not password:
        raise RuntimeError("Roxy 浏览器没有返回完整邮箱和密码")
    password_accepted = bool(
        browser_credentials.get("password_set")
        or browser_credentials.get("password_verified")
    )
    email_otp_verified = bool(browser_credentials.get("email_otp_verified"))
    if not (password_accepted or email_otp_verified):
        raise RuntimeError("Roxy 同一注册会话没有确认服务端接受密码或邮箱 OTP")

    cfg = Config()
    from config import resolve_proxy
    cfg.proxy = resolve_proxy((options or {}).get("proxy"))
    env_overrides = {
        "OTP_TIMEOUT": str(normalize_otp_timeout((options or {}).get("otp_timeout"))),
        "WEBUI_ALLOW_LOGIN": "1",
        "OAUTH_CODEX_RT_EXCHANGE": "0",
        "OAUTH_CODEX_RT_BEFORE_CALLBACK": "0",
    }
    # Roxy is released after account creation. The authoritative protocol
    # registrar consumes the browser cookie context for Session/Access and all
    # subsequent work.
    flow = AuthFlow(cfg, env_overrides=env_overrides)
    user_agent = str(browser_credentials.get("user_agent") or "").strip()
    if user_agent:
        flow._ua = user_agent
    for cookie in browser_credentials.get("browser_cookies") or []:
        name = str(cookie.get("name") or "")
        value = str(cookie.get("value") or "")
        if not name or not value:
            continue
        try:
            flow.session.cookies.set(
                name,
                value,
                domain=str(cookie.get("domain") or "") or None,
                path=str(cookie.get("path") or "/"),
            )
        except Exception:
            flow.session.cookies.set(name, value)
    session_token, access_token = flow.get_auth_session()
    if not session_token or not access_token:
        raise RuntimeError("协议注册机未能从浏览器会话取得完整 Session/Access")
    browser_credentials["session_token"] = session_token
    browser_credentials["access_token"] = access_token
    browser_credentials["cookie_header"] = flow.result.cookie_header
    # Authorization is independently valuable and must survive a later 2FA
    # enrollment failure. The candidate password row already exists here.
    persisted = db.merge_registered_credentials(email, {
        "access_token": access_token,
        "session_token": session_token,
        "cookie_header": flow.result.cookie_header,
    })
    if not persisted:
        raise RuntimeError("协议注册机取得 Session/Access，但授权凭据持久化失败")

    # The browser OTP handoff has already produced a fresh authenticated
    # ChatGPT flow and Session/Access. MFA must use this same flow regardless
    # of whether the provider offered a password route. Starting a second
    # protocol login here caused OAuth 409 after authorization was already
    # saved and needlessly repeated the account flow.
    info = retry_2fa_binding(
        lambda: bind_totp_2fa_durable(email, flow, access_token),
        max_attempts=int((options or {}).get("2fa_max_attempts") or 2),
        delay_seconds=float((options or {}).get("2fa_retry_delay", 2.0)),
    )
    if not info or not info.get("secret") or not info.get("factor_id"):
        raise RuntimeError("Roxy 浏览器建号成功，但 repo_0810 未取得完整 2FA Secret/Factor ID")
    completed = dict(browser_credentials)
    completed.update({
        "email": email,
        "password": password,
        "totp_secret": info["secret"],
        "totp_factor_id": info["factor_id"],
    })
    ensure_requested_registration_outputs(completed, normalize_registration_contract_options(options))
    return completed


def _compact_roxy_page_state(state: object) -> dict:
    """Keep a parseable, secret-free action snapshot below durable-error limits."""
    if not isinstance(state, dict):
        return {}

    def text(value: object, limit: int = 72) -> str:
        cleaned = sanitize_text(str(value or ""))
        cleaned = re.sub(
            r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", "[EMAIL]", cleaned
        )
        cleaned = re.sub(r"\b\d{4,}\b", "[NUMBER]", cleaned)
        # Opaque strings can be tokens even when an upstream alert does not
        # label them. Keep human-readable messages, never long opaque values.
        cleaned = re.sub(r"\b[A-Za-z0-9_-]{24,}\b", "[VALUE]", cleaned)
        return re.sub(r"\s+", " ", cleaned).strip()[:limit]

    def action(item: object) -> dict:
        if not isinstance(item, dict):
            return {}
        values = {
            "type": text(item.get("type"), 16),
            "name": text(item.get("name"), 48),
            "value": text(item.get("value"), 72),
            "testid": text(item.get("testid"), 48),
        }
        # These modes are compiler-owned, fixed enums; validate before generic
        # opaque-value scrubbing so a long safe enum is not mistaken for a token.
        click_mode = str(item.get("click_mode") or "").strip()
        if click_mode in {
            "async_dom_click", "cdp_pointer", "keyboard_enter",
            "webdriver_fallback_overlay",
        }:
            values["click_mode"] = click_mode
        pointer_hit = text(item.get("pointer_hit"), 16).lower()
        if pointer_hit in {"target", "descendant", "iframe", "other", "none"}:
            values["pointer_hit"] = pointer_hit
        return {key: value for key, value in values.items() if value}

    compact: dict = {}
    proxy_probe = safe_proxy_probe_metadata(state.get("proxy_probe"))
    if proxy_probe:
        compact["proxy_probe"] = proxy_probe
    url = safe_url(state.get("url"))
    if url:
        compact["url"] = url
    session_reason = state.get("session_reason")
    if isinstance(session_reason, str) and session_reason in {"auth_callback_error", "roxy_session_timeout"}:
        compact["session_reason"] = session_reason
        code = state.get("auth_error_code")
        if isinstance(code, str) and code in {
            "Callback", "OAuthCallback", "OAuthSignin", "OAuthCreateAccount",
            "AccessDenied", "Configuration", "Verification", "CredentialsSignin",
            "SessionRequired", "Default",
        }:
            compact["auth_error_code"] = code
        probe = state.get("session_probe")
        if isinstance(probe, str) and probe in {
            "pending", "ready", "error", "http_error", "invalid_json", "invalid_payload",
            "network_error", "timeout", "unavailable", "invalid_result", "cdp_error",
            "legacy", "webdriver_error",
        }:
            compact["session_probe"] = probe
        http_status = state.get("session_http")
        if isinstance(http_status, int) and not isinstance(http_status, bool) and 100 <= http_status <= 599:
            compact["session_http"] = http_status
        for key in ("access_present", "session_present", "profile_submit_dispatched"):
            if isinstance(state.get(key), bool):
                compact[key] = state[key]
        kind = state.get("session_exception")
        if isinstance(kind, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,79}", kind):
            compact["session_exception"] = kind
    email_reason = state.get("email_submit_reason")
    if isinstance(email_reason, str) and email_reason in {
        "auth_callback_error", "browser_transport_error", "auth_route_error_500",
    }:
        compact["email_submit_reason"] = email_reason
        code = state.get("auth_error_code")
        if email_reason == "auth_callback_error" and isinstance(code, str) and code in {
            "Callback", "OAuthCallback", "OAuthSignin", "OAuthCreateAccount",
            "AccessDenied", "Configuration", "Verification", "CredentialsSignin",
            "SessionRequired", "Default",
        }:
            compact["auth_error_code"] = code
    rejection = safe_roxy_rejection_metadata(state.get("roxy_rejection"))
    if rejection:
        compact["roxy_rejection"] = rejection
    roxy_code = state.get("roxy_api_code", state.get("roxy_code"))
    if type(roxy_code) is int and 1 <= roxy_code <= 9999999999:
        roxy_code = str(roxy_code)
    if type(roxy_code) is str and re.fullmatch(r"[1-9][0-9]{0,9}", roxy_code):
        compact["roxy_code"] = roxy_code
    # Raw msg and compact-like roxy_msg are never observable text inputs.
    roxy_block = state.get("roxy_profile_creation_blocked", state.get("roxy_block"))
    if type(roxy_block) is str and roxy_block == "daily_quota":
        compact["roxy_block"] = roxy_block
    kind = state.get("roxy_transport_exception")
    if type(kind) is str and kind in {
        "HTTPError", "JSONDecodeError", "ReadTimeout", "ConnectTimeout", "Timeout",
        "ConnectionError", "ProxyError", "SSLError", "ValueError", "TypeError",
    }:
        compact["roxy_transport_exception"] = kind
    for key in ("submit_disabled", "page_busy", "password_error"):
        if isinstance(state.get(key), bool):
            compact[key] = state[key]
    email_submit_stage = text(state.get("email_submit_stage"), 32).lower()
    if email_submit_stage in {
        "input_wait", "email_fill", "initial_submit", "initial_transition_wait",
        "stop_loading", "same_form_recovery", "post_recovery_wait", "legacy_entry",
    }:
        compact["email_submit_stage"] = email_submit_stage
    email_recovery_state = state.get("email_recovery_state")
    if isinstance(email_recovery_state, str) and email_recovery_state in {
        "queued", "click_dispatched", "submit_observed", "missing_email_input",
        "missing_form", "missing_submit", "page_busy", "input_changed",
        "form_invalid", "dispatch_exception",
    }:
        compact["email_recovery_state"] = email_recovery_state
    email_stage_names = {
        "before_initial_submit": "pre",
        "after_initial_submit": "click",
        "initial_wait_done": "wait1",
        "after_stop_loading": "stop",
        "recovery_result": "recover",
        "recovery_wait_done": "wait2",
    }
    email_state_names = {
        "email_page": "e",
        "loading": "l",
        "password": "p",
        "login_password": "lp",
        "otp": "o",
        "logged_in": "ok",
        "unknown": "u",
        "browser_error": "be",
        "route_error_500": "500",
        "auth_callback_error": "ae",
        "password_error": "pe",
    }
    email_trace = []
    for raw in (state.get("email_submit_trace") or [])[:6]:
        if not isinstance(raw, dict):
            continue
        # RoxyRegistrationError already carries compact, secret-free state.
        # Validate both forms so rendering that exception cannot erase its trace.
        stage_value = str(raw.get("stage", raw.get("s")) or "").strip().lower()
        stage = email_stage_names.get(
            stage_value, stage_value if stage_value in email_stage_names.values() else None
        )
        if not stage:
            continue
        entry = {"s": stage}
        state_value = str(raw.get("state", raw.get("c")) or "").strip().lower()
        classified = email_state_names.get(
            state_value, state_value if state_value in email_state_names.values() else None
        )
        if classified:
            entry["c"] = classified
        cleaned_url = safe_url(raw.get("url", raw.get("p")))
        if cleaned_url:
            try:
                path = urlsplit(cleaned_url).path or "/"
            except Exception:
                path = ""
            if path.startswith("/"):
                entry["p"] = text(path, 72)
        for source, target in (
            ("has_email_input", "e"),
            ("submit_disabled", "d"),
            ("page_busy", "b"),
            ("recovery_ok", "o"),
            ("has_form", "f"),
            ("has_submit", "t"),
        ):
            value = raw.get(source, raw.get(target))
            if isinstance(value, bool):
                entry[target] = value
        click_mode = str(raw.get("click_mode", raw.get("m")) or "").strip().lower()
        if click_mode in {
            "async_dom_click", "cdp_pointer", "keyboard_enter",
            "webdriver_fallback_overlay",
        }:
            entry["m"] = click_mode
        elapsed_ms = raw.get("elapsed_ms", raw.get("ms"))
        if not isinstance(elapsed_ms, bool):
            try:
                entry["ms"] = min(999999, max(0, int(elapsed_ms)))
            except (TypeError, ValueError):
                pass
        recovery_reason = text(raw.get("recovery_reason", raw.get("r")), 32).lower()
        if re.fullmatch(r"[a-z][a-z0-9_]{0,31}", recovery_reason):
            entry["r"] = recovery_reason
        email_trace.append(entry)
    if email_trace:
        compact["email_submit_trace"] = email_trace
    readiness = state.get("email_form_readiness")
    if isinstance(readiness, dict):
        email_form = {}
        for source, target in (
            ("ready", "ready"),
            ("stable", "stable"),
            ("has_input", "input"),
            ("has_submit", "submit"),
            ("busy", "busy"),
        ):
            if isinstance(readiness.get(source), bool):
                email_form[target] = readiness[source]
        ready_state = text(readiness.get("ready_state"), 16).lower()
        if ready_state in {"loading", "interactive", "complete"}:
            email_form["state"] = ready_state
        for source, target in (
            ("stable_samples", "stable_n"),
            ("sample_count", "samples"),
            ("ready_samples", "ready_n"),
            ("signature_changes", "changes"),
        ):
            value = readiness.get(source)
            if isinstance(value, bool):
                continue
            try:
                email_form[target] = min(999, max(0, int(value)))
            except (TypeError, ValueError):
                pass
        if email_form:
            compact["email_form"] = email_form
    password_submit_state = text(state.get("password_submit_state"), 32).lower()
    if password_submit_state in {
        "otp", "logged_in", "password_error", "password", "password_shell",
        "login_password", "login_password_shell", "loading", "email_page", "unknown",
    }:
        compact["password_submit_state"] = password_submit_state
    password_route_state = text(state.get("password_route_state"), 32).lower()
    if password_route_state in {
        "switching", "otp", "logged_in", "password_error", "password", "password_shell",
        "login_password", "login_password_shell", "loading", "email_page", "unknown",
    }:
        compact["password_route_state"] = password_route_state
    password_input_stage = text(state.get("password_input_stage"), 32).lower()
    if password_input_stage in {
        "select_existing", "clear_existing", "type_value", "readback", "value_not_stable",
    }:
        compact["password_input_stage"] = password_input_stage
    input_trace = []
    for raw in (state.get("password_input_diagnostics") or [])[:2]:
        if not isinstance(raw, dict):
            continue
        stage = text(raw.get("stage"), 12).lower()
        if stage not in {"before", "after"}:
            continue
        entry = {"s": stage}
        for source, target in (
            ("connected", "c"), ("active", "a"),
            ("disabled", "d"), ("read_only", "r"),
        ):
            if raw.get(source) is True:
                entry[target] = True
        for source, target in (
            ("dom_value_length", "v"),
            ("attribute_value_length", "av"),
            ("keydown_count", "k"),
            ("trusted_keydown_count", "tk"),
            ("beforeinput_count", "b"),
            ("trusted_beforeinput_count", "tb"),
            ("input_count", "i"),
            ("trusted_input_count", "ti"),
            ("change_count", "h"),
            ("focus_count", "f"),
            ("blur_count", "l"),
        ):
            value = raw.get(source)
            if isinstance(value, bool):
                continue
            try:
                number = min(99, max(0, int(value)))
            except (TypeError, ValueError):
                continue
            if number:
                entry[target] = number
        input_type = text(raw.get("last_input_type"), 40).lower()
        if re.fullmatch(r"[a-z][a-z0-9_-]{0,39}", input_type):
            entry["q"] = input_type
        input_trace.append(entry)
    if input_trace:
        compact["password_input_trace"] = input_trace
    trace = []
    for raw in (state.get("password_submit_trace") or [])[:4]:
        if not isinstance(raw, dict):
            continue
        stage = text(raw.get("s"), 20).lower()
        if stage not in {"pre", "post", "before_refresh", "after_refresh"}:
            continue
        entry = {"s": stage}
        ready = text(raw.get("r"), 16).lower()
        if ready in {"loading", "interactive", "complete"} and ready != "complete":
            entry["r"] = ready
        for key in ("i", "p", "v", "u", "f", "w"):
            value = raw.get(key)
            if isinstance(value, bool):
                continue
            try:
                number = min(99, max(0, int(value)))
            except (TypeError, ValueError):
                continue
            if key in {"i", "p", "v", "u"} or number != (0 if key == "f" else 1):
                entry[key] = number
        if isinstance(raw.get("d"), bool):
            entry["d"] = raw["d"]
        for key in ("b", "a"):
            if raw.get(key) is True:
                entry[key] = True
        challenge = text(raw.get("q"), 16).lower()
        if challenge in {"other", "captcha", "cloudflare", "arkose", "challenge"}:
            entry["q"] = challenge
        error_type = text(raw.get("e"), 48)
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,47}", error_type):
            entry["e"] = error_type
        trace.append(entry)
    if trace:
        compact["password_submit_trace"] = trace
    for key in ("visible_button_count", "visible_submit_count"):
        try:
            compact[key] = max(0, int(state.get(key)))
        except (TypeError, ValueError):
            pass
    snapshot_error = text(state.get("snapshot_error"), 48)
    if snapshot_error:
        compact["snapshot_error"] = snapshot_error
    raw_chrome_error_code = str(state.get("chrome_error_code") or "").strip()
    if re.fullmatch(r"ERR_[A-Z0-9_]{1,64}", raw_chrome_error_code):
        compact["chrome_error_code"] = raw_chrome_error_code
    else:
        chrome_error_code = text(raw_chrome_error_code, 48)
        if chrome_error_code:
            compact["chrome_error_code"] = chrome_error_code
    chrome_error_text = text(state.get("chrome_error_text"), 96)
    if chrome_error_text:
        compact["chrome_error_text"] = chrome_error_text
    alert_text = text(state.get("alert_text"), 72)
    if alert_text:
        compact["alert_text"] = alert_text

    # Worker/bridge boundary diagnostics are emitted only when the isolated
    # worker failed before returning a valid result JSON. Keep transport
    # metadata and a bounded, already-redacted stderr summary so a generic
    # ``registration failed`` cannot hide the actual startup/import error.
    worker_exit_code = state.get("worker_exit_code")
    if isinstance(worker_exit_code, int) and not isinstance(worker_exit_code, bool):
        compact["worker_exit_code"] = max(-999, min(999, worker_exit_code))
    worker_exception = text(state.get("worker_exception"), 64)
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", worker_exception):
        compact["worker_exception"] = worker_exception
    worker_boundary_reason = text(state.get("worker_boundary_reason"), 24).lower()
    if worker_boundary_reason in {"missing_stdout", "invalid_json", "invalid_result"}:
        compact["worker_boundary_reason"] = worker_boundary_reason
    worker_stderr_summary = text(state.get("worker_stderr_summary"), 180)
    if worker_stderr_summary:
        compact["worker_stderr_summary"] = worker_stderr_summary

    submit_target = action(state.get("submit_target"))
    if submit_target:
        compact["submit_target"] = submit_target

    inputs = []
    for item in state.get("inputs") or []:
        if not isinstance(item, dict):
            continue
        inputs.append({
            "type": text(item.get("type"), 32),
            "name": text(item.get("name"), 48),
            "autocomplete": text(item.get("autocomplete"), 48),
            "has_value": bool(item.get("has_value")),
        })
        break
    if inputs:
        compact["inputs"] = inputs

    # If WebDriver cannot report the clicked target, retain one actionable
    # visible submit button as a fallback. Do not retain display text or ARIA.
    for item in state.get("buttons") or []:
        candidate = action(item)
        if candidate.get("type") == "submit" or candidate.get("name") or candidate.get("value"):
            compact["buttons"] = [candidate]
            break

    # ``runs.error`` is intentionally capped at 500 chars. Preserve the action
    # outcome first; discard secondary diagnostics before a partial JSON write.
    while len(json.dumps(compact, ensure_ascii=True, separators=(",", ":"))) > 280:
        if compact.pop("inputs", None) is not None:
            continue
        if compact.pop("buttons", None) is not None:
            continue
        if compact.pop("alert_text", None) is not None:
            continue
        if compact.pop("snapshot_error", None) is not None:
            continue
        if compact.pop("visible_button_count", None) is not None:
            continue
        if compact.pop("visible_submit_count", None) is not None:
            continue
        if compact.pop("worker_stderr_summary", None) is not None:
            continue
        break
    return compact


def _roxy_daily_quota_notice(state: object) -> str:
    """Return a fixed, user-safe notice for Roxy's workspace quota stop.

    The upstream response is intentionally not passed through verbatim.  The
    bridge marks this one known, non-secret condition in ``page_state``; we
    expose only the code and the stable Chinese explanation so the UI/log does
    not collapse a pre-browser failure into the generic ``registration failed``
    text and we do not widen the error-text allowlist for arbitrary responses.
    """
    compact = _compact_roxy_page_state(state)
    if compact.get("roxy_block") != "daily_quota":
        return ""
    code = compact.get("roxy_code") or "416"
    message = "窗口单日创建次数已经超出"
    return f"Roxy 每日窗口创建额度已用尽（code={code}；{message}）"


def _roxy_page_state_error_suffix(
    error_prefix: str,
    page_state: object,
    *,
    max_total_chars: int = 480,
) -> str:
    """Serialize a Roxy state suffix without ever relying on DB truncation."""
    state = _compact_roxy_page_state(page_state)
    if not state:
        return ""
    separator = " | page_state="
    budget = max(0, int(max_total_chars) - len(error_prefix or "") - len(separator))
    if budget < 2:
        return ""

    def encoded() -> str:
        return json.dumps(state, ensure_ascii=True, separators=(",", ":"), sort_keys=True)

    def fits() -> bool:
        return len(encoded()) <= budget

    if state.get("roxy_rejection"):
        state = {"roxy_rejection": dict(state["roxy_rejection"])}
        for key in ("upstream_text_stored", "message_state", "reason_source", "http_status", "roxy_code"):
            if fits():
                break
            state["roxy_rejection"].pop(key, None)
        return separator + encoded() if fits() else ""

    if state.get("proxy_probe"):
        state = {"proxy_probe": dict(state["proxy_probe"])}
        for key in ("failure_locations", "exception_chain", "elapsed_ms", "errno", "winerror",
                    "exception_type", "service", "stage", "root_exception_type", "pass_index",
                    "http_status", "tunnel_http_status", "attempt_count", "reason"):
            if fits():
                break
            state["proxy_probe"].pop(key, None)
        return separator + encoded() if fits() else ""

    if state.get("email_submit_reason") in {
        "auth_callback_error", "browser_transport_error", "auth_route_error_500",
    }:
        state = {key: value for key, value in state.items() if key in {
            "url", "email_submit_reason", "auth_error_code", "email_submit_stage",
            "email_recovery_state", "email_submit_trace", "chrome_error_code",
        }}
        for key in ("email_submit_trace", "url", "email_recovery_state", "email_submit_stage"):
            if fits():
                break
            state.pop(key, None)
        return separator + encoded() if fits() else ""

    if state.get("session_reason") in {"auth_callback_error", "roxy_session_timeout"}:
        # Completed form traces must not crowd out the current session failure.
        state = {key: value for key, value in state.items() if key in {
            "url", "session_reason", "auth_error_code", "session_probe", "session_http",
            "session_exception", "access_present", "session_present", "profile_submit_dispatched",
        }}
        for key in ("url", "session_exception", "profile_submit_dispatched", "access_present", "session_present", "session_probe", "session_http"):
            if fits():
                break
            state.pop(key, None)
        return separator + encoded() if fits() else ""

    if not fits() and str(state.get("url") or "").startswith("chrome-error://chromewebdata/"):
        # A current browser transport failure outranks completed form activity.
        # Keep the network route and validated error code rather than spending
        # the durable error budget on stale password/email submit traces.
        network_state = {"url": state["url"]}
        network_code = str(state.get("chrome_error_code") or "")
        if re.fullmatch(r"ERR_[A-Z0-9_]{1,64}", network_code):
            network_state["chrome_error_code"] = network_code
        if "email_recovery_state" in state:
            network_state["email_recovery_state"] = state["email_recovery_state"]
        network_json = json.dumps(
            network_state, ensure_ascii=True, separators=(",", ":"), sort_keys=True
        )
        if len(network_json) > budget and "email_recovery_state" in network_state:
            # Current transport evidence remains mandatory under a tighter cap.
            network_state.pop("email_recovery_state")
            network_json = json.dumps(
                network_state, ensure_ascii=True, separators=(",", ":"), sort_keys=True
            )
        if len(network_json) <= budget:
            return separator + network_json

    if not fits():
        # Secondary display-oriented diagnostics are the first to go. The
        # trace is the actual evidence for a stuck password transition.
        for key in (
            "inputs", "buttons", "alert_text", "snapshot_error",
            "chrome_error_text", "visible_button_count", "visible_submit_count",
            "chrome_error_code",
        ):
            state.pop(key, None)
            if fits():
                break

    if not fits():
        # Preserve the exit code/type when possible; the free-form stderr
        # summary is useful but secondary under the durable error-size cap.
        state.pop("worker_stderr_summary", None)
        if fits():
            return separator + encoded()

    if not fits() and isinstance(state.get("password_submit_trace"), list):
        # Keep the two facts needed to distinguish a React value loss from a
        # disabled form.  Other DOM counts are secondary and can crowd out the
        # click provenance under the durable 500-character run-error limit.
        for entry in state["password_submit_trace"]:
            if isinstance(entry, dict):
                for key in ("r", "i", "p", "u", "f", "w", "b", "a", "q", "e"):
                    entry.pop(key, None)
        fits()

    if not fits() and isinstance(state.get("email_submit_trace"), list):
        for entry in state["email_submit_trace"]:
            if isinstance(entry, dict):
                for key in ("p", "b", "ms"):
                    entry.pop(key, None)
        fits()

    if not fits():
        for key in ("password_error", "page_busy", "submit_disabled", "password_submit_state"):
            state.pop(key, None)
            if fits():
                break

    if not fits():
        # The route is already present in the error prefix.  Preserve whether
        # React kept the password value and disabled the submit control at each
        # checkpoint before retaining duplicate URL or click metadata.
        state.pop("url", None)

    if not fits() and isinstance(state.get("password_submit_trace"), list):
        state["password_submit_trace"] = [
            {
                key: item[key]
                for key in ("s", "v", "d")
                if key in item
            }
            for item in state["password_submit_trace"]
            if isinstance(item, dict) and item.get("s")
        ]

    if not fits() and isinstance(state.get("email_submit_trace"), list):
        state["email_submit_trace"] = [
            {
                key: item[key]
                for key in ("s", "c", "e", "d", "m", "o", "r", "f", "t")
                if key in item
            }
            for item in state["email_submit_trace"]
            if isinstance(item, dict) and item.get("s")
        ]

    if not fits():
        state.pop("submit_target", None)
    if not fits() and isinstance(state.get("email_submit_trace"), list):
        # Repeated input flags can exceed the budget even after URL/timing
        # removal. Keep every transition and the recovery/click outcome first.
        state["email_submit_trace"] = [
            {
                key: item[key]
                for key in ("s", "c", "m", "o", "r", "f", "t")
                if key in item
            }
            for item in state["email_submit_trace"]
            if isinstance(item, dict) and item.get("s")
        ]
    if not fits():
        state.pop("password_submit_trace", None)
    if not fits() and isinstance(state.get("email_submit_trace"), list):
        # A last-resort stage/state timeline is still better than losing the
        # entire trace. Do not enlarge the durable error limit or truncate JSON.
        state["email_submit_trace"] = [
            {key: item[key] for key in ("s", "c") if key in item}
            for item in state["email_submit_trace"]
            if isinstance(item, dict) and item.get("s")
        ]
    if not fits():
        state.pop("email_submit_trace", None)
    if not state or not fits():
        return ""
    return separator + encoded()


class RoxyRegistrationError(RuntimeError):
    """Secret-free worker failure with authoritative structured provenance."""

    def __init__(
        self,
        message: str,
        *,
        failure_phase: str,
        exception_type: str,
        page_state: dict | None = None,
        failure_cause: str = "",
        failure_locations: str = "",
        otp_metadata: dict | None = None,
    ):
        self.failure_phase = failure_phase
        self.exception_type = exception_type
        self.page_state = dict(page_state) if isinstance(page_state, dict) else {}
        self.roxy_rejection = safe_roxy_rejection_metadata(self.page_state.get("roxy_rejection"))
        if failure_phase == "otp_wait":
            metadata = safe_otp_failure_metadata(otp_metadata)
            self.exception_type = metadata.get("exception_type", "Error")
            exception_type = self.exception_type
            for key in ("exception_type", "failure_cause", "relay_network_error_kind", "otp_wait_diagnostics"):
                if key in metadata:
                    setattr(self, key, metadata[key])
        if failure_phase == "session" and failure_cause in {
            "auth_callback_error", "roxy_session_timeout",
        }:
            self.failure_cause = failure_cause
            self.safe_message = {
                "auth_callback_error": "ChatGPT auth callback failed; Access/Session unavailable",
                "roxy_session_timeout": "ChatGPT Access/Session wait timed out",
            }[failure_cause]
            message = self.safe_message
        if failure_phase == "email_submit" and failure_cause in {
            "auth_callback_error", "browser_transport_error", "auth_route_error_500",
        }:
            self.failure_cause = failure_cause
            self.safe_message = {
                "auth_callback_error": "Email authentication ended on /auth/error",
                "browser_transport_error": "Email authentication browser transport failed",
                "auth_route_error_500": "Email authentication returned HTTP 500",
            }[failure_cause]
            message = self.safe_message
        self.worker_failure_locations = " > ".join(
            entry for entry in str(failure_locations or "").split(" > ")[-8:]
            if re.fullmatch(
                r"(?:roxy_worker\.py:[1-9][0-9]{0,6}:(?:run|_fetch_session_state_driven|_read_chatgpt_session_cdp_once|_otp|_otp_with_one_resend|_submit_email_with_validated_legacy|_raise_email_terminal_error)"
                r"|roxy_bridge\.py:[1-9][0-9]{0,6}:(?:_wait_for_otp_with_budget|do_POST)"
                r"|icloud_relay\.py:[1-9][0-9]{0,6}:(?:wait_for_otp|_poll_messages))",
                entry,
            )
        )
        super().__init__(
            f"{message} | failure_phase={failure_phase}; "
            f"exception_type={exception_type}"
        )


def _record_registration_phase(run_id: str, phase: str) -> None:
    """Best-effort secret-free timing ledger write."""
    if not run_id:
        return
    ledger_phase = "two_fa_bound" if phase == "2fa_bound" else phase
    try:
        recorded = db.record_run_phase(run_id, ledger_phase)
    except Exception:  # noqa: BLE001 - timing must never interrupt registration
        recorded = False
    if not recorded:
        logging.getLogger("registrar").warning(
            "[register] phase timing write failed"
        )


def run_repo_owned_roxy_registration(
    account: dict,
    options: dict,
    mail_provider,
    *,
    name: str = "",
    birthday: str = "",
) -> dict:
    """Run browser creation with Roxy while repo_0810 owns every durable ledger."""
    from .roxy_bridge import run_browser_registration

    worker_options = dict(options or {})
    email = (account.get("email") or "").strip().lower()
    saved = db.get_registered(email, include_pending_password=True) or {}
    candidate_password = (saved.get("password") or "").strip()
    saved_extra = saved.get("extra") if isinstance(saved.get("extra"), dict) else {}
    candidate_password_verified = bool(
        candidate_password and saved_extra.get("pending") is False
    )
    if not candidate_password:
        candidate_password = generate_candidate_password()
        db.save_password_candidate(email, candidate_password)
        confirmed = db.get_registered(email, include_pending_password=True) or {}
        if (confirmed.get("password") or "") != candidate_password:
            raise RuntimeError("Roxy 候选密码启动前持久化回读失败")
    worker_options["candidate_password"] = candidate_password
    worker_options["candidate_password_verified"] = candidate_password_verified

    run_id = str(worker_options.pop("_run_id", "") or "")

    def report_roxy_phase(phase: str) -> None:
        if run_id:
            _record_registration_phase(run_id, f"roxy_{phase}")
            _emit_status(
                run_id,
                "phase",
                {"phase": f"roxy_{phase}", "email": email},
            )

    def reserve_roxy_profile(profile_id: str, ip_tag: str) -> dict:
        return db.reserve_roxy_profile_use(
            profile_id,
            ip_tag,
            limit=ROXY_PROFILE_USE_LIMIT,
        )

    def retire_roxy_profile_egress(profile_id: str, ip_tag: str) -> None:
        db.retire_roxy_profile_egress(profile_id, ip_tag)

    system_direct = bool(worker_options.get("roxy_system_direct"))
    result = run_browser_registration(
        account=account,
        options=worker_options,
        mail_provider=mail_provider,
        name=name,
        birthday=birthday,
        progress_callback=report_roxy_phase,
        profile_reserver=None if system_direct else reserve_roxy_profile,
        profile_retirer=None if system_direct else retire_roxy_profile_egress,
        retired_profile_ids=(
            set() if system_direct else set(db.list_retired_roxy_profile_ids())
        ),
        retired_ip_tags=(
            set() if system_direct else set(db.list_retired_roxy_ip_tags())
        ),
    )
    result = _enforce_roxy_password_acceptance_evidence(result)
    email = (result.get("email") or account.get("email") or "").strip().lower()
    password = (result.get("password") or "").strip()
    password_accepted = bool(
        result.get("password_set") or result.get("password_verified")
    )
    if password_accepted and email and password:
        # The candidate was saved before worker startup. Promote it only after
        # this same browser registration session confirms password acceptance.
        if not db.mark_password_verified(email, password):
            raise RuntimeError("Roxy 服务端已接受密码，但本地候选密码提升失败")
    if not result.get("success"):
        message = safe_public_error(
            str(result.get("error") or "Roxy 浏览器注册失败"),
            "Roxy browser registration",
        )
        failure_phase = str(result.get("failure_phase") or "unknown")
        exception_type = str(result.get("exception_type") or "Error")
        if failure_phase not in {
            "worker_preflight", "open_profile", "browser_prepare", "email_submit",
            "password_route", "password_submit", "otp", "otp_wait", "otp_submit",
            "profile", "session", "otp_submitted", "browser_complete",
        }:
            failure_phase = "unknown"
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,79}", exception_type):
            exception_type = "Error"
        if failure_phase == "otp_wait":
            # OTP numbers come from structured timing/count fields, never HTTP text.
            message = "Roxy OTP wait failed"
        safe_state = _compact_roxy_page_state(result.get("page_state"))
        quota_notice = _roxy_daily_quota_notice(safe_state)
        if quota_notice:
            message = quota_notice
        if safe_state:
            message += " | page_state=" + json.dumps(
                safe_state, ensure_ascii=True, separators=(",", ":"), sort_keys=True
            )
        raise RoxyRegistrationError(
            message,
            failure_phase=failure_phase,
            exception_type=exception_type,
            page_state=safe_state,
            failure_cause=str(result.get("failure_cause") or ""),
            failure_locations=str(result.get("failure_locations") or ""),
            otp_metadata=result if failure_phase == "otp_wait" else None,
        )
    try:
        return complete_roxy_browser_credentials(result, mail_provider, options)
    except RoxyRegistrationError:
        raise
    except Exception as exc:
        raise RoxyRegistrationError(
            safe_public_error(exc, "Roxy browser completion"),
            failure_phase="browser_complete",
            exception_type=type(exc).__name__,
        ) from exc


def run_repo_owned_roxy_password_reset(
    account: dict,
    options: dict,
    mail_provider,
) -> dict:
    """Run the browser-only forgot-password flow under the repo-owned ledger."""
    from .roxy_bridge import run_browser_password_reset

    worker_options = dict(options or {})
    email = (account.get("email") or "").strip().lower()
    run_id = str(worker_options.pop("_run_id", "") or "")

    def report_roxy_phase(phase: str) -> None:
        if run_id:
            _record_registration_phase(run_id, f"roxy_{phase}")
            _emit_status(run_id, "phase", {"phase": f"roxy_{phase}", "email": email})

    def reserve_roxy_profile(profile_id: str, ip_tag: str) -> dict:
        return db.reserve_roxy_profile_use(profile_id, ip_tag, limit=ROXY_PROFILE_USE_LIMIT)

    def retire_roxy_profile_egress(profile_id: str, ip_tag: str) -> None:
        db.retire_roxy_profile_egress(profile_id, ip_tag)

    system_direct = bool(worker_options.get("roxy_system_direct"))
    result = run_browser_password_reset(
        account=account,
        options=worker_options,
        mail_provider=mail_provider,
        progress_callback=report_roxy_phase,
        profile_reserver=None if system_direct else reserve_roxy_profile,
        profile_retirer=None if system_direct else retire_roxy_profile_egress,
        retired_profile_ids=(set() if system_direct else set(db.list_retired_roxy_profile_ids())),
        retired_ip_tags=(set() if system_direct else set(db.list_retired_roxy_ip_tags())),
    )
    if (result.get("success") is True and result.get("password_set") is True
            and result.get("password_verified") is True
            and result.get("password") == worker_options.get("candidate_password")
            and result.get("password")):
        return result
    if not result.get("success"):
        failure_phase = str(result.get("failure_phase") or "password_reset")
        exception_type = str(result.get("exception_type") or "Error")
        safe_state = _compact_roxy_page_state(result.get("page_state"))
        message = safe_public_error(
            str(result.get("error") or "Roxy 自动重置密码失败"),
            "Roxy password reset",
        )
        if safe_state:
            message += " | page_state=" + json.dumps(
                safe_state, ensure_ascii=True, separators=(",", ":"), sort_keys=True
            )
        raise RoxyRegistrationError(
            message,
            failure_phase=failure_phase,
            exception_type=exception_type,
            page_state=safe_state,
            failure_cause=str(result.get("failure_cause") or ""),
            failure_locations=str(result.get("failure_locations") or ""),
        )
    raise RoxyRegistrationError(
        "Roxy 自动重置密码未返回明确成功证据",
        failure_phase="password_reset_submit",
        exception_type="RuntimeError",
    )


def run_protocol_password_reset(
    account: dict,
    options: dict,
    mail_provider,
) -> dict:
    """通过官方 auth API 完成传统 forgot-password 重置，不创建 Roxy profile。"""
    from config import resolve_proxy
    from auth_flow import AuthFlow

    worker_options = dict(options or {})
    email = (account.get("email") or "").strip().lower()
    candidate_password = str(worker_options.pop("candidate_password", "") or "")
    if not candidate_password:
        raise RuntimeError("协议重置缺少本轮候选密码")
    cfg = Config()
    cfg.proxy = resolve_proxy(worker_options.get("proxy"))
    env_overrides = {
        "OTP_TIMEOUT": str(normalize_otp_timeout(worker_options.get("otp_timeout"))),
        "WEBUI_ALLOW_LOGIN": "1",
        "OAUTH_CODEX_RT_EXCHANGE": "0",
        "OAUTH_CODEX_RT_BEFORE_CALLBACK": "0",
    }
    flow = AuthFlow(cfg, env_overrides=env_overrides)
    run_id = str(worker_options.get("_run_id") or "")
    current_phase = "starting"
    flow._password_reset_phase = current_phase
    flow._password_reset_last_response_metadata = {}

    def progress(phase: str, message: str) -> None:
        nonlocal current_phase
        current_phase = phase
        flow._password_reset_phase = phase
        flow._password_reset_last_response_metadata = {}
        if run_id:
            _record_registration_phase(run_id, f"protocol_{phase}")
            _emit_status(run_id, "phase", {"phase": f"protocol_{phase}", "email": email, "message": message})

    try:
        return flow.run_protocol_password_reset(
            mail_provider,
            email,
            candidate_password,
            otp_timeout=normalize_otp_timeout(worker_options.get("otp_timeout")),
            cancel_event=worker_options.get("_cancel_event"),
            progress_callback=progress,
        )
    except Exception as exc:
        if not getattr(exc, "failure_phase", None):
            exc.failure_phase = current_phase
        response_metadata = flow._password_reset_last_response_metadata
        if not getattr(exc, "http_status", None) and response_metadata.get("http_status"):
            exc.http_status = response_metadata["http_status"]
        if not getattr(exc, "error_code", None) and response_metadata.get("error_code"):
            exc.error_code = response_metadata["error_code"]
        for key in (
            'error_type', 'error_code_source', 'error_code_state', 'upstream_error_present',
        ):
            if key in response_metadata:
                setattr(exc, key, response_metadata[key])
        if not getattr(exc, "failure_cause", None) and response_metadata.get("http_status", 0) >= 400:
            exc.failure_cause = "upstream_http_error"
        exc.diagnostics = safe_password_reset_diagnostics(
            getattr(getattr(flow, "result", None), "registration_diagnostics", None),
        )
        exc.failure_locations = safe_traceback_summary(exc, {
            str(ROOT / "auth_flow.py"), str(ROOT / "webui/registrar.py"),
            str(ROOT / "mail_providers/icloud_relay.py"),
        })
        raise
    finally:
        # Each proxy attempt owns its auth session. Do not carry cookies across
        # endpoints or keep a failed connection alive after releasing its lease.
        try:
            flow.session.close()
        except Exception:
            pass


def _password_reset_result(email: str, status: str, message: str, **metadata) -> dict:
    return safe_password_reset_result({"email": email, "status": status, **metadata})


def _password_reset_mailbox(email: str) -> dict | None:
    mailbox = db.get_account(email)
    if not mailbox:
        mailbox = db.get_rebind_mailbox(email)
        if mailbox:
            mailbox = dict(mailbox, kind="rebind_api")
    return mailbox


def _password_reset_preflight(email: str) -> dict | None:
    """Local-only prerequisites, before acquiring a proxy or touching the mailbox."""
    eligibility, _registered = get_password_reset_eligibility(email)
    if eligibility == "not_found":
        return _password_reset_result(email, "not_found", "")
    if eligibility != "eligible":
        return _password_reset_result(email, "skipped", "")
    if not _password_reset_mailbox(email):
        return _password_reset_result(
            email, "mailbox_missing", "", failure_phase="mailbox_lookup", failure_cause="mailbox_missing",
        )
    return None


def get_password_reset_eligibility(email: str) -> tuple[str, dict | None]:
    """Return whether an identity is still explicitly waiting for recovery."""
    normalized = (email or "").strip().lower()
    registered = (
        db.get_registered(normalized, include_pending_password=True)
        if normalized else None
    )
    if not registered:
        return "not_found", None
    extra = registered.get("extra")
    if not isinstance(extra, dict):
        extra = {}
    reason = str(extra.get("pending_reason") or "").strip()
    if extra.get('frozen'):
        return 'frozen', registered
    if reason not in db.PASSWORD_RECOVERY_PENDING_REASONS:
        return "not_pending", registered
    return "eligible", registered


def reset_registered_password_account(
    email: str,
    options: dict,
    emit=None,
    cancel_event: threading.Event | None = None,
) -> dict:
    """Automatically reset one explicitly password-recovery-pending account."""
    normalized = (email or "").strip().lower()
    if cancel_event is not None and cancel_event.is_set():
        return _password_reset_result(normalized, "cancelled", "任务已取消")
    eligibility, registered = get_password_reset_eligibility(normalized)
    if eligibility == "not_found" or not registered:
        return _password_reset_result(normalized, "not_found", "找不到注册结果")
    if eligibility != "eligible":
        return _password_reset_result(normalized, "skipped", "账号当前不是待自动重置状态")
    mailbox = _password_reset_mailbox(normalized)
    if not mailbox:
        return _password_reset_result(
            normalized,
            "mailbox_missing",
            "邮箱池中找不到对应接码记录",
            failure_phase="mailbox_lookup",
            failure_cause="mailbox_missing",
        )

    def push(phase: str, message: str) -> None:
        if emit:
            emit("phase", {"email": normalized, "phase": phase, "message": message})

    try:
        mailbox_kind = (mailbox.get("kind") or "outlook").strip().lower()
        if mailbox_kind == "rebind_api":
            from .rebind_mail_provider import RebindApiMailProvider
            provider = RebindApiMailProvider.from_config({}, mailbox)
        else:
            provider = create_mail_provider(mailbox_kind, db.get_mail_settings(), mailbox)
        if cancel_event is not None:
            try:
                provider._cancel_event = cancel_event
            except Exception:
                pass
        if callable(getattr(provider, "prepare_for_otp", None)):
            provider.prepare_for_otp()
        password = generate_candidate_password()
        push("password_reset_start", "正在为账号生成一次性新密码")
        run_id = str(getattr(_current_run, "run_id", "") or "")
        account_options = {
            **dict(options or {}),
            "_run_id": run_id,
            "_cancel_event": cancel_event,
            "candidate_password": password,
            "otp_timeout": normalize_otp_timeout((options or {}).get("otp_timeout")),
        }
        result = run_protocol_password_reset(
            {"email": normalized},
            account_options,
            provider,
        )
        if (
            not isinstance(result, dict)
            or result.get("success") is not True
            or result.get("password_set") is not True
        ):
            return _password_reset_result(
                normalized,
                "reset_failed",
                "官网未返回明确的密码重置成功证据，本地未保存新密码",
                failure_phase="password_submit",
                failure_cause="missing_reset_success",
            )
        # The website may already have committed the password when cancellation
        # arrives. Always persist that confirmed result before stopping the batch.
        if not db.mark_password_verified(normalized, password, allow_recovery_replace=True):
            return _password_reset_result(normalized, "persist_failed", "官网已返回成功，但本地密码未能安全保存")
        push("password_reset_saved", "官网密码已重置，新密码已安全保存")
        return _password_reset_result(normalized, "success", "密码已自动重置并保存")
    except Exception as exc:
        metadata = safe_password_reset_failure_metadata(exc)
        return _password_reset_result(
            normalized,
            "cancelled" if metadata.get("failure_cause") == "cancelled" or (cancel_event is not None and cancel_event.is_set()) else "reset_failed",
            "", **metadata,
        )


PASSWORD_RESET_MAX_PROXY_ATTEMPTS = 3


def _password_reset_can_switch_proxy(result: dict) -> bool:
    """Recover transport faults before any OTP or password submission only."""
    if result.get('status') != 'reset_failed' or result.get('failure_phase') not in {
        'proxy_check', 'warmup', 'csrf', 'auth_url', 'oauth_init', 'sentinel',
        'identify_account', 'reset_page',
    }:
        return False
    status = result.get('http_status')
    if status in {400, 401, 403, 429}:
        return False
    if result.get('transport_code') == 60 or result.get('transport_reason') in {
        'tls_verification_failed', 'ssl_error',
    }:
        return False
    if status is not None:
        return status in {407, 502, 503, 504}
    if result.get('error_code'):
        return False
    return result.get('failure_cause') == 'transport_failed' and result.get('transport_kind') in {
        'dns', 'tls', 'timeout', 'connection',
    }


def _reset_password_with_proxy_failover(email: str, options: dict, emit, cancel_event) -> dict:
    """Bounded recovery with exclusive, distinct endpoints and fresh auth flows."""
    from .auto_loop import CONTROLLER as AUTO_LOOP, _proxy_resource_key

    if not (options.get('protocol_use_proxy_pool') or options.get('fixed_asn_config')):
        return reset_registered_password_account(email, options, emit=emit, cancel_event=cancel_event)
    tried: set[tuple] = set()
    history = []
    result = _password_reset_result(email, 'reset_failed', '')
    stop = 'not_retryable'
    for attempt in range(1, PASSWORD_RESET_MAX_PROXY_ATTEMPTS + 1):
        if cancel_event.is_set():
            result = _password_reset_result(email, 'cancelled', '')
            stop = 'cancelled'
            break
        lease = None
        try:
            lease = AUTO_LOOP.acquire_protocol_proxy(
                str(options.get('proxy_pool') or ''), options.get('fixed_asn_config'),
                timeout=30, excluded_keys=tried, cancel_event=cancel_event,
            )
        except Exception as exc:
            if cancel_event.is_set():
                result = _password_reset_result(email, 'cancelled', '')
                stop = 'cancelled'
            else:
                stop = 'no_next_proxy'
                if not history:
                    metadata = safe_password_reset_failure_metadata(exc)
                    metadata.update(failure_phase='proxy_acquire', failure_cause='proxy_unavailable')
                    result = _password_reset_result(email, 'reset_failed', '', **metadata)
            break
        release_failed = False
        try:
            key = _proxy_resource_key(lease.proxy)
            if key[0] in {'direct', 'raw'} or key[0] not in {'http', 'https', 'socks5', 'socks5h'}:
                result = _password_reset_result(email, 'reset_failed', '',
                    failure_phase='proxy_acquire', failure_cause='proxy_unavailable')
                stop = 'no_next_proxy'
                break
            if key in tried:
                stop = 'no_next_proxy'
                break
            tried.add(key)
            attempt_options = dict(options, proxy=lease.proxy)
            attempt_options.pop('proxy_screening', None)
            if lease.screening:
                attempt_options['proxy_screening'] = dict(lease.screening)
            result = reset_registered_password_account(
                email, attempt_options, emit=emit, cancel_event=cancel_event)
        finally:
            try:
                lease.release()
            except Exception:
                # A confirmed remote/password persistence result must survive
                # resource cleanup failures, but no additional lease is taken.
                release_failed = True
                result['proxy_release_failed'] = True
                stop = 'lease_release_failed'
                logging.getLogger('registrar').error(
                    'password reset proxy lease release failed; further proxy attempts stopped')
        result = safe_password_reset_result(result)
        history.append({key: value for key, value in result.items()
                        if key not in {'email', 'message', 'diagnostics', 'index', 'category'}})
        if release_failed:
            break
        if result['status'] == 'success':
            stop = 'completed'
            break
        if cancel_event.is_set() or result['status'] == 'cancelled':
            stop = 'cancelled'
            break
        if not _password_reset_can_switch_proxy(result):
            stop = 'not_retryable'
            break
        if attempt == PASSWORD_RESET_MAX_PROXY_ATTEMPTS:
            stop = 'max_attempts'
            break
        emit('phase', {'email': email, 'phase': 'proxy_switch',
                      'message': f'当前连接失败，正在获取下一条代理（最多 {PASSWORD_RESET_MAX_PROXY_ATTEMPTS} 次）'})
        if cancel_event.wait(1.0 * attempt):
            result = _password_reset_result(email, 'cancelled', '')
            stop = 'cancelled'
            break
    result.update(proxy_attempts=len(history), proxy_switches=max(0, len(history) - 1),
                  proxy_max_attempts=PASSWORD_RESET_MAX_PROXY_ATTEMPTS,
                  proxy_retry_stop=stop, proxy_attempt_history=history)
    return safe_password_reset_result(result)


def _do_registered_password_reset_batch(
    run_id: str,
    emails: list[str],
    options: dict,
    log_file: Path,
    cancel_event: threading.Event,
) -> None:
    """Run the protocol forgot-password flow for each pending identity."""
    _current_run.run_id = run_id
    counts: dict[str, int] = {}
    account_results: list[dict] = []
    handler = QueueLogHandler(run_id, log_file)
    handler.setLevel(logging.INFO)
    root_logger = logging.getLogger()
    root_logger.addHandler(handler)

    def record_result(index: int, result: dict) -> None:
        # The authoritative index/email come from this run, not from an exception.
        result = safe_password_reset_result({**result, "email": emails[index - 1], "index": index})
        account_results.append(result)
        counts[result["status"]] = counts.get(result["status"], 0) + 1
        event = {
            "event": "password_reset_account_result", "v": 1, "run_id": run_id,
            "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "upstream_text_stored": False, **result,
        }
        logging.getLogger("registrar").log(
            logging.INFO if result["status"] in {"success", "skipped", "cancelled"} else logging.WARNING,
            json.dumps(event, ensure_ascii=False, separators=(",", ":"), sort_keys=True),
        )
        _emit_status(run_id, "account_result", result)

    def outcome() -> dict:
        return {
            "type": "password_reset_batch", "total": len(emails),
            "accounts": sorted(account_results, key=lambda item: item["index"]),
        }

    def batch_category() -> str:
        categories = {item["category"] for item in account_results if item.get("category")}
        return (next(iter(categories)) if len(categories) == 1 else "mixed") if categories else ""
    try:
        _emit_status(
            run_id,
            "batch_start",
            {
                "total": len(emails),
                "message": f"开始自动重置 {len(emails)} 个待处理账号",
            },
        )
        try:
            concurrency = int((options or {}).get("concurrency") or 1)
        except (TypeError, ValueError):
            concurrency = 1
        concurrency = max(1, min(3, concurrency))
        stopped_for_rate_limit = False
        next_index = 0

        def process_account(index: int, email: str) -> tuple[int, dict]:
            _current_run.run_id = run_id
            try:
                if cancel_event.is_set():
                    result = _password_reset_result(email, "cancelled", "任务已取消")
                elif (preflight := _password_reset_preflight(email)) is not None:
                    result = preflight
                else:
                    _emit_status(
                        run_id,
                        "phase",
                        {
                            "phase": "account_start",
                            "email": email,
                            "index": index,
                            "total": len(emails),
                            "message": f"正在自动重置第 {index}/{len(emails)} 个账号",
                        },
                    )
                    result = _reset_password_with_proxy_failover(
                        email, dict(options or {}),
                        lambda kind, payload: _emit_status(run_id, kind, payload), cancel_event,
                    )
            except Exception as exc:
                result = _password_reset_result(
                    email,
                    "reset_failed",
                    safe_public_error(exc, "password reset"),
                    **safe_password_reset_failure_metadata(exc),
                )
            finally:
                _current_run.run_id = None
            return index, safe_password_reset_result({**result, "email": email})

        from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait

        with ThreadPoolExecutor(
            max_workers=concurrency,
            thread_name_prefix=f"password-reset-{run_id}",
        ) as executor:
            active = {}

            def fill_available_workers() -> None:
                nonlocal next_index
                while (
                    len(active) < concurrency
                    and next_index < len(emails)
                    and not cancel_event.is_set()
                    and not stopped_for_rate_limit
                ):
                    index = next_index + 1
                    email = emails[next_index]
                    next_index += 1
                    context = copy_context()
                    active[executor.submit(context.run, process_account, index, email)] = (index, email)

            fill_available_workers()
            while active:
                done, _pending = wait(active, return_when=FIRST_COMPLETED)
                completed = []
                for future in done:
                    index, email = active.pop(future)
                    try:
                        _returned_index, result = future.result()
                    except Exception as exc:
                        result = _password_reset_result(
                            email,
                            "reset_failed",
                            safe_public_error(exc, "password reset"),
                            **safe_password_reset_failure_metadata(exc),
                        )
                    completed.append((index, result))
                for _index, result in sorted(completed, key=lambda item: item[0]):
                    record_result(_index, result)
                    message = str(result.get("message") or "").lower()
                    error_code = str(result.get("error_code") or "").lower()
                    if (
                        "rate limit" in message
                        or "限流" in message
                        or "429" in message
                        or error_code == "rate_limit_exceeded"
                        or result.get("http_status") == 429
                    ):
                        stopped_for_rate_limit = True
                if not cancel_event.is_set() and not stopped_for_rate_limit:
                    fill_available_workers()

        cancelled = cancel_event.is_set()
        if cancelled:
            for index, email in enumerate(emails[next_index:], start=next_index + 1):
                result = _password_reset_result(email, "cancelled", "任务已取消，未处理")
                record_result(index, result)
            db.finish_run(run_id, "cancelled", "用户取消", result=outcome())
            _emit_status(
                run_id,
                "batch_cancelled",
                {"total": len(emails), "counts": counts, "message": "任务已取消"},
            )
        elif stopped_for_rate_limit:
            for index, email in enumerate(emails[next_index:], start=next_index + 1):
                result = _password_reset_result(
                    email, "deferred_rate_limited", "检测到授权限流，已停止剩余账号",
                )
                record_result(index, result)
            message = "检测到授权限流，已停止剩余账号"
            db.finish_run(run_id, "failed", message, batch_category(), result=outcome())
            _emit_status(
                run_id,
                "batch_done",
                {
                    "total": len(emails),
                    "counts": counts,
                    "outcome": "failed",
                    "message": message,
                },
            )
        else:
            failed = any(
                status not in {"success", "skipped"}
                and status != "cancelled"
                for status in counts
            )
            message = "处理完成" if not failed else "部分账号自动重置失败"
            db.finish_run(run_id, "failed" if failed else "done", message if failed else "", batch_category(), result=outcome())
            _emit_status(
                run_id,
                "batch_done",
                {
                    "total": len(emails),
                    "counts": counts,
                    "outcome": "failed" if failed else "done",
                    "message": message,
                },
            )
    except Exception as exc:
        safe_error = safe_public_error(exc, "password reset batch")
        db.finish_run(run_id, "failed", safe_error, "unknown", result=outcome())
        _emit_status(run_id, "error", {"message": safe_error})
    finally:
        try:
            root_logger.removeHandler(handler)
            handler.close()
        except Exception:
            pass
        q = _run_queues.get(run_id)
        if q is not None:
            q.put(None)
        with _lock:
            _run_cancel_events.pop(run_id, None)
        _current_run.run_id = None


def get_registered_password_reset_snapshot(run_id: str) -> dict | None:
    """Read bounded, whitelisted progress without consuming the SSE queue."""
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,96}', str(run_id or '')):
        return None
    task = db.password_reset_task_metadata(run_id)
    if not task:
        return None
    active = task['status'] in {'running', 'pending', 'in_progress', 'cancelling'}
    results = {}
    receipt = {}
    try:
        receipt = json.loads(task.get('result_json') or '{}')
    except (TypeError, ValueError):
        pass
    if not isinstance(receipt, dict):
        receipt = {}
    if receipt.get('type') == 'password_reset_batch' and isinstance(receipt.get('accounts'), list):
        for item in receipt['accounts'][:100]:
            if isinstance(item, dict):
                safe = safe_password_reset_result(item)
                if safe['email']:
                    results[safe['email']] = safe
    if active:
        # Each completed account was already logged/flushed by record_result.
        # A bounded local tail is sanitized again; never return raw log lines.
        path = LOG_DIR / f'{run_id}.log'
        try:
            with path.open('rb') as stream:
                stream.seek(0, 2)
                stream.seek(max(0, stream.tell() - 512 * 1024))
                raw = stream.read(512 * 1024)
            allowed_emails = set(task['emails'])
            for line in raw.decode('utf-8', errors='replace').splitlines():
                try:
                    event = json.loads(line[line.index('{'):])
                except (ValueError, TypeError):
                    continue
                if not isinstance(event, dict) or event.get('event') != 'password_reset_account_result' or event.get('run_id') != run_id:
                    continue
                safe = safe_password_reset_result(event)
                if safe['email'] in allowed_emails:
                    results[safe['email']] = safe
        except OSError:
            pass
        accounts = [results.get(email, {'email':email, 'status':'pending', 'message':'等待处理或正在重置'}) for email in task['emails']]
        total = len(task['emails'])
    else:
        accounts = list(results.values())
        count = receipt.get('total')
        total = count if type(count) is int and 1 <= count <= 100 else 0
    return {'ok':True, 'run_id':run_id, 'status':task['status'], 'total':total,
            'accounts':accounts, 'receipt_complete':not active and total > 0 and len(accounts) == total,
            'upstream_text_stored':False}


def start_registered_password_reset_batch(emails: list[str], options: dict, *, client_run_id: str = "") -> str:
    cleaned = _normalize_reauthorization_emails(emails)
    if not cleaned:
        raise ValueError("没有可处理的待重置账号")
    if client_run_id and not re.fullmatch(r'[a-f0-9]{32}', client_run_id):
        raise ValueError('invalid password reset task identity')
    run_id = client_run_id or uuid.uuid4().hex[:12]
    log_file = LOG_DIR / f"{run_id}.log"
    db.create_run(
        run_id,
        cleaned[0],
        str(log_file),
        run_kind="password_reset",
        required_registered_emails=cleaned,
    )
    q: queue.Queue = queue.Queue()
    cancel_event = threading.Event()
    with _lock:
        _run_queues[run_id] = q
        _run_cancel_events[run_id] = cancel_event
    context = copy_context()
    thread = threading.Thread(
        target=context.run,
        args=(_do_registered_password_reset_batch, run_id, cleaned, dict(options or {}), log_file, cancel_event),
        daemon=True,
        name=f"password-reset-{run_id}",
    )
    try:
        thread.start()
    except BaseException:
        db.finish_run(run_id, "failed", "自动重置任务启动失败", "unknown")
        with _lock:
            _run_queues.pop(run_id, None)
            _run_cancel_events.pop(run_id, None)
        raise
    return run_id


def cancel_registered_password_reset_batch(run_id: str) -> bool:
    normalized = (run_id or "").strip()
    with _lock:
        cancel_event = _run_cancel_events.get(normalized)
    if cancel_event is None:
        return False
    cancel_event.set()
    _emit_status(
        normalized,
        "phase",
        {"phase": "cancelling", "message": "正在取消任务，当前账号会尽快停止"},
    )
    return True


def select_registration_credentials(credentials: dict, options: dict) -> dict:
    """Keep mandatory password/session/2FA fields plus optional refresh data."""
    selected = {
        "email": credentials.get("email", ""),
        "password": credentials.get("password", ""),
        "access_token": credentials.get("access_token", ""),
        "session_token": credentials.get("session_token", ""),
        "cookie_header": credentials.get("cookie_header", ""),
        "totp_secret": credentials.get("totp_secret", ""),
        "totp_factor_id": credentials.get("totp_factor_id", ""),
    }
    diagnostics = credentials.get("registration_diagnostics")
    if diagnostics:
        selected["registration_diagnostics"] = diagnostics
    if options.get("want_refresh_token", True):
        selected["refresh_token"] = credentials.get("refresh_token", "")
        selected["id_token"] = credentials.get("id_token", "")
    return selected


def ensure_requested_registration_outputs(credentials: dict, options: dict) -> None:
    """Require password, ChatGPT authorization, and local TOTP recovery data.

    A Codex refresh token is optional: accounts without an SMS provider may be
    unable to pass the add-phone gate, while their password, ChatGPT session,
    and TOTP enrollment are already complete and independently usable.
    """
    required_fields = (
        "password",
        "access_token",
        "session_token",
        "totp_secret",
        "totp_factor_id",
    )
    missing = [field for field in required_fields if not credentials.get(field)]
    if missing:
        raise RuntimeError(
            "流程未取得必需结果，不能标记为完成：" + ", ".join(missing)
        )


def _reauthorization_result(email: str, status: str, message: str) -> dict:
    return {"email": email, "status": status, "message": message}


_REAUTHORIZATION_SUCCESS_STATUSES = {
    'reauthorized_2fa_bound',
    'reauthorized_already_2fa',
}
_REAUTHORIZATION_SKIPPED_STATUSES = {
    'skipped_no_password',
    'not_found',
    'mailbox_missing',
}


def _summarize_reauthorization_failure(counts: dict[str, int], results: list[dict]) -> str:
    failed_count = sum(
        count
        for status, count in counts.items()
        if status not in _REAUTHORIZATION_SUCCESS_STATUSES
        and status not in _REAUTHORIZATION_SKIPPED_STATUSES
        and status != 'cancelled'
    )
    first_message = next(
        (
            (result.get('message') or '').strip()
            for result in results
            if result.get('status') not in _REAUTHORIZATION_SUCCESS_STATUSES
            and result.get('status') not in _REAUTHORIZATION_SKIPPED_STATUSES
            and result.get('status') != 'cancelled'
            and (result.get('message') or '').strip()
        ),
        '',
    )
    if '普通邮箱验证码待完成' in first_message:
        reason = '普通邮箱验证码待完成'
    elif 'verify-your-identity' in first_message.lower():
        reason = '邮箱验证待完成'
    else:
        reason = first_message[:180] or '账号登录、授权或 2FA 处理失败'
    return f'{failed_count} 个账号处理失败：{reason}'


_ACCOUNT_BANNED_MARKERS = (
    "account_deactivated",
    "accountdeactivated",
    "deactivated",
    "has been deactivated",
    "disabled",
    "suspended",
    "banned",
    "violat",
    "potential abuse",
    "terminated",
    "账号已停用",
    "账号被停用",
    "账号已封禁",
    "账号被封禁",
)


def _looks_account_banned(message: str) -> bool:
    lowered = (message or "").lower()
    return any(marker in lowered for marker in _ACCOUNT_BANNED_MARKERS)


def _looks_invalid_password(message: str) -> bool:
    lowered = (message or "").lower()
    return (
        "invalid_username_or_password" in lowered
        or "密码登录失败: 401" in message
    )


def _looks_authorization_throttled(message: str) -> bool:
    """判断错误是否表示授权入口被限流/拦截。

    这类错误不能按普通账号失败继续跑下一个账号，否则同一批任务会在
    限流窗口内持续撞击 authorize/continue，最终更容易升级为 Cloudflare
    拦截。这里只匹配明确的限流或挑战页信号，不把普通 HTTP 403 一概当成限流。
    """
    lowered = (message or "").lower()
    return any(
        marker in lowered
        for marker in (
            "rate_limit_exceeded",
            "http 429",
            "授权会话被限流",
            "just a moment",
            "cloudflare",
        )
    )


def _looks_incomplete_registered_account(registered: dict) -> bool:
    """判断本地记录是否像“只生成过密码、尚未完成授权”的中间态。

    旧版本只依赖 extra.pending；历史任务有些没有写入该标记，但也没有任何
    access/session/refresh 凭证。此时密码登录 401 不应直接判定为密码错误，
    而应允许回到注册阶段重新完成密码和邮箱验证码流程。
    """
    if db.has_completed_registration_evidence(registered):
        return False

    has_authorization = any(
        (registered.get(field) or "").strip()
        for field in ("access_token", "session_token", "refresh_token")
    )
    # A pending marker can survive after browser/email-OTP authorization has
    # already persisted Session/Access. That row is now an existing-account
    # recovery, not a registration fallback candidate. Keeping the fallback
    # enabled wrongly turns require_password_registration on and rejects the
    # email-OTP continuation needed to establish recent auth for MFA.
    if has_authorization:
        return False

    extra = registered.get("extra") or {}
    if isinstance(extra, str):
        try:
            extra = json.loads(extra)
        except Exception:
            extra = {}
    if isinstance(extra, dict) and extra.get("pending"):
        return True
    # 已经有 TOTP 的记录通常是完成过注册的账号，只是授权凭证失效；
    # 这类账号应严格走密码登录，不能误回退到注册流程。
    return not (registered.get("totp_secret") or "").strip()


def reauthorize_registered_account(
    email: str,
    options: dict,
    emit=None,
    cancel_event: threading.Event | None = None,
) -> dict:
    """Reauthorize one saved account and optionally bind its missing TOTP secret."""
    if cancel_event is not None and cancel_event.is_set():
        raise ReauthorizationCancelled("任务已取消")
    normalized = (email or "").strip().lower()
    # Recovery is the one path that must consume the escrowed candidate
    # password of an incomplete row.  The default DB read intentionally hides
    # that value from normal list/API callers until it has been verified.
    registered = db.get_registered(
        normalized,
        include_pending_password=True,
    )
    if not registered:
        return _reauthorization_result(
            normalized,
            "not_found",
            "\u6ce8\u518c\u7ed3\u679c\u4e2d\u627e\u4e0d\u5230\u8be5\u8d26\u53f7",
        )

    password = (registered.get("password") or "").strip()
    extra = registered.get("extra") or {}
    if isinstance(extra, str):
        try:
            extra = json.loads(extra)
        except Exception:
            extra = {}
    pending_reason = str(extra.get("pending_reason") or "") if isinstance(extra, dict) else ""
    has_saved_authorization = any(
        (registered.get(field) or "").strip()
        for field in ("access_token", "session_token", "refresh_token")
    )
    has_saved_mfa = bool(
        (registered.get("totp_secret") or "").strip()
        and (registered.get("totp_factor_id") or "").strip()
    )
    # A pending password is an escrowed candidate, regardless of whether it
    # came from the early registration callback or from a browser-side
    # candidate path.  OTP/session/2FA success does not verify that password.
    # Do not feed it into reauthorization, where it would create the repeated
    # "confirm password"/401 noise seen for newly-created accounts.
    recovery_required = bool(extra.get("pending")) or pending_reason in {
        db.PASSWORD_PENDING_REGISTERED,
        db.PASSWORD_PENDING_CANDIDATE,
        db.PASSWORD_RECOVERY_REQUIRED,
        "existing_account_password_unknown",
    }
    if recovery_required:
        # Do not leave a stale candidate in the durable row.  A pending marker
        # is authoritative: the password has not crossed a successful login
        # boundary, even when OTP/session/MFA evidence is already present.
        if password or pending_reason != db.PASSWORD_RECOVERY_REQUIRED:
            db.mark_password_recovery_required(normalized)
        return _reauthorization_result(
            normalized,
            db.PASSWORD_RECOVERY_REQUIRED,
            "本地密码未经服务端确认，不能用于登录，需重新设置",
        )

    plus_check = extra.get("plus_check") if isinstance(extra, dict) else {}
    passwordless_reauthorization = (
        isinstance(plus_check, dict)
        and plus_check.get("status") == "token_invalid"
        and not password
    )
    authorized_pending_reauthorization = bool(
        isinstance(extra, dict)
        and extra.get("pending")
        and has_saved_authorization
        and not (registered.get("totp_secret") or "").strip()
    )
    if not password and not passwordless_reauthorization:
        return _reauthorization_result(
            normalized,
            "skipped_no_password",
            "\u672c\u5730\u6ca1\u6709\u5bc6\u7801\uff0c\u5df2\u8df3\u8fc7",
        )

    can_resume_registration = _looks_incomplete_registered_account(registered)

    # Registration-resume and passwordless recovery always need an inbox.
    # Completed accounts with a confirmed password may authenticate with the
    # password and local TOTP alone, so do not reject those before login starts.
    mailbox = db.get_account(normalized) or db.get_rebind_mailbox(normalized)
    if not mailbox and (passwordless_reauthorization or can_resume_registration):
        return _reauthorization_result(
            normalized,
            "mailbox_missing",
            "\u90ae\u7bb1\u6c60\u4e2d\u627e\u4e0d\u5230\u5bf9\u5e94\u63a5\u7801\u8bb0\u5f55",
        )

    def push(phase: str, message: str) -> None:
        if emit:
            emit("phase", {"email": normalized, "phase": phase, "message": message})

    try:
        from config import resolve_proxy

        cfg = Config()
        cfg.proxy = resolve_proxy((options or {}).get("proxy"))
        otp_timeout = normalize_otp_timeout((options or {}).get("otp_timeout"))
        env_overrides = {
            "OTP_TIMEOUT": str(otp_timeout),
            "AUTH_SESSION_TIMEOUT": "60",
            "WEBUI_ALLOW_LOGIN": "1",
            # Keep the primary ChatGPT callback/session intact. The optional
            # pre-callback Codex OAuth branch can fall into add-phone and
            # corrupt an otherwise completed email/password login.
            "OAUTH_CODEX_RT_BEFORE_CALLBACK": "0",
            # This repair path needs a ChatGPT session/access token for 2FA;
            # a Codex refresh token is optional and must never trigger phone
            # verification or turn a completed email flow into a failure.
            "OAUTH_CODEX_RT_EXCHANGE": "0",
        }
        env_overrides['OTP_TIMEOUT'] = str(otp_timeout)

        saved_session_2fa = (
            bool((options or {}).get("bind_missing_2fa", True))
            and not passwordless_reauthorization
            and not (registered.get("totp_secret") or "").strip()
            and bool((registered.get("access_token") or "").strip())
            and bool((registered.get("session_token") or "").strip())
        )
        if saved_session_2fa:
            if cancel_event is not None and cancel_event.is_set():
                raise ReauthorizationCancelled("任务已取消")
            push("bind_2fa_saved_session", "正在复用已保存会话补绑 2FA")
            recent_auth_required = False
            try:
                info = retry_2fa_binding(
                    lambda: bind_totp_2fa_from_saved_session(
                        normalized,
                        registered,
                        cfg,
                        env_overrides,
                    ),
                    max_attempts=int((options or {}).get("2fa_max_attempts") or 2),
                    delay_seconds=float((options or {}).get("2fa_retry_delay", 2.0)),
                )
            except TOTPRecentAuthRequired:
                # A valid session can still be too old for enrollment. Only
                # this verified 401 condition may fall through to the existing
                # same-identity password/OTP reauthorization chain.
                recent_auth_required = True
                push("recent_auth_required", "保存会话需要近期认证，继续同身份重新授权")
            except Exception as exc:  # noqa: BLE001 - saved auth remains intact
                return _reauthorization_result(
                    normalized,
                    "reauthorized_2fa_failed",
                    "已保存会话 2FA 补绑失败："
                    + safe_public_error(exc, "saved-session 2FA"),
                )
            if not recent_auth_required:
                if info and info.get("already_enabled"):
                    return _reauthorization_result(
                        normalized,
                        "reauthorized_already_2fa",
                        "已保存会话有效，服务端已有 2FA（Secret 无法从服务端取回）",
                    )
                if info and info.get("secret"):
                    saved = db.save_missing_totp_secret(
                        normalized,
                        info["secret"],
                        info.get("factor_id", ""),
                    )
                    if saved:
                        return _reauthorization_result(
                            normalized,
                            "reauthorized_2fa_bound",
                            "已保存会话有效，2FA 补绑成功",
                        )
                    current = db.get_registered(normalized) or {}
                    if (current.get("totp_secret") or "").strip():
                        return _reauthorization_result(
                            normalized,
                            "reauthorized_2fa_bound",
                            "已保存会话有效，2FA 已由安全落库流程保存",
                        )
                return _reauthorization_result(
                    normalized,
                    "reauthorized_2fa_failed",
                    "已保存会话有效，但 2FA 补绑未返回可保存的 TOTP Secret",
                )

        if mailbox:
            mailbox_kind = (mailbox.get("kind") or "outlook").strip().lower()
            if mailbox_kind == "rebind_api":
                from .rebind_mail_provider import RebindApiMailProvider

                provider = RebindApiMailProvider.from_config({}, mailbox)
            else:
                provider = create_mail_provider(
                    mailbox_kind,
                    db.get_mail_settings(),
                    mailbox,
                )
        else:
            provider = _CredentialOnlyMailProvider()
        if cancel_event is not None:
            try:
                provider._cancel_event = cancel_event
            except Exception:
                pass

        def account_callback(callback_email: str) -> dict:
            saved = db.get_registered(
                callback_email,
                include_pending_password=True,
            ) or registered
            return {
                "password": saved.get("password", ""),
                "totp_secret": saved.get("totp_secret", ""),
            }

        def new_flow(on_password=None):
            return AuthFlow(
                cfg,
                env_overrides=env_overrides,
                on_password=on_password,
                account_callback=account_callback,
            )

        flow = new_flow(on_password=_save_password_early if can_resume_registration else None)
        if can_resume_registration:
            prepare_for_otp = getattr(provider, "prepare_for_otp", None)
            if callable(prepare_for_otp):
                # A prior failed attempt may deliver its OTP late.  Snapshot
                # the mailbox before this auth flow so only messages generated
                # by the current attempt can satisfy its OTP challenge.
                prepare_for_otp()
        push("login", "\u6b63\u5728\u767b\u5f55\u5df2\u6709\u8d26\u53f7")
        if can_resume_registration:
            push(
                "resume_registration",
                "账号可能处于注册中间态；将在同一会话内先尝试密码登录，失败时直接续注册",
            )
        auth_result = flow.run_protocol_login(
            provider,
            normalized,
            password,
            allow_registration_fallback=can_resume_registration,
            # Existing accounts can land on email OTP first even when they
            # have a password. Keep the proven password -> email OTP path
            # enabled without also allowing a registration fallback.
            allow_email_otp_after_password=bool(password),
            require_password_registration=can_resume_registration,
            prefer_email_otp_without_password=(
                passwordless_reauthorization
                or authorized_pending_reauthorization
            ),
        )

        # A positive login_password response is provider acceptance of the
        # exact durable candidate used in this run. Promote only at this
        # explicit boundary; Session/Access or later MFA evidence alone must
        # never clear the password-pending marker.
        if password and getattr(flow, "_password_verified_in_run", False):
            if not db.mark_password_verified(normalized, password):
                raise RuntimeError("服务端已验证候选密码，但本地密码提升失败")

        credentials = auth_result.to_dict()
        push("save_credentials", "\u6b63\u5728\u4fdd\u5b58\u65b0\u6388\u6743\u51ed\u8bc1")
        db.merge_registered_credentials(normalized, credentials)

        refreshed = db.get_registered(normalized) or registered
        if (refreshed.get("totp_secret") or "").strip():
            return _reauthorization_result(
                normalized,
                "reauthorized_already_2fa",
                "\u6388\u6743\u6210\u529f\uff0c\u8d26\u53f7\u5df2\u6709 2FA",
            )
    except Exception as exc:
        if cancel_event is not None and cancel_event.is_set():
            raise ReauthorizationCancelled("任务已取消") from exc
        if isinstance(exc, ReauthorizationMailboxRequired):
            return _reauthorization_result(
                normalized,
                "mailbox_missing",
                str(exc),
            )
        raw_message = str(exc)
        if _looks_account_banned(raw_message):
            return _reauthorization_result(
                normalized,
                "banned",
                "账号已被停用或封禁，无法重新授权",
            )
        message = safe_public_error(exc, "reauthorization")
        return _reauthorization_result(normalized, "login_failed", message)

    if not (options or {}).get("bind_missing_2fa", True):
        return _reauthorization_result(
            normalized,
            "reauthorized_2fa_failed",
            "\u6388\u6743\u6210\u529f\uff0c\u672a\u542f\u7528\u7f3a\u5931 2FA \u8865\u7ed1",
        )

    if cancel_event is not None and cancel_event.is_set():
        raise ReauthorizationCancelled("任务已取消")

    push("bind_2fa", "\u6b63\u5728\u4e3a\u7f3a\u5931\u8d26\u53f7\u7ed1\u5b9a 2FA")
    try:
        info = retry_2fa_binding(
            lambda: bind_totp_2fa_durable(
                normalized, flow, auth_result.access_token
            ),
            max_attempts=int((options or {}).get("2fa_max_attempts") or 2),
            delay_seconds=float((options or {}).get("2fa_retry_delay", 2.0)),
        )
    except Exception as exc:  # noqa: BLE001 - authorization was already persisted
        if cancel_event is not None and cancel_event.is_set():
            raise ReauthorizationCancelled("任务已取消") from exc
        return _reauthorization_result(
            normalized,
            "reauthorized_2fa_failed",
            "授权已保存，2FA 补绑失败："
            + safe_public_error(exc, "reauthorization 2FA"),
        )
    if info and info.get("already_enabled"):
        return _reauthorization_result(
            normalized,
            "reauthorized_already_2fa",
            "重新授权成功，服务端已有 2FA，已保留原 2FA（Secret 无法从服务端取回）",
        )
    if info and info.get("secret"):
        saved = db.save_missing_totp_secret(
            normalized,
            info["secret"],
            info.get("factor_id", ""),
        )
        if saved:
            return _reauthorization_result(
                normalized,
                "reauthorized_2fa_bound",
                "\u6388\u6743\u6210\u529f\uff0c2FA \u8865\u7ed1\u6210\u529f",
            )
        current = db.get_registered(normalized) or {}
        if (current.get("totp_secret") or "").strip():
            return _reauthorization_result(
                normalized,
                "reauthorized_already_2fa",
                "\u6388\u6743\u6210\u529f\uff0c2FA \u5df2\u7531\u5176\u4ed6\u4efb\u52a1\u4fdd\u5b58",
            )

    return _reauthorization_result(
        normalized,
        "reauthorized_2fa_failed",
        "\u6388\u6743\u5df2\u4fdd\u5b58\uff0c2FA \u8865\u7ed1\u5931\u8d25",
    )

# 当前线程正在跑哪个 run。
# ⚠️ 为什么需要这个：QueueLogHandler 是挂在 **root logger** 上的，而 root logger
#    是进程全局的。auto_loop 并发时 N 个 run 各挂一个 handler，每条日志会被
#    广播进**所有** run 的文件和 SSE 流 —— 实测 2026-08-04 三 worker 并发，
#    一个号的记录同时出现在 3 个 .log 里，WebUI 上三个号的日志搅在一起，
#    而 "[4/10] 获取 Sentinel Token..." 这类行不带邮箱，根本分不清是谁的。
#
#    注册链路（auth_flow / mail_providers / sentinel）内部不开任何线程，
#    一个 run 的日志全在自己那条线程上产生，所以线程绑定就能干净切开。
_current_run = threading.local()

LOG_DIR = Path(__file__).resolve().parent / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)


class QueueLogHandler(logging.Handler):
    """把 logging 记录扔进 run queue + 写 log 文件。

    只收**本 run 线程**产生的日志，见 emit 里的过滤。
    """

    def __init__(self, run_id: str, log_file: Path):
        super().__init__()
        self.run_id = run_id
        self._fh = open(log_file, "a", encoding="utf-8")
        self.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%H:%M:%S",
        ))

    def emit(self, record: logging.LogRecord):
        try:
            # emit 是在**打日志的那条线程**里同步跑的，所以这里读到的就是
            # 日志产生者的 run_id。别人 run 的日志直接丢掉。
            rid = getattr(_current_run, "run_id", None)
            if rid != self.run_id:
                return
            # Only logs carrying this exact run's thread context enter its file
            # and SSE queue. Unscoped request/callback logs are never broadcast
            # across concurrently running identities.
            msg = sanitize_text(self.format(record))
            self._fh.write(msg + "\n")
            self._fh.flush()
            q = _run_queues.get(self.run_id)
            if q is not None:
                q.put(msg)
        except Exception:
            pass

    def close(self):
        try:
            self._fh.close()
        except Exception:
            pass
        super().close()


def _record_roxy_create_rejection(run_id: str, exc: BaseException) -> dict:
    """Record a fixed JSON payload through this run's existing log/SSE sink."""
    if (type(run_id) is not str or not re.fullmatch(r"[0-9a-f]{12}", run_id)
            or getattr(_current_run, "run_id", None) != run_id):
        return {}
    state = getattr(exc, "page_state", None)
    if not isinstance(state, dict):
        return {}
    rejection = safe_roxy_rejection_metadata(state.get("roxy_rejection"))
    if not rejection:
        return {}
    phase = getattr(exc, "failure_phase", None)
    if type(phase) is not str or phase not in {"create_profile", "open_profile"}:
        return {}
    kind = getattr(exc, "exception_type", None)
    if type(kind) is not str or kind not in {"RuntimeError", "RoxyProfileQuotaError", "RoxyStartupError", "RoxyRegistrationError"}:
        kind = "RuntimeError"
    event = {
        "event": "roxy_create_rejected", "v": 1, "operation": "create_profile",
        "run_id": run_id, "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "failure_phase": phase, "exception_type": kind, **rejection,
        "failure_locations": safe_traceback_summary(exc, {
            str(ROOT / "webui/registrar.py"), str(ROOT / "webui/roxy_bridge.py"),
        }),
    }
    logging.getLogger("registrar").error(json.dumps(event, ensure_ascii=True, separators=(",", ":"), sort_keys=True))
    return event


def _record_roxy_proxy_failure(run_id: str, exc: BaseException) -> dict:
    """Send fixed probe metadata through the owning task's log and SSE."""
    if (type(run_id) is not str or not re.fullmatch(r"[0-9a-f]{12}", run_id)
            or getattr(_current_run, "run_id", None) != run_id
            or getattr(exc, "failure_phase", None) != "proxy_check"):
        return {}
    state = getattr(exc, "page_state", None)
    probe = safe_proxy_probe_metadata(state.get("proxy_probe")) if isinstance(state, dict) else {}
    if probe.get("service") != "ipinfo" or not probe.get("reason"):
        return {}
    cause = getattr(exc, "failure_cause", None)
    if cause not in {"proxy_auth_failed", "proxy_connect_timeout", "exit_lookup_failed", "proxy_probe_failed"}:
        return {}
    event = {
        "event": "roxy_proxy_check_failed", "v": 1, "operation": "proxy_check",
        "run_id": run_id, "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "failure_phase": "proxy_check", "failure_cause": cause, "proxy_probe": probe,
        "upstream_text_stored": False,
        "failure_locations": safe_traceback_summary(exc, {
            str(ROOT / "webui/registrar.py"), str(ROOT / "webui/roxy_bridge.py"),
        }),
    }
    logging.getLogger("registrar").error(json.dumps(event, ensure_ascii=True, separators=(",", ":"), sort_keys=True))
    return event


def _emit_status(run_id: str, kind: str, payload: dict | str = ""):
    """前端约定：以 `__EVENT__:` 开头的行被解析成 JSON 状态事件。"""
    import json as _json
    q = _run_queues.get(run_id)
    if q is None:
        return
    body = dict(payload) if isinstance(payload, dict) else {"message": str(payload)}
    recovery_required = body.pop("password_recovery_required", None)
    body = sanitize_observable(body)
    if kind == "account_result" and isinstance(payload, dict):
        # Restore only independently allowlisted metadata, including the OTP
        # counters that the generic credential-key filter conservatively masks.
        body.update(safe_password_reset_failure_metadata(payload))
    if type(recovery_required) is bool:
        body["password_recovery_required"] = recovery_required
    body["kind"] = kind
    q.put("__EVENT__:" + _json.dumps(body, ensure_ascii=False))


# 网络/环境层错误特征：命中任一就把号放回 available（号本身没问题，是环境炸了）
_NETWORK_ERROR_PATTERNS = [
    "tls", "ssl", "sslerror", "connection", "connect error", "timeout", "timed out",
    "proxy", "socks", "dns", "name resolution", "name or service",
    "cloudflare", "just a moment", "403 forbidden",
    "csrf token 获取失败", "csrf token 失败",
    "/sentinel/req", "sentinel /req", "sentinel quickjs",
    "check_proxy 失败", "网络预检查",
    "curl: (35)", "curl: (28)", "curl: (6)", "curl: (7)",
    "remote disconnected", "connection reset", "connection aborted",
    "max retries exceeded",
    "invalid_state",
    "chrome-error://chromewebdata/", "http 500",
]


def classify_error(err: str, mail_source: str = "") -> str:
    """分类错误：'network'（环境/代理问题，号无辜）/ 'account'（号本身有问题）/ 'unknown'。

    mail_source 用来问 provider 要不要豁免某些模式 —— 比如 iCloud 中转号
    本来就是买的老号，"已有账号"是正常流程不是失败（见
    MailProvider.accepts_existing_account）。留空则按最严格的规则判。
    """
    s = (err or "").lower()
    if mail_source == 'icloud_relay' and 'failure_cause=relay_layout_unsupported' in s:
        return 'unknown'

    # Warmup never seeded oai-did: the proxy egress was unreachable or blocked
    # by Cloudflare before any mailbox work happened.  The mailbox itself is
    # innocent, so return it to the pool (network) instead of stranding it in
    # ``failed`` behind a misleading generic HTTP 409 summary.
    if "failure_cause=proxy_warmup_failed" in s:
        return "network"
    # Sentinel /sentinel/req hit a link-level break (curl 56 connection closed
    # etc.): PoW was never the problem, the proxy egress blinked.
    if "failure_cause=sentinel_link_error" in s:
        return "network"

    if mail_source == "icloud_relay" and any(
        marker in s
        for marker in (
            "failure_cause=relay_mailbox_missing",
            "failure_cause=relay_link_unauthorized",
        )
    ):
        return "account"

    # Reaching otp_wait proves the browser and password path already worked.
    # For pooled iCloud relays, putting that mailbox back into `available`
    # makes the next task select the same non-delivering alias again. Keep it
    # quarantined as an account/mailbox failure so later work can move on.
    # A Chrome error page is different: the browser lost its upstream
    # connection after OTP submission, so the mailbox must remain retryable.
    if (
        mail_source == "icloud_relay"
        and "failure_phase=otp_wait" in s
        and "chrome-error://chromewebdata/" not in s
    ):
        if "failure_cause=relay_sync_unavailable" in s:
            return "network"
        return "account"

    # Account creation reached the session-establishment boundary, so this
    # identity now needs same-email continuation rather than being returned to
    # the fresh-account pool.  Classify the structured cause before the generic
    # exception-type rule below turns every custom exception into ``unknown``.
    if "failure_cause=auth_session_missing" in s:
        return "account"
    # An allowlisted upstream account-state code is authoritative even when
    # the exception wrapper also carries a generic worker exception type.
    if "error_code=account_deactivated" in s:
        return "account"

    # Retaining the real probe exception must not change the existing mailbox
    # release policy for pre-browser exit-check failures (e.g. HTTPError).
    if (re.search(r"\bfailure_phase=proxy_check\b", s)
            and re.search(r"\bfailure_cause=(?:proxy_auth_failed|proxy_connect_timeout|"
                          r"intel_conflict|exit_lookup_failed|proxy_probe_failed)\b", s)):
        return "network"

    # Roxy reports the primary worker exception separately from its diagnostic
    # page snapshot.  A snapshot may itself time out after an immediate branch
    # error (for example NameError); classify from the primary exception first
    # so that the secondary timeout cannot release an account as a network fault.
    primary_exception = re.search(
        r"\bexception_type=([a-z_][a-z0-9_]{0,79})\b",
        s,
    )
    if primary_exception:
        exception_name = primary_exception.group(1)
        if (
            exception_name == "webdriverexception"
            and re.search(r"\bfailure_phase=browser_prepare\b", s)
            and re.search(
                r'"chrome_error_code"\s*:\s*"err_tunnel_connection_failed"', s,
            )
        ):
            return "network"
        if exception_name in {
            "timeouterror", "timeoutexception", "connectionerror",
            "connectionreseterror", "connectionabortederror",
            "connecttimeout", "readtimeout", "readtimeouterror", "proxyerror", "sslerror",
        }:
            return "network"
        if exception_name not in {"error", "exception", "runtimeerror"}:
            return "unknown"

    account_patterns = [
        "wrong_email_otp_code", "account_deactivated", "invalid_grant", "imap xoauth2",
        "outlook imap account unusable", "user is authenticated but not connected",
        "outlook refresh failed", "authentication failed", "authenticate failed",
        "outlook otp timeout", "registration_disallowed",
        "已有账号", "账号被", "refresh_token 失效",
    ]
    if mail_source:
        try:
            exempt = get_provider_class(mail_source).accepts_existing_account
        except MailProviderError:
            exempt = False  # 未知来源 —— 按默认最严格规则走
        # ⚠️ 用 if-in 而不是裸 remove()：上面的模式表将来被人改动/重排后，
        #    remove 抛的 ValueError 会跟 get_provider_class 的错混在同一个
        #    except 里被一起吞掉，豁免静默失效且没人看得出来。
        if exempt and "已有账号" in account_patterns:
            account_patterns.remove("已有账号")

    # 先匹配 account 特征（更具体），避免子串误命中（如 "outlook OTP timeout" 含 "timeout"）
    if any(p in s for p in account_patterns):
        return "account"
    # The authorization page rejected initialization before email submission.
    # Keep account-state and primary-exception evidence authoritative above.
    if (
        re.search(r"\bhttp\s+403\b", s)
        and re.search(r"\bfailure_phase=oauth_init\b", s)
        and re.search(r"\bfailure_cause=oauth_init_http_error\b", s)
    ):
        return "network"
    if any(p in s for p in _NETWORK_ERROR_PATTERNS):
        return "network"
    return "unknown"


def _prepare_existing_account_password_state(
    email: str,
    persisted: dict,
) -> tuple[dict, str, bool, bool] | None:
    """Normalize a continuation password without treating an escrowed candidate as valid."""
    extra = persisted.get("extra") if isinstance(persisted.get("extra"), dict) else {}
    password = str(persisted.get("password") or "").strip()
    pending_reason = str(extra.get("pending_reason") or "").strip()

    if password and not extra.get("pending"):
        # This is the only existing-account branch where the stored password
        # is already trusted.  Do not downgrade it to a candidate merely
        # because this run continued through an OTP screen.
        return persisted, "verified", True, False

    # A browser candidate may be retained as an explicitly unverified value.
    # Older rows used only ``pending=true`` without a reason, so normalize them
    # before emitting the continuation result.  This must happen only after the
    # caller proved that this run produced fresh authorization evidence.
    if password and not pending_reason:
        if not db.save_password_candidate(email, password):
            return None
        persisted = db.get_registered(email, include_pending_password=True) or {}
        return persisted, db.PASSWORD_PENDING_CANDIDATE, False, False

    # A server-accepted-but-unverified password is deliberately not promoted by
    # an OTP-only existing-account continuation.  That continuation proves the
    # authorization session, not that the saved password can log in.
    if pending_reason != db.PASSWORD_RECOVERY_REQUIRED or password:
        if not db.mark_password_recovery_required(email):
            return None
        persisted = db.get_registered(email, include_pending_password=True) or {}
    return persisted, db.PASSWORD_RECOVERY_REQUIRED, False, True


def _has_new_continuation_authorization(before_registered: dict, persisted: dict) -> bool:
    """Prove this run refreshed authorization instead of reusing an old pending row."""
    before_auth = (
        str(before_registered.get("access_token") or "").strip(),
        str(before_registered.get("session_token") or "").strip(),
    )
    current_auth = (
        str(persisted.get("access_token") or "").strip(),
        str(persisted.get("session_token") or "").strip(),
    )
    return bool(all(current_auth) and current_auth != before_auth)


def _recover_existing_account_continuation_tail_failure(
    run_id: str,
    email: str,
    *,
    flow,
    is_pooled: bool,
    before_registered: dict | None = None,
) -> bool:
    """Recover a durable OTP/MFA continuation from a non-credential tail error.

    Existing-account passwordless login is intentionally not a completed new
    registration: any candidate password remains unverified.  Once the same-email
    OTP flow has durably stored Session/Access and TOTP evidence, a later local
    serialization/finalization error must preserve that usable continuation,
    clear the untrusted password, and mark password recovery as required instead
    of demoting it to a generic failed run.
    """
    if getattr(flow, "_password_registered_in_run", False):
        return False

    persisted = db.get_registered(email, include_pending_password=True) or {}
    flow_proves_continuation = bool(getattr(flow, "_is_existing_account", False))
    durable_auth_proves_continuation = _has_new_continuation_authorization(
        before_registered or {},
        persisted,
    )
    if not flow_proves_continuation and not durable_auth_proves_continuation:
        return False

    prepared = _prepare_existing_account_password_state(email, persisted)
    if prepared is None:
        return False
    persisted, password_route, primary_present, recovery_required = prepared
    extra = persisted.get("extra") if isinstance(persisted.get("extra"), dict) else {}
    required = ("access_token", "session_token", "totp_secret", "totp_factor_id")
    if not extra.get("pending"):
        return False
    if any(not str(persisted.get(field) or "").strip() for field in required):
        return False
    if not db.touch_registered_authorized_pending(email):
        return False

    if is_pooled:
        if recovery_required:
            reason = "[account] 账号授权和 2FA 已保存，但首次注册密码已遗失，需要重置"
        elif password_route == db.PASSWORD_PENDING_CANDIDATE:
            reason = "[account] 账号授权和 2FA 已保存，候选密码已保留但尚未被服务端确认"
        else:
            reason = "[account] 账号授权和 2FA 已保存，注册密码待确认"
        db.mark_failed(email, reason)
    result_summary = {
        "email": email,
        "credential_summary": {
            "primary_present": primary_present,
            "authenticator_present": True,
            "access_length": len(persisted.get("access_token") or ""),
            "session_length": len(persisted.get("session_token") or ""),
            "refresh_length": len(persisted.get("refresh_token") or ""),
        },
        "partial": True,
        "route": password_route,
        "registration_pending": True,
        "registration_complete": False,
        "password_recovery_required": recovery_required,
        "tail_warning": True,
    }
    _record_registration_phase(run_id, "done")
    db.finish_run(run_id, "done", result=result_summary)
    _emit_status(run_id, "done", result_summary)
    return True

def _recover_completed_registration_tail_failure(
    run_id: str,
    email: str,
    *,
    flow=None,
    is_pooled: bool,
    had_completed_before: bool = False,
    proxy: str = "",
) -> bool:
    """Recover a new registration when only a post-credential tail step failed.

    ``save_password_early`` deliberately marks the password as pending until the
    registration session has completed.  A tail exception can happen after the
    server accepted that password and after access/session/2FA were persisted,
    so the pending marker must be promoted from this *same* new-registration
    flow before checking completion evidence.  Existing-account OTP continuations
    must not use this promotion path.
    """
    if had_completed_before:
        return False
    if flow is not None and getattr(flow, "_password_registered_in_run", False):
        result = getattr(flow, "result", None)
        password = (getattr(result, "password", "") or "").strip()
        if not password:
            return False
        # Only an exact match to the escrowed value is promotable.  This keeps a
        # stale/candidate password from becoming trusted merely because tokens
        # and MFA happened to be present in the database.
        if not db.mark_password_verified(email, password):
            return False
    persisted = db.get_registered(email, include_pending_password=True) or {}
    if not db.has_completed_registration_evidence(persisted):
        return False
    if is_pooled:
        db.mark_done(email)
    _auto_check_registered_status(email, (proxy or "").strip())
    result_summary = {
        "email": email,
        "credential_summary": {
            "primary_present": True,
            "authenticator_present": True,
            "access_length": len(persisted.get("access_token") or ""),
            "session_length": len(persisted.get("session_token") or ""),
            "refresh_length": len(persisted.get("refresh_token") or ""),
        },
        "partial": False,
        "registration_complete": True,
        "registration_pending": False,
        "tail_warning": True,
    }
    _record_registration_phase(run_id, "done")
    db.finish_run(run_id, "done", result=result_summary)
    _emit_status(run_id, "done", result_summary)
    return True


def _do_register(
    run_id: str,
    account: dict,
    options: dict,
    log_file: Path,
):
    """实际注册任务。

    options:
        want_access_token: bool
        want_session_token: bool
        want_refresh_token: bool
        proxy: Optional[str]
        otp_timeout: int
        allow_existing_login: bool
    """
    # 先认领本线程，再挂 handler —— 顺序不能反：中间要是有日志产生，
    # 没打标记的话会被广播到其他并发 run 的日志里去。
    _current_run.run_id = run_id

    handler = QueueLogHandler(run_id, log_file)
    handler.setLevel(logging.INFO)
    root_logger = logging.getLogger()
    root_logger.addHandler(handler)
    # 第一次需要的话提到 INFO 级别
    if root_logger.level > logging.INFO or root_logger.level == 0:
        root_logger.setLevel(logging.INFO)

    email = account["email"]
    before_registered = db.get_registered(email, include_pending_password=True) or {}
    had_completed_before = db.has_completed_registration_evidence(before_registered)
    # 提前读取，避免在 try 块前异常时 except 引用未定义
    mail_source = str(
        options.get("mail_source")
        or account.get("kind")
        or db.get_setting("mail_source", "outlook")
    ).strip().lower()
    # 要不要操作号池（mark_done / mark_failed / release）由 provider 声明的
    # pooled 决定。未知 kind 时保守当池化处理 —— 号池里真有这行的话
    # 至少不会漏掉状态回写，把号永远卡在 in_use。
    try:
        is_pooled = get_provider_class(mail_source).pooled
    except MailProviderError:
        is_pooled = True

    try:
        # 本次注册专属的配置覆盖。
        # ⚠️ 以前是写 os.environ + finally 还原，但 auto_loop 并发跑多个 worker，
        #    os.environ 是**进程全局**的：A 设的 OTP_TIMEOUT/WEBUI_ALLOW_LOGIN 会被
        #    B 读到，B 跑完还原成 A 之前的值，A 后半程就用上别人的配置了。
        #    现在整个 dict 直接传给 AuthFlow，只挂在实例上，谁都污染不到谁。
        env_overrides = {}
        # outlook 接码邮箱常被 OpenAI 走 passwordless_signup 流程（新号收码而非设密码），
        # auth_flow 会误判为"已有账号"分支 → 不设 WEBUI_ALLOW_LOGIN 会 fast-fail。
        # 单号 WebUI 场景下 fast-fail 没意义（批量跑才需要"跳过被识别的号"），故强制 ON。
        env_overrides["WEBUI_ALLOW_LOGIN"] = "1"
        env_overrides["OTP_TIMEOUT"] = str(normalize_otp_timeout(options.get("otp_timeout")))
        env_overrides["PROTOCOL_PASSWORDLESS_SIGNUP_SEND"] = (
            "1" if options.get("protocol_passwordless_send") else "0"
        )
        env_overrides["PROTOCOL_PASSWORDLESS_RELAXED_WINDOW"] = (
            "1" if options.get("protocol_passwordless_relaxed_window") else "0"
        )
        # 用户不要 refresh_token → 直接跳过 Codex OAuth（每次都失败浪费 ~10s + 一堆告警）
        if not options.get("want_refresh_token", True):
            env_overrides["SKIP_OAUTH_TOKEN_EXCHANGE"] = "1"
            env_overrides["OAUTH_CODEX_RT_EXCHANGE"] = "0"
            env_overrides["OAUTH_CODEX_RT_BEFORE_CALLBACK"] = "0"
        # PROXY 走 cfg.proxy，无需 env

        cfg = Config()
        from config import resolve_proxy
        cfg.proxy = resolve_proxy(options.get("proxy"))
        screening = options.get("proxy_screening") or {}
        if screening:
            logging.getLogger("registrar").info(
                "[proxy-screening] run=%s 使用已复测通过的新 Session：ASN=%s 质量分=%s 探测=%s次",
                run_id,
                screening.get("asn", "-"),
                screening.get("quality_score", 0),
                screening.get("probe_count", 0),
            )

        # ─ 邮箱来源路由 ─
        # 原来是 if cf_temp / else outlook 的写死分支，加一种邮箱就得回来改。
        # 现在交给注册表工厂：provider 自己从 settings + account 里取需要的字段。
        mail = create_mail_provider(
            mail_source,
            dict(options.get("mail_settings_snapshot") or db.get_mail_settings()),
            account,
        )
        logging.getLogger("registrar").info(
            f"[register] 邮箱来源: {mail_source} ({mail.display_name})"
        )

        def _account_callback_for_flow(email: str) -> dict:
            """从数据库加载账号凭证（密码和 totp_secret）供 AuthFlow 登录时使用。

            用于既有账号登录场景：当服务端返回 mfa-challenge 时，AuthFlow 需要
            totp_secret 来计算 6 位动态码完成 2FA 验证。
            """
            try:
                data = db.get_registered(email)
                if data:
                    return {
                        "password": data.get("password", ""),
                        "totp_secret": data.get("totp_secret", ""),
                    }
            except Exception as e:
                logging.getLogger("registrar").warning(safe_public_error(e, "account callback"))
            return {}

        inline_2fa_info: dict = {}
        inline_2fa_error: Registration2FAError | None = None

        def _bind_registration_2fa_on_session_ready(ready_flow, access_token):
            """Bind mandatory 2FA on the just-created account session."""
            nonlocal inline_2fa_error
            if not options.get("want_2fa", True):
                return
            try:
                session_token = str(
                    getattr(getattr(ready_flow, "result", None), "session_token", "")
                    or ""
                ).strip()
                if not session_token or not (access_token or "").strip():
                    raise RuntimeError("当前注册会话未取得完整 Session/Access")
                persisted = db.merge_registered_credentials(
                    email,
                    {
                        "access_token": access_token,
                        "session_token": session_token,
                        "cookie_header": str(
                            getattr(
                                getattr(ready_flow, "result", None),
                                "cookie_header",
                                "",
                            )
                            or ""
                        ),
                    },
                    create_if_missing=True,
                )
                if not persisted:
                    raise RuntimeError("当前注册会话取得 Session/Access，但提前落库失败")
                _record_registration_phase(run_id, "bind_2fa")
                _emit_status(run_id, "phase", {"phase": "bind_2fa", "email": email})
                info = retry_2fa_binding(
                    lambda: bind_totp_2fa_durable(
                        email, ready_flow, access_token
                    ),
                    max_attempts=int(options.get("2fa_max_attempts") or 2),
                    delay_seconds=float(options.get("2fa_retry_delay", 2.0)),
                )
                secret = (info or {}).get("secret", "")
                factor_id = (info or {}).get("factor_id", "")
                if not secret or not factor_id:
                    raise RuntimeError(
                        "当前注册会话绑定 2FA 未返回完整 TOTP Secret/Factor ID"
                    )

                # Persist one-time MFA material before run_register continues
                # into any optional credential branch.
                saved = db.save_missing_totp_secret(email, secret, factor_id)
                if not saved:
                    current = db.get_registered(email, include_pending_password=True) or {}
                    if not current.get("totp_secret") or not current.get("totp_factor_id"):
                        raise RuntimeError("当前注册会话已绑定 2FA，但 TOTP 凭据未能安全落库")
                inline_2fa_info.update({"secret": secret, "factor_id": factor_id})
                logging.getLogger("registrar").info(
                    "[2fa] 当前注册会话已完成绑定并立即保存 Secret/Factor"
                )
            except Exception as exc:
                inline_2fa_error = Registration2FAError()
                logging.getLogger("registrar").warning(
                    "[2fa] 当前注册会话快路径失败: %s",
                    safe_public_error(inline_2fa_error, "registration 2FA"),
                )

        flow = AuthFlow(
            cfg,
            sms_callback=_build_sms_callback(run_id),
            env_overrides=env_overrides,
            # Password is persisted as soon as the provider accepts it.
            on_password=_save_password_early,
            on_session_ready=_bind_registration_2fa_on_session_ready,
            account_callback=_account_callback_for_flow,
        )
        record_diag = getattr(flow, "record_registration_diagnostic", None)
        if callable(record_diag):
            record_diag(
                "run_context",
                run_id=run_id,
                proxy_present=bool(cfg.proxy),
                proxy_ip=screening.get("ip") or screening.get("exit_ip") or "",
                asn=screening.get("asn") or "",
                country=screening.get("country") or screening.get("country_code") or "",
                quality_score=screening.get("quality_score") or 0,
                probe_count=screening.get("probe_count") or 0,
                mail_source=mail_source,
            )
        _record_registration_phase(run_id, "starting")
        _emit_status(run_id, "phase", {"phase": "starting", "email": email})
        logging.getLogger("registrar").info(f"[register] 开始: {email}")

        partial = False
        d: dict
        if str(options.get("driver") or "protocol").strip().lower() == "roxy":
            logging.getLogger("registrar").info(
                "[register] driver=roxy；邮箱、OTP、任务和结果仍由 repo_0810 管理"
            )
            roxy_options = dict(options)
            roxy_options["_run_id"] = run_id
            d = run_repo_owned_roxy_registration(
                account,
                roxy_options,
                mail,
            )
            flow._password_registered_in_run = bool(
                d.get("password_set") or d.get("password_verified")
            )
            inline_2fa_info.update({
                "secret": d.get("totp_secret", ""),
                "factor_id": d.get("totp_factor_id", ""),
            })
        else:
            try:
                result = flow.run_register(mail)
                d = result.to_dict()
                actual_email = (d.get("email") or "").strip().lower()
                if actual_email and actual_email != (email or "").strip().lower():
                    db.update_run_email(run_id, actual_email)
            except RuntimeError as e:
                # 部分凭证也算成功（OTP 验证通过 + create_account 成功 → flow.result 有 token）
                d = flow.result.to_dict()
                need_access = options.get("want_access_token", True)
                need_session = options.get("want_session_token", True)
                need_refresh = options.get("want_refresh_token", True)
                # 用户勾选的凭证全拿到 → 算正常完成（不视为 partial）
                wanted_ok = (
                    (not need_access or d.get("access_token"))
                    and (not need_session or d.get("session_token"))
                    and (not need_refresh or d.get("refresh_token"))
                )
                has_any = bool(
                    d.get("access_token") or d.get("refresh_token") or d.get("session_token")
                )
                if wanted_ok and has_any:
                    logging.getLogger("registrar").warning(
                        "[register] 流程末段异常但用户勾选的凭证已齐: %s",
                        safe_public_error(e, "registration tail"),
                    )
                elif has_any:
                    partial = True
                    logging.getLogger("registrar").warning(
                        "[register] 部分凭证 (缺用户勾选的某项): %s",
                        safe_public_error(e, "registration partial"),
                    )
                else:
                    raise

        verified_existing_account_continuation = False
        is_existing_account_continuation = bool(
            (
                str(d.get("account_route") or "").strip().lower() == "existing_account"
                or getattr(flow, "_is_existing_account", False)
            )
            and not getattr(flow, "_password_registered_in_run", False)
        )
        if is_existing_account_continuation:
            # Existing-account continuation has two distinct password states:
            # a previously verified password may finish through the normal
            # persistence/finalization path, while an unverified or missing
            # password must remain pending until the provider accepts it.
            persisted = db.get_registered(
                email,
                include_pending_password=True,
            ) or {}
            prepared = _prepare_existing_account_password_state(email, persisted)
            if prepared is None:
                raise RuntimeError("账号授权已保存，但密码状态落盘失败")
            persisted, password_route, primary_present, recovery_required = prepared
            persisted_extra = (
                persisted.get("extra")
                if isinstance(persisted.get("extra"), dict)
                else {}
            )
            missing = [
                field
                for field in (
                    "access_token", "session_token", "totp_secret", "totp_factor_id",
                )
                if not (persisted.get(field) or "").strip()
            ]
            if inline_2fa_error is not None and any(
                field in missing for field in ("totp_secret", "totp_factor_id")
            ):
                raise inline_2fa_error
            if missing:
                raise RuntimeError(
                    "账号续接结果未满足授权和 2FA 持久化契约"
                )

            if password_route == "verified":
                # The durable row contains the trusted password and the
                # Session/Access/TOTP evidence refreshed by this continuation.
                # Hydrate the in-memory result so the ordinary success path can
                # validate, persist, status-check and export it without a false
                # tail-warning recovery.
                for field in (
                    "password", "access_token", "session_token",
                    "totp_secret", "totp_factor_id",
                ):
                    value = persisted.get(field)
                    if value:
                        d[field] = value
                inline_2fa_info.setdefault("secret", persisted.get("totp_secret", ""))
                inline_2fa_info.setdefault("factor_id", persisted.get("totp_factor_id", ""))
                verified_existing_account_continuation = True
            else:
                if not persisted_extra.get("pending"):
                    raise RuntimeError(
                        "账号续接结果未满足授权和 2FA 持久化契约"
                    )
                if is_pooled:
                    if recovery_required:
                        reason = "[account] 账号授权和 2FA 已保存，但首次注册密码已遗失，需要重置"
                    elif password_route == db.PASSWORD_PENDING_CANDIDATE:
                        reason = "[account] 账号授权和 2FA 已保存，候选密码已保留但尚未被服务端确认"
                    else:
                        reason = "[account] 账号授权和 2FA 已保存，注册密码待确认"
                    db.mark_failed(email, reason)
                result_summary = {
                    "email": email,
                    "credential_summary": {
                        "primary_present": primary_present,
                        "authenticator_present": True,
                        "access_length": len(persisted.get("access_token") or ""),
                        "session_length": len(persisted.get("session_token") or ""),
                        "refresh_length": len(persisted.get("refresh_token") or ""),
                    },
                    "partial": True,
                    "route": password_route,
                    "registration_pending": True,
                    "registration_complete": False,
                    "password_recovery_required": recovery_required,
                }
                _record_registration_phase(run_id, "done")
                db.finish_run(run_id, "done", result=result_summary)
                _emit_status(run_id, "done", result_summary)
                logging.getLogger("registrar").info(
                    "[register] 账号授权和 2FA 已保存，但首次注册密码已遗失，需要重置"
                    if recovery_required
                    else (
                        "[register] 账号授权和 2FA 已保存，候选密码已保留但尚未被服务端确认"
                        if password_route == db.PASSWORD_PENDING_CANDIDATE
                        else "[register] 账号授权和 2FA 已保存，注册密码待确认"
                    )
                )
                return

        if (
            not getattr(flow, "_password_registered_in_run", False)
            and not verified_existing_account_continuation
        ):
            raise RuntimeError(
                "本轮没有在注册阶段成功设置密码；拒绝把邮箱验证码登录或已有账号显示为注册成功"
            )

        if options.get("want_2fa"):
            if inline_2fa_error is not None:
                raise inline_2fa_error
            if not inline_2fa_info.get("secret") or not inline_2fa_info.get("factor_id"):
                raise RuntimeError(
                    "当前注册会话未完成 2FA；拒绝启动额外密码复核或标记成功"
                )
            d["totp_secret"] = inline_2fa_info["secret"]
            d["totp_factor_id"] = inline_2fa_info["factor_id"]
            _record_registration_phase(run_id, "2fa_bound")
            _emit_status(
                run_id,
                "phase",
                {"phase": "2fa_bound", "email": d.get("email")},
            )

        # ─ 用户选项过滤：未勾选的字段从结果里抹掉，DB 只存用户想要的
        ensure_requested_registration_outputs(d, options)

        full = d
        d = select_registration_credentials(full, options)

        # 落库
        diagnostics = d.get("registration_diagnostics")
        if not isinstance(diagnostics, dict):
            diagnostics = {}
        diagnostics = dict(diagnostics)
        diagnostics["completed_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        diagnostics["final_credentials"] = {
            "access_present": bool(d.get("access_token")),
            "session_present": bool(d.get("session_token")),
            "refresh_present": bool(d.get("refresh_token")),
            "csrf_present": bool(d.get("csrf_token")),
            "device_id_present": bool(d.get("device_id")),
            "token_claims": _public_token_claims(d.get("access_token")),
        }
        d["registration_diagnostics"] = diagnostics
        db.save_registered(d)
        status_info = _auto_check_registered_status(
            d.get("email") or email,
            (options.get("proxy") or "").strip(),
        )
        diagnostics["post_registration_status"] = {
            "status": str(status_info.get("status", "unchecked"))[:80]
            if isinstance(status_info, dict) else "unchecked",
            "plan_type": str(
                (status_info.get("plan_type") or status_info.get("plan") or "")
            )[:80] if isinstance(status_info, dict) else "",
            "http_status": status_info.get("http_status")
            if isinstance(status_info, dict) and isinstance(status_info.get("http_status"), (int, float))
            else None,
        }
        db.update_registered_diagnostics(d.get("email") or email, diagnostics)
        logging.getLogger("registrar").info(
            "[register] 溯源摘要 run=%s callback=%s session=%s plan=%s",
            run_id,
            next((e.get("consumed") for e in diagnostics.get("events", []) if e.get("event") == "callback" and "consumed" in e), None),
            diagnostics["final_credentials"]["session_present"],
            diagnostics["final_credentials"]["token_claims"].get("chatgpt_plan_type", ""),
        )
        # ⚠️ d 是**本轮内存里**的结果，它不一定知道这个号有密码：
        #    重跑一个之前设过密码的邮箱时，OpenAI 会认成已有账号 → passwordless_login
        #    → register_password 根本不执行 → d["password"] 是空的。
        #    但上一轮 save_password_early 存的密码还在库里，save_registered 刚刚
        #    已经把它保留下来了（空值不覆盖非空旧值）——「注册结果」页读 DB 显示正确，
        #    唯独跑完这一刻的 done 事件拿的是 d，前端 `v-if="lastRunResult.password"`
        #    判空 → 密码行连同「复制密码」「复制 email----password」两个按钮一起消失，
        #    主人会以为密码又丢了。所以这里从库里回读补回来。
        #    只在 d 里密码为空时查一次，正常路径零额外开销。
        if not (d.get("password") or "").strip():
            try:
                _saved = db.get_registered(d.get("email") or "")
                _pw = ((_saved or {}).get("password") or "").strip()
                if _pw:
                    d["password"] = _pw
                    logging.getLogger("registrar").info(
                        "[register] 本轮未设密码，沿用库中已存密码（上一轮 register_password 留下的）"
                    )
            except Exception as e:
                logging.getLogger("registrar").warning(safe_public_error(e, "saved password readback"))
        # 非池化 provider 的 email 是虚拟占位（xxx_placeholder_N@placeholder.local），
        # 号池里根本没这行，不能去 mark。判据用 provider 的 pooled，不写死 kind。
        if is_pooled:
            db.mark_done(email)

        # ─ 可选：导出到 CPA / SUB2API 面板（仅勾选启用时才执行） ─
        _try_export_to_panels(run_id, d)

        result_summary = {
            "email": d.get("email"),
            # 凭据不得进入 SSE。前端收到 done 后，以 email 调用已存在的
            # /api/registered/{email} 读取刚刚持久化的密码与 TOTP Secret。
            "credential_summary": {
                "primary_present": bool(d.get("password")),
                "authenticator_present": bool(d.get("totp_secret")),
                "access_length": len(d.get("access_token") or ""),
                "session_length": len(d.get("session_token") or ""),
                "refresh_length": len(d.get("refresh_token") or ""),
            },
            "partial": partial,
            "registration_complete": True,
            "registration_pending": False,
        }
        _record_registration_phase(run_id, "done")
        db.finish_run(run_id, "done", result=result_summary)
        _emit_status(run_id, "done", result_summary)
        logging.getLogger("registrar").info(
            f"[register] 完成 email={d.get('email')} "
            f"pw={'set' if d.get('password') else 'none'} "
            f"at={result_summary['credential_summary']['access_length']} "
            f"st={result_summary['credential_summary']['session_length']} "
            f"rt={result_summary['credential_summary']['refresh_length']}"
        )

    except Exception as e:
        err = safe_public_error(e, "registration")
        rejection_event = _record_roxy_create_rejection(run_id, e)
        _record_roxy_proxy_failure(run_id, e)
        classification_error = err
        failed_flow = locals().get("flow")
        record_failed_diag = getattr(failed_flow, "record_registration_diagnostic", None)
        if callable(record_failed_diag):
            record_failed_diag("registration_failed", error_type=type(e).__name__)
        failed_result = getattr(failed_flow, "result", None)
        failed_email = str(getattr(failed_result, "email", "") or email).strip().lower()
        failed_diag = getattr(failed_result, "registration_diagnostics", None)
        if failed_email and isinstance(failed_diag, dict):
            try:
                db.update_registered_diagnostics(failed_email, failed_diag)
            except Exception:
                logging.getLogger("registrar").debug(
                    "registration diagnostics failure-path persistence skipped",
                    exc_info=True,
                )
        page_state = getattr(e, "page_state", {})
        quota_notice = _roxy_daily_quota_notice(page_state)
        if quota_notice:
            err = quota_notice + " | " + err
        if isinstance(page_state, dict) and page_state:
            err += _roxy_page_state_error_suffix(err, page_state)
        if _recover_existing_account_continuation_tail_failure(
            run_id,
            email,
            flow=locals().get("flow"),
            is_pooled=is_pooled,
            before_registered=before_registered,
        ):
            logging.getLogger("registrar").warning(
                "[register] 已有账号 OTP/MFA 续接凭据已安全落库；后置收尾步骤有告警，"
                "任务按待确认密码的部分成功处理: %s",
                err,
            )
            return
        if _recover_completed_registration_tail_failure(
            run_id,
            email,
            flow=locals().get("flow"),
            is_pooled=is_pooled,
            had_completed_before=had_completed_before,
            proxy=(options.get("proxy") or "").strip(),
        ):
            logging.getLogger("registrar").warning(
                "[register] 核心注册已完成，凭据五项已安全落库；后置收尾步骤有告警，账号仍按成功处理: %s",
                err,
            )
            return
        category = "roxy_daily_quota" if quota_notice else classify_error(
            classification_error if rejection_event else err, mail_source,
        )
        logging.getLogger("registrar").error(f"[register] 失败 (category={category}): {err}")
        # register_password 的成功回调已经提前保存候选密码。失败收尾再做一次
        # 幂等写入和回读校验，避免瞬时数据库错误留下需要重置密码的孤儿账号。
        log_pending_password_saved(flow, email)
        logging.getLogger('registrar').error(
            'registration failure locations: %s',
            safe_traceback_summary(e, {
                str(ROOT / 'webui/registrar.py'), str(ROOT / 'auth_flow.py'),
                str(ROOT / 'mail_providers/icloud_relay.py'),
                str(ROOT / 'webui/roxy_bridge.py'),
            }),
        )
        worker_locations = getattr(e, "worker_failure_locations", "")
        if worker_locations:
            logging.getLogger('registrar').error(
                'registration worker failure locations: %s', worker_locations,
            )
        # 非池化 provider 没有号池记录，不操作
        if is_pooled:
            if category in {"network", "roxy_daily_quota"}:
                release_reason = (
                    "Roxy 创建额度问题" if category == "roxy_daily_quota" else "网络/环境错误"
                )
                released_status = db.release_unused(email)
                if released_status == "available":
                    logging.getLogger("registrar").warning(
                        f"[register] {email} 判定为{release_reason}，号已 release 回 available"
                    )
                else:
                    logging.getLogger("registrar").warning(
                        f"[register] {email} 判定为{release_reason}；"
                        "检测到已有注册进度，账号保持 failed，等待续接"
                    )
            else:
                db.mark_failed(email, f"[{category}] {err}")
        _record_registration_phase(run_id, "failed")
        db.finish_run(run_id, "failed", err, category=category)
        _emit_status(run_id, "error", {"message": err, "category": category})

    finally:
        # env 覆盖现在只挂在 AuthFlow 实例上，随实例一起回收，无需还原。
        # 关闭 handler
        try:
            root_logger.removeHandler(handler)
            handler.close()
        except Exception:
            pass
        q = _run_queues.get(run_id)
        if q is not None:
            q.put(None)  # sentinel: 流结束
        # 线程标记清掉。理论上线程跑完就回收了，但 threading.local 是绑在
        # 线程对象上的，万一以后换成线程池复用线程，残留的 run_id 会让下一个
        # 任务的日志全被投递到上一个 run 的（已关闭的）文件里去。
        _current_run.run_id = None
        _run_registration_finalizer(run_id)


def _try_export_to_panels(run_id: str, cred: dict) -> None:
    """注册完成后可选地把凭证导出到 CPA / SUB2API 面板。

    - 任一目标的"启用"开关关闭时,该目标跳过(不发请求);两者都未启用时整段 no-op。
    - 任何异常都不抛,只 emit 日志/状态(不影响注册主流程)。
    """
    try:
        cfg = db.get_export_internal_config()
    except Exception as e:
        logging.getLogger("registrar").warning(safe_public_error(e, "export configuration read"))
        return

    cpa_enabled = bool(cfg.get("cpa", {}).get("enabled"))
    sub2api_enabled = bool(cfg.get("sub2api", {}).get("enabled"))
    if not (cpa_enabled or sub2api_enabled):
        return  # 用户没勾选任何目标 → 完全不执行

    from . import exporter  # 懒 import,避免未启用时强依赖

    explog = logging.getLogger("registrar")

    def _log(msg: str, level: str = "info") -> None:
        if level == "error":
            explog.error(f"[export] {msg}")
        elif level == "warn":
            explog.warning(f"[export] {msg}")
        else:
            explog.info(f"[export] {msg}")
        try:
            _emit_status(run_id, "phase", {"phase": "export", "message": msg, "level": level})
        except Exception:
            pass

    try:
        results = exporter.run_exports(
            cred,
            cpa_cfg=cfg.get("cpa") if cpa_enabled else None,
            sub2api_cfg=cfg.get("sub2api") if sub2api_enabled else None,
            log_fn=_log,
        )
    except Exception as e:
        _log(safe_public_error(e, "credential export"), "error")
        return

    # 汇总成一个事件给前端
    summary = {}
    if results.get("cpa") is not None:
        summary["cpa"] = {"ok": bool(results["cpa"].get("ok")),
                          "message": results["cpa"].get("message") or results["cpa"].get("error") or ""}
    if results.get("sub2api") is not None:
        summary["sub2api"] = {"ok": bool(results["sub2api"].get("ok")),
                              "message": results["sub2api"].get("message") or results["sub2api"].get("error") or ""}
    try:
        _emit_status(run_id, "phase", {"phase": "export_done", "summary": summary})
    except Exception:
        pass


def _save_password_early(email: str, password: str) -> None:
    """AuthFlow 的 on_password 回调：密码在 OpenAI 侧一生效就落盘。

    以前密码只在流程**全部**跑通后才随 save_registered 一起入库，
    中间任何一步失败（实测最常见的是 OTP 超时）密码就只剩一行 ERROR 日志兜底 ——
    换台机器、日志轮转、或者干脆没人去翻，号就废了。

    这里存的是"有密码、无凭证"的半成品行，跑通后 save_registered 会用
    同一个 email 主键覆盖补全，不会多出一行对不上的记录。
    """
    log = logging.getLogger("registrar")
    try:
        db.save_password_early(email, password)
        log.info(f"[register] 密码已落盘: {email}（凭证待补）")
    except Exception as e:
        # 落盘失败不能影响注册；下面 except 里那行 ERROR 日志仍然是兜底
        log.warning(safe_public_error(e, "registration password persistence"))


def _auto_check_registered_status(email: str, proxy: str = "") -> dict:
    """Run the existing online/plan check after durable registration save.

    Status checking is post-commit acceptance data. A transport or upstream
    failure must leave the successful registration intact and unchecked.
    """
    log = logging.getLogger("registrar")
    try:
        from .app import CheckPlusReq, api_check_plus

        result = api_check_plus(CheckPlusReq(emails=[email], proxy=proxy or ""))
        info = (result.get("results") or {}).get(email, {})
        log.info(
            "[register] 注册后状态检测: email=%s status=%s",
            email,
            info.get("status") or "unchecked",
        )
        return info if isinstance(info, dict) else {}
    except Exception as exc:
        log.warning(safe_public_error(exc, "post-registration status check"))
        return {"status": "unchecked", "error_type": type(exc).__name__}


def _public_token_claims(token: object) -> dict:
    """Decode only allowlisted non-secret JWT claims for provenance."""
    raw = str(token or "")
    parts = raw.split(".")
    if len(parts) < 2:
        return {}
    try:
        padded = parts[1] + "=" * (-len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))
    except Exception:
        return {}
    if not isinstance(payload, dict):
        return {}
    auth = payload.get("https://api.openai.com/auth")
    if not isinstance(auth, dict):
        auth = payload.get("auth") if isinstance(payload.get("auth"), dict) else {}
    out = {}
    for key in ("chatgpt_plan_type", "amr", "account_id"):
        value = auth.get(key, payload.get(key))
        if key == "amr" and isinstance(value, list):
            out[key] = [str(item)[:80] for item in value[:20]]
        elif isinstance(value, (str, int, float, bool)):
            out[key] = str(value)[:120] if isinstance(value, str) else value
    return out


_SMS_PHONE_RE = re.compile(r"(?<!\d)\+?\d{7,15}(?!\d)")
_SMS_ACTIVATION_RE = re.compile(
    r"(activation_id\s*=\s*)[A-Za-z0-9._:-]+", re.IGNORECASE
)


def _sanitize_sms_progress_message(
    message: object,
    *,
    secret_values: tuple[str, ...] = (),
) -> str:
    """Return SMS progress text safe for logs and SSE."""
    text = sanitize_text(message)
    for secret in secret_values:
        if secret:
            text = text.replace(secret, "[REDACTED]")
    text = _SMS_ACTIVATION_RE.sub(r"\1[REDACTED]", text)
    return _SMS_PHONE_RE.sub("[PHONE_REDACTED]", text)


def _build_sms_callback(
    run_id: str,
    *,
    email: str = "",
    emit=None,
) -> Optional[PhoneCallbackController]:
    """根据 webui 配置创建 SMS 接码 controller。

    未启用接码或未配置 API key 时返回 None，flow 会回退到环境变量路径。
    log_fn 把租号/等码的脱敏状态推到 SSE 流，前端可见。
    """
    cfg = db.get_sms_internal_config()
    if not cfg.get("sms_enabled"):
        return None
    api_key = (cfg.get("sms_api_key") or "").strip()
    if not api_key:
        logging.getLogger("registrar").warning("[sms] 已启用接码但未配置 sms_api_key，跳过")
        return None

    smslog = logging.getLogger("registrar")

    def _log(msg: str) -> None:
        safe_message = _sanitize_sms_progress_message(
            msg, secret_values=(api_key,)
        )
        smslog.info("[sms] %s", safe_message)
        payload = {"phase": "sms", "message": safe_message}
        if email:
            payload["email"] = email
        try:
            if emit is not None:
                emit("phase", payload)
            else:
                _emit_status(run_id, "phase", payload)
        except Exception:
            pass

    try:
        return PhoneCallbackController(
            provider_key=cfg["sms_provider"],
            config=cfg,
            service=cfg.get("sms_service") or "openai",
            country=cfg.get("sms_country") or "52",
            log_fn=_log,
            auto_select_country=bool(cfg.get("sms_auto_country")),
        )
    except Exception as e:
        smslog.warning(safe_public_error(e, "SMS controller creation"))
        return None

def _normalize_reauthorization_emails(emails: list[str]) -> list[str]:
    cleaned = []
    seen = set()
    for value in emails or []:
        email = (value or "").strip().lower()
        if not email or email in seen:
            continue
        seen.add(email)
        cleaned.append(email)
    return cleaned


def get_refresh_token_eligibility(email: str) -> tuple[str, dict | None]:
    """Return whether one saved registered account may enter the RT-only flow."""
    normalized = (email or "").strip().lower()
    registered = db.get_registered(normalized) if normalized else None
    if not registered:
        return "not_found", None
    if (registered.get("refresh_token") or "").strip():
        return "already_has_refresh_token", registered
    extra = registered.get("extra")
    if not isinstance(extra, dict):
        extra = {}
    plus_check = extra.get("plus_check")
    if not isinstance(plus_check, dict) or plus_check.get("status") != "plus_active":
        return "not_plus_active", registered
    if not (registered.get("password") or "").strip():
        return "missing_password", registered
    return "eligible", registered


def _refresh_token_result(email: str, status: str, message: str) -> dict:
    return {"email": email, "status": status, "message": message}


def _looks_phone_verification_required(message: str) -> bool:
    lowered = (message or "").lower()
    return any(
        marker in lowered
        for marker in (
            "add-phone",
            "add_phone",
            "phone verification",
            "phone-verification",
            "手机号验证",
            "sms 接码",
        )
    )


def acquire_registered_refresh_token(
    email: str,
    options: dict,
    emit=None,
    cancel_event=None,
) -> dict:
    """Acquire a Codex OAuth refresh token for one existing registered account."""
    normalized = (email or "").strip().lower()
    if cancel_event is not None and cancel_event.is_set():
        return _refresh_token_result(normalized, "cancelled", "任务已取消")

    eligibility, registered = get_refresh_token_eligibility(normalized)
    if eligibility != "eligible" or not registered:
        messages = {
            "not_found": "找不到注册结果",
            "already_has_refresh_token": "账号已有 Refresh Token，已跳过",
            "not_plus_active": "账号不是 Plus 生效中，已跳过",
            "missing_password": "本地没有可用密码，无法获取 Refresh Token",
        }
        return _refresh_token_result(
            normalized, eligibility, messages.get(eligibility, "账号不符合获取条件")
        )

    def push(phase: str, message: str) -> None:
        if emit:
            emit("phase", {"email": normalized, "phase": phase, "message": message})

    sms_callback = None
    try:
        from config import resolve_proxy

        cfg = Config()
        cfg.proxy = resolve_proxy((options or {}).get("proxy"))
        run_id = str(getattr(_current_run, "run_id", "") or "")
        sms_callback = _build_sms_callback(
            run_id,
            email=normalized,
            emit=emit,
        )
        env_overrides = {
            "AUTH_SESSION_TIMEOUT": "60",
            "WEBUI_ALLOW_LOGIN": "1",
            "OAUTH_CODEX_RT_EXCHANGE": "1",
            "OAUTH_CODEX_RT_ALLOW_RETRY": "0",
            "OAUTH_CODEX_ADD_PHONE_REFRESH_RETRY": "1" if sms_callback is not None else "0",
        }

        def account_callback(callback_email: str) -> dict:
            saved = db.get_registered(
                callback_email, include_pending_password=True
            ) or registered
            return {
                "password": saved.get("password", ""),
                "totp_secret": saved.get("totp_secret", ""),
            }

        push("authorization", "正在使用已保存账号凭证获取 Refresh Token")
        flow = AuthFlow(
            cfg,
            sms_callback=sms_callback,
            env_overrides=env_overrides,
            account_callback=account_callback,
        )
        flow.from_existing_credentials(
            str(registered.get("session_token") or "").strip(),
            str(registered.get("access_token") or "").strip(),
            str(registered.get("device_id") or "").strip(),
        )
        for pair in str(registered.get("cookie_header") or "").split(";"):
            if "=" not in pair:
                continue
            name, value = pair.strip().split("=", 1)
            if name and value:
                flow.session.cookies.set(name, value, domain=".chatgpt.com")

        flow.result.email = normalized
        flow.result.password = str(registered.get("password") or "")
        flow.result.totp_secret = str(registered.get("totp_secret") or "")
        flow.oauth_codex_rt_exchange(mail_provider=_CredentialOnlyMailProvider())

        refresh_token = str(getattr(flow.result, "refresh_token", "") or "").strip()
        if not refresh_token:
            reason = str(getattr(flow, "_authorization_failure_reason", "") or "")
            if _looks_phone_verification_required(reason):
                return _refresh_token_result(
                    normalized,
                    "phone_verification_required",
                    "需要手机号验证，当前任务未启用 SMS 接码",
                )
            return _refresh_token_result(
                normalized, "authorization_failed", "授权完成但未取得 Refresh Token"
            )

        merged = db.merge_registered_oauth_tokens(
            normalized,
            refresh_token=refresh_token,
            access_token=str(getattr(flow.result, "access_token", "") or "").strip(),
            id_token=str(getattr(flow.result, "id_token", "") or "").strip(),
        )
        if merged is None:
            return _refresh_token_result(
                normalized, "authorization_failed", "账号记录已不存在，Refresh Token 未保存"
            )
        push("saved", "Refresh Token 已安全保存")
        return _refresh_token_result(
            normalized, "refresh_token_acquired", "Refresh Token 获取成功"
        )
    except AuthorizeRateLimitError:
        return _refresh_token_result(
            normalized,
            "deferred_rate_limited",
            "OpenAI 授权会话限流，已停止并等待稍后重试",
        )
    except Exception as exc:
        safe_message = safe_public_error(exc, "refresh token authorization")
        if _looks_phone_verification_required(str(exc)):
            return _refresh_token_result(
                normalized,
                "phone_verification_required",
                "需要手机号验证，当前任务未启用 SMS 接码",
            )
        if _looks_authorization_throttled(str(exc)):
            return _refresh_token_result(
                normalized,
                "deferred_rate_limited",
                "OpenAI 授权会话限流，已停止并等待稍后重试",
            )
        logging.getLogger("registrar").warning("RT 获取失败: %s", safe_message)
        return _refresh_token_result(
            normalized, "authorization_failed", "Refresh Token 授权失败"
        )
    finally:
        if sms_callback is not None:
            try:
                sms_callback.cleanup()
            except Exception:
                pass


def _do_registered_refresh_token_batch(
    run_id: str,
    emails: list[str],
    options: dict,
    log_file: Path,
    cancel_event: threading.Event,
) -> None:
    """Run the refresh-token-only workflow without entering registration."""
    _current_run.run_id = run_id
    counts: dict[str, int] = {}
    handler = QueueLogHandler(run_id, log_file)
    handler.setLevel(logging.INFO)
    root_logger = logging.getLogger()
    root_logger.addHandler(handler)
    try:
        _emit_status(
            run_id,
            "batch_start",
            {"total": len(emails), "message": f"开始获取 {len(emails)} 个账号的 Refresh Token"},
        )
        try:
            concurrency = int((options or {}).get("concurrency") or 3)
        except (TypeError, ValueError):
            concurrency = 3
        concurrency = max(1, min(5, concurrency))
        cancelled = False
        rate_limited = False
        next_index = 0

        def process_account(index: int, email: str) -> tuple[int, dict]:
            _current_run.run_id = run_id
            try:
                if cancel_event.is_set():
                    result = _refresh_token_result(email, "cancelled", "任务已取消")
                else:
                    _emit_status(
                        run_id,
                        "phase",
                        {
                            "phase": "account_start",
                            "email": email,
                            "index": index,
                            "total": len(emails),
                            "message": f"正在获取 {email} 的 Refresh Token",
                        },
                    )
                    try:
                        result = acquire_registered_refresh_token(
                            email,
                            options,
                            emit=lambda kind, payload: _emit_status(run_id, kind, payload),
                            cancel_event=cancel_event,
                        )
                    except Exception as exc:
                        result = _refresh_token_result(
                            email,
                            "authorization_failed",
                            safe_public_error(exc, "refresh token authorization"),
                        )
                return index, {
                    "email": result.get("email", email),
                    "status": result.get("status", "authorization_failed"),
                    "message": result.get("message", ""),
                }
            finally:
                _current_run.run_id = None

        from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait

        with ThreadPoolExecutor(
            max_workers=concurrency,
            thread_name_prefix=f"refresh-token-{run_id}",
        ) as executor:
            active = {}

            def fill_available_workers() -> None:
                nonlocal next_index
                while (
                    len(active) < concurrency
                    and next_index < len(emails)
                    and not cancel_event.is_set()
                    and not rate_limited
                ):
                    index = next_index + 1
                    email = emails[next_index]
                    next_index += 1
                    active[executor.submit(process_account, index, email)] = (index, email)

            fill_available_workers()
            while active:
                done, _pending = wait(active, return_when=FIRST_COMPLETED)
                completed = []
                for future in done:
                    index, email = active.pop(future)
                    try:
                        _returned_index, result = future.result()
                    except Exception as exc:
                        result = _refresh_token_result(
                            email,
                            "authorization_failed",
                            safe_public_error(exc, "refresh token authorization"),
                        )
                    completed.append((index, result))

                for _index, result in sorted(completed, key=lambda item: item[0]):
                    status = result["status"]
                    counts[status] = counts.get(status, 0) + 1
                    _emit_status(run_id, "account_result", result)
                    if status == "deferred_rate_limited":
                        rate_limited = True

                if cancel_event.is_set():
                    cancelled = True
                if not cancelled and not rate_limited:
                    fill_available_workers()

        if cancel_event.is_set():
            cancelled = True

        if cancelled:
            for email in emails[next_index:]:
                result = _refresh_token_result(email, "cancelled", "任务已取消，未处理")
                counts["cancelled"] = counts.get("cancelled", 0) + 1
                _emit_status(run_id, "account_result", result)
            _emit_status(
                run_id,
                "batch_cancelled",
                {"total": len(emails), "counts": counts, "message": "任务已取消"},
            )
            db.finish_run(run_id, "cancelled", "用户取消")
        elif rate_limited:
            for email in emails[next_index:]:
                result = _refresh_token_result(
                    email,
                    "deferred_rate_limited",
                    "前一账号触发 OpenAI 授权限流，已停止，稍后再试",
                )
                counts["deferred_rate_limited"] = counts.get(
                    "deferred_rate_limited", 0
                ) + 1
                _emit_status(run_id, "account_result", result)
            _emit_status(
                run_id,
                "batch_done",
                {
                    "total": len(emails),
                    "counts": counts,
                    "stopped_reason": "authorization_rate_limit",
                    "message": "检测到 OpenAI 授权限流，已停止剩余账号",
                },
            )
            db.finish_run(
                run_id,
                "failed",
                "OpenAI 授权会话限流，已停止剩余账号",
                "network",
            )
        else:
            failed = any(
                status not in {
                    "refresh_token_acquired",
                    "already_has_refresh_token",
                    "not_plus_active",
                }
                and status != "cancelled"
                for status in counts
            )
            message = "处理完成" if not failed else "部分账号未取得 Refresh Token"
            _emit_status(
                run_id,
                "batch_done",
                {
                    "total": len(emails),
                    "counts": counts,
                    "outcome": "failed" if failed else "done",
                    "message": message,
                },
            )
            if failed:
                db.finish_run(run_id, "failed", message, "account")
            else:
                db.finish_run(run_id, "done")
    except Exception as exc:
        safe_error = safe_public_error(exc, "refresh token batch")
        db.finish_run(run_id, "failed", safe_error, "unknown")
        _emit_status(run_id, "error", {"message": safe_error})
    finally:
        try:
            root_logger.removeHandler(handler)
            handler.close()
        except Exception:
            pass
        q = _run_queues.get(run_id)
        if q is not None:
            q.put(None)
        with _lock:
            _run_cancel_events.pop(run_id, None)
        _current_run.run_id = None


def start_registered_refresh_token_batch(emails: list[str], options: dict) -> str:
    cleaned = _normalize_reauthorization_emails(emails)
    if not cleaned:
        raise ValueError("没有可处理的账号")

    run_id = uuid.uuid4().hex[:12]
    log_file = LOG_DIR / f"{run_id}.log"
    db.create_run(
        run_id,
        cleaned[0],
        str(log_file),
        run_kind="refresh_token",
        required_registered_emails=cleaned,
    )
    q: queue.Queue = queue.Queue()
    cancel_event = threading.Event()
    with _lock:
        _run_queues[run_id] = q
        _run_cancel_events[run_id] = cancel_event

    thread = threading.Thread(
        target=_do_registered_refresh_token_batch,
        args=(run_id, cleaned, dict(options or {}), log_file, cancel_event),
        daemon=True,
        name=f"refresh-token-{run_id}",
    )
    thread.start()
    return run_id


def cancel_registered_refresh_token_batch(run_id: str) -> bool:
    normalized = (run_id or "").strip()
    with _lock:
        cancel_event = _run_cancel_events.get(normalized)
    if cancel_event is None:
        return False
    cancel_event.set()
    _emit_status(
        normalized,
        "phase",
        {"phase": "cancelling", "message": "正在取消任务，当前账号会尽快停止"},
    )
    return True

def _do_registered_reauthorization_batch(
    run_id: str,
    emails: list[str],
    options: dict,
    log_file: Path,
    cancel_event: threading.Event,
) -> None:
    _current_run.run_id = run_id
    counts: dict[str, int] = {}
    handler = QueueLogHandler(run_id, log_file)
    handler.setLevel(logging.INFO)
    root_logger = logging.getLogger()
    root_logger.addHandler(handler)
    try:
        _emit_status(
            run_id,
            "phase",
            {"phase": "batch_start", "message": f"开始处理 {len(emails)} 个账号"},
        )
        try:
            concurrency = int((options or {}).get("concurrency") or 5)
        except (TypeError, ValueError):
            concurrency = 5
        concurrency = max(1, min(5, concurrency))
        cancelled = False
        rate_limited = False
        account_results: list[dict] = []

        def process_account(index: int, email: str) -> tuple[int, dict]:
            _current_run.run_id = run_id
            try:
                if cancel_event.is_set():
                    result = _reauthorization_result(email, "cancelled", "任务已取消")
                else:
                    _emit_status(
                        run_id,
                        "phase",
                        {
                            "phase": "account_start",
                            "email": email,
                            "index": index,
                            "total": len(emails),
                            "message": f"正在处理 {email}",
                        },
                    )
                    try:
                        result = reauthorize_registered_account(
                            email,
                            options,
                            emit=lambda kind, payload: _emit_status(run_id, kind, payload),
                            cancel_event=cancel_event,
                        )
                    except ReauthorizationCancelled:
                        result = _reauthorization_result(email, "cancelled", "任务已取消")
                    except Exception as exc:
                        result = _reauthorization_result(
                            email,
                            "login_failed",
                            safe_public_error(exc, "reauthorization"),
                        )
                safe_result = {
                    "email": result.get("email", email),
                    "status": result.get("status", "login_failed"),
                    "message": result.get("message", ""),
                }
                if (options or {}).get("reconcile_failed_continuation"):
                    saved = db.get_registered(email, include_pending_password=True) or {}
                    complete = db.has_completed_registration_evidence(saved)
                    if complete:
                        db.touch_registered_completion(email)
                        db.mark_done(email)
                        _auto_check_registered_status(
                            email,
                            ((options or {}).get("proxy") or "").strip(),
                        )
                return index, safe_result
            finally:
                _current_run.run_id = None

        from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait

        next_index = 0
        with ThreadPoolExecutor(
            max_workers=concurrency,
            thread_name_prefix=f"reauthorize-{run_id}",
        ) as executor:
            active = {}

            def fill_available_workers() -> None:
                nonlocal next_index
                while (
                    len(active) < concurrency
                    and next_index < len(emails)
                    and not cancel_event.is_set()
                    and not rate_limited
                ):
                    index = next_index + 1
                    email = emails[next_index]
                    next_index += 1
                    active[executor.submit(process_account, index, email)] = (index, email)

            fill_available_workers()
            while active:
                done, _pending = wait(active, return_when=FIRST_COMPLETED)
                completed = []
                for future in done:
                    index, email = active.pop(future)
                    try:
                        _result_index, safe_result = future.result()
                    except Exception as exc:
                        safe_result = _reauthorization_result(
                            email,
                            "login_failed",
                            safe_public_error(exc, "reauthorization"),
                        )
                    completed.append((index, safe_result))

                for _index, safe_result in sorted(completed, key=lambda item: item[0]):
                    status = safe_result["status"]
                    counts[status] = counts.get(status, 0) + 1
                    account_results.append(safe_result)
                    _emit_status(run_id, "account_result", safe_result)
                    if _looks_authorization_throttled(safe_result["message"]):
                        rate_limited = True

                if cancel_event.is_set():
                    cancelled = True
                if not cancelled and not rate_limited:
                    fill_available_workers()

        if cancel_event.is_set():
            cancelled = True

        if cancelled:
            for email in emails[next_index:]:
                result = _reauthorization_result(email, "cancelled", "任务已取消，未处理")
                counts["cancelled"] = counts.get("cancelled", 0) + 1
                _emit_status(run_id, "account_result", result)
            _emit_status(
                run_id,
                "batch_cancelled",
                {"total": len(emails), "counts": counts, "message": "任务已取消"},
            )
            db.finish_run(run_id, "cancelled", "用户取消")
        elif rate_limited:
            for email in emails[next_index:]:
                result = _reauthorization_result(
                    email,
                    "deferred_rate_limited",
                    "前一账号触发 OpenAI 授权限流，已停止，稍后再试",
                )
                counts["deferred_rate_limited"] = counts.get(
                    "deferred_rate_limited", 0
                ) + 1
                _emit_status(run_id, "account_result", result)
            _emit_status(
                run_id,
                "batch_done",
                {
                    "total": len(emails),
                    "counts": counts,
                    "stopped_reason": "authorization_rate_limit",
                    "message": "检测到 OpenAI 授权限流，已停止剩余账号",
                },
            )
            db.finish_run(
                run_id,
                "failed",
                "OpenAI 授权会话限流，已停止剩余账号",
                "network",
            )
        else:
            failed = any(
                status not in _REAUTHORIZATION_SUCCESS_STATUSES
                and status not in _REAUTHORIZATION_SKIPPED_STATUSES
                and status != "cancelled"
                for status in counts
            )
            failure_message = (
                _summarize_reauthorization_failure(counts, account_results)
                if failed
                else ""
            )
            _emit_status(
                run_id,
                "batch_done",
                {
                    "total": len(emails),
                    "counts": counts,
                    "outcome": "failed" if failed else "done",
                    "message": failure_message if failed else "处理完成",
                },
            )
            if failed:
                db.finish_run(run_id, "failed", failure_message, "account")
            else:
                db.finish_run(run_id, "done")
    except Exception as exc:
        safe_error = safe_public_error(exc, "reauthorization batch")
        db.finish_run(run_id, "failed", safe_error, "unknown")
        _emit_status(run_id, "error", {"message": safe_error})
    finally:
        try:
            root_logger.removeHandler(handler)
            handler.close()
        except Exception:
            pass
        q = _run_queues.get(run_id)
        if q is not None:
            q.put(None)
        with _lock:
            _run_cancel_events.pop(run_id, None)
        _current_run.run_id = None


def start_registered_reauthorization(emails: list[str], options: dict) -> str:
    cleaned = _normalize_reauthorization_emails(emails)
    if not cleaned:
        raise ValueError("没有可处理的账号")

    run_id = uuid.uuid4().hex[:12]
    log_file = LOG_DIR / f"{run_id}.log"
    db.create_run(
        run_id,
        cleaned[0],
        str(log_file),
        run_kind="reauthorization",
        required_registered_emails=cleaned,
    )
    q: queue.Queue = queue.Queue()
    cancel_event = threading.Event()
    with _lock:
        _run_queues[run_id] = q
        _run_cancel_events[run_id] = cancel_event

    thread = threading.Thread(
        target=_do_registered_reauthorization_batch,
        args=(run_id, cleaned, dict(options or {}), log_file, cancel_event),
        daemon=True,
        name=f"reauthorize-{run_id}",
    )
    thread.start()
    return run_id


def cancel_registered_reauthorization(run_id: str) -> bool:
    with _lock:
        cancel_event = _run_cancel_events.get((run_id or "").strip())
    if cancel_event is None:
        return False
    cancel_event.set()
    _emit_status(
        run_id,
        "phase",
        {"phase": "cancelling", "message": "正在取消任务，当前操作会尽快停止"},
    )
    return True


def start_registration(
    account: dict,
    options: dict,
    *,
    required_registered_emails: list[str] | None = None,
    claim_account_email: str = "",
    on_finished=None,
) -> str:
    """启动一次注册任务，返回 run_id。"""
    options = normalize_registration_contract_options(options)
    run_id = uuid.uuid4().hex[:12]
    log_file = LOG_DIR / f"{run_id}.log"
    claimed_account = db.create_run(
        run_id,
        account["email"],
        str(log_file),
        run_kind="registration",
        required_registered_emails=required_registered_emails,
        claim_account_email=claim_account_email,
    )
    if claimed_account is not None:
        account = claimed_account

    q: queue.Queue = queue.Queue()
    with _lock:
        _run_queues[run_id] = q
        if on_finished is not None:
            if not callable(on_finished):
                _run_queues.pop(run_id, None)
                raise TypeError("on_finished 必须是可调用对象")
            _run_finalizers[run_id] = on_finished

    th = threading.Thread(
        target=_do_register,
        args=(run_id, account, options, log_file),
        daemon=True,
        name=f"register-{run_id}",
    )
    try:
        th.start()
    except BaseException:
        with _lock:
            _run_queues.pop(run_id, None)
        _run_registration_finalizer(run_id)
        raise
    return run_id


def get_run_queue(run_id: str) -> Optional[queue.Queue]:
    return _run_queues.get(run_id)


def remove_run_queue(run_id: str) -> None:
    with _lock:
        _run_queues.pop(run_id, None)
