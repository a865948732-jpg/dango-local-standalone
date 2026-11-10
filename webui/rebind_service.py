"""批量换绑服务。

这个模块只消费已完成的注册结果，不参与注册流程。换绑成功后通过 db 的
事务性身份迁移把新邮箱和重新登录得到的凭证一次写回注册结果。
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlsplit

from safe_diagnostics import safe_public_error
from mail_providers import create_mail_provider

from . import db

_EMAIL_RE = r"[^@\s]+@[^@\s]+\.[^@\s]+"
_REBIND_MAX_CONCURRENCY = 20
_REBIND_MAILBOX_COOLDOWN_SECONDS = 10 * 60
_PRE_CHANGE_RELEASE_SAFE_CODES = frozenset({
    "OLD_EMAIL_OTP_UNAVAILABLE",
    "OLD_EMAIL_OTP_TIMEOUT",
    "OLD_EMAIL_OTP_FAILED",
    "OLD_ACCOUNT_EMAIL_CHANGED",
    "LOGIN_IDENTITY_UNVERIFIED",
})
# The upstream protocol login can wait indefinitely on a proxy/TLS/OAuth state
# transition. Keep one stuck account from blocking the whole retry batch.
REBIND_AUTHORIZATION_TIMEOUT_SECONDS = 90.0
_REBIND_ACCOUNT_DEACTIVATED_MARKERS = (
    "account_deactivated",
    "accountdeactivated",
    "account has been deactivated",
    "account is deactivated",
    "account disabled",
    "account suspended",
    "account banned",
    "账号已停用",
    "账号被停用",
    "账号已封禁",
    "账号被封禁",
)


def _root() -> Path:
    configured = os.environ.get("REBIND_STANDALONE_ROOT", "").strip()
    candidates = [Path(configured)] if configured else []
    candidates.append(
        Path(r"C:\Users\37661\Documents\Codex\2026-08-23\https-github-com-mervlis-chatgpt-rebind\outputs\chatgpt-rebind-standalone")
    )
    for candidate in candidates:
        if candidate and (candidate / "rebind_core" / "pipeline.py").exists():
            return candidate.resolve()
    raise RuntimeError("未找到换绑核心，请设置 REBIND_STANDALONE_ROOT")


def _runner():
    root = _root()
    root_text = str(root)
    if root_text not in sys.path:
        sys.path.insert(0, root_text)
    from rebind_core import pipeline as pipeline_module  # type: ignore
    print(f"[rebind_runner_module] {Path(pipeline_module.__file__).resolve()}", flush=True)
    return pipeline_module.run_rebind_email


def _create_old_mail_provider(
    old_email: str,
    cancel_event: threading.Event | None = None,
) -> Any | None:
    """Build one worker-private, read-only provider for the old mailbox."""
    normalized = _email(old_email)
    if not normalized:
        return None
    try:
        account = db.get_account(normalized)
        if not account:
            return None
        kind = str(account.get("kind") or "").strip().lower()
        if not kind:
            return None
        if kind == "icloud_relay" and not str(account.get("relay_url") or "").strip():
            return None
        provider = create_mail_provider(kind, db.get_mail_settings(), account)
        if cancel_event is not None:
            try:
                setattr(provider, "_cancel_event", cancel_event)
            except Exception:
                pass
        return provider
    except Exception:
        # The row may contain a private relay URL. Keep construction failures
        # out of logs and UI messages.
        return None


def _authorization_tools():
    """Use the current existing-account protocol for post-rebind recovery.

    Retry-pending rebinds already changed the email.  They need a fresh
    session for the new identity using only the saved password and TOTP
    secret.  Reusing ``AuthFlow.run_protocol_login`` keeps its proxy check,
    ChatGPT warmup/oai-did setup, Sentinel state, and MFA handling together
    without touching the registration workflow.
    """
    root = _root()
    root_text = str(root)
    if root_text not in sys.path:
        sys.path.insert(0, root_text)

    from auth_flow import AuthFlow as CurrentAuthFlow
    from config import Config as CurrentConfig, resolve_proxy
    from rebind_core.session_export import build_login_bundle as standalone_build_login_bundle  # type: ignore

    class CredentialOnlyMailProvider:
        kind = "credential_only"
        exhausted = True

        def prepare_for_otp(self):
            return None

        def wait_for_otp(self, *_args, **_kwargs):
            raise RuntimeError("换绑补授权不允许邮箱验证码，只能使用已保存密码和 2FA")

    def login_with_password_and_totp(
        email: str,
        password: str,
        totp_secret: str,
        *,
        proxy: str | None = None,
    ):
        normalized = _email(email)
        saved_password = str(password or "").strip()
        saved_totp_secret = str(totp_secret or "").strip()
        if not normalized or not saved_password or not saved_totp_secret:
            raise ValueError("换绑补授权缺少新邮箱、密码或 2FA Secret")

        cfg = CurrentConfig()
        cfg.proxy = resolve_proxy(proxy)

        def account_callback(callback_email: str) -> dict:
            if _email(callback_email) != normalized:
                return {}
            return {
                "password": saved_password,
                "totp_secret": saved_totp_secret,
            }

        flow = CurrentAuthFlow(
            cfg,
            env_overrides={
                "AUTH_SESSION_TIMEOUT": "60",
                "WEBUI_ALLOW_LOGIN": "1",
                "OAUTH_CODEX_RT_BEFORE_CALLBACK": "0",
                "OAUTH_CODEX_RT_EXCHANGE": "0",
            },
            account_callback=account_callback,
        )
        auth_result = flow.run_protocol_login(
            CredentialOnlyMailProvider(),
            normalized,
            saved_password,
            allow_registration_fallback=False,
            allow_email_otp_after_password=True,
            prefer_email_otp_without_password=False,
        )
        return SimpleNamespace(
            result=auth_result,
            account_id="",
            trace=[],
        )

    def build_login_bundle(login, **kwargs):
        result = getattr(login, "result", None)
        if result is not None and not hasattr(result, "auth_session_json"):
            # Current AuthResult stores the usable session/AT directly.  The
            # legacy exporter treats the raw auth-session JSON as optional.
            result.auth_session_json = ""
        return standalone_build_login_bundle(login, **kwargs)

    return login_with_password_and_totp, build_login_bundle


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _email(value: str) -> str:
    return (value or "").strip().lower()


def _looks_rebind_account_deactivated(message: str) -> bool:
    lowered = str(message or "").lower()
    return any(marker in lowered for marker in _REBIND_ACCOUNT_DEACTIVATED_MARKERS)



class _AuthorizationTimeoutError(TimeoutError):
    """Raised when an external authorization call exceeds its safety bound."""


class _AuthorizationCancelledError(RuntimeError):
    """Raised when a pending authorization call is cancelled by the user."""


def _run_authorization_call(
    func,
    *args: Any,
    timeout: float,
    cancel_event: threading.Event | None = None,
    **kwargs: Any,
):
    """Run an untrusted protocol call without keeping a pool worker blocked.

    ``Future.result(timeout=...)`` is not sufficient here: the executor worker
    remains occupied until the underlying function returns. A daemon thread
    gives the caller a hard upper bound while allowing the process to exit even
    if a third-party network stack ignores its own timeout.
    """
    result: list[Any] = []
    error: list[BaseException] = []

    def invoke() -> None:
        try:
            result.append(func(*args, **kwargs))
        except BaseException as exc:  # propagate the original exception
            error.append(exc)

    thread = threading.Thread(
        target=invoke,
        name="rebind-auth-call",
        daemon=True,
    )
    thread.start()
    deadline = time.monotonic() + max(0.01, float(timeout))
    while thread.is_alive():
        if cancel_event is not None and cancel_event.is_set():
            raise _AuthorizationCancelledError("补授权登录已取消")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise _AuthorizationTimeoutError(
                f"补授权登录超过 {float(timeout):g} 秒未完成"
            )
        thread.join(min(0.1, remaining))
    if error:
        raise error[0]
    return result[0] if result else None

def _classify_authorization_failure(exc: BaseException) -> dict[str, str]:
    """Map a post-rebind login failure to a safe, actionable stage.

    The upstream exception text is used only for local routing.  No arbitrary
    exception text, request id, email, credential, or response body is copied
    into the returned values.
    """
    lowered = str(exc or "").lower()

    if isinstance(exc, _AuthorizationTimeoutError):
        return {
            "phase": "补授权超时",
            "code": "REBIND_AUTH_TIMEOUT",
            "failure_stage": "重新登录授权/网络等待",
            "message": "补授权登录超时，账号和换绑邮箱已保留，可稍后重试",
            "reason": "补授权登录超时，等待重试",
        }
    if "invalid_state" in lowered:
        return {
            "phase": "授权会话失效",
            "code": "REBIND_AUTH_INVALID_STATE",
            "failure_stage": "新邮箱登录授权/建立会话",
            "message": "登录授权会话失效；账号和换绑邮箱已保留，可更换代理后重试",
            "reason": "授权会话失效，等待重试",
        }
    if "password login" in lowered or "密码登录" in lowered:
        return {
            "phase": "密码登录被拒绝",
            "code": "REBIND_PASSWORD_REJECTED",
            "failure_stage": "新邮箱登录授权/密码验证",
            "message": "新邮箱的密码登录被拒绝；可能尚未完成换绑或保存的密码不匹配，未释放邮箱",
            "reason": "新邮箱密码登录被拒绝，等待核验",
        }
    if "totp verification" in lowered or "mfa/verify" in lowered or "totp 验证" in lowered:
        return {
            "phase": "2FA 验证被拒绝",
            "code": "REBIND_TOTP_REJECTED",
            "failure_stage": "新邮箱登录授权/2FA 验证",
            "message": "密码步骤已通过，但 2FA 验证被拒绝；账号和换绑邮箱已保留",
            "reason": "2FA 验证被拒绝，等待核验",
        }
    if "邮箱验证码" in lowered or "email_otp_verification" in lowered:
        return {
            "phase": "需要额外邮箱验证",
            "code": "REBIND_EXTRA_EMAIL_VERIFICATION",
            "failure_stage": "新邮箱登录授权/额外邮箱验证",
            "message": "服务端要求额外邮箱验证；本补授权任务未接码，账号和换绑邮箱已保留",
            "reason": "需要额外邮箱验证，等待处理",
        }
    if any(marker in lowered for marker in ("warmup 失败", "oai-did", "cloudflare", " curl:", "tls", "connection", "timeout")):
        return {
            "phase": "代理或网络异常",
            "code": "REBIND_AUTH_NETWORK_ERROR",
            "failure_stage": "新邮箱登录授权/网络预热",
            "message": "代理或认证网络链路异常；账号和换绑邮箱已保留，可更换代理后重试",
            "reason": "代理或认证网络异常，等待重试",
        }
    if "authorize/continue" in lowered:
        return {
            "phase": "登录入口被拒绝",
            "code": "REBIND_LOGIN_ENTRY_REJECTED",
            "failure_stage": "新邮箱登录授权/账号探测",
            "message": "新邮箱登录入口被拒绝；尚不能判定是否已换绑，账号和邮箱均保留",
            "reason": "新邮箱登录入口被拒绝，等待核验",
        }
    if "缺少密码" in lowered or "2fa secret" in lowered or "totp_secret" in lowered:
        return {
            "phase": "本地凭证不完整",
            "code": "REBIND_SAVED_CREDENTIALS_MISSING",
            "failure_stage": "新邮箱登录授权/读取凭证",
            "message": "原账号缺少保存的密码或 2FA Secret；未执行登录，换绑邮箱保持保护",
            "reason": "本地保存凭证不完整",
        }
    return {
        "phase": "登录授权待补",
        "code": "REBIND_RETRY_AUTH_REQUIRED",
        "failure_stage": "重新获取凭证",
        "message": "授权失败，已保留原账号和换绑邮箱，可稍后重试",
        "reason": "补授权失败，等待重试",
    }


class _ProxyLease:
    def __init__(self, pool: "ProxyLeasePool", proxy: str) -> None:
        self.proxy = proxy
        self._pool = pool
        self._released = False

    def release(self) -> None:
        if self._released:
            return
        self._released = True
        self._pool._release(self.proxy)


class ProxyLeasePool:
    """Batch-local exclusive leases for normalized proxy exits."""

    def __init__(self, proxies: list[str] | tuple[str, ...]) -> None:
        values = list(dict.fromkeys(str(proxy).strip() for proxy in proxies if str(proxy).strip()))
        if not values:
            raise ValueError("换绑专用代理池不能为空")
        self._condition = threading.Condition()
        self._available = values
        self._leased: set[str] = set()

    def acquire(
        self,
        *,
        cancel_event: threading.Event | None = None,
        timeout: float | None = None,
    ) -> _ProxyLease | None:
        deadline = time.monotonic() + timeout if timeout is not None else None
        with self._condition:
            while not self._available:
                if cancel_event is not None and cancel_event.is_set():
                    return None
                if deadline is not None:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        return None
                    self._condition.wait(min(remaining, 0.25))
                else:
                    self._condition.wait(0.25)
            if cancel_event is not None and cancel_event.is_set():
                return None
            proxy = self._available.pop(0)
            self._leased.add(proxy)
            return _ProxyLease(self, proxy)

    def _release(self, proxy: str) -> None:
        with self._condition:
            if proxy not in self._leased:
                return
            self._leased.remove(proxy)
            self._available.append(proxy)
            self._condition.notify()

    @property
    def leased_count(self) -> int:
        with self._condition:
            return len(self._leased)


class StartGate:
    """Serialize worker starts with a bounded monotonic interval."""

    def __init__(self, interval: float = 1.25) -> None:
        self.interval = max(0.0, float(interval))
        self._condition = threading.Condition()
        self._next_allowed = 0.0

    def acquire(
        self,
        *,
        cancel_event: threading.Event | None = None,
        timeout: float | None = None,
    ) -> bool:
        deadline = time.monotonic() + timeout if timeout is not None else None
        with self._condition:
            while True:
                if cancel_event is not None and cancel_event.is_set():
                    return False
                now = time.monotonic()
                wait_for = self._next_allowed - now
                if wait_for <= 0:
                    self._next_allowed = now + self.interval
                    return True
                if deadline is not None:
                    remaining = deadline - now
                    if remaining <= 0:
                        return False
                    self._condition.wait(min(wait_for, remaining, 0.25))
                else:
                    self._condition.wait(min(wait_for, 0.25))


def effective_rebind_concurrency(requested: int, proxy_count: int, task_count: int) -> int:
    return max(1, min(int(requested), _REBIND_MAX_CONCURRENCY, int(proxy_count), int(task_count)))


class RebindService:
    def __init__(self, *, run_maintenance: bool = True) -> None:
        self._lock = threading.RLock()
        self._jobs: dict[str, dict[str, Any]] = {}
        self._authorization_jobs: dict[str, dict[str, Any]] = {}
        self._maintenance_lock = threading.Lock()
        self._maintenance_started = False
        self._maintenance_complete = False
        # 8767 的旧版换绑工具把 trace 持久化在 outputs/rebind_runs；维护任务
        # 只读这些脱敏 trace，导入到新结果页，不会触碰注册流程或注册数据。
        if run_maintenance:
            self.initialize_maintenance()

    def initialize_maintenance(self) -> None:
        """Run historical rebind cleanup once, outside the import/startup path.

        The legacy importer scans hundreds of trace files and backup databases.
        Keeping it explicit lets the WebUI bind its port first and run this
        maintenance in a background worker after the server is ready.
        """
        with self._maintenance_lock:
            if self._maintenance_started:
                return
            self._maintenance_started = True
        try:
            self._import_legacy_records()
            self._recover_verified_rebind_failures()
            self._recover_retryable_login_failures()
            self._normalize_credential_refresh_pending()
            self._purge_retry_pending_without_new_email()
        finally:
            with self._maintenance_lock:
                self._maintenance_complete = True

    def start(
        self,
        emails: list[str],
        *,
        proxy: str = "",
        proxies: list[str] | None = None,
        mail_timeout: float = 120.0,
        concurrency: int = 3,
    ) -> dict[str, Any]:
        normalized = list(dict.fromkeys(_email(item) for item in emails if _email(item)))
        if not normalized:
            raise ValueError("至少选择一个账号")
        if len(normalized) > 100:
            raise ValueError("单次最多处理 100 个账号")
        concurrency = max(1, min(int(concurrency), _REBIND_MAX_CONCURRENCY))
        mail_timeout = max(10.0, min(float(mail_timeout), 600.0))
        dedicated_proxies = self._normalize_proxies(proxy=proxy, proxies=proxies)
        if not dedicated_proxies:
            raise ValueError("请先配置至少一个换绑专用代理")

        for old_email in normalized:
            state = db.get_registered_operation_state(old_email)
            if not state.get("exists"):
                raise ValueError(f"注册结果不存在: {old_email}")
            if state.get("active"):
                raise ValueError(f"账号当前有其他任务运行: {old_email}")
            row = db.get_registered(old_email, include_pending_password=True) or {}
            missing = [
                label for field, label in (
                    ("password", "密码"), ("totp_secret", "TOTP"),
                    ("access_token", "Access Token"), ("session_token", "Session Token"),
                ) if not str(row.get(field) or "").strip()
            ]
            if missing:
                raise ValueError(f"{old_email} 缺少换绑所需凭证: {', '.join(missing)}")

        run_id = f"rebind-{uuid.uuid4().hex}"
        boxes = db.claim_rebind_mailboxes(len(normalized), run_id)
        if len(boxes) != len(normalized):
            for box in boxes:
                db.set_rebind_mailbox_result(box["email"], status="available", run_id=run_id)
            raise ValueError(
                f"换绑邮箱池可用数量不足，需要 {len(normalized)} 个，当前仅有 {len(boxes)} 个"
            )

        items = []
        assignments = []
        for assignment_index, (old_email, box) in enumerate(zip(normalized, boxes)):
            new_email = _email(box["email"])
            if new_email == old_email or db.get_registered(new_email, include_pending_password=True):
                db.set_rebind_mailbox_result(
                    new_email, status="failed", old_email=old_email,
                    reason="新邮箱已被注册结果占用或与旧邮箱相同", run_id=run_id,
                )
                items.append(self._item(old_email, new_email, "failed", "新邮箱已被占用"))
                continue
            # Proxy assignment happens at worker start through the batch-local
            # exclusive lease pool; never pass another worker's candidates.
            assignments.append((old_email, box, None, []))
            items.append(self._item(old_email, new_email))

        if not assignments:
            with self._lock:
                self._jobs[run_id] = self._job(run_id, items, "failed")
                self._persist_job(self._jobs[run_id])
            return {"run_id": run_id, "count": len(items)}

        effective_concurrency = effective_rebind_concurrency(
            concurrency, len(dedicated_proxies), len(assignments)
        )
        job = self._job(run_id, items, "running")
        job["options"] = {
            "proxy": dedicated_proxies[0],
            "proxies": dedicated_proxies,
            "mail_timeout": mail_timeout,
            "concurrency": effective_concurrency,
            "requested_concurrency": concurrency,
        }
        job["cancel_event"] = threading.Event()
        job["proxy_pool"] = ProxyLeasePool(dedicated_proxies)
        job["start_gate"] = StartGate()
        with self._lock:
            self._jobs[run_id] = job
            self._persist_job(job)
        executor = ThreadPoolExecutor(max_workers=effective_concurrency, thread_name_prefix="rebind")
        job["executor"] = executor
        for old_email, box, assigned_proxy, proxy_candidates in assignments:
            executor.submit(
                self._worker, run_id, old_email, box, assigned_proxy, proxy_candidates
            )
        return {"run_id": run_id, "count": len(items)}

    @staticmethod
    def _normalize_proxy(candidate: str) -> str:
        value = str(candidate or "").strip()
        if not value:
            raise ValueError("换绑专用代理格式无效")

        if "://" not in value:
            if "@" in value:
                value = f"http://{value}"
            else:
                parts = value.split(":")
                if len(parts) == 4:
                    username, password, host, port = (part.strip() for part in parts)
                    if not username or not password or not host or not port:
                        raise ValueError("换绑专用代理格式无效")
                    value = f"http://{username}:{password}@{host}:{port}"
                elif len(parts) == 2 and parts[0].strip() and parts[1].strip():
                    value = f"http://{value}"
                else:
                    raise ValueError("换绑专用代理格式无效")

        try:
            parsed = urlsplit(value)
            port = parsed.port
        except ValueError as exc:
            raise ValueError("换绑专用代理格式无效") from exc
        if parsed.scheme.lower() not in {
            "http", "https", "socks4", "socks4a", "socks5", "socks5h",
        } or not parsed.hostname:
            raise ValueError("换绑专用代理格式无效")
        if port is not None and not 1 <= port <= 65535:
            raise ValueError("换绑专用代理格式无效")
        return value

    @classmethod
    def _normalize_proxies(cls, *, proxy: str = "", proxies: list[str] | None = None) -> list[str]:
        values = [*(proxies or []), proxy]
        normalized: list[str] = []
        seen: set[str] = set()
        for index, value in enumerate(values, start=1):
            candidate = str(value or "").strip()
            if not candidate or candidate.startswith("#"):
                continue
            try:
                canonical = cls._normalize_proxy(candidate)
            except ValueError as exc:
                raise ValueError(f"换绑专用代理格式无效（第 {index} 条）") from exc
            if canonical in seen:
                continue
            seen.add(canonical)
            normalized.append(canonical)
        return normalized

    @staticmethod
    def _item(old_email: str, new_email: str, status: str = "pending", message: str = "等待处理") -> dict[str, Any]:
        return {
            "old_email": old_email, "new_email": new_email, "status": status,
            "phase": "等待中" if status == "pending" else "失败",
            "message": message, "code": "", "started_at": "", "finished_at": "",
            "logs": [],
        }

    @staticmethod
    def _job(run_id: str, items: list[dict[str, Any]], status: str) -> dict[str, Any]:
        return {
            "run_id": run_id, "status": status, "items": items,
            "created_at": _now(), "created_at_ts": time.time(),
            "started_at": _now() if status == "running" else "",
            "finished_at": _now() if status == "failed" else "",
        }

    def _find_item(self, job: dict[str, Any], old_email: str) -> dict[str, Any] | None:
        return next((item for item in job["items"] if item["old_email"] == old_email), None)

    @staticmethod
    def _format_trace_entry(entry: dict[str, Any]) -> str:
        step = str(entry.get("step") or "trace")
        details = []
        for key, value in entry.items():
            if key in {"time", "step"} or value in (None, "", [], {}):
                continue
            details.append(f"{key}={value}")
        return step if not details else f"{step}: " + ", ".join(details)

    def _append_log(
        self,
        run_id: str,
        old_email: str,
        message: str,
        *,
        phase: str = "",
        level: str = "info",
        at: str | None = None,
    ) -> None:
        with self._lock:
            job = self._jobs.get(run_id)
            item = self._find_item(job, old_email) if job else None
            if not item or not str(message or "").strip():
                return
            logs = item.setdefault("logs", [])
            entry = {
                "time": at or _now(),
                "phase": phase or item.get("phase") or "",
                "level": level,
                "message": str(message).replace("\n", " ")[:2000],
            }
            if logs and logs[-1].get("message") == entry["message"] and logs[-1].get("phase") == entry["phase"]:
                return
            logs.append(entry)
            if len(logs) > 200:
                del logs[:-200]

    def _append_trace(self, run_id: str, old_email: str, trace: Any) -> None:
        if not isinstance(trace, list):
            return
        for entry in trace:
            if not isinstance(entry, dict):
                continue
            self._append_log(
                run_id,
                old_email,
                self._format_trace_entry(entry),
                phase=str(entry.get("step") or ""),
                at=str(entry.get("time") or "") or None,
            )

    @staticmethod
    def _trace_has_step(trace: Any, step: str) -> bool:
        if not isinstance(trace, list):
            return False
        expected = str(step or "").strip().lower()
        return any(
            str(entry.get("step") or entry.get("phase") or "").strip().lower() == expected
            for entry in trace
            if isinstance(entry, dict)
        )

    @classmethod
    def _trace_reached_rebind_begin(cls, trace: Any) -> bool:
        return any(
            cls._trace_has_step(trace, step)
            for step in ("begin", "mail_code", "verify", "export")
        )

    @staticmethod
    def _definitive_verify_rejection(entries: list[dict[str, Any]]) -> bool:
        """Return true only when the server clearly rejected the verify request."""
        combined = " ".join(
            f"{entry.get('code', '')} {entry.get('message', '')}"
            for entry in entries
        ).lower()
        if "verify_failed" not in combined and "verify http" not in combined:
            return False
        return any(
            marker in combined
            for marker in (
                "invalid otp",
                "invalid code",
                "incorrect code",
                "expired code",
                "verify http 400",
                "verify http 401",
                "verify http 403",
                "verify http 404",
                "verify http 409",
                "verify http 410",
                "verify http 422",
                "verify http 429",
            )
        )

    @staticmethod
    def _verify_request_never_connected(entries: list[dict[str, Any]]) -> bool:
        """Recognize transport failures that occurred before an HTTP request completed."""
        combined = " ".join(str(entry.get("message") or "") for entry in entries).lower()
        return any(
            marker in combined
            for marker in (
                "wrong_version_number",
                "tls connect error",
                "ssl_connect",
                "ssl_error_syscall",
                "connection closed abruptly",
            )
        )

    @classmethod
    def _classify_failure(
        cls,
        *,
        trace: Any = None,
        phase: str = "",
        logs: Any = None,
    ) -> dict[str, Any]:
        """Classify failure from explicit progress rather than the outer error code.

        ``EXPORT_FAILED`` is the pipeline's generic catch-all and can be emitted
        during old-account login or the verify request itself.  It therefore
        cannot prove that email verification succeeded.  Only a successful
        verify/export marker is post-rebind evidence.  A server-side verify
        rejection, or a TLS failure before the request connected, is a known
        pre-completion failure and the replacement mailbox can be released.
        Ambiguous verify timeouts remain protected.
        """
        entries: list[dict[str, Any]] = []
        for source in (trace, logs):
            if isinstance(source, list):
                entries.extend(entry for entry in source if isinstance(entry, dict))
        markers = {
            str(entry.get("step") or entry.get("phase") or "").strip().lower()
            for entry in entries
        }
        current_phase = str(phase or "").strip()

        if "export" in markers or any(
            cls._verify_entry_succeeded(entry) for entry in entries
        ):
            return {"stage": "重新获取凭证", "safe_to_release": False, "verification_risk": True}

        if "mail_code" in markers or "verify" in markers:
            if cls._definitive_verify_rejection(entries) or cls._verify_request_never_connected(entries):
                return {"stage": "提交换绑", "safe_to_release": True, "verification_risk": False}
            return {"stage": "提交换绑", "safe_to_release": False, "verification_risk": True}

        if "begin" in markers or "等待验证码" in current_phase:
            return {"stage": "等待验证码", "safe_to_release": True, "verification_risk": False}
        if "begin_need_reauth" in markers:
            return {"stage": "旧邮箱重新授权", "safe_to_release": True, "verification_risk": False}
        if "eligibility" in markers:
            return {"stage": "换绑资格检查", "safe_to_release": True, "verification_risk": False}
        if (
            "login_old" in markers
            or "旧邮箱登录" in markers
            or "旧邮箱登录" in current_phase
        ):
            return {"stage": "旧邮箱登录", "safe_to_release": True, "verification_risk": False}
        if "等待中" in current_phase or current_phase in {"等待中", "等待执行"}:
            return {"stage": "等待执行", "safe_to_release": True, "verification_risk": False}

        # If the runner raised before returning a trace, preserve any UI phase
        # that proves it had already reached verify/export.  Unknown states are
        # intentionally protected rather than guessed as releasable.
        if any(marker in current_phase for marker in ("验证换绑", "提交换绑")):
            return {"stage": "提交换绑", "safe_to_release": False, "verification_risk": True}
        if any(marker in current_phase for marker in ("重新获取凭证", "凭证待刷新")):
            return {"stage": "重新获取凭证", "safe_to_release": False, "verification_risk": True}
        return {"stage": "未知阶段", "safe_to_release": False, "verification_risk": True}

    def _finalize_worker_failure(
        self,
        run_id: str,
        old_email: str,
        new_email: str,
        *,
        code: str,
        message: str,
        trace: Any = None,
    ) -> None:
        with self._lock:
            job = self._jobs.get(run_id)
            item = next(
                (entry for entry in (job or {}).get("items", []) if entry.get("old_email") == old_email),
                {},
            )
            phase = str(item.get("phase") or "")
            logs = list(item.get("logs") or [])
        classification = self._classify_failure(trace=trace, phase=phase, logs=logs)
        stage = str(classification["stage"])
        normalized_code = str(code or "").strip().upper()
        is_pre_change_code = normalized_code in _PRE_CHANGE_RELEASE_SAFE_CODES
        pre_change_release_safe = (
            is_pre_change_code
            and not self._trace_reached_rebind_begin(trace)
            and not self._verified_without_export(trace)
        )
        if pre_change_release_safe:
            stage = "旧邮箱登录"
        safe_to_release = (
            pre_change_release_safe
            if is_pre_change_code
            else bool(classification["safe_to_release"])
        )
        if pre_change_release_safe:
            original = "旧邮箱登录或身份核验未完成"
        else:
            original = str(message or "换绑失败").replace("\n", " ")[:1000]
        if safe_to_release:
            cooldown_seconds = (
                _REBIND_MAILBOX_COOLDOWN_SECONDS if stage == "等待验证码" else 0
            )
            if cooldown_seconds:
                public_message = (
                    f"{stage}失败；换绑尚未提交，新邮箱已自动释放，"
                    f"10分钟内暂停使用，后续换绑将自动跳过。原始错误：{original}"
                )
            else:
                public_message = (
                    f"{stage}失败；换绑尚未提交，新邮箱已自动释放。原始错误：{original}"
                )
            db.set_rebind_mailbox_result(
                new_email,
                status="available",
                reason=public_message,
                failure_stage=stage,
                cooldown_seconds=cooldown_seconds,
            )
            self._update_item(
                run_id,
                old_email,
                status="failed",
                phase=f"换绑前失败·{stage}",
                message=public_message,
                code=code or "REBIND_FAILED",
                failure_stage=stage,
                release_safe=True,
                mailbox_disposition="released",
                finished_at=_now(),
            )
            return

        public_message = (
            f"失败发生在{stage}阶段，换绑可能已提交；新邮箱已保留并禁止释放，"
            f"请进入待补授权/待核验继续处理。原始错误：{original}"
        )
        db.set_rebind_mailbox_result(
            new_email,
            status="retry_pending",
            old_email=old_email,
            reason=public_message,
            run_id=run_id,
            failure_stage=stage,
        )
        self._update_item(
            run_id,
            old_email,
            status="retry_pending",
            phase="换绑状态待核验",
            message=public_message,
            code="REBIND_STATE_REVIEW_REQUIRED",
            failure_stage=stage,
            release_safe=False,
            mailbox_disposition="protected",
            finished_at=_now(),
        )
    @staticmethod
    def _verify_entry_succeeded(entry: dict[str, Any]) -> bool:
        if str(entry.get("step") or entry.get("phase") or "").strip().lower() != "verify":
            return False
        response_keys = entry.get("resp_keys")
        if isinstance(response_keys, (list, tuple, set)) and any(
            str(key or "").strip().lower() == "success" for key in response_keys
        ):
            return True
        response = entry.get("response")
        if isinstance(response, dict) and response.get("success") is True:
            return True
        if entry.get("success") is True:
            return True
        message = str(entry.get("message") or "").lower()
        return "resp_keys" in message and "success" in message

    @classmethod
    def _verified_without_export(cls, trace: Any) -> bool:
        if not isinstance(trace, list) or cls._trace_has_step(trace, "export"):
            return False
        return any(
            cls._verify_entry_succeeded(entry)
            for entry in trace
            if isinstance(entry, dict)
        )

    @classmethod
    def _item_verified_without_export(cls, item: dict[str, Any]) -> bool:
        return cls._verified_without_export(item.get("logs"))

    @staticmethod
    def _restore_archived_registered_identity(
        old_email: str,
        archived: dict[str, Any] | None,
    ) -> dict[str, Any] | None:
        """Restore credentials needed for a verified legacy rebind retry.

        The row deliberately remains under the old email and outside the rebind
        result group until authorization succeeds and the existing atomic
        migration moves it to the replacement email.
        """
        source = dict(archived or {})
        password = str(source.get("password") or "").strip()
        totp_secret = str(source.get("totp_secret") or "").strip()
        if not password or not totp_secret:
            return None
        extra = source.get("extra")
        if not isinstance(extra, dict):
            try:
                extra = json.loads(source.get("extra_json") or "{}")
            except (TypeError, ValueError, json.JSONDecodeError):
                extra = {}
        payload = dict(extra) if isinstance(extra, dict) else {}
        payload.pop("result_group", None)
        payload.pop("rebind_origin", None)
        payload.pop("rebind_history", None)
        payload.update(email=_email(old_email))
        for field in (
            "password", "access_token", "session_token", "refresh_token",
            "id_token", "device_id", "csrf_token", "cookie_header",
            "totp_secret", "totp_factor_id",
        ):
            value = source.get(field)
            if value not in (None, ""):
                payload[field] = value
        db.save_registered(payload)
        restored = db.get_registered(old_email, include_pending_password=True)
        if not restored:
            return None
        if not str(restored.get("password") or "").strip():
            return None
        if not str(restored.get("totp_secret") or "").strip():
            return None
        return restored

    @staticmethod
    def _credential_refresh_required_updates(migrated: dict[str, Any], new_email: str) -> dict[str, Any]:
        return {
            # The email change is confirmed, but the account is not fully
            # usable until the new credentials are authorized.  Keep the row
            # in rebind results while exposing it to the pending-authorization
            # workflow.
            "status": "retry_pending",
            "phase": "换绑完成·凭证待刷新",
            "message": "邮箱已换绑并替换；新凭证自动获取失败，请重新授权",
            "code": "REBIND_OK_CREDENTIAL_REFRESH_REQUIRED",
            "account": RebindService._account_snapshot(migrated, email=new_email),
            "finished_at": _now(),
        }

    @staticmethod
    def _migrate_verified_identity(run_id: str, old_email: str, new_email: str) -> dict[str, Any]:
        old_row = db.get_registered(old_email, include_pending_password=True)
        new_row = db.get_registered(new_email, include_pending_password=True)
        if old_row and not new_row:
            migrated = db.replace_registered_identity(
                old_email,
                new_email,
                {},
                rebind_run_id=run_id,
            )
        elif new_row and not old_row:
            migrated = new_row
        else:
            raise ValueError("换绑后的账号状态无法安全迁移")
        db.set_rebind_mailbox_result(
            new_email,
            status="used",
            old_email=old_email,
            run_id=run_id,
        )
        return migrated

    def _recover_verified_rebind_failures(self) -> int:
        recovered = 0
        archive: dict[str, dict[str, Any]] | None = None
        for run in db.list_rebind_runs(limit=500):
            if str(run.get("status") or "") in {"running", "cancelling"}:
                continue
            changed = False
            for item in run.get("items") or []:
                if not isinstance(item, dict) or item.get("status") != "failed":
                    continue
                if str(item.get("code") or "").strip().upper() == "REBIND_ACCOUNT_DEACTIVATED":
                    continue
                if not self._item_verified_without_export(item):
                    continue
                old_email = _email(str(item.get("old_email") or ""))
                new_email = _email(str(item.get("new_email") or ""))
                if not old_email or not new_email:
                    continue
                run_id = str(run.get("run_id") or "")
                old_row = db.get_registered(old_email, include_pending_password=True)
                new_row = db.get_registered(new_email, include_pending_password=True)
                if not old_row and not new_row:
                    if archive is None:
                        archive = self._legacy_archive()
                    restored = self._restore_archived_registered_identity(
                        old_email,
                        archive.get(old_email) if isinstance(archive, dict) else None,
                    )
                    if not restored:
                        continue
                    item.update(
                        status="retry_pending",
                        phase="换绑完成·凭证待刷新",
                        message="邮箱已换绑；已恢复原账号凭证，请重新授权获取新凭证",
                        code="REBIND_RETRY_AUTH_REQUIRED",
                        account=self._account_snapshot(restored, email=new_email),
                        finished_at=item.get("finished_at") or _now(),
                    )
                    logs = item.setdefault("logs", [])
                    logs.append({
                        "time": _now(),
                        "phase": "换绑完成·凭证待刷新",
                        "level": "warning",
                        "message": "检测到换绑确认成功；已从本地历史备份恢复登录凭证，等待补授权",
                    })
                    db.set_rebind_mailbox_result(
                        new_email,
                        status="retry_pending",
                        old_email=old_email,
                        reason="等待补授权",
                        run_id=run_id,
                        failure_stage="重新获取凭证",
                    )
                    changed = True
                    recovered += 1
                    continue
                try:
                    migrated = self._migrate_verified_identity(
                        run_id,
                        old_email,
                        new_email,
                    )
                except Exception:
                    continue
                item.update(self._credential_refresh_required_updates(migrated, new_email))
                changed = True
                recovered += 1
            if changed:
                statuses = {item.get("status") for item in run.get("items") or []}
                run["status"] = "cancelled" if statuses and statuses <= {"cancelled"} else "finished"
                run["finished_at"] = run.get("finished_at") or _now()
                public_run = self._public_job(run)
                db.save_rebind_run(
                    public_run | {"created_at_ts": run.get("created_at_ts")},
                    source=str(run.get("source") or "webui"),
                )
        return recovered

    def _update_item(self, run_id: str, old_email: str, **updates: Any) -> None:
        with self._lock:
            job = self._jobs.get(run_id)
            item = self._find_item(job, old_email) if job else None
            if not item:
                return
            item.update(updates)
            if updates.get("message"):
                self._append_log(
                    run_id,
                    old_email,
                    str(updates["message"]),
                    phase=str(updates.get("phase") or item.get("phase") or ""),
                )
            if updates.get("status") in {"success", "failed", "retry_pending", "cancelled"}:
                item.setdefault("finished_at", _now())
            self._refresh_job(job)
            self._persist_job(job)

    def _refresh_job(self, job: dict[str, Any] | None) -> None:
        if not job:
            return
        statuses = {item["status"] for item in job["items"]}
        if statuses and statuses <= {"success", "failed", "retry_pending", "cancelled"}:
            job["status"] = "cancelled" if statuses <= {"cancelled"} else "finished"
            job["finished_at"] = _now()

    def _worker(
        self,
        run_id: str,
        old_email: str,
        box: dict[str, Any],
        assigned_proxy: str | None = None,
        proxy_candidates: list[str] | None = None,
    ) -> None:
        with self._lock:
            job = self._jobs.get(run_id)
            cancelled = bool(job and job["cancel_event"].is_set())
        if cancelled:
            db.set_rebind_mailbox_result(box["email"], status="available", old_email=old_email, run_id=run_id)
            self._update_item(run_id, old_email, status="cancelled", phase="已取消", message="任务已取消", finished_at=_now())
            return

        new_email = _email(box["email"])
        trace: Any = None
        failure_code = "REBIND_FAILED"
        lease: _ProxyLease | None = None
        try:
            with self._lock:
                job = self._jobs.get(run_id)
            if not job:
                db.set_rebind_mailbox_result(
                    new_email, status="available", old_email=old_email, run_id=run_id,
                    reason="换绑任务已不存在",
                )
                return
            cancel_event = job["cancel_event"]
            proxy_pool = job.get("proxy_pool")
            start_gate = job.get("start_gate")
            if proxy_pool is not None:
                lease = proxy_pool.acquire(cancel_event=cancel_event)
                if lease is None:
                    db.set_rebind_mailbox_result(
                        new_email, status="available", old_email=old_email, run_id=run_id,
                        reason="任务已取消，换绑邮箱已释放",
                    )
                    self._update_item(
                        run_id, old_email, status="cancelled", phase="已取消",
                        message="任务已取消", finished_at=_now(),
                    )
                    return
                if start_gate is not None and not start_gate.acquire(cancel_event=cancel_event):
                    lease.release()
                    lease = None
                    db.set_rebind_mailbox_result(
                        new_email, status="available", old_email=old_email, run_id=run_id,
                        reason="任务已取消，换绑邮箱已释放",
                    )
                    self._update_item(
                        run_id, old_email, status="cancelled", phase="已取消",
                        message="任务已取消", finished_at=_now(),
                    )
                    return
            row = db.get_registered(old_email, include_pending_password=True) or {}
            self._update_item(run_id, old_email, status="running", phase="旧邮箱登录", message="正在登录旧邮箱", started_at=_now())
            mail_timeout = float(job["options"].get("mail_timeout") or 120)
            old_mail_provider = _create_old_mail_provider(old_email, cancel_event)
            runner = _runner()
            result = runner(
                old_email=old_email,
                password=str(row.get("password") or ""),
                totp_secret=str(row.get("totp_secret") or ""),
                new_email=new_email,
                mail_api=str(box.get("mail_api") or ""),
                proxy=(
                    lease.proxy if lease is not None
                    else str(assigned_proxy or "").strip()
                    or str(job["options"].get("proxy") or "").strip()
                    or None
                ),
                proxy_candidates=(
                    [lease.proxy] if lease is not None
                    else list(proxy_candidates or job["options"].get("proxies") or [])
                ),
                mail_timeout=mail_timeout,
                old_mail_provider=old_mail_provider,
                old_mail_timeout=mail_timeout,
                existing_credentials={
                    key: str(row.get(key) or "")
                    for key in (
                        "access_token",
                        "session_token",
                        "device_id",
                        "cookie_header",
                    )
                },
                on_code_wait=lambda: self._update_item(run_id, old_email, phase="等待验证码", message="已发送验证码，正在轮询新邮箱"),
                on_code_received=lambda: self._update_item(run_id, old_email, phase="验证换绑", message="已收到验证码，正在提交换绑"),
            )
            trace = getattr(result, "trace", None)
            self._append_trace(run_id, old_email, trace)
            if not getattr(result, "ok", False):
                if self._verified_without_export(trace):
                    migrated = self._migrate_verified_identity(
                        run_id, old_email, new_email
                    )
                    self._update_item(
                        run_id,
                        old_email,
                        **self._credential_refresh_required_updates(migrated, new_email),
                    )
                    return
                code = str(getattr(result, "code", "REBIND_FAILED") or "REBIND_FAILED")
                message = str(getattr(result, "message", "换绑失败") or "换绑失败")
                failure_code = code
                if self._is_retryable_login_authorization(code=code, message=message, trace=trace):
                    db.set_rebind_mailbox_result(
                        new_email,
                        status="retry_pending",
                        old_email=old_email,
                        reason=message,
                        run_id=run_id,
                        failure_stage="重新获取凭证",
                    )
                    self._update_item(
                        run_id,
                        old_email,
                        status="retry_pending",
                        phase="登录授权待补",
                        message="登录已完成但授权凭证未取回；已保留换绑邮箱，稍后继续",
                        code="REBIND_RETRY_AUTH_REQUIRED",
                        failure_stage="重新获取凭证",
                        release_safe=False,
                        mailbox_disposition="protected",
                        finished_at=_now(),
                    )
                    return
                self._finalize_worker_failure(
                    run_id,
                    old_email,
                    new_email,
                    code=code,
                    message=message,
                    trace=trace,
                )
                return
            self._update_item(run_id, old_email, phase="重新获取凭证", message="换绑成功，正在保存新凭证")
            bundle_path = Path(str(getattr(result, "bundle_path", "") or ""))
            bundle = json.loads(bundle_path.read_text(encoding="utf-8")) if bundle_path.exists() else {}
            inject_hint = bundle.get("inject_hint") if isinstance(bundle.get("inject_hint"), dict) else {}
            updates = {
                "access_token": bundle.get("access_token", ""),
                "session_token": bundle.get("session_token", ""),
                "device_id": bundle.get("device_id", ""),
                "cookie_header": inject_hint.get("cookie_header", ""),
            }
            migrated = db.replace_registered_identity(
                old_email,
                new_email,
                updates,
                password_recovery_required=not bool(
                    getattr(result, "password_verified", False)
                ),
                rebind_run_id=run_id,
            )
            db.set_rebind_mailbox_result(new_email, status="used", old_email=old_email, run_id=run_id)
            self._update_item(
                run_id,
                old_email,
                status="success",
                phase="完成",
                message="已替换邮箱并写回新凭证",
                code="OK",
                account=self._account_snapshot(migrated, email=new_email),
                finished_at=_now(),
            )
        except Exception as exc:  # noqa: BLE001 - isolate one account in a batch
            message = str(exc).replace("\n", " ")[:1000]
            self._finalize_worker_failure(
                run_id,
                old_email,
                new_email,
                code=failure_code,
                message=message,
                trace=trace,
            )
        finally:
            if lease is not None:
                lease.release()

    @staticmethod
    def _is_retryable_login_authorization(*, code: str = "", message: str = "", trace: Any = None) -> bool:
        fragments = [str(code or ""), str(message or "")]
        if isinstance(trace, list):
            for entry in trace:
                if isinstance(entry, dict):
                    fragments.extend([str(entry.get("code") or ""), str(entry.get("message") or "")])
        combined = " ".join(fragments).lower()
        return RebindService._trace_has_step(trace, "verify") and "login_failed" in combined and (
            "缺少 access_token" in combined or "missing access_token" in combined
        )

    @classmethod
    def _item_needs_login_authorization_retry(cls, item: dict[str, Any]) -> bool:
        return cls._is_retryable_login_authorization(
            code=str(item.get("code") or ""),
            message=str(item.get("message") or ""),
            trace=item.get("logs"),
        )

    def _recover_retryable_login_failures(self) -> int:
        recovered = 0
        for run in db.list_rebind_runs(limit=500):
            if str(run.get("status") or "") not in {"finished", "cancelled", "failed"}:
                continue
            changed = False
            for item in run.get("items") or []:
                if not isinstance(item, dict) or item.get("status") != "failed":
                    continue
                if not self._item_needs_login_authorization_retry(item):
                    continue
                new_email = _email(str(item.get("new_email") or ""))
                old_email = _email(str(item.get("old_email") or ""))
                item.update(
                    status="retry_pending",
                    phase="登录授权待补",
                    message="登录已完成但授权凭证未取回；已保留换绑邮箱，稍后继续",
                    code="REBIND_RETRY_AUTH_REQUIRED",
                )
                if new_email:
                    db.set_rebind_mailbox_result(
                        new_email,
                        status="retry_pending",
                        old_email=old_email,
                        reason="等待补授权",
                        run_id=str(run.get("run_id") or ""),
                        failure_stage="重新获取凭证",
                    )
                changed = True
                recovered += 1
            if changed:
                run["status"] = "finished"
                run["summary"] = self._summary(run.get("items") or [])
                db.save_rebind_run(run, source=str(run.get("source") or "webui"))
        return recovered

    def _normalize_credential_refresh_pending(self) -> int:
        """Repair historical rows that were marked success too early.

        A confirmed email change with failed credential refresh must remain in
        rebind results, but it also needs to be selectable by the reauthorization
        workflow.  Older runs used ``success`` for this intermediate state, so
        normalize them once at startup without touching registration runs.
        """
        normalized = 0
        target_code = "REBIND_OK_CREDENTIAL_REFRESH_REQUIRED"
        for run in db.list_rebind_runs(limit=500):
            if str(run.get("status") or "") in {"running", "cancelling"}:
                continue
            changed = False
            for item in run.get("items") or []:
                if not isinstance(item, dict):
                    continue
                if str(item.get("code") or "").strip().upper() != target_code:
                    continue
                if item.get("status") != "success":
                    continue
                new_email = _email(str(item.get("new_email") or ""))
                old_email = _email(str(item.get("old_email") or ""))
                item["status"] = "retry_pending"
                item["phase"] = "换绑完成·凭证待刷新"
                item["message"] = "邮箱已换绑并替换；新凭证自动获取失败，请重新授权"
                item["failure_stage"] = "重新获取凭证"
                item["release_safe"] = False
                item["mailbox_disposition"] = "protected"
                changed = True
                normalized += 1
            if changed:
                run["summary"] = self._summary(run.get("items") or [])
                db.save_rebind_run(run, source=str(run.get("source") or "webui"))
        return normalized

    def _purge_retry_pending_without_new_email(self) -> int:
        """Delete unusable retry rows that have no replacement email mapping."""
        removed = 0
        for run in db.list_rebind_runs(limit=500):
            if str(run.get("status") or "") in {"running", "cancelling"}:
                continue
            items = run.get("items")
            if not isinstance(items, list):
                continue
            next_items = [
                item for item in items
                if not (
                    isinstance(item, dict)
                    and item.get("status") == "retry_pending"
                    and not _email(str(item.get("new_email") or ""))
                )
            ]
            removed += len(items) - len(next_items)
            if len(next_items) == len(items):
                continue
            run_id = str(run.get("run_id") or "").strip()
            if not next_items:
                db.delete_rebind_run(run_id)
                continue
            run["items"] = next_items
            run["summary"] = self._summary(next_items)
            db.save_rebind_run(run, source=str(run.get("source") or "webui"))
        return removed

    @staticmethod
    def _account_snapshot(row: dict[str, Any] | None, *, email: str = "") -> dict[str, Any]:
        """Return the full credential projection used by the registered page.

        Rebind result rows are persisted with their own snapshot so the result page
        remains usable after the old identity is atomically removed.  Values are
        intentionally not masked: this is the operator-facing local UI requested
        for credential export/copy.
        """
        source = dict(row or {})
        extra = source.get("extra")
        if not isinstance(extra, dict):
            try:
                extra = json.loads(source.get("extra_json") or "{}")
            except (TypeError, ValueError, json.JSONDecodeError):
                extra = {}
        if not isinstance(extra, dict):
            extra = {}
        def value(key: str) -> str:
            value = source.get(key, "")
            return "" if value is None else str(value)
        snapshot = {
            "email": email or value("email"),
            "password": value("password"),
            "totp_secret": value("totp_secret"),
            "totp_factor_id": value("totp_factor_id"),
            "access_token": value("access_token"),
            "session_token": value("session_token"),
            "refresh_token": value("refresh_token"),
            "id_token": value("id_token"),
            "device_id": value("device_id"),
            "csrf_token": value("csrf_token"),
            "cookie_header": value("cookie_header"),
            "created_at": source.get("created_at", ""),
            "at_len": len(value("access_token")),
            "st_len": len(value("session_token")),
            "rt_len": len(value("refresh_token")),
            "totp_factor_len": len(value("totp_factor_id")),
            "plus_check": extra.get("plus_check") if isinstance(extra.get("plus_check"), dict) else {},
            "extra": extra,
        }
        return snapshot

    @staticmethod
    def _legacy_archive() -> dict[str, dict[str, Any]]:
        """Read old local registered credentials without modifying any database."""
        candidates: list[Path] = []
        configured = os.environ.get("REBIND_LEGACY_DB_ARCHIVE", "").strip()
        if configured:
            configured_path = Path(configured)
            if configured_path.is_dir():
                for pattern in ("*.db", "*.bak", "*.sqlite", "*.sqlite3"):
                    candidates.extend(configured_path.rglob(pattern))
            else:
                candidates.append(configured_path)
        webui_dir = Path(__file__).resolve().parent
        candidates.extend([
            webui_dir / "webui.db.before-rollback-retry-1787074545.bak",
            *sorted(webui_dir.glob("webui.db.before-*.bak")),
        ])
        backups_dir = webui_dir / "backups"
        if backups_dir.is_dir():
            nested_backups: list[Path] = []
            for pattern in ("*.db", "*.bak", "*.sqlite", "*.sqlite3"):
                nested_backups.extend(backups_dir.rglob(pattern))
            candidates.extend(sorted(
                nested_backups,
                key=lambda item: item.stat().st_mtime if item.is_file() else 0,
                reverse=True,
            ))
        archive: dict[str, dict[str, Any]] = {}
        seen: set[str] = set()
        for path in candidates:
            path = Path(path)
            key = str(path.resolve()) if path else ""
            if not key or key in seen or not path.is_file():
                continue
            seen.add(key)
            try:
                con = sqlite3.connect(str(path))
                con.row_factory = sqlite3.Row
                rows = con.execute("SELECT * FROM registered").fetchall()
            except Exception:
                continue
            finally:
                try:
                    con.close()
                except Exception:
                    pass
            for row in rows:
                record = dict(row)
                email = _email(str(record.get("email") or ""))
                if not email:
                    continue
                try:
                    record["extra"] = json.loads(record.get("extra_json") or "{}")
                except (TypeError, ValueError, json.JSONDecodeError):
                    record["extra"] = {}
                target = archive.setdefault(email, {"email": email})
                for field, value in record.items():
                    if (
                        target.get(field) in (None, "", {}, [])
                        and value not in (None, "", {}, [])
                    ):
                        target[field] = value
        return archive

    @staticmethod
    def _legacy_account_snapshot(
        run_dir: Path,
        *,
        old_email: str,
        new_email: str,
        entries: list[dict[str, Any]],
        archive: dict[str, dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Merge old DB credentials with the 8767 exported login bundle."""
        old_email = _email(old_email)
        new_email = _email(new_email)
        merged: dict[str, Any] = {}
        archive = archive if isinstance(archive, dict) else {}
        for key in (old_email, new_email):
            record = archive.get(key)
            if isinstance(record, dict):
                for field, value in record.items():
                    if value not in (None, "", {}, []):
                        merged[field] = value
        for key in (new_email, old_email):
            try:
                record = db.get_registered(key, include_pending_password=True)
            except Exception:
                record = None
            if record:
                for field, value in record.items():
                    if value not in (None, "", {}, []):
                        merged[field] = value
        bundle: dict[str, Any] = {}
        bundle_path = Path(run_dir) / "login_bundle.json"
        try:
            parsed = json.loads(bundle_path.read_text(encoding="utf-8"))
            if isinstance(parsed, dict):
                bundle = parsed
        except (OSError, TypeError, ValueError, json.JSONDecodeError):
            bundle = {}
        inject_hint = bundle.get("inject_hint") if isinstance(bundle.get("inject_hint"), dict) else {}
        for field in (
            "access_token", "session_token", "refresh_token", "id_token",
            "device_id", "csrf_token", "cookie_header",
        ):
            candidate = bundle.get(field)
            if field == "cookie_header" and not candidate:
                candidate = inject_hint.get("cookie_header") or bundle.get("cookie")
            if candidate not in (None, ""):
                merged[field] = candidate
        if bundle.get("email"):
            merged["email"] = bundle["email"]
        login_old = next((entry for entry in entries if entry.get("step") == "login_old"), {})
        exported = next((entry for entry in reversed(entries) if entry.get("step") == "export"), {})
        if not merged.get("totp_factor_id") and login_old.get("factor_id"):
            merged["totp_factor_id"] = login_old["factor_id"]
        if not merged.get("access_token") and exported.get("at"):
            merged["access_token"] = exported["at"]
        merged["email"] = new_email or merged.get("email") or old_email
        return RebindService._account_snapshot(merged, email=merged["email"])

    @classmethod
    def _refresh_success_accounts(cls, job: dict[str, Any] | None) -> dict[str, Any] | None:
        """Overlay successful result snapshots with current rebind credentials.

        Reauthorization updates the authoritative ``registered`` row.  Rebind
        history keeps its own immutable task details, while credential columns
        must show the newly fetched tokens and newly bound 2FA immediately.
        """
        if not job:
            return job
        refreshed = dict(job)
        refreshed_items: list[dict[str, Any]] = []
        for raw_item in job.get("items") or []:
            item = dict(raw_item)
            if item.get("status") == "success":
                account = item.get("account") if isinstance(item.get("account"), dict) else {}
                email = _email(str(item.get("new_email") or account.get("email") or ""))
                current = db.get_registered(email, include_pending_password=True) if email else None
                if current:
                    item["account"] = cls._account_snapshot(current, email=email)
            refreshed_items.append(item)
        refreshed["items"] = refreshed_items
        # Persisted historical runs may carry a stale summary created before
        # retry_pending existed.  Always derive public counts from the items.
        refreshed["summary"] = cls._summary(refreshed_items)
        return refreshed


    @staticmethod
    def _summary(items: list[dict[str, Any]]) -> dict[str, int]:
        statuses = ("pending", "running", "success", "failed", "retry_pending", "cancelled")
        return {
            "total": len(items),
            **{status: sum(item.get("status") == status for item in items) for status in statuses},
        }

    @staticmethod
    def _public_job(job: dict[str, Any]) -> dict[str, Any]:
        result = {
            key: value for key, value in job.items()
            if key not in {"options", "cancel_event", "executor", "created_at_ts", "proxy_pool", "start_gate"}
        }
        items = result.get("items") or []
        result["summary"] = RebindService._summary(items)
        return result

    def _persist_job(self, job: dict[str, Any] | None, *, source: str = "webui") -> None:
        if job:
            db.save_rebind_run(self._public_job(job) | {"created_at_ts": job.get("created_at_ts")}, source=source)

    def status(self, run_id: str) -> dict[str, Any] | None:
        with self._lock:
            job = self._jobs.get(run_id)
            if job:
                return self._refresh_success_accounts(self._public_job(job))
        return self._refresh_success_accounts(db.get_rebind_run(run_id))

    @staticmethod
    def _authorization_item(
        source_run_id: str,
        old_email: str,
        new_email: str,
    ) -> dict[str, Any]:
        return {
            "source_run_id": source_run_id,
            "old_email": old_email,
            "new_email": new_email,
            "email": new_email,
            "status": "pending",
            "phase": "等待补授权",
            "message": "等待处理",
            "started_at": "",
            "finished_at": "",
            "logs": [],
        }

    @staticmethod
    def _find_authorization_item(
        job: dict[str, Any],
        source_run_id: str,
        old_email: str,
        new_email: str,
    ) -> dict[str, Any] | None:
        return next((
            item for item in (job.get("items") or [])
            if str(item.get("source_run_id") or "") == source_run_id
            and _email(str(item.get("old_email") or "")) == old_email
            and _email(str(item.get("new_email") or "")) == new_email
        ), None)

    @staticmethod
    def _find_source_item(
        run: dict[str, Any], old_email: str, new_email: str
    ) -> dict[str, Any] | None:
        return next((
            item for item in (run.get("items") or [])
            if isinstance(item, dict)
            and _email(str(item.get("old_email") or "")) == old_email
            and _email(str(item.get("new_email") or "")) == new_email
        ), None)

    def _authorization_mapping_is_active(
        self, source_run_id: str, old_email: str, new_email: str
    ) -> bool:
        for job in self._authorization_jobs.values():
            if str(job.get("status") or "") not in {"running", "cancelling"}:
                continue
            item = self._find_authorization_item(job, source_run_id, old_email, new_email)
            if item and item.get("status") in {"pending", "running"}:
                return True
        return False

    def _update_authorization_item(
        self,
        job_id: str,
        source_run_id: str,
        old_email: str,
        new_email: str,
        *,
        log_message: str = "",
        log_level: str = "info",
        **updates: Any,
    ) -> None:
        with self._lock:
            job = self._authorization_jobs.get(job_id)
            item = (
                self._find_authorization_item(job, source_run_id, old_email, new_email)
                if job else None
            )
            if not item:
                return
            item.update(updates)
            if log_message:
                logs = item.setdefault("logs", [])
                logs.append({
                    "time": _now(),
                    "phase": str(updates.get("phase") or item.get("phase") or ""),
                    "level": log_level,
                    "message": str(log_message).replace("\n", " ")[:1000],
                })
                if len(logs) > 200:
                    del logs[:-200]
            if item.get("status") in {"success", "failed", "retry_pending", "cancelled"}:
                item["finished_at"] = str(item.get("finished_at") or _now())
            statuses = {str(row.get("status") or "") for row in (job.get("items") or [])}
            if statuses and statuses <= {"success", "failed", "retry_pending", "cancelled"}:
                job["status"] = "cancelled" if statuses <= {"cancelled"} else "finished"
                job["finished_at"] = _now()

    def _update_authorization_source(
        self,
        source_run_id: str,
        old_email: str,
        new_email: str,
        *,
        log_message: str = "",
        log_level: str = "info",
        **updates: Any,
    ) -> None:
        """Update the authoritative original rebind item, including live jobs."""
        with self._lock:
            live = self._jobs.get(source_run_id)
            run = live if live is not None else db.get_rebind_run(source_run_id)
            if not run:
                raise ValueError("原换绑任务不存在")
            item = self._find_source_item(run, old_email, new_email)
            if not item:
                raise ValueError("原换绑记录与账号映射不一致")
            item.update(updates)
            if log_message:
                logs = item.setdefault("logs", [])
                logs.append({
                    "time": _now(),
                    "phase": str(updates.get("phase") or item.get("phase") or ""),
                    "level": log_level,
                    "message": str(log_message).replace("\n", " ")[:1000],
                })
                if len(logs) > 200:
                    del logs[:-200]
            if live is not None:
                self._refresh_job(live)
                public = self._public_job(live) | {"created_at_ts": live.get("created_at_ts")}
            else:
                run["summary"] = self._summary(run.get("items") or [])
                public = run
            db.save_rebind_run(public, source=str(run.get("source") or "webui"))

    def _authorization_credential_source(
        self,
        source_run_id: str,
        old_email: str,
        new_email: str,
        source: dict[str, Any] | None = None,
        source_item: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Resolve password/TOTP from the post-rebind identity, not only the old row.

        A completed rebind intentionally removes the old registered row.  The new
        mailbox row (or the durable result snapshot) is therefore the authoritative
        source for a later credential refresh.  Fields are merged independently so
        a partially restored row can still use the missing values from the snapshot.
        """
        source = source or self._jobs.get(source_run_id) or db.get_rebind_run(source_run_id)
        source_item = source_item or (
            self._find_source_item(source, old_email, new_email) if source else None
        )
        old_row = db.get_registered(old_email, include_pending_password=True) or {}
        new_row = db.get_registered(new_email, include_pending_password=True) or {}
        snapshot = (source_item or {}).get("account")
        if not isinstance(snapshot, dict):
            snapshot = {}

        candidates = (old_row, new_row, snapshot)

        def first_value(field: str) -> str:
            for candidate in candidates:
                value = candidate.get(field) if isinstance(candidate, dict) else ""
                if value is not None and str(value).strip():
                    return str(value).strip()
            return ""

        return {
            "password": first_value("password"),
            "totp_secret": first_value("totp_secret"),
            "totp_factor_id": first_value("totp_factor_id"),
            "old_row": old_row,
            "new_row": new_row,
            "snapshot": snapshot,
        }

    def start_authorization_retry(
        self,
        items: list[dict[str, Any]],
        *,
        proxy: str = "",
        concurrency: int = 1,
    ) -> dict[str, Any]:
        """Retry credential export for completed rebinds using new email + old password/TOTP."""
        if not isinstance(items, list) or not items:
            raise ValueError("至少选择一个待补授权账号")
        if len(items) > 100:
            raise ValueError("单次最多处理 100 个账号")
        concurrency = max(1, min(int(concurrency), _REBIND_MAX_CONCURRENCY))
        normalized: list[tuple[str, str, str]] = []
        seen: set[tuple[str, str, str]] = set()

        with self._lock:
            for raw in items:
                if not isinstance(raw, dict):
                    raise ValueError("待补授权账号映射格式错误")
                source_run_id = str(
                    raw.get("source_run_id") or raw.get("run_id") or ""
                ).strip()
                old_email = _email(str(raw.get("old_email") or ""))
                new_email = _email(str(raw.get("new_email") or ""))
                if not source_run_id:
                    raise ValueError("缺少原换绑任务 ID")
                if not old_email:
                    raise ValueError("缺少原注册邮箱")
                if not new_email:
                    raise ValueError("缺少换绑邮箱")
                if old_email == new_email:
                    raise ValueError("换绑邮箱不能与原邮箱相同")
                key = (source_run_id, old_email, new_email)
                if key in seen:
                    continue
                seen.add(key)

                source = self._jobs.get(source_run_id) or db.get_rebind_run(source_run_id)
                if not source:
                    raise ValueError(f"原换绑任务不存在: {source_run_id}")
                source_item = self._find_source_item(source, old_email, new_email)
                if not source_item:
                    raise ValueError(f"原换绑记录映射不一致: {old_email} → {new_email}")
                if str(source_item.get("status") or "") != "retry_pending":
                    raise ValueError(f"账号不是待补授权状态: {new_email}")
                if self._authorization_mapping_is_active(source_run_id, old_email, new_email):
                    raise ValueError(f"账号正在补授权: {new_email}")

                old_state = db.get_registered_operation_state(old_email)
                new_state = db.get_registered_operation_state(new_email)
                if old_state.get("active"):
                    raise ValueError(f"账号当前有其他任务运行: {old_email}")
                if new_state.get("active"):
                    raise ValueError(f"账号当前有其他任务运行: {new_email}")
                credentials = self._authorization_credential_source(
                    source_run_id,
                    old_email,
                    new_email,
                    source=source,
                    source_item=source_item,
                )
                if not credentials.get("password"):
                    raise ValueError(f"{new_email} 缺少密码，无法补授权")
                if not credentials.get("totp_secret"):
                    raise ValueError(f"{new_email} 缺少 2FA Secret，无法补授权")
                # The new row is expected after a completed rebind.  It is a valid
                # retry target, not a duplicate registration result.
                normalized.append(key)

            if not normalized:
                raise ValueError("至少选择一个待补授权账号")

            job_id = f"rebind-auth-{uuid.uuid4().hex}"
            job = self._job(
                job_id,
                [self._authorization_item(*mapping) for mapping in normalized],
                "running",
            )
            job["kind"] = "rebind_authorization"
            job["proxy"] = str(proxy or "").strip()
            job["cancel_event"] = threading.Event()
            job["rate_limit_event"] = threading.Event()
            self._authorization_jobs[job_id] = job

            executor = ThreadPoolExecutor(
                max_workers=concurrency,
                thread_name_prefix="rebind-authorization",
            )
            job["executor"] = executor
            for mapping in normalized:
                executor.submit(self._authorization_worker, job_id, *mapping)
        return {"run_id": job_id, "count": len(normalized)}

    def _authorization_worker(
        self,
        job_id: str,
        source_run_id: str,
        old_email: str,
        new_email: str,
    ) -> None:
        with self._lock:
            job = self._authorization_jobs.get(job_id)
            cancel_event = (job or {}).get("cancel_event") or threading.Event()
            cancelled = cancel_event.is_set()
            rate_limited = bool(job and job["rate_limit_event"].is_set())
            proxy = str((job or {}).get("proxy") or "").strip() or None
        if cancelled:
            self._update_authorization_item(
                job_id, source_run_id, old_email, new_email,
                status="cancelled", phase="已取消", message="任务已取消",
                log_message="补授权任务已取消",
            )
            return
        if rate_limited:
            message = "授权接口限流，本账号未发起登录，请稍后重试"
            self._update_authorization_source(
                source_run_id, old_email, new_email,
                status="retry_pending", phase="授权限流待重试",
                message=message, code="REBIND_RETRY_AUTH_REQUIRED",
                log_message=message, log_level="warning",
            )
            self._update_authorization_item(
                job_id, source_run_id, old_email, new_email,
                status="retry_pending", phase="授权限流待重试", message=message,
                finished_at=_now(), log_message=message, log_level="warning",
            )
            return

        self._update_authorization_item(
            job_id, source_run_id, old_email, new_email,
            status="running", phase="新邮箱登录", message="正在使用新邮箱和已保存的密码、2FA 登录",
            started_at=_now(), log_message="开始新邮箱密码 + 2FA 授权（无需邮箱验证码）",
        )
        self._update_authorization_source(
            source_run_id, old_email, new_email,
            status="retry_pending", phase="正在补授权",
            message="正在使用换绑邮箱重新获取凭证",
            code="REBIND_RETRY_AUTH_REQUIRED",
            log_message="开始补授权：使用换绑邮箱和已保存的密码、2FA",
        )
        try:
            source = self._jobs.get(source_run_id) or db.get_rebind_run(source_run_id)
            source_item = (
                self._find_source_item(source, old_email, new_email)
                if source else None
            )
            credentials = self._authorization_credential_source(
                source_run_id,
                old_email,
                new_email,
                source=source,
                source_item=source_item,
            )
            password = str(credentials.get("password") or "").strip()
            totp_secret = str(credentials.get("totp_secret") or "").strip()
            if not password or not totp_secret:
                raise ValueError("换绑账号缺少密码或 2FA Secret")

            login_with_password_and_totp, build_login_bundle = _authorization_tools()
            login = _run_authorization_call(
                login_with_password_and_totp,
                new_email,
                password,
                totp_secret,
                proxy=proxy,
                timeout=REBIND_AUTHORIZATION_TIMEOUT_SECONDS,
                cancel_event=cancel_event,
            )

            with self._lock:
                job = self._authorization_jobs.get(job_id)
                cancelled = bool(job and job["cancel_event"].is_set())
            if cancelled:
                db.set_rebind_mailbox_result(
                    new_email, status="retry_pending", old_email=old_email,
                    reason="补授权任务已取消", run_id=source_run_id,
                    failure_stage="重新获取凭证",
                )
                self._update_authorization_source(
                    source_run_id, old_email, new_email,
                    status="retry_pending", phase="登录授权待补",
                    message="补授权已取消；已保留原账号和换绑邮箱",
                    code="REBIND_RETRY_AUTH_REQUIRED",
                    log_message="补授权任务已取消，可稍后重试",
                )
                self._update_authorization_item(
                    job_id, source_run_id, old_email, new_email,
                    status="cancelled", phase="已取消", message="任务已取消",
                    log_message="补授权任务已取消",
                )
                return

            self._update_authorization_item(
                job_id, source_run_id, old_email, new_email,
                phase="获取凭证", message="登录成功，正在获取并保存新凭证",
                log_message="新邮箱登录成功，正在生成凭证包",
            )
            bundle = build_login_bundle(
                login,
                rebind_email=new_email,
                login_method="password+2fa",
            )
            if not isinstance(bundle, dict):
                raise RuntimeError("凭证包格式错误")
            bundle_email = _email(str(bundle.get("email") or bundle.get("rebind_email") or ""))
            if bundle_email and bundle_email != new_email:
                raise RuntimeError("授权返回账号与换绑邮箱不一致")
            access_token = str(bundle.get("access_token") or "").strip()
            session_token = str(bundle.get("session_token") or "").strip()
            if not access_token:
                raise RuntimeError("授权完成但缺少 access_token")
            inject_hint = bundle.get("inject_hint") if isinstance(bundle.get("inject_hint"), dict) else {}
            updates = {
                "access_token": access_token,
                "session_token": session_token,
                "refresh_token": str(bundle.get("refresh_token") or "").strip(),
                "id_token": str(bundle.get("id_token") or "").strip(),
                "device_id": str(bundle.get("device_id") or "").strip(),
                "csrf_token": str(bundle.get("csrf_token") or "").strip(),
                "cookie_header": str(inject_hint.get("cookie_header") or bundle.get("cookie_header") or "").strip(),
            }
            old_row = db.get_registered(old_email, include_pending_password=True)
            new_row = db.get_registered(new_email, include_pending_password=True)
            if old_row and not new_row:
                migrated = db.replace_registered_identity(
                    old_email,
                    new_email,
                    updates,
                    rebind_run_id=source_run_id,
                )
            else:
                # Post-rebind retries normally already have the new-mailbox row.
                # Fill any missing password/TOTP/snapshot data first, then replace
                # only the fresh authorization fields so the new row is preserved.
                snapshot = dict(credentials.get("snapshot") or {})
                snapshot.update({
                    "email": new_email,
                    "password": password,
                    "totp_secret": totp_secret,
                    "totp_factor_id": str(credentials.get("totp_factor_id") or "").strip(),
                })
                db.restore_rebind_result_credentials_if_missing(
                    snapshot,
                    old_email=old_email,
                    run_id=source_run_id,
                )
                if not db.merge_registered_credentials(
                    new_email,
                    updates,
                    create_if_missing=True,
                ):
                    raise RuntimeError("换绑账号注册结果不存在，无法保存新凭证")
                migrated = db.get_registered(
                    new_email,
                    include_pending_password=True,
                ) or {}
            db.set_rebind_mailbox_result(
                new_email, status="used", old_email=old_email, run_id=source_run_id,
            )
            self._update_authorization_source(
                source_run_id, old_email, new_email,
                status="success", phase="完成",
                message="补授权成功，已替换邮箱并写回新凭证",
                code="OK", account=self._account_snapshot(migrated, email=new_email),
                finished_at=_now(),
                log_message="补授权成功，账号已迁移到换绑邮箱",
            )
            self._update_authorization_item(
                job_id, source_run_id, old_email, new_email,
                status="success", phase="完成", message="补授权成功，已写回新凭证",
                finished_at=_now(), log_message="补授权成功",
            )
        except _AuthorizationCancelledError:
            # Cancellation must never release or delete the mailbox. The source
            # result remains retryable, while this job item is terminal so the
            # batch can finish and the same mapping can be started again.
            db.set_rebind_mailbox_result(
                new_email,
                status="retry_pending",
                old_email=old_email,
                reason="补授权任务已取消，等待重试",
                run_id=source_run_id,
                failure_stage="重新获取凭证",
            )
            message = "补授权已取消；账号和换绑邮箱已保留，可稍后重试"
            self._update_authorization_source(
                source_run_id,
                old_email,
                new_email,
                status="retry_pending",
                phase="已取消",
                message=message,
                code="REBIND_RETRY_AUTH_REQUIRED",
                failure_stage="重新获取凭证",
                log_message=message,
                log_level="warning",
            )
            self._update_authorization_item(
                job_id,
                source_run_id,
                old_email,
                new_email,
                status="cancelled",
                phase="已取消",
                message="补授权任务已取消",
                code="REBIND_RETRY_AUTH_REQUIRED",
                failure_stage="重新获取凭证",
                log_message=message,
                log_level="warning",
            )
        except Exception as exc:  # noqa: BLE001 - isolate one account in a batch
            diagnostic = re.sub(
                r";?\s*request_id=[^;)\s]+",
                "",
                safe_public_error(exc, "换绑补授权"),
            )
            status_code = getattr(exc, "status_code", None)
            response = getattr(exc, "response", None)
            response_status = getattr(response, "status_code", None)
            error_text = str(exc).lower()
            is_rate_limited = (
                status_code == 429
                or response_status == 429
                or "http 429" in error_text
                or "rate limited" in error_text
                or "rate_limit" in error_text
            )
            if _looks_rebind_account_deactivated(error_text):
                public_message = (
                    "账号已停用，不可继续补授权；已保留原账号记录并保护换绑邮箱，禁止释放"
                )
                db.set_rebind_mailbox_result(
                    new_email,
                    status="failed",
                    old_email=old_email,
                    reason="账号已停用，换绑邮箱禁止释放",
                    run_id=source_run_id,
                    failure_stage="新邮箱登录授权",
                    release_safe=False,
                )
                self._update_authorization_source(
                    source_run_id,
                    old_email,
                    new_email,
                    status="failed",
                    phase="账号已停用",
                    message=public_message,
                    code="REBIND_ACCOUNT_DEACTIVATED",
                    finished_at=_now(),
                    mailbox_disposition="protected",
                    log_message=f"{public_message}；{diagnostic}",
                    log_level="error",
                )
                self._update_authorization_item(
                    job_id,
                    source_run_id,
                    old_email,
                    new_email,
                    status="failed",
                    phase="账号已停用",
                    message=public_message,
                    code="REBIND_ACCOUNT_DEACTIVATED",
                    finished_at=_now(),
                    log_message=f"补授权终止；{diagnostic}",
                    log_level="error",
                )
                return
            classified = _classify_authorization_failure(exc)
            if (
                not is_rate_limited
                and classified["code"] in {
                    "REBIND_PASSWORD_REJECTED",
                    "REBIND_AUTH_INVALID_STATE",
                }
            ):
                source = self._jobs.get(source_run_id) or db.get_rebind_run(source_run_id)
                source_item = (
                    self._find_source_item(source, old_email, new_email)
                    if source else None
                )
                prior_failure = self._classify_failure(
                    trace=(source_item or {}).get("trace"),
                    phase=str((source_item or {}).get("phase") or ""),
                    logs=(source_item or {}).get("logs"),
                )
                rebind_was_confirmed = (
                    self._item_verified_without_export(source_item or {})
                    or prior_failure["stage"] == "重新获取凭证"
                )
                if not rebind_was_confirmed:
                    old_identity_authenticated = False
                    try:
                        old_login = _run_authorization_call(
                            login_with_password_and_totp,
                            old_email,
                            password,
                            totp_secret,
                            proxy=proxy,
                            timeout=REBIND_AUTHORIZATION_TIMEOUT_SECONDS,
                            cancel_event=cancel_event,
                        )
                        old_result = getattr(old_login, "result", None)
                        if isinstance(old_result, dict):
                            old_access_token = str(old_result.get("access_token") or "").strip()
                            old_session_token = str(old_result.get("session_token") or "").strip()
                        else:
                            old_access_token = str(
                                getattr(old_result, "access_token", "") or ""
                            ).strip()
                            old_session_token = str(
                                getattr(old_result, "session_token", "") or ""
                            ).strip()
                        old_identity_authenticated = bool(
                            old_access_token or old_session_token
                        )
                    except Exception:
                        # An inconclusive old-identity check must never release the mailbox.
                        old_identity_authenticated = False

                    if old_identity_authenticated:
                        failure_stage = str(prior_failure["stage"] or "换绑前")
                        phase = f"换绑前失败·{failure_stage}"
                        public_message = (
                            "已确认换绑未完成：旧账号仍可认证，换绑邮箱已自动释放"
                        )
                        db.set_rebind_mailbox_result(
                            new_email,
                            status="available",
                            reason="已确认换绑未完成，邮箱已自动释放",
                            failure_stage=failure_stage,
                        )
                        self._update_authorization_source(
                            source_run_id,
                            old_email,
                            new_email,
                            status="failed",
                            phase=phase,
                            message=public_message,
                            code="REBIND_NOT_COMPLETED",
                            failure_stage=failure_stage,
                            release_safe=True,
                            mailbox_disposition="released",
                            finished_at=_now(),
                            log_message=public_message,
                            log_level="warning",
                        )
                        self._update_authorization_item(
                            job_id,
                            source_run_id,
                            old_email,
                            new_email,
                            status="failed",
                            phase=phase,
                            message=public_message,
                            code="REBIND_NOT_COMPLETED",
                            failure_stage=failure_stage,
                            release_safe=True,
                            mailbox_disposition="released",
                            finished_at=_now(),
                            log_message=public_message,
                            log_level="warning",
                        )
                        return

            if is_rate_limited:
                with self._lock:
                    job = self._authorization_jobs.get(job_id)
                    if job:
                        job["rate_limit_event"].set()
                phase = "授权限流待重试"
                code = "REBIND_RETRY_AUTH_REQUIRED"
                failure_stage = "重新获取凭证"
                public_message = "授权接口限流，已停止启动后续账号，请稍后重试"
                reason = "授权接口限流，等待重试"
            else:
                phase = classified["phase"]
                code = classified["code"]
                failure_stage = classified["failure_stage"]
                public_message = classified["message"]
                reason = classified["reason"]
            db.set_rebind_mailbox_result(
                new_email, status="retry_pending", old_email=old_email,
                reason=reason, run_id=source_run_id,
                failure_stage=failure_stage,
            )
            self._update_authorization_source(
                source_run_id, old_email, new_email,
                status="retry_pending", phase=phase,
                message=public_message, code=code,
                failure_stage=failure_stage,
                log_message=f"{public_message}；{diagnostic}", log_level="error",
            )
            self._update_authorization_item(
                job_id, source_run_id, old_email, new_email,
                status="retry_pending", phase=phase, code=code,
                failure_stage=failure_stage,
                message=public_message, finished_at=_now(),
                log_message=f"授权失败（{phase}）；{diagnostic}", log_level="error",
            )

    @staticmethod
    def _public_authorization_job(job: dict[str, Any]) -> dict[str, Any]:
        result = {
            key: value for key, value in job.items()
            if key not in {"proxy", "cancel_event", "rate_limit_event", "executor", "created_at_ts"}
        }
        result["summary"] = RebindService._summary(result.get("items") or [])
        return result

    def authorization_status(self, job_id: str) -> dict[str, Any] | None:
        with self._lock:
            job = self._authorization_jobs.get(str(job_id or "").strip())
            return self._public_authorization_job(job) if job else None

    def cancel_authorization_retry(self, job_id: str) -> bool:
        with self._lock:
            job = self._authorization_jobs.get(str(job_id or "").strip())
            if not job or job.get("status") not in {"running", "cancelling"}:
                return False
            job["cancel_event"].set()
            job["status"] = "cancelling"
            for item in job.get("items") or []:
                if item.get("status") == "pending":
                    item.update(
                        status="cancelled", phase="已取消", message="任务已取消",
                        finished_at=_now(),
                    )
                    item.setdefault("logs", []).append({
                        "time": _now(), "phase": "已取消", "level": "info",
                        "message": "补授权任务已取消",
                    })
            statuses = {str(item.get("status") or "") for item in (job.get("items") or [])}
            if statuses and statuses <= {"success", "retry_pending", "cancelled"}:
                job["status"] = "cancelled" if statuses <= {"cancelled"} else "finished"
                job["finished_at"] = _now()
            return True

    def list_runs(self, limit: int = 500) -> list[dict[str, Any]]:
        return [
            self._refresh_success_accounts(run)
            for run in db.list_rebind_runs(limit)
        ]

    def export_rows(self, selections: list[dict[str, str]]) -> list[dict[str, Any]]:
        """Return selected successful snapshots in the caller-selected order."""
        normalized: list[tuple[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for selection in selections or []:
            if not isinstance(selection, dict):
                continue
            key = (str(selection.get("run_id") or "").strip(), _email(selection.get("email") or ""))
            if not key[0] or not key[1] or key in seen:
                continue
            seen.add(key)
            normalized.append(key)
        if not normalized:
            raise ValueError("至少选择一个换绑成功账号")
        if len(normalized) > 100:
            raise ValueError("单次最多导出 100 个换绑账号")

        rows: list[dict[str, Any]] = []
        exported_emails: set[str] = set()
        for run_id, target_email in normalized:
            if target_email in exported_emails:
                continue
            run = self.status(run_id)
            if not run:
                raise ValueError(f"换绑结果不存在或已删除: {target_email}")
            matched = None
            for item in run.get("items") or []:
                account = item.get("account") if isinstance(item.get("account"), dict) else {}
                item_email = _email(item.get("new_email") or account.get("email") or item.get("email") or "")
                if item.get("status") == "success" and item_email == target_email:
                    matched = account
                    break
            if matched is None:
                raise ValueError(f"只能导出仍存在的换绑成功结果: {target_email}")
            rows.append(self._account_snapshot(matched, email=target_email))
            exported_emails.add(target_email)
        return rows

    def delete_result(self, run_id: str, email: str) -> bool:
        """Delete one finished in-memory result and persist the same snapshot."""
        target_run_id = str(run_id or '').strip()
        target_email = _email(email)
        if not target_run_id or not target_email:
            return False
        with self._lock:
            job = self._jobs.get(target_run_id)
            if not job or job.get('status') in {'running', 'cancelling'}:
                return False
            items = job.get('items') or []
            next_items = []
            removed = False
            for item in items:
                account = item.get('account') if isinstance(item.get('account'), dict) else {}
                item_email = _email(account.get('email') or item.get('new_email') or item.get('email') or '')
                if item_email == target_email:
                    removed = True
                else:
                    next_items.append(item)
            if not removed:
                return False
            job['items'] = next_items
            self._persist_job(job)
            return True

    def _import_legacy_records(self) -> None:
        """Import every readable 8767 trace once; existing rows are idempotently updated."""
        try:
            runs_dir = _root() / "outputs" / "rebind_runs"
            trace_paths = sorted(runs_dir.glob("*/trace.json"))
        except Exception:
            return
        archive = self._legacy_archive()
        for trace_path in trace_paths:
            try:
                entries = json.loads(trace_path.read_text(encoding="utf-8"))
            except (OSError, TypeError, ValueError, json.JSONDecodeError):
                continue
            if not isinstance(entries, list) or not entries:
                continue
            entries = [entry for entry in entries if isinstance(entry, dict)]
            if not entries:
                continue
            old_email = next((str(entry.get("email") or "").strip().lower()
                              for entry in entries if entry.get("step") == "login_old" and entry.get("email")), "")
            new_email = next((str(entry.get("new_email") or "").strip().lower()
                              for entry in entries if entry.get("new_email")), "")
            if not new_email:
                new_email = next((str(entry.get("email") or "").strip().lower()
                                  for entry in entries if entry.get("step") == "export" and entry.get("email")), "")
            legacy_run_id = f"legacy-8767-{trace_path.parent.name}"
            if not new_email:
                db.delete_rebind_run(legacy_run_id)
                continue
            existing = db.get_rebind_run(legacy_run_id)
            if existing is not None:
                existing_items = [item for item in (existing.get("items") or []) if isinstance(item, dict)]
                if any(
                    str(item.get("code") or "").strip().upper() == "REBIND_ACCOUNT_DEACTIVATED"
                    for item in existing_items
                ):
                    continue
                existing_statuses = {str(item.get("status") or "") for item in existing_items}
                # Failed legacy rows may be re-imported so newer trace parsing can
                # recover an explicit verify success.  Once a row has been
                # recovered, completed, cancelled, or manually emptied, the
                # immutable legacy trace must not overwrite that newer state.
                if not existing_statuses or existing_statuses - {"failed"}:
                    continue
            failed = next((entry for entry in reversed(entries) if entry.get("step") == "failed"), None)
            success = any(entry.get("step") == "export" for entry in entries) and not failed
            item_status = "success" if success else "failed"
            item = self._item(
                old_email or "未知账号（旧版记录未保存旧邮箱）",
                new_email,
                item_status,
                "已从旧版换绑记录导入" if success else str((failed or {}).get("message") or "旧版换绑失败"),
            )
            if success and new_email:
                item["account"] = self._legacy_account_snapshot(
                    trace_path.parent,
                    old_email=old_email,
                    new_email=new_email,
                    entries=entries,
                    archive=archive,
                )
                db.restore_rebind_result_credentials_if_missing(
                    item["account"],
                    old_email=old_email,
                    run_id=legacy_run_id,
                    rebound_at=str(entries[-1].get("time") or "") or None,
                )
            item.update(
                phase="完成" if success else "失败",
                code="OK" if success else str((failed or {}).get("code") or "LEGACY_REBIND_FAILED"),
                started_at=str(entries[0].get("time") or ""),
                finished_at=str(entries[-1].get("time") or ""),
                logs=[{
                    "time": str(entry.get("time") or ""),
                    "phase": str(entry.get("step") or "trace"),
                    "level": "error" if entry.get("step") == "failed" else "info",
                    "message": self._format_legacy_entry(entry),
                } for entry in entries],
            )
            run = {
                "run_id": legacy_run_id,
                "status": "finished",
                "items": [item],
                "created_at": str(entries[0].get("time") or ""),
                "started_at": str(entries[0].get("time") or ""),
                "finished_at": str(entries[-1].get("time") or ""),
                "created_at_ts": trace_path.stat().st_mtime,
            }
            try:
                db.save_rebind_run(run, source="legacy-8767")
            except Exception:
                continue

    @staticmethod
    def _format_legacy_entry(entry: dict[str, Any]) -> str:
        step = str(entry.get("step") or "trace")
        if step == "failed":
            return str(entry.get("message") or "旧版换绑失败")[:2000]
        labels = {"login_old": "旧邮箱登录", "eligibility": "检查换绑资格", "begin": "发送新邮箱验证码", "mail_code": "收到邮箱验证码", "verify": "提交换绑", "export": "重新获取凭证"}
        if step == "export":
            return "换绑成功，已重新获取凭证"
        if step == "verify" and RebindService._verify_entry_succeeded(entry):
            return "提交换绑成功（resp_keys=['success']）"
        if step == "begin" and entry.get("new_email"):
            return f"{labels.get(step, step)}：{entry['new_email']}"
        return labels.get(step, step)

    def cancel(self, run_id: str) -> bool:
        with self._lock:
            job = self._jobs.get(run_id)
            if not job or job["status"] in {"finished", "cancelled", "failed"}:
                return False
            job["cancel_event"].set()
            job["status"] = "cancelling"
            for item in job["items"]:
                if item["status"] == "pending":
                    item.update(status="cancelled", phase="已取消", message="任务已取消", finished_at=_now())
            self._refresh_job(job)
            self._persist_job(job)
            return True


# Historical rebind maintenance is started by the FastAPI startup hook in a
# background thread so importing ``webui.app`` does not block the listener.
SERVICE = RebindService(run_maintenance=False)

