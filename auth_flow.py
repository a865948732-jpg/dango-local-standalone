"""
注册/登录流程 - 协议直连方式
完整链路:
  chatgpt_csrf -> chatgpt_signin_openai -> auth_oauth_init -> sentinel
  -> signup -> send_otp -> verify_otp -> create_account
  -> redirect_chain -> auth_session -> (optional) oauth_token_exchange
"""
import json
import base64
import hashlib
import inspect
import hmac
import logging
import os
import random
import re
import secrets
import struct
import subprocess
import time
import uuid
from datetime import datetime
from typing import Optional, Any
from urllib.parse import urlparse, parse_qs, parse_qsl, urljoin, urlencode, urlunparse

from config import Config
from password_verification import PasswordVerificationError, run_verification_step
from fingerprint import (
    generate_fingerprint,
    ua_for_impersonate,
    fingerprint_for_impersonate,
)
from mail_providers import MailProvider
from http_client import create_http_session, rotate_proxy_session_id, USER_AGENT, _TlsRetrySession
from safe_diagnostics import (
    safe_auth_response_metadata,
    safe_error_code,
    safe_network_error_kind,
    safe_otp_wait_diagnostics,
    safe_public_error,
    safe_response_error_code,
    safe_response_summary,
    safe_url,
)

logger = logging.getLogger(__name__)


def cookie_diagnostic_snapshot(cookies: Any) -> dict[str, Any]:
    """Return a secret-free, stable summary of a cookie mapping or jar."""
    names: list[str] = []
    try:
        jar = getattr(cookies, "jar", None)
        if jar is not None:
            cookies = jar
        if isinstance(cookies, dict):
            names = [str(name) for name in cookies if name]
        else:
            for cookie in cookies or []:
                name = str(getattr(cookie, "name", "") or "").strip()
                if name:
                    names.append(name)
    except Exception:
        names = []
    names = sorted(set(names))
    return {
        "count": len(names),
        "names": names,
        "name_hash": hashlib.sha256("\n".join(names).encode("utf-8")).hexdigest()[:16],
        "has_oai_did": "oai-did" in names,
        "has_session_cookie": "__Secure-next-auth.session-token" in names,
    }


class AuthorizeRateLimitError(RuntimeError):
    """authorize/continue 被服务端限流，调用方不得切换入口继续请求。"""


class AuthSessionMissingError(RuntimeError):
    """Account creation finished but no usable authentication session was established."""

    failure_phase = "session_establishment"
    failure_cause = "auth_session_missing"
    exception_type = "AuthSessionMissingError"

    def __init__(self):
        super().__init__("account created without a usable authentication session")


class OtpVerificationError(RuntimeError):
    """OTP validation failed with a safe, allowlisted upstream error code."""

    failure_phase = "otp_verify"
    exception_type = "OtpVerificationError"

    def __init__(self, summary: str, *, error_code: str = ""):
        self.error_code = safe_error_code(error_code)
        super().__init__(summary)


class ExistingAccountMfaRecoveryError(RuntimeError):
    """已有账号在邮箱 OTP 后需要 MFA，但本地缺少可用续接凭据。"""

    failure_phase = "existing_mfa_recovery"
    exception_type = "ExistingAccountMfaRecoveryError"

    def __init__(self, failure_cause: str):
        cause = str(failure_cause or "").strip().lower()
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,79}", cause):
            cause = "unknown"
        self.failure_cause = cause
        super().__init__("existing account MFA recovery failed")


class OtpWaitTimeoutError(TimeoutError):
    """邮件 OTP 等待窗口耗尽，保留阶段信息供外层正确分类。"""

    failure_phase = "otp_wait"
    exception_type = "OtpWaitTimeoutError"

    def __init__(
        self,
        provider_kind: str = "",
        timeout: object = "",
        failure_cause: object = "",
    ):
        provider = str(provider_kind or "mail").strip().lower()
        if not re.fullmatch(r"[a-z0-9_.-]{1,64}", provider):
            provider = "mail"
        timeout_text = str(timeout or "").strip()
        cause = str(failure_cause or "").strip().lower()
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,79}", cause):
            cause = ""
        self.failure_cause = cause
        suffix = f" provider={provider}"
        if timeout_text:
            suffix += f" timeout={timeout_text}s"
        if cause:
            suffix += f" failure_cause={cause}"
        super().__init__(f"OTP wait timed out ({suffix.strip()})")


class PasswordResetProtocolError(RuntimeError):
    """协议密码重置失败；只携带阶段和脱敏的上游错误码。"""

    exception_type = "PasswordResetProtocolError"

    def __init__(self, failure_phase: str, failure_cause: str, *, error_code: str = "", http_status: int | None = None):
        self.failure_phase = str(failure_phase or "unknown")[:80]
        self.failure_cause = str(failure_cause or "unknown")[:80]
        self.error_code = safe_error_code(error_code)
        self.http_status = int(http_status) if http_status else 0
        details = [f"failure_phase={self.failure_phase}", f"failure_cause={self.failure_cause}"]
        if self.http_status:
            details.append(f"http_status={self.http_status}")
        if self.error_code:
            details.append(f"error_code={self.error_code}")
        super().__init__("protocol password reset failed (" + "; ".join(details) + ")")


# ── RFC 6238 TOTP 实现（用于 mfa-challenge 计算动态码）────────────
def _hotp(secret_b32: str, counter: int, digits: int = 6) -> str:
    """HOTP 算法（RFC 4226）"""
    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8))
    msg = struct.pack(">Q", counter)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    o = h[-1] & 0x0F
    code = (struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def _totp_now(secret_b32: str) -> str:
    """当前 30 秒窗口的 6 位 TOTP 码"""
    return _hotp(secret_b32, int(time.time()) // 30)


class AuthResult:
    """认证结果"""

    def __init__(self):
        self.email: str = ""
        self.password: str = ""
        self.session_token: str = ""
        self.access_token: str = ""
        self.device_id: str = ""
        self.csrf_token: str = ""
        self.id_token: str = ""
        self.refresh_token: str = ""
        self.cookie_header: str = ""
        self.totp_secret: str = ""
        # Secret-free provenance retained in registered.extra_json.
        self.registration_diagnostics: dict[str, Any] = {}

    def is_valid(self) -> bool:
        return bool(self.session_token and self.access_token)

    def to_dict(self) -> dict:
        out = {
            "email": self.email,
            "password": self.password,
            "session_token": self.session_token,
            "access_token": self.access_token,
            "device_id": self.device_id,
            "csrf_token": self.csrf_token,
            "id_token": self.id_token,
            "refresh_token": self.refresh_token,
            "cookie_header": self.cookie_header,
            "totp_secret": self.totp_secret,
        }
        if self.registration_diagnostics:
            out["registration_diagnostics"] = self.registration_diagnostics
        return out


class AuthFlow:
    """注册/登录协议流"""

    def __init__(
        self,
        config: Config,
        sms_callback: Optional[Any] = None,
        env_overrides: Optional[dict] = None,
        on_password: Optional[Any] = None,
        on_session_ready: Optional[Any] = None,
        account_callback: Optional[Any] = None,
    ):
        # 本次流程专属的配置覆盖（WEBUI_ALLOW_LOGIN / OTP_TIMEOUT / OAuth 开关等）。
        # ⚠️ 以前 registrar 是直接写 os.environ 再在 finally 里还原的，
        #    但 auto_loop 会并发跑多个 worker —— A 写的 OTP_TIMEOUT 会被 B 看见，
        #    B 跑完还原成 A 之前的值，A 后半程就读到别人的配置了。
        #    现在覆盖值只挂在实例上，进程全局环境一个字节都不动。
        self._env_overrides = dict(env_overrides or {})
        self.config = config
        self._country_code = ""  # IP 地理国家码，check_proxy() 时填充
        self._fingerprint = generate_fingerprint()  # 先生成默认指纹
        self._ua = self._fingerprint["user_agent"]
        self._impersonate_candidates = self._fingerprint.get(
            "fallback_impersonates",
            [self._fingerprint["impersonate"], "safari17_0", "safari15_5"],
        )
        self._impersonate_idx = 0
        self.session = create_http_session(
            proxy=config.proxy,
            impersonate=self._impersonate_candidates[self._impersonate_idx],
            user_agent=self._ua,
        )
        self.result = AuthResult()
        # 可选 SMS 接码控制器（sms_provider.PhoneCallbackController 实例）
        # 命中 add-phone 时自动租手机号 + 接 SMS 验证码，否则回退到环境变量路径
        self._sms_callback = sms_callback
        # 密码一在 OpenAI 侧生效就回调出去，调用方负责立刻落盘。
        # 签名 (email: str, password: str) -> None，异常由 register_password 吞掉。
        # ⚠️ 协议层不认识 webui.db，所以只给回调，"存哪"留给调用方决定，
        #    auth_flow 单独当 CLI 用时不传就是了，行为和以前一模一样。
        self._on_password = on_password
        # 拿到 session（access_token）之后、Codex 授权之前的钩子。
        # 签名 (flow: AuthFlow, access_token: str) -> None，异常由调用点吞掉。
        # 为的是把 2FA 绑定插进主人指定的顺序：
        #     创建账户 → 重定向链 → 拿 session → ★绑 2FA★ → Codex 授权 → 接码
        # ⚠️ 传了这个钩子会**顺带关掉** run_register 里 callback 前那次 Codex 抢跑
        #    （:3051 OAUTH_CODEX_RT_BEFORE_CALLBACK），否则 Codex 会跑在钩子前面，
        #    顺序就白调了。不传则一个字节都不变，老行为。
        self._on_session_ready = on_session_ready
        # 账号凭证回调：已有账号登录时从数据库加载密码和 totp_secret。
        # 签名 (email: str) -> dict，返回 {"password": "...", "totp_secret": "..."}。
        # 用于 mfa-challenge 路径：密码验证后需要 TOTP 码，从库里读 secret。
        self._account_callback = account_callback
        self._http_trace_enabled = str(os.getenv("AUTH_HTTP_TRACE", "0")).lower() in ("1", "true", "yes", "on")
        # signup() 会在分支里 set；run_protocol_login 命中已有账号路径会跳过 signup，
        # 导致 kickoff_otp_delivery 读未初始化属性 AttributeError。这里给个默认值。
        self._is_existing_account = False
        self._password_registered_in_run = False
        self._password_verified_in_run = False
        # OTP delivery state is per AuthFlow run.  A page transition alone does
        # not establish a challenge; the successful delivery request does.
        self._otp_challenge_established = False
        self._otp_delivery_requested = False
        self._existing_email_verification_mode = ""
        self._existing_page_type = ""
        self._authorization_failure_reason = ""
        self._manual_login_verifier = (os.getenv("LOGIN_VERIFIER", "") or "").strip()
        self._captured_login_verifier = ""
        self._oauth_client_secret = (os.getenv("OAUTH_CLIENT_SECRET", "") or "").strip()
        self._oauth_client_id = "YOUR_OPENAI_WEB_CLIENT_ID"
        self._oauth_redirect_uri = "https://chatgpt.com/api/auth/callback/openai"
        self._oauth_scope = ""
        self._oauth_state = ""
        self._oauth_auth_url = ""
        self._client_auth_session_dump: dict[str, Any] = {}
        self._client_auth_session_id: str = ""
        self._dump_login_verifier: str = ""
        self._codex_rt_attempted: bool = False
        self._trace_dump_enabled = str(os.getenv("AUTH_TRACE_DUMP", "0")).lower() in ("1", "true", "yes", "on")
        self._trace_include_cookie = str(os.getenv("AUTH_TRACE_INCLUDE_COOKIE", "0")).lower() in (
            "1", "true", "yes", "on"
        )
        self._trace_dump_path = ""
        self._registration_diagnostics: dict[str, Any] = {
            "started_at": datetime.utcnow().isoformat() + "Z",
            "events": [],
        }
        logger.debug(
            f"指纹: impersonate={self._fingerprint['impersonate']} "
            f"screen={self._fingerprint['screen']} lang={self._fingerprint['lang']} "
            f"ua={self._ua}"
        )

    def record_registration_diagnostic(self, event: str, **fields: Any) -> None:
        """Append bounded, secret-free registration provenance metadata."""
        if not hasattr(self, "_registration_diagnostics") or not isinstance(
            getattr(self, "_registration_diagnostics", None), dict
        ):
            self._registration_diagnostics = {"started_at": datetime.utcnow().isoformat() + "Z", "events": []}
        name = re.sub(r"[^a-z0-9_.-]", "_", str(event or "event").lower())[:80]
        safe: dict[str, Any] = {"event": name, "ts": datetime.utcnow().isoformat() + "Z"}
        for key, value in fields.items():
            key = re.sub(r"[^a-z0-9_.-]", "_", str(key).lower())[:80]
            if key in {"cookie", "cookies", "token", "password", "secret", "body", "value"}:
                continue
            if isinstance(value, (str, int, float, bool)) or value is None:
                safe[key] = value if not isinstance(value, str) else value[:240]
            elif isinstance(value, (list, tuple)):
                safe[key] = [str(item)[:120] for item in value[:50]]
            elif isinstance(value, dict):
                safe[key] = {
                    str(k)[:80]: (str(v)[:240] if isinstance(v, (str, int, float, bool)) else v)
                    for k, v in list(value.items())[:50]
                    if str(k).lower() not in {"value", "token", "password", "secret", "cookie"}
                }
        events = self._registration_diagnostics.setdefault("events", [])
        if isinstance(events, list):
            events.append(safe)
            del events[:-200]
        self._registration_diagnostics["last_event"] = name
        result = getattr(self, "result", None)
        if result is not None:
            result.registration_diagnostics = self._registration_diagnostics

    def _record_cookie_diagnostic(self, event: str, cookies: Any = None, **fields: Any) -> None:
        if cookies is None:
            try:
                cookies = self.session.cookies
            except Exception:
                cookies = []
        self.record_registration_diagnostic(
            event,
            cookie_snapshot=cookie_diagnostic_snapshot(cookies),
            **fields,
        )

    def _build_chatgpt_cookie_header(self) -> str:
        """
        导出当前会话中的 chatgpt.com 相关 cookie。

        说明：
        - `/backend-api/payments/checkout` 的 modern/custom 入口不仅依赖
          `__Secure-next-auth.session-token`，还会校验若干同域 cookie
          （如 csrf / oai-sc / Cloudflare 相关 cookie 等）。
        - 因此这里不能只回传 session_token，需要尽量保留当前会话里已经拿到的
          `chatgpt.com` 域 cookie 集合。
        """
        cookie_pairs: list[tuple[str, str]] = []
        seen: set[str] = set()

        try:
            jar_iter = list(self.session.cookies)
        except Exception:
            jar_iter = []

        for cookie in jar_iter:
            try:
                name = (getattr(cookie, "name", "") or "").strip()
                value = getattr(cookie, "value", "") or ""
                domain = (getattr(cookie, "domain", "") or "").strip().lower()
            except Exception:
                continue
            if not name or not value:
                continue
            if domain and "chatgpt.com" not in domain:
                continue
            if name in seen:
                continue
            seen.add(name)
            cookie_pairs.append((name, value))

        # 兜底补齐关键 cookie，避免某些 cookiejar 迭代行为差异导致遗漏
        critical_names = [
            "__Secure-next-auth.session-token",
            "__Host-next-auth.csrf-token",
            "__Secure-next-auth.callback-url",
            "oai-did",
            "oai-sc",
            "cf_clearance",
            "__cf_bm",
            "_cfuvid",
            "__cflb",
            "__stripe_mid",
            "__stripe_sid",
            "oai-client-auth-info",
            "oai-gn",
            "oai-nav-state",
            "oai-hlib",
            "_account_is_fedramp",
            "oai_consent_analytics",
            "oai_consent_marketing",
            "oai-allow-ne",
            "_ga",
            "_ga_9SHBSK2D9J",
            "_gcl_au",
            "_fbp",
            "_puid",
            "_dd_s",
            "g_state",
        ]
        for name in critical_names:
            if name in seen:
                continue
            try:
                value = self.session.cookies.get(name, "")
            except Exception:
                value = ""
            if value:
                seen.add(name)
                cookie_pairs.append((name, value))

        return "; ".join(f"{name}={value}" for name, value in cookie_pairs if name and value)
        if self._trace_dump_enabled:
            try:
                os.makedirs("outputs", exist_ok=True)
                ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
                self._trace_dump_path = os.path.join("outputs", f"auth_trace_{ts}_{os.getpid()}.jsonl")
                logger.info(f"HTTP 安全元数据追踪已启用: {self._trace_dump_path}")
            except Exception as e:
                logger.warning(safe_public_error(e, "HTTP metadata trace initialization"))
                self._trace_dump_enabled = False

    def _trace_http(self, step: str, resp, extra_request: dict | None = None):
        """可选安全 HTTP 元数据追踪；永不记录凭据、请求体或响应体。"""
        reset_phase = getattr(self, "_password_reset_phase", "")
        if reset_phase and resp is not None:
            metadata = safe_auth_response_metadata(resp)
            self._password_reset_last_response_metadata = metadata
            self.record_registration_diagnostic("password_reset_http", phase=reset_phase, **metadata)
        if (not self._http_trace_enabled and not self._trace_dump_enabled) or resp is None:
            return
        try:
            req = getattr(resp, "request", None)
            method = getattr(req, "method", "") if req else ""
            req_url = getattr(req, "url", "") if req else ""
            if isinstance(extra_request, dict):
                method = method or str(extra_request.get("method", "") or "")
                req_url = req_url or str(extra_request.get("url", "") or "")

            status = getattr(resp, "status_code", "N/A")
            final_url = str(getattr(resp, "url", "") or "")
            location = (resp.headers.get("Location", "") or "")[:180]
            req_id = (resp.headers.get("x-request-id", "") or "")[:120]
            ctype = (resp.headers.get("Content-Type", "") or "")[:120]

            safe_req_url = safe_url(req_url)
            safe_final_url = safe_url(final_url)
            safe_location = safe_url(location)

            if self._http_trace_enabled:
                logger.info(
                    "[HTTP TRACE] %s | %s %s -> %s | url=%s | location=%s | req_id=%s | ctype=%s",
                    step,
                    method,
                    safe_req_url[:180],
                    status,
                    safe_final_url[:180],
                    safe_location,
                    req_id,
                    ctype,
                )

            # Sniff verifier only in memory for protocol continuity. Never log or dump it.
            self._sniff_login_verifier(req_url, f"{step}:req_url")
            self._sniff_login_verifier(final_url, f"{step}:final_url")
            self._sniff_login_verifier(location, f"{step}:location")

            if self._trace_dump_enabled and self._trace_dump_path:
                try:
                    record = {
                        "ts": datetime.utcnow().isoformat() + "Z",
                        "step": step,
                        "request": {"method": method, "url": safe_req_url},
                        "response": {
                            "status_code": status,
                            "url": safe_final_url,
                            "location": safe_location,
                            "x_request_id": resp.headers.get("x-request-id", ""),
                            "content_type": resp.headers.get("Content-Type", ""),
                        },
                    }
                    with open(self._trace_dump_path, "a", encoding="utf-8") as fw:
                        fw.write(json.dumps(record, ensure_ascii=False) + "\n")
                except Exception as e:
                    logger.debug(safe_public_error(e, "HTTP metadata trace write"))
        except Exception as e:
            logger.debug(safe_public_error(e, "HTTP trace output"))

    def _sniff_login_verifier(self, text: str, source: str = ""):
        """从任意文本中提取 login_verifier/code_verifier。"""
        if not text:
            return
        try:
            patterns = [
                r"(?:login_verifier|code_verifier|verifier)=([A-Za-z0-9._~-]{8,})",
                r'"(?:login_verifier|code_verifier|verifier)"\s*:\s*"([^"]{8,})"',
            ]
            for p in patterns:
                m = re.search(p, text)
                if not m:
                    continue
                v = (m.group(1) or "").strip()
                if not v:
                    continue
                if v != self._captured_login_verifier:
                    self._captured_login_verifier = v
                    logger.info("捕获 login_verifier 来源=%s len=%s", source or "unknown", len(v))
                return
        except Exception:
            return

    @staticmethod
    def _walk_collect_str_fields(obj: Any, wanted_keys: set[str], out: dict[str, str], depth: int = 0, max_depth: int = 6):
        """递归收集目标字段（仅字符串值）。"""
        if depth > max_depth or obj is None:
            return
        if isinstance(obj, dict):
            for k, v in obj.items():
                kk = (str(k) or "").strip().lower()
                if kk in wanted_keys and isinstance(v, str) and v.strip():
                    out[kk] = v.strip()
                AuthFlow._walk_collect_str_fields(v, wanted_keys, out, depth + 1, max_depth)
        elif isinstance(obj, list):
            for it in obj:
                AuthFlow._walk_collect_str_fields(it, wanted_keys, out, depth + 1, max_depth)

    def fetch_client_auth_session_dump(self, stage: str = "") -> dict:
        """
        尝试读取 auth.openai 的 client_auth_session_dump：
        - 可能包含 session_id / client_auth_session 的额外状态
        - 若出现 verifier/refresh 相关字段，自动注入当前流程
        """
        headers = self._common_headers("https://auth.openai.com/email-verification")
        headers["Accept"] = "application/json"
        try:
            resp = self.session.get(
                "https://auth.openai.com/api/accounts/client_auth_session_dump",
                headers=headers,
                timeout=30,
            )
            self._trace_http(f"client_auth_session_dump_{stage or 'default'}", resp)
        except Exception as e:
            logger.debug(safe_public_error(e, f"client auth session dump {stage}"))
            return {}

        if resp.status_code != 200:
            logger.debug(
                "client_auth_session_dump(%s) 可选诊断接口不可用，已跳过 (HTTP %s)",
                stage or "default",
                resp.status_code,
            )
            return {}

        try:
            data = resp.json()
        except Exception:
            logger.warning(f"client_auth_session_dump({stage}) JSON 解析失败")
            return {}

        if not isinstance(data, dict):
            return {}

        self._client_auth_session_dump = data
        cas = data.get("client_auth_session", {}) if isinstance(data.get("client_auth_session"), dict) else {}

        def _optional_text(value: object) -> str:
            return value.strip() if isinstance(value, str) else ""

        sid = _optional_text(data.get("session_id")) or _optional_text(cas.get("session_id"))
        if sid:
            self._client_auth_session_id = sid

        # 同步 OAuth client_id（若 dump 给出更准确值）。该接口是可选诊断，
        # 上游字段类型变化不得打断 OTP/MFA 主流程。
        dump_client_id = _optional_text(cas.get("openai_client_id")) or _optional_text(
            data.get("openai_client_id")
        )
        if dump_client_id:
            self._oauth_client_id = dump_client_id

        wanted = {
            "login_verifier", "code_verifier", "verifier", "pkce_verifier", "oauth_code_verifier",
            "refresh_token", "oauth_refresh_token", "access_token", "id_token",
        }
        found: dict[str, str] = {}
        self._walk_collect_str_fields(data, wanted, found)

        # verifier 候选
        for key in ("login_verifier", "code_verifier", "verifier", "pkce_verifier", "oauth_code_verifier"):
            v = (found.get(key, "") or "").strip()
            if v and len(v) >= 8:
                self._dump_login_verifier = v
                self._captured_login_verifier = v
                logger.info("client_auth_session_dump 捕获 verifier: key=%s len=%s", key, len(v))
                break

        # token 候选（极少见，但若有直接收下）
        refresh = (found.get("refresh_token", "") or found.get("oauth_refresh_token", "")).strip()
        if refresh:
            self.result.refresh_token = refresh
        acc = (found.get("access_token", "") or "").strip()
        if acc:
            self.result.access_token = acc
        idt = (found.get("id_token", "") or "").strip()
        if idt:
            self.result.id_token = idt

        logger.debug(
            "client_auth_session_dump(%s) 成功: top_keys=%s cas_keys=%s session_id=%s refresh=%s verifier=%s",
            stage or "default",
            list(data.keys())[:12],
            list(cas.keys())[:18] if isinstance(cas, dict) else [],
            (self._client_auth_session_id[:24] if self._client_auth_session_id else ""),
            "有" if self.result.refresh_token else "无",
            "有" if self._dump_login_verifier else "无",
        )
        return data

    @staticmethod
    def _is_tls_error(exc: Exception) -> bool:
        msg = str(exc).lower()
        markers = ["curl: (35)", "tls connect error", "openssl_internal", "sslerror"]
        return any(m in msg for m in markers)

    @staticmethod
    def _is_registration_disallowed_error(exc: Exception) -> bool:
        msg = str(exc).lower()
        return "registration_disallowed" in msg

    def _get_cookie_value_by_name(self, name: str) -> str:
        """按 cookie 名称获取值（忽略 domain 冲突）。"""
        try:
            jar = getattr(self.session.cookies, "jar", None)
            if jar is None:
                return ""
            target = (name or "").strip().lower()
            for c in jar:
                if (getattr(c, "name", "") or "").strip().lower() == target:
                    return (getattr(c, "value", "") or "").strip()
        except Exception:
            pass
        return ""

    def _get_cookie_value_for_host(self, name: str, host: str) -> str:
        """按请求 host 选择同名 cookie，避免跨域 cookie 顺序造成状态错配。

        curl/requests 的 cookie jar 允许同一个名字在 chatgpt.com 和
        auth.openai.com 下同时存在。OAuth 初始化必须优先使用当前授权 host
        的值；只有 cookie 没有 domain 或 jar 不暴露 domain 时，才回退到任意
        同名值。
        """
        target = (name or "").strip().lower()
        target_host = (host or "").strip().lower().split(":", 1)[0].lstrip(".")
        fallback = ""
        try:
            jar = getattr(self.session.cookies, "jar", None)
            if jar is None:
                return ""
            for cookie in jar:
                cookie_name = (getattr(cookie, "name", "") or "").strip().lower()
                if cookie_name != target:
                    continue
                value = (getattr(cookie, "value", "") or "").strip()
                if not value:
                    continue
                domain = (getattr(cookie, "domain", "") or "").strip().lower().lstrip(".")
                if not domain:
                    fallback = fallback or value
                    continue
                if target_host == domain or target_host.endswith("." + domain):
                    return value
        except Exception:
            return ""
        return fallback

    def _extract_login_challenge_from_cookie(self) -> str:
        """
        从 login_session cookie 中提取 login_challenge。
        login_session 的第一段通常是 base64url(JSON)。
        """
        raw = self._get_cookie_value_by_name("login_session")
        if not raw:
            return ""
        try:
            p0 = raw.split(".")[0]
            p0 += "=" * (-len(p0) % 4)
            payload = json.loads(base64.urlsafe_b64decode(p0.encode("utf-8")).decode("utf-8"))
            return (payload.get("login_challenge", "") or "").strip()
        except Exception:
            return ""

    @staticmethod
    def _extract_query_first(url: str, keys: list[str]) -> str:
        if not url:
            return ""
        try:
            qs = parse_qs(urlparse(url).query)
        except Exception:
            return ""
        for k in keys:
            val = qs.get(k, [None])[0]
            if val:
                return val
        return ""

    @staticmethod
    def _extract_page_type(resp_json: dict | None) -> str:
        if not isinstance(resp_json, dict):
            return ""
        page = resp_json.get("page", {})
        if not isinstance(page, dict):
            return ""
        return (page.get("type", "") or "").strip()

    @staticmethod
    def _extract_continue_url_from_step(resp_json: dict | None) -> str:
        """
        从 auth step 响应提取 continue_url：
        - 顶层 continue_url
        - page.type=external_url 时 payload.url
        """
        if not isinstance(resp_json, dict):
            return ""
        continue_url = (resp_json.get("continue_url", "") or "").strip()
        if continue_url:
            return continue_url
        page = resp_json.get("page", {})
        if not isinstance(page, dict):
            return ""
        if (page.get("type", "") or "").strip() != "external_url":
            return ""
        payload = page.get("payload", {})
        if not isinstance(payload, dict):
            return ""
        return (payload.get("url", "") or "").strip()

    def _get_env(self, name: str, default: str = "") -> str:
        """读配置：本次流程的 env_overrides 优先，回退进程环境变量。

        registrar 通过 AuthFlow(env_overrides=...) 传入，不再写 os.environ，
        所以并发跑多个号时互不干扰。命令行入口（register_outlook.py）没传
        overrides，行为跟以前完全一样。
        """
        v = self._env_overrides.get(name)
        return os.getenv(name, default) if v is None else str(v)

    def _env_flag(self, name: str, default: str = "0") -> bool:
        # 原本是 @staticmethod，为了读 self._env_overrides 改成实例方法。
        # 调用点全是 self._env_flag(...)，签名不变。
        return self._get_env(name, default).lower() in ("1", "true", "yes", "on")

    def _mark_otp_delivery(self) -> None:
        """记录一次已被服务端接受的 OTP 发码请求。"""
        self._otp_challenge_established = True
        self._otp_delivery_requested = True

    def _wait_for_otp(
        self,
        mail_provider: MailProvider,
        email: str,
        *,
        timeout: int,
        issued_after: float | None = None,
        **kwargs,
    ) -> str:
        """等待邮件 OTP，并把超时标记为 otp_wait 而不是普通网络超时。"""
        try:
            return mail_provider.wait_for_otp(
                email,
                timeout=timeout,
                issued_after=issued_after,
                **kwargs,
            )
        except TimeoutError as exc:
            error = OtpWaitTimeoutError(
                getattr(mail_provider, "kind", "mail"),
                timeout,
                failure_cause=getattr(exc, "failure_cause", ""),
            )
            error.relay_network_error_kind = safe_network_error_kind(
                getattr(exc, 'relay_network_error_kind', ''),
            )
            error.otp_wait_diagnostics = safe_otp_wait_diagnostics(
                getattr(exc, 'otp_wait_diagnostics', None),
            )
            raise error from exc

    def _wait_for_otp_with_one_resend(
        self,
        mail_provider: MailProvider,
        email: str,
        *,
        timeout: int,
        issued_after: float | None = None,
        strict_issued_after: bool = False,
        resend_after: int | None = None,
    ) -> str:
        """在同一个 OTP 预算内等待，并在首次超时后最多重发一次。

        指纹浏览器的成功路径不是“发一次后一直卡满整个超时”，而是先给
        首封邮件一个短窗口；没有收到时复用当前 challenge 点一次 resend，
        再用剩余预算等待。协议端也必须保持这个边界，否则中转邮件偶发延迟
        时会在仍有机会恢复的情况下直接失败，或者重试时又重新等待完整的
        OTP_TIMEOUT。
        """
        total_timeout = max(1, int(timeout))
        if resend_after is None:
            try:
                resend_after = int(self._get_env("OTP_RESEND_AFTER", "20"))
            except Exception:
                resend_after = 20
        first_timeout = max(1, min(total_timeout - 1, int(resend_after)))
        started = time.monotonic()

        try:
            return self._wait_for_otp(
                mail_provider,
                email,
                timeout=first_timeout,
                issued_after=issued_after,
                strict_issued_after=strict_issued_after,
            )
        except TimeoutError as first_exc:
            # Provider 已经判定收件链路失效时，再点 resend 只会浪费一个号。
            if getattr(mail_provider, "exhausted", False):
                raise

            # 用“预留窗口”和真实耗时两重上限，确保两段等待加起来不会
            # 变成两个完整 OTP_TIMEOUT。重发请求本身消耗的时间也要扣除。
            elapsed = max(0.0, time.monotonic() - started)
            remaining = min(
                float(total_timeout - first_timeout),
                float(total_timeout) - elapsed,
            )
            if remaining <= 0:
                raise first_exc

            relay_unavailable = (
                getattr(mail_provider, 'kind', '') == 'icloud_relay'
                and getattr(first_exc, 'failure_cause', '') == 'relay_sync_unavailable'
            )
            resend_ok = False
            if relay_unavailable:
                logger.warning(
                    '中转同步不可用，跳过自动重发，沿用当前验证码继续等待（剩余预算约 %.1fs）',
                    remaining,
                )
            else:
                logger.warning(
                    "首个 OTP 等待 %ss 未收到，复用当前 challenge 尝试一次重发（剩余预算约 %.1fs）",
                    first_timeout,
                    remaining,
                )
                try:
                    resend_ok = bool(
                        self.resend_otp("https://auth.openai.com/email-verification")
                    )
                    if resend_ok:
                        self._mark_otp_delivery()
                except Exception as exc:
                    logger.warning(safe_public_error(exc, "OTP resend after initial wait"))

            # resend 复用的是同一个 OTP challenge，第二段等待必须沿用首次
            # 发码边界。首封可能在 resend 后才出现在中转站，但 received_at
            # 仍是首次发送时刻；若把边界推进到 resend 完成时刻，接口会在
            # 服务端直接把这封延迟首封过滤掉，表现为“邮件到了却一直超时”。
            retry_issued_after = issued_after
            elapsed = max(0.0, time.monotonic() - started)
            remaining = min(
                remaining,
                float(total_timeout) - elapsed,
            )
            if remaining <= 0:
                raise first_exc

            logger.info(
                "OTP 重发请求%s，继续等待剩余预算约 %.1fs",
                "因中转故障已跳过" if relay_unavailable else (
                    "已接受" if resend_ok else "未接受（继续等待首封）"
                ),
                remaining,
            )
            return self._wait_for_otp(
                mail_provider,
                email,
                timeout=max(1, int(remaining)),
                issued_after=retry_issued_after,
                strict_issued_after=strict_issued_after,
            )

    @staticmethod
    def _b64url_no_pad(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")

    def _remember_oauth_params(self, auth_url: str):
        """从 authorize URL 记住 OAuth 参数，供后续 token exchange 使用。"""
        if not auth_url:
            return
        self._oauth_auth_url = auth_url
        try:
            qs = parse_qs(urlparse(auth_url).query)
            self._oauth_client_id = (qs.get("client_id", [self._oauth_client_id])[0] or self._oauth_client_id).strip()
            self._oauth_redirect_uri = (
                qs.get("redirect_uri", [self._oauth_redirect_uri])[0] or self._oauth_redirect_uri
            ).strip()
            self._oauth_scope = (qs.get("scope", [""])[0] or "").strip()
            self._oauth_state = (qs.get("state", [""])[0] or "").strip()
        except Exception:
            return

    def _build_pkce_pair(self, raw_bytes: int = 64) -> tuple[str, str]:
        """生成 (code_verifier, code_challenge)。"""
        verifier = self._b64url_no_pad(secrets.token_bytes(max(32, int(raw_bytes))))
        if len(verifier) < 43:
            verifier = (verifier + ("A" * 43))[:43]
        if len(verifier) > 128:
            verifier = verifier[:128]
        challenge = self._b64url_no_pad(hashlib.sha256(verifier.encode("utf-8")).digest())
        return verifier, challenge

    def _build_codex_authorize(self, prompt_override: Optional[str] = None) -> tuple[str, str, str, str, str]:
        """
        构建用于获取 refresh_token 的 Codex OAuth 授权 URL。
        参考 any-auto-register 的实现：独立 client_id + redirect_uri + 可控 PKCE。
        """
        client_id = (os.getenv("OAUTH_CODEX_CLIENT_ID", "") or "").strip() or "app_EMoamEEZ73f0CkXaXp7hrann"
        redirect_uri = (os.getenv("OAUTH_CODEX_REDIRECT_URI", "") or "").strip() or "http://localhost:1455/auth/callback"
        scope = (os.getenv("OAUTH_CODEX_SCOPE", "") or "").strip() or "openid email profile offline_access"
        state = self._b64url_no_pad(secrets.token_bytes(24))
        verifier, challenge = self._build_pkce_pair()
        prompt = (
            (os.getenv("OAUTH_CODEX_PROMPT", "login") or "").strip()
            if prompt_override is None
            else (prompt_override or "").strip()
        )
        params = {
            "client_id": client_id,
            "response_type": "code",
            "redirect_uri": redirect_uri,
            "scope": scope,
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "id_token_add_organizations": "true",
            "codex_cli_simplified_flow": "true",
        }
        if prompt:
            params["prompt"] = prompt
        auth_url = f"https://auth.openai.com/oauth/authorize?{urlencode(params)}"
        return auth_url, state, verifier, redirect_uri, client_id

    @staticmethod
    def _callback_has_code(url: str, redirect_uri: str) -> bool:
        if not url:
            return False
        try:
            cb_base = (redirect_uri or "").split("?", 1)[0].rstrip("/")
            target = url.split("?", 1)[0].rstrip("/")
            if cb_base and target == cb_base:
                qs = parse_qs(urlparse(url).query)
                return bool((qs.get("code", [""])[0] or "").strip())
        except Exception:
            return False
        return False

    def _follow_authorize_for_callback(self, start_url: str, redirect_uri: str, trace_prefix: str) -> tuple[str, str]:
        """
        跟随 auth.openai.com 授权链路，捕获 callback（不消费 callback）。
        返回 (callback_url, final_url)。
        """
        current = start_url
        callback_url = ""
        chose_account = False  # /choose-an-account 每条链路只选一次，防 200/同 URL 循环
        for i in range(12):
            if self._callback_has_code(current, redirect_uri):
                callback_url = current
                break
            resp = self.session.get(
                current,
                headers={
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Referer": "https://chatgpt.com/",
                    "User-Agent": self._ua,
                },
                timeout=30,
                allow_redirects=False,
            )
            self._trace_http(f"{trace_prefix}_hop_{i+1}", resp)

            # workspace/consent 页面 200 时，主动选择 workspace，拿下一跳 continue_url
            if resp.status_code == 200:
                is_workspace_like = (
                    ("/workspace" in current)
                    or ("/sign-in-with-chatgpt/" in current)
                    or ("/consent" in current)
                )
                if is_workspace_like:
                    workspace_id = self._extract_workspace_id() or self._extract_workspace_id_from_html(resp.text or "")
                    if workspace_id:
                        next_url = self._workspace_select(workspace_id)
                        if next_url:
                            if next_url.startswith("/"):
                                next_url = urljoin("https://auth.openai.com", next_url)
                            current = next_url
                            continue

                # /choose-an-account：OpenAI 已登录多账号的选择页（react-router SSR）。
                # HTML 里 streamController.enqueue 注入 unified_sessions[].id (us_*) 和
                # authsess_*。protocol 端要主动选第一个 us_*，否则 codex callback 拿不到。
                if "/choose-an-account" in current and not chose_account:
                    chose_account = True
                    next_url = self._choose_account_select(resp.text or "", current)
                    if next_url:
                        if next_url.startswith("/"):
                            next_url = urljoin("https://auth.openai.com", next_url)
                        current = next_url
                        continue

            if resp.status_code not in (301, 302, 303, 307, 308):
                break
            loc = (resp.headers.get("Location", "") or "").strip()
            if not loc:
                break
            if loc.startswith("/"):
                loc = urljoin(current, loc)
            if self._callback_has_code(loc, redirect_uri):
                callback_url = loc
                current = loc
                break
            current = loc
        return callback_url, current

    @staticmethod
    def _drop_query_keys(url: str, drop_keys: set[str]) -> str:
        if not url:
            return ""
        try:
            parsed = urlparse(url)
            params = parse_qsl(parsed.query, keep_blank_values=True)
            kept = [(k, v) for (k, v) in params if (k or "").strip() not in drop_keys]
            return urlunparse(parsed._replace(query=urlencode(kept)))
        except Exception:
            return url

    def _exchange_codex_callback_code(
        self,
        callback_url: str,
        expected_state: str,
        verifier: str,
        redirect_uri: str,
        client_id: str,
    ) -> bool:
        qs = parse_qs(urlparse(callback_url).query)
        code = (qs.get("code", [""])[0] or "").strip()
        got_state = (qs.get("state", [""])[0] or "").strip()
        if not code:
            logger.warning("Codex callback 缺少 code")
            return False
        if expected_state and got_state and got_state != expected_state:
            logger.warning("Codex callback state 不匹配（值已脱敏）")
            return False

        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
            "Origin": "https://auth.openai.com",
            "Referer": "https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
            "User-Agent": self._ua,
        }
        form = {
            "grant_type": "authorization_code",
            "client_id": client_id,
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": verifier,
        }
        encoded_form = urlencode(form)
        resp = self.session.post(
            "https://auth.openai.com/oauth/token",
            headers=headers,
            data=encoded_form,
            timeout=30,
        )
        self._trace_http(
            "oauth_token_exchange_codex_pkce",
            resp,
            extra_request={
                "method": "POST",
                "url": "https://auth.openai.com/oauth/token",
                "body": encoded_form,
                "headers": headers,
            },
        )
        if resp.status_code != 200:
            logger.warning(safe_response_summary(resp, "Codex OAuth token exchange"))
            return False
        data = resp.json() if resp is not None else {}
        self.result.id_token = data.get("id_token", self.result.id_token)
        self.result.access_token = data.get("access_token", self.result.access_token)
        self.result.refresh_token = data.get("refresh_token", self.result.refresh_token)
        logger.info(
            "Codex OAuth 交换成功: access=%s refresh=%s",
            "有" if self.result.access_token else "无",
            "有" if self.result.refresh_token else "无",
        )
        return True

    def _codex_drive_login_from_log_in(self, mail_provider: Optional[MailProvider] = None) -> str:
        """
        当 Codex 授权回落到 /log-in 时，补走一次纯协议登录推进状态机。
        返回可继续跟随的 continue_url（若无则返回空字符串）。
        """
        email = (self.result.email or "").strip()
        if not email:
            logger.warning("Codex 登录推进缺少 email")
            return ""
        password = (self.result.password or "").strip() or self._default_password_from_email(email)
        self.result.password = password

        device_id = (self.result.device_id or "").strip() or (self._get_cookie_value_by_name("oai-did") or "").strip()
        if not device_id:
            device_id = str(uuid.uuid4())
            self.result.device_id = device_id

        sentinel = self.get_sentinel_token(device_id)
        step = self.authorize_continue(
            email=email,
            sentinel_token=sentinel,
            screen_hint="login",
            referer="https://auth.openai.com/log-in",
            trace_step="authorize_continue_login_codex",
        )
        page_type = self._extract_page_type(step)
        continue_url = self._normalize_continue_url(self._extract_continue_url_from_step(step))

        if page_type == "login_password" or "/log-in/password" in continue_url:
            step = self.login_password_verify(password)
            page_type = self._extract_page_type(step)
            continue_url = self._normalize_continue_url(self._extract_continue_url_from_step(step))

        # mfa-challenge 分支（密码验证后需要 TOTP 2FA）
        if self._is_mfa_challenge_state(page_type, continue_url):
            totp_secret = (self.result.totp_secret or "").strip()
            if not totp_secret and self._account_callback:
                # 从数据库加载凭证
                try:
                    cred = self._account_callback(email)
                    if cred and cred.get("totp_secret"):
                        totp_secret = cred["totp_secret"]
                        self.result.totp_secret = totp_secret
                        logger.info("已从数据库加载 totp_secret")
                except Exception as e:
                    logger.warning(safe_public_error(e, "account callback"))
            if not totp_secret:
                logger.warning("进入 mfa-challenge 但没有 totp_secret，无法继续")
                return continue_url or ""
            # 从 continue_url 提取 challenge_id
            challenge_id = continue_url.split("/")[-1] if "/mfa-challenge/" in continue_url else ""
            if not challenge_id:
                logger.warning("无法从 continue_url 提取 challenge_id")
                return continue_url or ""
            # 计算当前 TOTP 码并提交
            totp_code = _totp_now(totp_secret)
            logger.info(f"提交 TOTP 码进行 2FA 验证（challenge_id={challenge_id[:16]}...）")
            mfa_resp = self.submit_mfa_totp(totp_code, challenge_id)
            continue_url = self._normalize_continue_url(self._extract_continue_url_from_step(mfa_resp))

        need_otp = (page_type == "email_otp_verification") or ("/email-verification" in (continue_url or ""))
        if need_otp:
            if mail_provider is None:
                logger.warning("Codex 登录推进需要 OTP，但未提供 mail_provider")
                return continue_url or ""
            try:
                otp_timeout = max(10, int(self._get_env("OTP_TIMEOUT", "60")))
            except Exception:
                otp_timeout = 180
            otp_sent_at = time.time()
            if not self.kickoff_otp_delivery("codex_login_need_otp"):
                self.send_otp()
            otp_code = self._wait_for_otp_with_one_resend(
                mail_provider,
                email,
                timeout=otp_timeout,
                issued_after=otp_sent_at,
            )
            otp_resp = self.verify_otp(otp_code)
            continue_url = self._normalize_continue_url(self._extract_continue_url_from_step(otp_resp))

        # add-phone 分支（可选）：
        # 仅在配置了手机号与验证码获取方式时尝试自动推进
        if self._is_add_phone_state(page_type="", continue_url=continue_url):
            next_url = self._handle_add_phone_verification(continue_url=continue_url)
            if next_url:
                continue_url = self._normalize_continue_url(next_url)

        return continue_url or ""

    @staticmethod
    def _is_add_phone_state(page_type: str = "", continue_url: str = "") -> bool:
        pt = (page_type or "").strip().lower()
        cu = (continue_url or "").strip().lower()
        return (pt == "add_phone") or ("add-phone" in cu)

    @staticmethod
    def _is_mfa_challenge_state(page_type: str = "", continue_url: str = "") -> bool:
        """判断是否进入 mfa-challenge 状态（已有账号启用 2FA，密码验证后需要 TOTP 码）。"""
        pt = (page_type or "").strip().lower()
        cu = (continue_url or "").strip().lower()
        return (pt == "mfa_challenge") or ("/mfa-challenge/" in cu)

    def _phone_headers(self, referer: str) -> dict:
        headers = self._common_headers(referer)
        headers["Accept"] = "application/json"
        headers["Content-Type"] = "application/json"
        headers["Origin"] = "https://auth.openai.com"
        device_id = (self.result.device_id or "").strip() or (self._get_cookie_value_by_name("oai-did") or "").strip()
        if device_id:
            headers["oai-device-id"] = device_id
        return headers

    def _add_phone_send(self, phone_number: str) -> dict:
        headers = self._phone_headers("https://auth.openai.com/add-phone")
        try:
            resp = self.session.post(
                "https://auth.openai.com/api/accounts/add-phone/send",
                headers=headers,
                json={"phone_number": phone_number},
                timeout=30,
            )
        except Exception as e:
            logger.warning(safe_public_error(e, "add phone network request"))
            raise
        self._trace_http("add_phone_send", resp)

        if resp.status_code != 200:
            error_code = ""
            try:
                data = resp.json() or {}
                candidate = (data.get("error") or {}).get("code", "") if isinstance(data, dict) else ""
                if isinstance(candidate, str) and re.fullmatch(r"[A-Za-z0-9_.:-]{1,80}", candidate):
                    error_code = candidate
            except Exception:
                pass
            summary = safe_response_summary(resp, "add phone")
            if error_code:
                summary += f" error_code={error_code}"
            raise RuntimeError(summary)

        try:
            return resp.json() if resp is not None else {}
        except Exception:
            return {}

    def _phone_otp_resend(self) -> bool:
        headers = self._phone_headers("https://auth.openai.com/phone-verification")
        resp = self.session.post(
            "https://auth.openai.com/api/accounts/phone-otp/resend",
            headers=headers,
            timeout=30,
        )
        self._trace_http("phone_otp_resend", resp)
        return resp.status_code == 200

    def _phone_otp_validate(self, code: str) -> dict:
        headers = self._phone_headers("https://auth.openai.com/phone-verification")
        resp = self.session.post(
            "https://auth.openai.com/api/accounts/phone-otp/validate",
            headers=headers,
            json={"code": code},
            timeout=30,
        )
        self._trace_http("phone_otp_validate", resp)
        if resp.status_code != 200:
            raise RuntimeError(safe_response_summary(resp, "phone OTP validation"))
        try:
            return resp.json() if resp is not None else {}
        except Exception:
            return {}

    @staticmethod
    def _extract_otp6(text: str) -> str:
        if not text:
            return ""
        m = re.search(r"(?<!\d)(\d{6})(?!\d)", text)
        return (m.group(1) if m else "").strip()

    def _read_phone_otp_from_cmd(self) -> str:
        """
        从环境变量 OPENAI_PHONE_OTP_CMD 指定的命令读取手机验证码（stdout）。
        命令输出中只要出现 6 位数字即视为命中。
        """
        cmd = (os.getenv("OPENAI_PHONE_OTP_CMD", "") or "").strip()
        if not cmd:
            return ""
        try:
            out = subprocess.check_output(cmd, shell=True, text=True, timeout=20)
            return self._extract_otp6(out or "")
        except Exception:
            return ""

    def _wait_phone_otp(self, timeout: int = 180) -> str:
        static_otp = self._extract_otp6(os.getenv("OPENAI_PHONE_OTP", "") or "")
        if static_otp:
            return static_otp

        deadline = time.time() + max(20, int(timeout))
        while time.time() < deadline:
            code = self._read_phone_otp_from_cmd()
            if code:
                return code
            time.sleep(4)
        raise TimeoutError(f"等待手机 OTP 超时 ({timeout}s)")

    def _handle_add_phone_verification(self, continue_url: str = "") -> str:
        """
        处理 add-phone 验证分支：
        - 优先使用 self._sms_callback（SMS 接码 controller，自动租号 + 接码）
        - 回退到环境变量路径：OPENAI_PHONE_NUMBER + OPENAI_PHONE_OTP_CMD/OPENAI_PHONE_OTP
        """
        if self._sms_callback is not None:
            try:
                return self._handle_add_phone_via_sms(continue_url)
            except Exception as e:
                logger.warning(safe_public_error(e, "SMS provider flow"))
                try:
                    self._sms_callback.cleanup()
                except Exception:
                    pass
        return self._handle_add_phone_via_env(continue_url)

    def _handle_add_phone_via_sms(self, continue_url: str = "") -> str:
        """走 SMS 接码 controller：租号 → add-phone/send → 等 SMS → validate。

        支持平台：SmsBower（smsbower.page）。
        单号窗口 80s（每 20s × 3 触发一次 OpenAI 端 resend）；失败自动 cancel + 换新号。
        最多换号次数默认 3，主人可在 WebUI / 环境变量 OPENAI_PHONE_MAX_ATTEMPTS 自定义。
        """
        ctrl = self._sms_callback
        try:
            ctrl.set_resend_callback(self._phone_otp_resend)
        except Exception:
            pass

        # 用 try/finally 保证即使 for 循环抛异常，也能 release lock + 最后一次 cleanup
        try:
            return self._do_sms_loop(ctrl)
        finally:
            # 无论成败都释放 lock + cleanup 最后一个号（如果有）
            try:
                ctrl.cleanup()
            except Exception:
                pass
            try:
                ctrl._release_lock()
            except Exception:
                pass

    def _do_sms_loop(self, ctrl) -> str:
        """SMS 接码循环逻辑（for 0..max_attempts）。"""
        # provider 信息（目前只支持 SmsBower）
        provider_key = (getattr(ctrl, "provider_key", "") or "").lower()

        # 优先从 controller.config 读（前端配置） → 环境变量兜底 → 用默认
        ctrl_cfg = getattr(ctrl, "config", None) or {}

        def _read_int(cfg_key: str, env_key: str, default: str, min_v: int = 1) -> int:
            raw = (str(ctrl_cfg.get(cfg_key) or "")).strip()
            if not raw:
                raw = os.getenv(env_key, default)
            try:
                return max(min_v, int(raw))
            except Exception:
                return int(default)

        # 单号等待窗口（秒）：默认 80 = 20×3 + 20 缓冲
        per_phone_timeout = max(40, _read_int(
            "sms_per_phone_timeout", "OPENAI_PHONE_OTP_TIMEOUT", "80", min_v=40
        ))
        # 最多换几个号（默认 3）
        max_phone_attempts = _read_int(
            "sms_max_phone_attempts", "OPENAI_PHONE_MAX_ATTEMPTS", "3"
        )
        # 单号内 code validate 失败后的重试次数（如果还有时间）
        max_code_retries_per_phone = _read_int(
            "sms_code_retries_per_phone", "OPENAI_PHONE_OTP_CODE_RETRIES", "2"
        )

        logger.info(
            "[sms] 配置: provider=%s 单号窗口=%ds 最多换号=%d 单号内验证重试=%d",
            provider_key, per_phone_timeout, max_phone_attempts, max_code_retries_per_phone,
        )

        # OpenAI "号已被使用 / 不允许" 类错误关键字
        _PHONE_REJECTED_PATTERNS = (
            "phone_number_already_in_use", "already_in_use", "already_taken",
            "phone_already_verified", "already_verified",
            "disallowed_phone", "invalid_phone_number", "phone_number_invalid",
            "blocked_phone", "phone_number_blocked",
            "suspicious behavior from phone",  # OpenAI 风控：号段可疑
        )
        def _is_phone_rejected(s: str) -> bool:
            sl = (s or "").lower()
            return any(p in sl for p in _PHONE_REJECTED_PATTERNS)

        last_err: Optional[Exception] = None

        for phone_attempt in range(1, max_phone_attempts + 1):
            logger.info("[sms] 🔁 第 %d/%d 个号尝试...", phone_attempt, max_phone_attempts)

            # 阶段 1：租号（第 2+ 个号会自动租新号，SmsBower cache 已被前一次 cleanup 清掉）
            try:
                phone = ctrl.get_phone()
            except Exception as e:
                last_err = e
                logger.warning("[sms] 第 %d 个号码租用失败：%s", phone_attempt, safe_public_error(e, "rent SMS number"))
                continue
            if not phone:
                last_err = RuntimeError("SMS 接码 controller 未返回手机号")
                continue

            # 阶段 2：通知 OpenAI 发码到这个号
            send_resp = None
            try:
                logger.info("[sms] 📤 准备 POST add-phone/send (phone=%s) ...", phone)
                send_resp = self._add_phone_send(phone)
                logger.info("[sms] ✅ POST add-phone/send 成功 (phone=%s)", phone)
            except Exception as e:
                err_text = str(e)
                if "too many phone verification" in err_text.lower() \
                        or "phone_verification_rate_limit" in err_text.lower():
                    logger.warning(
                        "⚠️ OpenAI 频控: 这个 outlook 号/IP 已累积太多 add-phone 请求，"
                        "建议换 outlook 号或换代理 IP 后重试。本次放弃 add-phone（session_token 仍可保留）"
                    )
                    ctrl.mark_send_failed(err_text)
                    last_err = e
                    break
                if _is_phone_rejected(err_text):
                    logger.warning("[sms] 号码被 OpenAI 拒（号码与异常值已脱敏）")
                    ctrl.mark_send_failed(err_text)
                    last_err = e
                    continue
                # 其它未识别错误 → 也打详细日志但不视为"号码问题"
                logger.warning(safe_public_error(e, "add phone send"))
                ctrl.mark_send_failed(err_text)
                last_err = e
                continue

            send_page_type = self._extract_page_type(send_resp)
            send_continue = self._normalize_continue_url(self._extract_continue_url_from_step(send_resp))
            if send_page_type not in ("phone_otp_verification", "external_url") \
                    and "phone-verification" not in (send_continue or ""):
                logger.warning(
                    "add-phone/send 未进入手机验证码页: page=%s continue=%s",
                    send_page_type or "(empty)",
                    safe_url(send_continue),
                )
                ctrl.mark_send_failed("did not enter phone-verification page")
                last_err = RuntimeError(f"add-phone/send 未进入 phone-verification: page={send_page_type}")
                continue

            ctrl.mark_send_succeeded()

            # 阶段 3：等 SMS code（SmsBower 内部会按 20s × 3 调 OpenAI resend）
            phone_start = time.time()
            seen_codes: set[str] = set()
            code_attempt = 0
            phone_used = False

            while time.time() - phone_start < per_phone_timeout and code_attempt < max_code_retries_per_phone:
                remaining = per_phone_timeout - (time.time() - phone_start)
                if remaining < 10:
                    break
                code_attempt += 1
                logger.info(
                    "[sms] 号 %s 第 %d/%d 次等 SMS (剩余 %ds)",
                    phone, code_attempt, max_code_retries_per_phone, int(remaining),
                )
                code = ctrl.get_code(timeout=int(remaining))
                if not code:
                    break  # 超时换号
                if code in seen_codes:
                    logger.warning("[sms] 收到重复验证码（值已脱敏），跳过")
                    continue
                seen_codes.add(code)
                phone_used = True

                try:
                    validate_resp = self._phone_otp_validate(code)
                    next_url = self._normalize_continue_url(
                        self._extract_continue_url_from_step(validate_resp)
                    )
                    logger.info(
                        "[sms] ✅ phone-otp/validate 通过（号码和验证码已脱敏） next=%s",
                        safe_url(next_url),
                    )
                    ctrl.report_success()
                    return next_url or continue_url or ""
                except Exception as e:
                    last_err = e
                    err_text = str(e)
                    logger.warning(safe_public_error(e, "phone OTP validation"))
                    ctrl.mark_code_failed(err_text)
                    # 继续 while 循环等下一条 code（同号）

            # 单号窗口结束：cancel 这个号
            logger.warning("[sms] 号 %s 已用尽 %ds 窗口", phone, per_phone_timeout)
            try:
                ctrl.cleanup()
            except Exception:
                pass
            # cleanup 清掉 controller.activation，下一轮 get_phone 会租新号

        # 所有号都失败
        if last_err:
            raise last_err
        raise RuntimeError(f"SMS 接码 {max_phone_attempts} 个号均失败")

    def _handle_add_phone_via_env(self, continue_url: str = "") -> str:
        """
        处理 add-phone 验证分支（环境变量路径，旧用法）：
        - 需要通过环境变量提供号码与验证码来源：
          - OPENAI_PHONE_NUMBER=+1...
          - OPENAI_PHONE_OTP_CMD='...返回短信内容...' 或 OPENAI_PHONE_OTP=123456
        """
        phone_raw = (os.getenv("OPENAI_PHONE_NUMBER", "") or "").strip()
        phone_candidates = [x.strip() for x in phone_raw.split(",") if x.strip()]
        if not phone_candidates:
            self._authorization_failure_reason = (
                "需要手机号验证，但未配置可用的 SMS 接码或 OPENAI_PHONE_NUMBER"
            )
            logger.warning("命中 add-phone，但未配置 SMS 接码 / OPENAI_PHONE_NUMBER，无法继续推进")
            return continue_url or ""

        try:
            otp_timeout = max(30, int(os.getenv("OPENAI_PHONE_OTP_TIMEOUT", "180")))
        except Exception:
            otp_timeout = 180

        last_err = ""
        for idx, phone in enumerate(phone_candidates, 1):
            try:
                logger.info("add-phone 尝试号码 %s/%s: %s", idx, len(phone_candidates), phone)
                send_resp = self._add_phone_send(phone)
                send_page_type = self._extract_page_type(send_resp)
                send_continue = self._normalize_continue_url(self._extract_continue_url_from_step(send_resp))
                if send_page_type not in ("phone_otp_verification", "external_url") and "phone-verification" not in (send_continue or ""):
                    logger.warning(
                        "add-phone/send 未进入手机验证码页: page=%s continue=%s",
                        send_page_type or "(empty)",
                        safe_url(send_continue),
                    )
                    continue

                phone_code = self._wait_phone_otp(timeout=otp_timeout)
                validate_resp = self._phone_otp_validate(phone_code)
                next_url = self._normalize_continue_url(self._extract_continue_url_from_step(validate_resp))
                logger.info("add-phone 验证通过，next=%s", (next_url or "")[:180])
                return next_url or continue_url or ""
            except Exception as e:
                last_err = str(e)
                logger.warning(safe_public_error(e, "add phone candidate"))
                try:
                    self._phone_otp_resend()
                except Exception:
                    pass

        if last_err:
            logger.warning("add-phone 阶段未成功: %s", last_err)
        return continue_url or ""

    def _codex_refresh_retry_after_add_phone(
        self,
        auth_url: str,
        redirect_uri: str,
        attempts: int = 3,
        sleep_seconds: float = 1.2,
    ) -> tuple[str, str]:
        """
        当命中 add-phone 时，按“刷新重试”策略重复发起 authorize，
        期望命中不需要 add-phone 的分支并直接拿 callback code。
        """
        callback_url = ""
        final_url = ""
        start_url = self._drop_query_keys(auth_url, {"prompt"}) or auth_url
        rounds = max(1, int(attempts))
        wait_s = max(0.0, float(sleep_seconds))

        for i in range(rounds):
            callback_url, final_url = self._follow_authorize_for_callback(
                start_url,
                redirect_uri,
                f"codex_add_phone_refresh_retry_{i+1}",
            )
            if callback_url:
                return callback_url, final_url
            if i < rounds - 1 and wait_s > 0:
                time.sleep(wait_s)

        return callback_url, final_url

    def oauth_codex_rt_exchange(self, mail_provider: Optional[MailProvider] = None) -> bool:
        """
        纯协议方式获取 RT（参考 any-auto-register）：
        - 使用独立 Codex OAuth 参数重新授权（可控 PKCE）
        - 捕获 callback code（不消费）
        - 直接调 /oauth/token 交换 access_token + refresh_token
        """
        allow_retry = self._env_flag("OAUTH_CODEX_RT_ALLOW_RETRY", "0")
        if self._codex_rt_attempted and (not allow_retry):
            logger.debug("Codex RT 本轮已尝试过，跳过重复尝试")
            return False
        self._codex_rt_attempted = True

        logger.info("尝试 Codex OAuth 直连换取 refresh_token ...")
        try:
            auth_url, state, verifier, redirect_uri, client_id = self._build_codex_authorize()
            self._oauth_auth_url = auth_url
            self._oauth_client_id = client_id
            self._oauth_redirect_uri = redirect_uri
            self._oauth_state = state
            self._manual_login_verifier = verifier
            self._captured_login_verifier = verifier
            callback_url, final_url = self._follow_authorize_for_callback(
                auth_url, redirect_uri, "codex_authorize"
            )

            # 若被打回 /log-in，补走一次协议登录，再继续授权链路
            if (not callback_url) and "/log-in" in (final_url or ""):
                logger.info("Codex 授权回落到 /log-in，尝试协议推进登录状态...")
                continue_url = ""
                try:
                    continue_url = self._codex_drive_login_from_log_in(mail_provider=mail_provider)
                except AuthorizeRateLimitError:
                    raise
                except Exception as e:
                    logger.warning(safe_public_error(e, "Codex login continuation"))
                if continue_url:
                    # 命中 add-phone 时，支持“刷新重试”策略（不立刻放弃）
                    if self._is_add_phone_state(page_type="", continue_url=continue_url) and self._env_flag(
                        "OAUTH_CODEX_ADD_PHONE_REFRESH_RETRY", "1"
                    ):
                        try:
                            retry_count = max(1, int(os.getenv("OAUTH_CODEX_ADD_PHONE_REFRESH_RETRY_COUNT", "3")))
                        except Exception:
                            retry_count = 3
                        try:
                            retry_sleep = max(0.0, float(os.getenv("OAUTH_CODEX_ADD_PHONE_REFRESH_SLEEP", "1.2")))
                        except Exception:
                            retry_sleep = 1.2
                        logger.info("命中 add-phone，执行 authorize 刷新重试: count=%s sleep=%.1fs", retry_count, retry_sleep)
                        callback_url, final_url = self._codex_refresh_retry_after_add_phone(
                            auth_url=auth_url,
                            redirect_uri=redirect_uri,
                            attempts=retry_count,
                            sleep_seconds=retry_sleep,
                        )
                    else:
                        callback_url, final_url = self._follow_authorize_for_callback(
                            continue_url,
                            redirect_uri,
                            "codex_post_login",
                        )

            # Codex authorize 直接被打到 /add-phone（不经过 /log-in）：
            # 如果配了 SMS 接码 controller，先把手机号绑了再重新 authorize
            if (not callback_url) and self._is_add_phone_state(page_type="", continue_url=final_url or "") \
                    and self._sms_callback is not None:
                logger.info("Codex 授权直接落到 /add-phone，尝试 SMS 接码绑号 ...")
                try:
                    self._handle_add_phone_via_sms(continue_url=final_url)
                    # 绑号成功后重新 authorize 拿 callback code
                    callback_url, final_url = self._follow_authorize_for_callback(
                        auth_url, redirect_uri, "codex_authorize_after_add_phone"
                    )
                    if not callback_url:
                        no_prompt_url = self._drop_query_keys(auth_url, {"prompt"})
                        if no_prompt_url and no_prompt_url != auth_url:
                            callback_url, final_url = self._follow_authorize_for_callback(
                                no_prompt_url,
                                redirect_uri,
                                "codex_authorize_noprompt_after_add_phone",
                            )
                except Exception as e:
                    logger.warning(safe_public_error(e, "SMS phone binding"))

            # 兜底：去掉 prompt=login 再发起一次授权
            if not callback_url:
                no_prompt_url = self._drop_query_keys(auth_url, {"prompt"})
                if no_prompt_url and no_prompt_url != auth_url:
                    callback_url, final_url = self._follow_authorize_for_callback(
                        no_prompt_url,
                        redirect_uri,
                        "codex_authorize_noprompt",
                    )

            if not callback_url:
                logger.debug("Codex OAuth 未捕获 callback code, final=%s", (final_url or "")[:180])
                return False
            return self._exchange_codex_callback_code(
                callback_url=callback_url,
                expected_state=state,
                verifier=verifier,
                redirect_uri=redirect_uri,
                client_id=client_id,
            )
        except AuthorizeRateLimitError:
            raise
        except Exception as e:
            logger.warning(safe_public_error(e, "Codex OAuth exchange"))
            return False

    def _inject_pkce_into_auth_url(self, auth_url: str) -> str:
        """为 authorize URL 注入 PKCE 参数（可选）。"""
        if not auth_url:
            return auth_url
        if not self._env_flag("OAUTH_SECONDARY_PKCE", "0"):
            return auth_url

        try:
            parsed = urlparse(auth_url)
            params = dict(parse_qsl(parsed.query, keep_blank_values=True))
            if params.get("code_challenge") and params.get("code_challenge_method"):
                return auth_url

            verifier, challenge = self._build_pkce_pair()
            params["code_challenge"] = challenge
            params["code_challenge_method"] = "S256"
            new_url = urlunparse(parsed._replace(query=urlencode(params)))
            # 若用户未手动指定 verifier，则自动注入本轮 verifier
            if not self._manual_login_verifier:
                self._manual_login_verifier = verifier
            logger.info(
                "已启用二次 PKCE 注入: verifier_len=%s challenge=%s...",
                len(verifier),
                challenge[:16],
            )
            return new_url
        except Exception as e:
            logger.warning(safe_public_error(e, "PKCE parameter injection"))
            return auth_url

    @staticmethod
    def _safe_b64url_decode_text(data: str) -> str:
        if not data:
            return ""
        try:
            s = data + "=" * (-len(data) % 4)
            return base64.urlsafe_b64decode(s.encode("utf-8")).decode("utf-8", errors="replace")
        except Exception:
            return ""

    def _extract_hydra_redirect_values(self) -> list[str]:
        """从 hydra_redirect cookie 中提取可能的会话值。"""
        raw = self._get_cookie_value_by_name("hydra_redirect")
        if not raw:
            return []
        out: list[str] = []
        try:
            p0 = (raw.split(".", 1)[0] or "").strip()
            text = self._safe_b64url_decode_text(p0)
            if text:
                obj = json.loads(text)
                if isinstance(obj, dict):
                    for v in obj.values():
                        if isinstance(v, str) and v.strip():
                            vv = v.strip()
                            out.append(vv)
                            if "|" in vv:
                                out.extend([x for x in vv.split("|") if isinstance(x, str) and x.strip()])
        except Exception:
            return out
        return out

    def _collect_code_verifier_candidates(self, callback_url: str, continue_url: str) -> list[tuple[str, str]]:
        """收集 code_verifier 候选（来源 + 值）。"""
        raw_candidates: list[tuple[str, str]] = [
            ("query", self._extract_query_first(continue_url, ["login_verifier", "code_verifier", "verifier"])),
            ("query_callback", self._extract_query_first(callback_url, ["login_verifier", "code_verifier", "verifier"])),
            ("dump", self._dump_login_verifier),
            ("captured", self._captured_login_verifier),
            ("manual", self._manual_login_verifier),
            ("cookie_login_verifier", self._get_cookie_value_by_name("login_verifier")),
            ("cookie_code_verifier", self._get_cookie_value_by_name("code_verifier")),
            ("cookie_login_challenge", self._extract_login_challenge_from_cookie()),
            ("cookie_nextauth_state", self._get_cookie_value_by_name("__Secure-next-auth.state")),
        ]

        # hydra_redirect 中可能包含编码后的 csrf/session 串，作为实验候选
        for i, hv in enumerate(self._extract_hydra_redirect_values()):
            raw_candidates.append((f"hydra_{i}", hv))

        out: list[tuple[str, str]] = []
        seen: set[str] = set()

        max_len = max(128, int(os.getenv("OAUTH_MAX_VERIFIER_LEN", "4096")))
        for src, val in raw_candidates:
            v = (val or "").strip()
            if not v:
                continue
            if len(v) > max_len:
                v = v[:max_len]
            if v not in seen:
                seen.add(v)
                out.append((src, v))
            # PKCE 标准长度 43~128；对超长候选补一个截断版本
            if len(v) > 128:
                v128 = v[:128]
                if v128 not in seen:
                    seen.add(v128)
                    out.append((f"{src}_trunc128", v128))

        return out

    def _rotate_impersonate_session(self) -> bool:
        """仅在 curl_cffi 指纹模式内切换 UA 指纹版本重试，同时联动更新 UA。

        ⚠️ 这里必须连 self._fingerprint 里的 client hints 一起换掉。
        旧版只更新了 self._ua 和 session —— 但 _common_headers / _navigation_headers
        的 sec-ch-ua* 全是从 self._fingerprint 取的，于是换完会变成
        「UA 说 Chrome/136、sec-ch-ua 说 v=146」，连 not_a_brand 都对不上
        （三个版本各不相同："Not.A/Brand";v="99" / "Not/A)Brand";v="8" /
        "Not?A_Brand";v="99"）—— 这正是上一轮刚消灭的「UA 与头自相矛盾」，
        是 CF 最容易抓的特征。之前没爆只因这条路几乎没走到过。

        fallback_impersonates 是**同家族**构造的（见 fingerprint.py 各 _gen_*），
        所以只会 chrome→chrome、safari→safari，不会跨族；但同族换版本一样要同步头。
        """
        if self._impersonate_idx >= len(self._impersonate_candidates) - 1:
            return False
        self._impersonate_idx += 1
        imp = self._impersonate_candidates[self._impersonate_idx]
        self._ua = ua_for_impersonate(imp, self._ua)
        # 让 client hints 跟上新版本，保持 UA 与头自洽
        try:
            self._fingerprint = fingerprint_for_impersonate(imp, self._fingerprint)
        except Exception as e:  # 兜底：宁可维持旧指纹也不要把流程搞崩
            logger.warning(safe_public_error(e, "client hints synchronization"))
        logger.warning(f"TLS 异常，切换指纹重试: impersonate={imp}, ua={self._ua[:60]}...")
        self.session = create_http_session(
            proxy=self.config.proxy, impersonate=imp, user_agent=self._ua,
        )
        return True

    @staticmethod
    def _datadog_trace_headers() -> dict:
        """生成 Datadog RUM 追踪头（对齐 gptfree-register 格式）。"""
        tid = f"{random.getrandbits(64):016x}"
        sid = str(random.getrandbits(63))
        pid = str(random.getrandbits(63))
        ts_hex = f"{int(time.time()):08x}"
        return {
            "traceparent": f"00-0000000000000000{tid}-{random.getrandbits(64):016x}-01",
            "x-datadog-trace-id": sid,
            "x-datadog-parent-id": pid,
            "x-datadog-sampling-priority": "1",
            "x-datadog-origin": "rum",
            "x-datadog-tags": f"_dd.p.id={tid},_dd.p.tid={ts_hex}00000000,_dd.b.sr=1",
        }

    def _common_headers(self, referer: str = "https://chatgpt.com/") -> dict:
        """
        构造通用请求头。

        关键点：
        - Origin 必须与 Referer 同源（尤其 auth.openai.com 的状态机接口），
          否则容易触发 invalid_state / 风控分支。
        - 在 auth.openai.com 域下，尽量补充 oai-device-id，提升状态机连续性。
        - 全请求注入 Datadog trace 头，避免 OTP silent-drop。
        """
        origin = "https://chatgpt.com"
        try:
            parsed = urlparse(referer or "")
            if parsed.scheme and parsed.netloc:
                origin = f"{parsed.scheme}://{parsed.netloc}"
        except Exception:
            pass

        fp = self._fingerprint
        headers = {
            "Accept": "application/json",
            "Referer": referer,
            "Origin": origin,
            "User-Agent": self._ua,
            "Accept-Language": fp["lang_full"],
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "priority": "u=1, i",
        }
        if fp.get("sec_ch_ua"):
            headers["sec-ch-ua"] = fp["sec_ch_ua"]
            headers["sec-ch-ua-mobile"] = fp.get("sec_ch_ua_mobile") or "?0"
            headers["sec-ch-ua-platform"] = fp["sec_ch_ua_platform"]
            # Client Hints 全套（仅 Chromium 有值，其他浏览器为空串不下发）
            if fp.get("sec_ch_ua_full_version_list"):
                headers["sec-ch-ua-full-version-list"] = fp["sec_ch_ua_full_version_list"]
            if fp.get("sec_ch_ua_arch"):
                headers["sec-ch-ua-arch"] = fp["sec_ch_ua_arch"]
            if fp.get("sec_ch_ua_bitness"):
                headers["sec-ch-ua-bitness"] = fp["sec_ch_ua_bitness"]
            if fp.get("sec_ch_ua_model"):
                headers["sec-ch-ua-model"] = fp["sec_ch_ua_model"]
            if fp.get("sec_ch_ua_platform_version"):
                headers["sec-ch-ua-platform-version"] = fp["sec_ch_ua_platform_version"]

        # auth.openai.com 侧请求补设备标识（若可得）
        try:
            host = (urlparse(origin).netloc or "").lower()
        except Exception:
            host = ""
        if "auth.openai.com" in host:
            device_id = (self.result.device_id or "").strip() or (self._get_cookie_value_by_name("oai-did") or "").strip()
            if device_id:
                headers["oai-device-id"] = device_id

        headers.update(self._datadog_trace_headers())
        return headers

    def _access_flow_headers(self) -> dict[str, str]:
        """Return the official per-document/per-invocation Access Flow IDs."""
        document_id = getattr(self, "_access_flow_document_navigation_id", "")
        try:
            uuid.UUID(document_id)
        except (ValueError, TypeError, AttributeError):
            document_id = str(uuid.uuid4())
            self._access_flow_document_navigation_id = document_id
        return {
            "x-openai-document-navigation-id": document_id,
            "x-access-flow-invocation-id": str(uuid.uuid4()),
        }

    def _navigation_headers(self) -> dict:
        """文档导航请求（地址栏直达那种）的头，含 client hints。

        和 _common_headers 的区别只在 Sec-Fetch-* 那组：那边是 XHR（empty/cors/
        same-origin），这里是整页导航（document/navigate/none + user + UIR）。
        **client hints 两边必须一致**，都从 self._fingerprint 取：Chrome 指纹发
        全套，Safari/Firefox 指纹 sec_ch_ua 为空串、一个都不发——这正是真实浏览器
        的行为。旧 warmup 手搓头漏了这段，导致 Chrome UA 裸奔，实测 403 率 4/5，
        补齐后 5/5 通过（详见 warmup docstring）。
        """
        fp = self._fingerprint
        headers = {
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,"
                      "image/avif,image/webp,image/apng,*/*;q=0.8",
            "Accept-Language": fp["lang_full"],
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "none",
            "sec-fetch-user": "?1",
            "upgrade-insecure-requests": "1",
            "priority": "u=0, i",
            "User-Agent": self._ua,
        }
        if fp.get("sec_ch_ua"):
            headers["sec-ch-ua"] = fp["sec_ch_ua"]
            headers["sec-ch-ua-mobile"] = fp.get("sec_ch_ua_mobile") or "?0"
            headers["sec-ch-ua-platform"] = fp["sec_ch_ua_platform"]
            for key, name in (
                ("sec_ch_ua_full_version_list", "sec-ch-ua-full-version-list"),
                ("sec_ch_ua_arch", "sec-ch-ua-arch"),
                ("sec_ch_ua_bitness", "sec-ch-ua-bitness"),
                ("sec_ch_ua_model", "sec-ch-ua-model"),
                ("sec_ch_ua_platform_version", "sec-ch-ua-platform-version"),
            ):
                if fp.get(key):
                    headers[name] = fp[key]
        return headers

    def warmup(self) -> bool:
        """GET chatgpt.com 种全套 cookie（含 oai-did），成功返回 True。

        为什么这步不能失败（2026-08-10 实测 26 轮，跨 40+ 出口 IP）：
        `POST /api/auth/signin/openai` 依据 chatgpt.com 的 cookie 决定返回什么——
        有 oai-did 就返 auth.openai.com/authorize URL，没有就返 NextAuth 页，
        后者到 authorize/continue 必然 409 invalid_state。
        实测：无 oai-did 的 5 轮 **5/5 全 409**；有 oai-did 的 17 轮只有 3 次 409。

        旧实现两个问题，实测各占一半失败：
        1. 单次无重试 + timeout=15。实测种 cookie 失败率 19%，形态有三种：
           TLS curl(35) 断连、15s 超时、CF 403。成功轮实际耗时 3.4~10.9s，
           15s 卡边缘，40s 才有富余。
        2. **返回值和实际结果对不上**：只 catch 异常，不看 status_code——
           403 照样 return True（实测 3 轮 True 但没 cookie），
           而超时前 cookie 其实已经种上了却 return False（实测 1 轮）。
           所以判据改成直接查 cookie jar，这是唯一可信的信号。

        3. **没发 client hints，自称 Chrome 却不带 sec-ch-ua —— CF 一眼假。**
           这是 403 的真因。真 Chrome 每个导航请求必带 sec-ch-ua/-mobile/-platform，
           而旧 warmup 是手搓 headers、一个都没带（_common_headers 带了，只有这里漏）。
           2026-08-10 实测，同一 impersonate 各打 5 次（每次新 IP）：

               impersonate   裸头(旧)   补 CH 全套
               chrome146      1/5        5/5
               chrome136      1/5        5/5
               chrome142      4/5        4/5   ← 唯一失败是 SSL 断连，不是 403

           补齐后 403 **全部消失**。此前"chrome 族被 CF 拦"的结论是误判：
           safari/firefox 当时 4/4 不是因为它们更干净，而是**它们本来就不该发
           client hints**，裸头对它们恰好是正确的头。所以修法是把头补齐，
           不是换成 safari —— 换指纹只是绕开症状，且会让 self._fingerprint 与
           self._ua 不一致（后续 _common_headers 会拿旧家族的 CH 配新 UA，更假）。

        重试只换出口 IP，不换指纹（指纹本来就没问题，见上）：代理池按会话分配
        出口，新 session ≈ 新 IP，绕开连不上的坏 IP。cookie 跟着 session 一起
        清掉是对的：失败轮本来就没种到有用的东西。

        注：URL 保持首页 `/`。实测对比过 `/auth/login`（16 轮 vs 10 轮），
        失败率 18.75% vs 20%，无差异，不值得换。

        【最终验证 2026-08-10】本处 + auth_oauth_init + _follow_redirects 三处
        统一走 _navigation_headers 后，用真实 CF 域名跑完整 run_register
        **3/3 全成功**（各约 100s，password + access_token 齐全），409 = 0。
        """
        headers = self._navigation_headers()
        if getattr(self, "_password_reset_phase", "") == 'warmup':
            # Reset attempts keep the leased endpoint fixed. Let the account
            # worker choose another lease instead of mutating ssid/cookie state.
            self._password_reset_cancelled(getattr(self, '_password_reset_cancel_event', None))
            try:
                resp = self.session.get('https://chatgpt.com', headers=headers, timeout=30)
            except Exception as exc:
                self.record_registration_diagnostic('warmup_after', attempt=1, success=False)
                raise
            self._trace_http('password_reset_warmup', resp)
            metadata = safe_auth_response_metadata(resp)
            status = int(getattr(resp, 'status_code', 0) or 0)
            if status >= 400:
                self.record_registration_diagnostic('warmup_after', attempt=1, success=False, **metadata)
                raise PasswordResetProtocolError('warmup', 'upstream_http_error',
                    http_status=status, error_code=metadata.get('error_code', ''))
            try:
                cookies = self.session.cookies.get_dict()
            except Exception:
                cookies = {}
            seeded = bool(cookies.get('oai-did'))
            self.record_registration_diagnostic('warmup_after', attempt=1, success=seeded, **metadata)
            return seeded

        for attempt in range(4):
            if attempt:
                # 只换出口 IP（新 session = 新出口），指纹保持不变：
                # 403 是缺 client hints 导致的，已在头里修好，不是指纹的锅。
                # 2026-09-26：固定会话型住宅代理（用户名带 ssid_XXX）新 session
                # 仍是同一出口 —— IP 被 CF 拉黑时换指纹无用，必须轮换 ssid 换
                # 出口 IP（实测原 ssid 连续 403/连接失败，换 ssid 立即 200）。
                # 无 ssid_ 模式的代理原样返回，完全不受影响。
                time.sleep(3 + attempt * 2)
                rotated_proxy = rotate_proxy_session_id(self.config.proxy)
                if rotated_proxy != self.config.proxy:
                    logger.info("warmup 重试：已轮换代理会话 ID（ssid）获取新出口 IP")
                    self.config.proxy = rotated_proxy
                self.session = create_http_session(
                    proxy=self.config.proxy,
                    impersonate=self._impersonate_candidates[self._impersonate_idx],
                    user_agent=self._ua,
                )
            try:
                self._record_cookie_diagnostic("warmup_before", attempt=attempt + 1)
                resp = self.session.get(
                    "https://chatgpt.com", headers=headers, timeout=40,
                )
                status = resp.status_code
            except Exception as e:
                status = None
                logger.warning("warmup 第 %s/4 次请求失败: %s", attempt + 1, safe_public_error(e, "warmup request"))

            # 唯一判据：cookie 到底种上没有。HTTP 200 不代表拿到 oai-did（CF 403 只给
            # __cf_bm），请求抛异常也不代表没拿到（超时前可能已经种上了）。
            try:
                cookies = self.session.cookies.get_dict()
            except Exception:
                cookies = {}
            self._record_cookie_diagnostic(
                "warmup_after",
                cookies=cookies,
                attempt=attempt + 1,
                http_status=status,
                success="oai-did" in cookies,
                **({key: value for key, value in safe_auth_response_metadata(resp).items() if key != "http_status"} if status is not None else {}),
            )
            if "oai-did" in cookies:
                logger.info(
                    f"chatgpt.com warmup 完成（第 {attempt + 1} 次，oai-did 已种，"
                    f"共 {len(cookies)} 个 cookie）"
                )
                return True

            logger.warning(
                f"warmup 第 {attempt + 1}/4 次未种到 oai-did"
                + (f"（HTTP {status}）" if status is not None else "")
                + (f"，已有 cookie: {sorted(cookies)}" if cookies else "，无任何 cookie")
            )

        logger.error("warmup 4 次均未种到 oai-did cookie，无法建立初始认证状态")
        return False

    # ── Step 1: 检查代理连通性 ──
    def check_proxy(self) -> bool:
        logger.info("检查网络连通性...")
        try:
            resp = self.session.get("https://cloudflare.com/cdn-cgi/trace", timeout=15)
            if resp.status_code == 200:
                loc = re.search(r"loc=(\w+)", resp.text)
                ip = re.search(r"ip=([^\n]+)", resp.text)
                country_code = loc.group(1) if loc else ""
                logger.info(f"网络正常 - IP: {ip.group(1) if ip else 'N/A'}, "
                            f"地区: {country_code or 'N/A'}")
                self.record_registration_diagnostic(
                    "proxy_check",
                    success=True,
                    exit_ip=(ip.group(1) if ip else ""),
                    country=(country_code or ""),
                    http_status=resp.status_code,
                )

                # IP 地理联动：检测到国家码后，重新生成指纹（带时区/语言联动）
                if country_code and country_code != self._country_code:
                    self._country_code = country_code
                    import random
                    session_seed = id(self.session) % (2**32)
                    rng = random.Random(session_seed)
                    self._fingerprint = generate_fingerprint(rng=rng, country_code=country_code)
                    self._ua = self._fingerprint["user_agent"]
                    new_imp = self._fingerprint["impersonate"]
                    self._impersonate_candidates = self._fingerprint.get(
                        "fallback_impersonates",
                        [new_imp, "safari17_0", "safari15_5"],
                    )
                    self._impersonate_idx = 0
                    self.session = create_http_session(
                        proxy=self.config.proxy,
                        impersonate=new_imp,
                        user_agent=self._ua,
                    )
            else:
                logger.warning(f"网络探测异常: cloudflare trace {resp.status_code}")
                self.record_registration_diagnostic(
                    "proxy_check",
                    success=False,
                    http_status=resp.status_code,
                )

            return True
        except Exception as e:
            logger.error(safe_public_error(e, "network check"))
            self.record_registration_diagnostic("proxy_check", success=False, error_type=type(e).__name__)
        return False

    # ── Step 2: 获取 CSRF Token ──
    def get_csrf_token(self) -> str:
        logger.info("[1/10] 获取 CSRF Token...")
        headers = self._common_headers("https://chatgpt.com/auth/login")

        # Cloudflare 可能在短时间内多次请求后返回 403，重试 3 次
        for attempt in range(3):
            try:
                resp = self.session.get(
                    "https://chatgpt.com/api/auth/csrf",
                    headers=headers,
                    timeout=30,
                )
            except Exception as e:
                if getattr(self, '_password_reset_phase', '') == 'csrf':
                    raise
                if self._is_tls_error(e) and self._rotate_impersonate_session():
                    continue
                if self._is_tls_error(e):
                    raise RuntimeError(
                        "chatgpt.com TLS 握手失败，当前网络无法建立到 /api/auth/csrf 的 HTTPS 连接。"
                        "请切换可直连 chatgpt.com 的网络或在界面中配置可用代理后重试。"
                    ) from e
                raise
            if resp.status_code == 403 and attempt < 2 and not getattr(self, '_password_reset_phase', ''):
                wait = (attempt + 1) * 5
                logger.warning(f"Cloudflare 403, {wait}s 后重试 ({attempt + 1}/3)...")
                import time
                time.sleep(wait)
                continue
            if getattr(self, '_password_reset_phase', '') == 'csrf':
                self._trace_http('chatgpt_csrf', resp)
            resp.raise_for_status()
            break

        self._trace_http("chatgpt_csrf", resp)
        csrf = resp.json().get("csrfToken", "")
        if not csrf:
            raise RuntimeError("CSRF Token 获取失败")
        self.result.csrf_token = csrf
        logger.debug(f"CSRF Token: {csrf[:20]}...")
        return csrf

    # ── Step 3: 获取 auth URL ──
    def get_auth_url(self, csrf_token: str, email: str = "") -> str:
        logger.info("[2/10] 获取 OpenAI 授权地址...")
        headers = self._common_headers("https://chatgpt.com/auth/login")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        if not self.result.device_id:
            self.result.device_id = str(uuid.uuid4())
        query_params: dict[str, str] = {
            "prompt": "login",
            "screen_hint": "login_or_signup",
            "ext-oai-did": self.result.device_id,
            "auth_session_logging_id": str(uuid.uuid4()),
            "ext-passkey-client-capabilities": "1111",
        }
        if email:
            query_params["login_hint"] = email
        signin_url = f"https://chatgpt.com/api/auth/signin/openai?{urlencode(query_params)}"
        resp = self.session.post(
            signin_url,
            headers=headers,
            data={
                "csrfToken": csrf_token,
                "callbackUrl": "https://chatgpt.com/",
                "json": "true",
            },
            timeout=30,
        )
        resp.raise_for_status()
        self._trace_http("chatgpt_signin_openai", resp)
        auth_url = resp.json().get("url", "")
        if not auth_url:
            raise RuntimeError("Auth URL 获取失败")
        # 记住 OAuth 参数，并根据开关可选注入 PKCE
        self._remember_oauth_params(auth_url)
        auth_url = self._inject_pkce_into_auth_url(auth_url)
        self._remember_oauth_params(auth_url)
        logger.debug("Auth URL: %s", safe_url(auth_url))
        return auth_url

    # ── Step 4: OAuth 初始化 & 获取 device_id ──
    def auth_oauth_init(self, auth_url: str) -> str:
        """跟随 authorize 链，落 authorize 会话状态并取回 oai-did。

        这一步**建立的就是后面 authorize/continue 要用的那个 state**，头不像真
        浏览器就拿不到有效状态，下一步必 409 invalid_state。

        旧实现只发 Accept/Referer/UA，缺 client hints、**整组 Sec-Fetch-* 也没有**
        （真浏览器跳转必带 document/navigate/cross-site）。2026-08-10 实测 A/B
        对照各 6 轮（400 invalid_username 视为会话正常，只是 .test 域名被拒）：

            A 现状裸头        会话正常 2/6，**409 = 3**
            B 补齐 CH+SecFetch 会话正常 5/6，**409 = 0**

        和 warmup 那处是同一个病（详见 warmup docstring），当时只修了 warmup，
        漏了这里，所以主人实跑仍 409。头统一从 _navigation_headers 派生，
        保证 client hints 与 self._fingerprint / self._ua 同族。
        """
        logger.info("[3/10] OAuth 初始化...")
        headers = self._navigation_headers()
        headers["Referer"] = "https://chatgpt.com/"
        # chatgpt.com -> auth.openai.com 是跨站跳转，不是首次直达
        headers["sec-fetch-site"] = "cross-site"
        # 302 自动跟随不是用户手动点击，真浏览器此时不发 sec-fetch-user
        headers.pop("sec-fetch-user", None)
        self._record_cookie_diagnostic("oauth_init_before")
        if getattr(self, "_password_reset_phase", "") == "oauth_init" and isinstance(self.session, _TlsRetrySession):
            resp = self.session.get_authorization_init(
                auth_url, headers=headers, timeout=30, allow_redirects=True,
                cancel_event=getattr(self, "_password_reset_cancel_event", None),
                diagnostic_callback=self.record_registration_diagnostic,
            )
        else:
            resp = self.session.get(auth_url, headers=headers, timeout=30, allow_redirects=True)
        self._trace_http("auth_oauth_init", resp)

        # 从授权 host 对应的 cookie 获取 oai-did。
        # 同名 cookie 可能同时存在于 chatgpt.com 和 auth.openai.com；
        # 按 jar 顺序取值会把两套 OAuth 状态混在一起，随后 authorize/continue
        # 表现为 409 invalid_state。
        auth_host = ""
        try:
            auth_host = urlparse(auth_url).hostname or ""
        except Exception:
            pass
        device_id = self._get_cookie_value_for_host("oai-did", auth_host)
        try:
            final = urlparse(str(getattr(resp, "url", "") or ""))
        except ValueError:
            final = urlparse("")
        final_https = final.scheme == "https"
        final_host_matches = bool(auth_host and final.hostname == auth_host)
        final_error = (
            final.path.rstrip("/").split("/")[-1].lower() == "error"
            or "error" in parse_qs(final.query, keep_blank_values=True)
        )
        self._record_cookie_diagnostic(
            "oauth_init_after",
            http_status=resp.status_code,
            final_https=final_https,
            final_host_matches=final_host_matches,
            final_error=final_error,
            auth_oai_did_present=bool(device_id),
            **{key: value for key, value in safe_auth_response_metadata(resp).items() if key != "http_status"},
        )
        logger.info(
            "OAuth 初始化检查: status=%s final_https=%s same_auth_host=%s error_page=%s auth_oai_did_present=%s",
            resp.status_code, final_https, final_host_matches, final_error, bool(device_id),
        )

        cause = ""
        guidance = ""
        if resp.status_code != 200:
            cause = "oauth_init_http_error"
            guidance = "OAuth 初始化返回非成功状态，本轮已停止"
        elif not final_https or not final_host_matches or final_error:
            cause = "oauth_init_redirect_invalid"
            guidance = "OAuth 初始化未停留在有效的 HTTPS 授权页面，本轮已停止"
        elif not device_id:
            cause = "oauth_init_cookie_missing"
            guidance = "OAuth 初始化未获取到授权域的 oai-did cookie，本轮已停止"
        if cause:
            error = RuntimeError(f"{guidance} (HTTP {resp.status_code})")
            error.failure_phase = "oauth_init"
            error.failure_cause = cause
            error.http_status = resp.status_code
            error.error_code = safe_response_error_code(resp)
            error.safe_message = guidance
            raise error

        self.result.device_id = device_id
        cookie_device_id = self._get_cookie_value_for_host("oai-did", auth_host)
        self.record_registration_diagnostic(
            "device_identity",
            device_id_present=bool(device_id),
            oai_did_present=bool(cookie_device_id),
            device_matches_oai_did=bool(cookie_device_id and cookie_device_id == device_id),
        )
        logger.debug("OAuth device identity available: %s", bool(device_id))
        return device_id

    # ── Step 5: 获取 Sentinel Token ──
    def _sentinel_fp_kwargs(self) -> dict:
        """从 self._fingerprint 抽出 sentinel 需要的指纹/硬件字段。

        保证 4 处 sentinel 调用（authorize_continue / username_password_create /
        create_account 等）用的是同一套一致画像——UA↔platform↔vendor↔硬件全程不变。
        """
        fp = self._fingerprint or {}
        return {
            "user_agent": self._ua,
            "sec_ch_ua": fp.get("sec_ch_ua", ""),
            "sec_ch_ua_platform": fp.get("sec_ch_ua_platform", ""),
            "sec_ch_ua_mobile": fp.get("sec_ch_ua_mobile", ""),
            # Client Hints 全套（仅 Chromium 有值）
            "sec_ch_ua_full_version_list": fp.get("sec_ch_ua_full_version_list", ""),
            "sec_ch_ua_arch": fp.get("sec_ch_ua_arch", ""),
            "sec_ch_ua_bitness": fp.get("sec_ch_ua_bitness", ""),
            "sec_ch_ua_model": fp.get("sec_ch_ua_model", ""),
            "sec_ch_ua_platform_version": fp.get("sec_ch_ua_platform_version", ""),
            "screen": fp.get("screen", ""),
            "lang": fp.get("lang", ""),
            "lang_full": fp.get("lang_full", ""),
            "browser_type": fp.get("browser_type", ""),
            "navigator_platform": fp.get("navigator_platform", ""),
            "navigator_vendor": fp.get("navigator_vendor"),
            "hardware_concurrency": fp.get("hardware_concurrency", 0),
            "device_memory": fp.get("device_memory"),
            "max_touch_points": fp.get("max_touch_points", 0),
            "device_pixel_ratio": fp.get("device_pixel_ratio", 0.0),
            "timezone": fp.get("timezone", ""),  # IP 联动时区
        }

    def get_sentinel_token(self, device_id: str, flow: str = "authorize_continue") -> str:
        """获取与当前官方 auth 页面匹配的 Sentinel。

        ``authorize_continue`` 是既有注册/登录默认值；密码重置的验证码校验和
        新密码提交使用官方页面声明的独立 flow，不能复用旧 token。
        """
        flow = str(flow or "authorize_continue").strip() or "authorize_continue"
        logger.info("[4/10] 获取 Sentinel Token (flow=%s)...", flow)
        from sentinel import get_sentinel_token
        try:
            result = get_sentinel_token(
                self.session,
                device_id=device_id,
                flow=flow,
                **self._sentinel_fp_kwargs(),
            )
        except Exception as exc:
            self.record_registration_diagnostic(
                "sentinel",
                flow=flow,
                success=False,
                error_type=type(exc).__name__,
            )
            raise
        token, so_token = result
        self._last_sentinel_token = token or ""
        self._last_sentinel_so_token = so_token or ""
        self.record_registration_diagnostic(
            "sentinel",
            flow=flow,
            success=bool(token),
            token_length=len(token or ""),
            so_token_present=bool(so_token),
            so_token_length=len(so_token or ""),
        )
        logger.debug("Sentinel Token 获取成功")
        return token

    # ── Step 6: 提交注册邮箱 ──
    def authorize_continue(
        self,
        email: str,
        sentinel_token: str,
        screen_hint: str = "signup",
        referer: str = "https://auth.openai.com/create-account",
        trace_step: str = "",
    ) -> dict:
        """调用 /api/accounts/authorize/continue，返回 JSON。"""
        headers = self._common_headers(referer)
        headers["Content-Type"] = "application/json"
        if sentinel_token:
            headers["openai-sentinel-token"] = sentinel_token
        if getattr(self, "_last_sentinel_so_token", ""):
            headers["openai-sentinel-so-token"] = self._last_sentinel_so_token
        payload = {
            "username": {"value": email, "kind": "email"},
            "screen_hint": screen_hint,
        }
        trace_step = trace_step or f"authorize_continue_{screen_hint}"
        resp = self.session.post(
            "https://auth.openai.com/api/accounts/authorize/continue",
            headers=headers,
            json=payload,
            timeout=30,
        )
        self._trace_http(trace_step, resp)
        if resp.status_code == 200:
            try:
                return resp.json() if resp is not None else {}
            except Exception:
                return {}

        response_metadata = safe_auth_response_metadata(resp)
        error_code = ""
        try:
            payload = resp.json() or {}
            if isinstance(payload, dict):
                candidate = payload.get("error")
                if isinstance(candidate, dict):
                    candidate = candidate.get("code") or candidate.get("type")
                error_code = safe_error_code(candidate)
        except Exception:
            pass
        is_rate_limited = (
            resp.status_code == 429
            or error_code.lower() == "rate_limit_exceeded"
        )
        logger.error(
            "authorize/continue 非 200: status=%s screen_hint=%s request_id_present=%s response_kind=%s error_code=%s",
            resp.status_code, screen_hint, response_metadata["request_id_present"], response_metadata["response_kind"], error_code or "unknown",
        )
        if is_rate_limited:
            error = AuthorizeRateLimitError(
                "OpenAI 授权会话被限流（HTTP 429 rate_limit_exceeded）："
                "已停止本次请求，不再立即重试；这不等于密码错误，"
                "请等待限流恢复后再继续；"
                f"screen_hint={screen_hint}"
            )
            error.http_status = resp.status_code
            error.error_code = "rate_limit_exceeded"
            error.failure_phase = "authorize_continue"
            raise error
        error = RuntimeError(
            f"authorize/continue 失败(screen_hint={screen_hint}): "
            f"HTTP {resp.status_code} error_code={error_code or 'unknown'}"
        )
        error.error_code = error_code
        error.failure_phase = "authorize_continue"
        error.http_status = resp.status_code
        if error_code == "invalid_state":
            error.safe_message = "授权流程状态无效，本轮已停止；请先检查 OAuth 初始化和会话连续性"
        raise error

    def signup(self, email: str, sentinel_token: str) -> bool:
        """提交注册邮箱。返回 True 表示走新注册流程，False 表示已有账号走 OTP 登录流程"""
        logger.info("[5/10] 提交注册邮箱...")
        data = self.authorize_continue(
            email=email,
            sentinel_token=sentinel_token,
            screen_hint="signup",
            referer="https://auth.openai.com/create-account",
            trace_step="authorize_continue_signup",
        )

        # 检测 page_type/continue_url，区分新账号与已有账号
        try:
            page = (data.get("page") or {}) if isinstance(data, dict) else {}
            page_type = (page.get("type") or "").strip()
            payload = (page.get("payload") or {}) if isinstance(page, dict) else {}
            continue_url = (data.get("continue_url") or "").strip()

            # 新账号标准分支
            if page_type == "create_account_password" or "/create-account/password" in continue_url:
                self._is_existing_account = False
                self._existing_email_verification_mode = ""
                self._existing_page_type = page_type
                self.record_registration_diagnostic(
                    "signup_branch",
                    is_new=True,
                    page_type=page_type,
                    email_verification_mode="",
                    continue_path=urlparse(continue_url).path if continue_url else "",
                )
                logger.info("注册邮箱已提交")
                return True

            # OTP 验证分支（passwordless 新注册 或 已有账号登录）
            if page_type == "email_otp_verification":
                mode = (payload.get("email_verification_mode", "") or "").strip()
                self._existing_email_verification_mode = mode
                self._existing_page_type = page_type
                self.record_registration_diagnostic(
                    "signup_branch",
                    is_new=(mode == "passwordless_signup"),
                    page_type=page_type,
                    email_verification_mode=mode,
                    continue_path=urlparse(continue_url).path if continue_url else "",
                )
                if mode == "passwordless_signup":
                    logger.info("服务端选择 passwordless 注册流程（新账号，无密码），等待 OTP")
                    self._is_existing_account = False
                else:
                    logger.info("检测到已有账号，切换到 OTP 登录流程")
                    self._is_existing_account = True
                return False

            # 未知 page_type：通常是社交登录/风控分支，按已有账号处理，避免误进 register_password 导致 invalid_state
            self._existing_email_verification_mode = (payload.get("email_verification_mode", "") or "").strip()
            self._existing_page_type = page_type
            self.record_registration_diagnostic(
                "signup_branch",
                is_new=False,
                page_type=page_type,
                email_verification_mode=self._existing_email_verification_mode,
                continue_path=urlparse(continue_url).path if continue_url else "",
            )
            self._is_existing_account = True
            logger.warning(
                "authorize/continue 返回非标准注册页面: page_type=%s continue_url=%s，按已有账号流程处理",
                page_type or "(empty)",
                safe_url(continue_url) or "(empty)",
            )
            return False
        except Exception:
            # JSON 解析失败时保守按新注册处理
            self._is_existing_account = False
            self._existing_email_verification_mode = ""
            self._existing_page_type = ""
            self.record_registration_diagnostic("signup_branch", is_new=True, page_type="parse_error")
            logger.info("注册邮箱已提交")
            return True

    # ── Step 6.5: 注册密码 ──
    def register_password(self, email: str) -> bool:
        self._password_registered_in_run = False
        self._registration_page_type = ""
        self._registration_continue_url = ""
        self._registration_email_verification_mode = ""
        logger.info("[5.5/10] 注册密码...")
        password = self._random_password()
        self.result.password = password

        # 先访问 create-account/password 页面（HAR 确认需要此步建立服务端状态）
        try:
            pw_page = self.session.get(
                "https://auth.openai.com/create-account/password",
                headers=self._common_headers("https://auth.openai.com/create-account"),
                timeout=15,
            )
            logger.info(f"create-account/password 页面: {pw_page.status_code}")
        except Exception as e:
            logger.warning(safe_public_error(e, "create account password page"))

        # 注册前需要刷新 sentinel token，且 flow 必须为 username_password_create
        #
        # ⚠️ SO token 只在**本次请求**范围内决定带不带，绝不回写实例上的
        #    _last_sentinel_so_token。原因：send_otp / verify_otp 这些后续步骤
        #    自己不刷 sentinel，直接复用实例字段。本 flow 服务端不要求 SO token
        #    （so_token 为空），要是把空值写回实例，等于顺手把后续所有请求的
        #    SO 头也一起摘掉了 —— 那几步的 flow 服务端是要 SO 的。
        so_token_for_request = getattr(self, "_last_sentinel_so_token", "")
        if self.result.device_id:
            try:
                from sentinel import get_sentinel_token as _get_st
                token, so_token = _get_st(self.session, device_id=self.result.device_id,
                                flow="username_password_create",
                                **self._sentinel_fp_kwargs())
                self._last_sentinel_token = token or ""
                so_token_for_request = so_token or ""
                if so_token:
                    self._last_sentinel_so_token = so_token
                logger.debug("Sentinel Token 获取成功")
            except Exception as e:
                # 注：username_password_create 这个 flow 服务端**不下发 so 块**
                #    （实测 2026-08-06，见 sentinel_quickjs.py 里的说明），
                #    所以 so_token 为空是正常的，已在 sentinel_quickjs 按服务端要求判定，
                #    不再走到这个 except。这里只兜网络/子进程一类的真异常。
                #    走到这里说明用的是上一步的 token，flow 对不上是风控特征，
                #    但比当场崩掉（POST 根本发不出去）强，故降级继续。
                logger.warning(
                    f"注册前刷新 sentinel 失败，将改用 flow 不匹配的现有 sentinel token 提交: {e}"
                )

        headers = self._common_headers("https://auth.openai.com/create-account/password")
        headers["Content-Type"] = "application/json"
        headers.update(self._access_flow_headers())
        if self._last_sentinel_token:
            headers["openai-sentinel-token"] = self._last_sentinel_token
        # 服务端对该 flow 没下发 so 块时 so_token_for_request 为空 → 不带这个头，
        # 与真实浏览器一致；不要退回实例字段拿别的 flow 的 SO token 来凑。
        if so_token_for_request:
            headers["openai-sentinel-so-token"] = so_token_for_request
        resp = self.session.post(
            "https://auth.openai.com/api/accounts/user/register",
            headers=headers,
            json={"password": password, "username": email},
            timeout=30,
        )
        self._trace_http("register_password", resp)
        self.record_registration_diagnostic(
            "password_registration",
            success=resp.status_code == 200,
            http_status=resp.status_code,
        )
        if resp.status_code != 200:
            logger.warning("密码注册失败: %s", safe_response_summary(resp, "password registration"))
            return False
        try:
            registration_data = resp.json()
        except Exception:
            registration_data = {}
        if isinstance(registration_data, dict):
            page = registration_data.get("page") or {}
            if not isinstance(page, dict):
                page = {}
            payload = page.get("payload") or {}
            if not isinstance(payload, dict):
                payload = {}
            self._registration_page_type = str(page.get("type") or "").strip()
            self._registration_continue_url = str(
                registration_data.get("continue_url") or ""
            ).strip()
            self._registration_email_verification_mode = str(
                payload.get("email_verification_mode") or ""
            ).strip()
        logger.info("密码注册成功")
        # ⚠️ 走到这里 = OpenAI 侧账号连同这个密码**已经建好了**，但注册流程后面还有
        #    发码 → 验证 OTP → create_account 三步，任何一步挂掉都到不了 save_registered。
        #    密码是这个方法现生成的、只活在内存里，进程一退就永久没了 ——
        #    号还在 OpenAI 那边好好的，却谁也登不进去（实测 2026-08-07 被 OTP 超时坑过一次）。
        #    所以在这里立刻回调落盘。
        #    位置刻意选在 POST 200 **之后**而不是生成密码时：POST 失败的密码
        #    OpenAI 侧根本没生效，写进库里反而误导人以为能用。
        self._password_registered_in_run = True
        if self._on_password is not None:
            try:
                self._on_password(email, password)
            except Exception as e:
                logger.warning(safe_public_error(e, "password persistence callback"))
        return True

    # ── Step 7: 发送 OTP ──
    @staticmethod
    def _otp_delivery_response_ok(resp, endpoint: str, action: str) -> bool:
        """Reject redirects and HTML pages masquerading as API success."""
        status = int(getattr(resp, "status_code", 0) or 0)
        response_url = str(getattr(resp, "url", "") or "")
        headers = getattr(resp, "headers", {}) or {}
        location = str(headers.get("Location") or headers.get("location") or "")
        content_type = str(headers.get("Content-Type") or headers.get("content-type") or "").lower()
        request_id = str(headers.get("x-request-id") or headers.get("X-Request-Id") or "")
        expected_path = urlparse(endpoint).path.rstrip("/")
        actual_path = urlparse(response_url).path.rstrip("/") if response_url else ""
        safe_response_url = safe_url(response_url)
        safe_location = safe_url(location)
        logger.info(
            "%s response: status=%s url=%s location=%s content_type=%s request_id=%s",
            action, status, safe_response_url or "<missing>", safe_location or "<none>",
            content_type or "<missing>", request_id or "<missing>",
        )
        if status == 200 and actual_path == expected_path and not location and "text/html" not in content_type:
            return True
        raise RuntimeError(
            f"{action}未确认验证码已发送: status={status}, url={safe_response_url or '<missing>'}, "
            f"location={safe_location or '<none>'}, content_type={content_type or '<missing>'}, "
            f"request_id={request_id or '<missing>'}"
        )
    def send_otp(self, referer: str = "https://auth.openai.com/create-account/password"):
        logger.info(f"[6/10] 发送 OTP (referer={referer.split('/')[-1]})...")
        headers = self._common_headers(referer)
        headers.update(self._access_flow_headers())
        if self._last_sentinel_token:
            headers["openai-sentinel-token"] = self._last_sentinel_token
        if getattr(self, "_last_sentinel_so_token", ""):
            headers["openai-sentinel-so-token"] = self._last_sentinel_so_token
        # zhuce6 用 GET /api/accounts/email-otp/send
        endpoint = "https://auth.openai.com/api/accounts/email-otp/send"
        resp = self.session.get(
            endpoint,
            headers=headers,
            timeout=30,
            allow_redirects=False,
        )
        self._trace_http("send_email_otp", resp)
        self._otp_delivery_response_ok(resp, endpoint, "发码接口")
        logger.info("发码接口已接受请求")
        self._mark_otp_delivery()
        return True

    def send_passwordless_otp(self, referer: str = "https://auth.openai.com/create-account/password") -> bool:
        """
        走 passwordless 发码（create-account/password 页面可触发该路径）。
        """
        headers = self._common_headers(referer)
        headers["Content-Type"] = "application/json"
        if self._last_sentinel_token:
            headers["openai-sentinel-token"] = self._last_sentinel_token
        if getattr(self, "_last_sentinel_so_token", ""):
            headers["openai-sentinel-so-token"] = self._last_sentinel_so_token
        endpoint = "https://auth.openai.com/api/accounts/passwordless/send-otp"
        resp = self.session.post(
            endpoint,
            headers=headers,
            timeout=30,
            allow_redirects=False,
        )
        self._trace_http("send_passwordless_otp", resp)
        try:
            self._otp_delivery_response_ok(resp, endpoint, "passwordless 发码接口")
            logger.info("passwordless 发码接口已接受请求")
            self._mark_otp_delivery()
            return True
        except RuntimeError as exc:
            logger.warning(safe_public_error(exc, "email OTP delivery"))
            return False

    def _registration_otp_strict_window(self, mode: str) -> bool:
        """Keep strict OTP filtering unless a passwordless A/B opts out."""
        return not (
            (mode or "").strip().lower() == "passwordless_signup"
            and self._env_flag("PROTOCOL_PASSWORDLESS_RELAXED_WINDOW", "0")
        )

    def _send_registration_otp_after_password(self, *, mode: str, referer: str) -> bool:
        """Use the delivery endpoint matching the server's passwordless branch."""
        if (
            (mode or "").strip().lower() == "passwordless_signup"
            and self._env_flag("PROTOCOL_PASSWORDLESS_SIGNUP_SEND", "0")
        ):
            logger.info("passwordless_signup 密码成功后优先走专用 passwordless 发码接口")
            if self.send_passwordless_otp(referer):
                return True
            logger.warning("专用 passwordless 发码未确认，回退 email-otp/send")
        return self.send_otp(referer)

    def resend_otp(self, referer: str = "https://auth.openai.com/email-verification") -> bool:
        """
        重发 OTP（适用于已有账号 passwordless/login_challenge）。
        返回 True 代表请求成功。
        """
        headers = self._common_headers(referer)
        headers["Content-Type"] = "application/json"
        if self._last_sentinel_token:
            headers["openai-sentinel-token"] = self._last_sentinel_token
        if getattr(self, "_last_sentinel_so_token", ""):
            headers["openai-sentinel-so-token"] = self._last_sentinel_so_token
        endpoint = "https://auth.openai.com/api/accounts/email-otp/resend"
        resp = self.session.post(
            endpoint,
            headers=headers,
            timeout=30,
            allow_redirects=False,
        )
        self._trace_http("resend_email_otp", resp)
        try:
            self._otp_delivery_response_ok(resp, endpoint, "重发接口")
            logger.info("重发接口已接受请求")
            self._mark_otp_delivery()
            return True
        except RuntimeError as exc:
            logger.warning(safe_public_error(exc, "email OTP delivery"))
            return False

    def kickoff_otp_delivery(self, mode: str = "") -> bool:
        """
        统一发码策略, 根据 mode hint 区分"新注册" vs "已有账号" referer:

        - 新注册 (create-account/password 页面 state): passwordless/send-otp → email-otp/send
        - 协议首次进入 OTP 页：passwordless/send-otp → send_otp 兼容兜底
        - 已有账号已有 challenge / 验证码重试：resend_otp → send_otp 兜底
        """
        mode_lc = (mode or "").strip().lower()
        initial_passwordless = mode_lc in {
            "protocol_need_otp",
            "existing_need_otp",
            "codex_login_need_otp",
        }
        is_existing = (
            "existing" in mode_lc
            or "passwordless_login" in mode_lc
            or getattr(self, "_is_existing_account", False)
        )

        # The first direct protocol OTP entry has no guaranteed server-side
        # challenge yet.  resend_otp() only works after a challenge exists and
        # therefore must not be the first request on this path.
        if initial_passwordless and not getattr(self, "_otp_challenge_established", False):
            try:
                if self.send_passwordless_otp("https://auth.openai.com/log-in"):
                    self._mark_otp_delivery()
                    return True
            except Exception as exc:
                logger.warning(safe_public_error(exc, "initial passwordless OTP delivery"))

            # Keep a compatibility fallback for providers/server revisions that
            # reject passwordless/send-otp even though the email-otp endpoint is
            # available.  This is still a first-send request; resend is delayed
            # until the bounded waiter has actually timed out.
            try:
                if self.send_otp("https://auth.openai.com/email-verification"):
                    self._mark_otp_delivery()
                    return True
            except Exception as exc:
                logger.warning(safe_public_error(exc, "initial email OTP delivery"))
            return False

        if is_existing:
            # 后续重试或密码验证后的邮箱 OTP 已经有 challenge，优先复用
            # challenge 重发。只有 resend 被服务端拒绝时才用 send_otp 兜底。
            if self.resend_otp("https://auth.openai.com/email-verification"):
                self._mark_otp_delivery()
                return True
            # resend 失败兜底: send_otp 新建 challenge (旧 state 已坏, 不得不重启)
            logger.warning(f"已有账号 resend 失败, 兜底 send_otp 新建 challenge (邮件 X 将失效)")
            try:
                if self.send_otp(referer="https://auth.openai.com/email-verification"):
                    self._mark_otp_delivery()
                    return True
            except Exception as e:
                logger.warning(safe_public_error(e, "existing account OTP delivery"))
            return False

        # 新注册 (原顺序)
        if self.send_passwordless_otp("https://auth.openai.com/create-account/password"):
            self._mark_otp_delivery()
            return True
        if self.resend_otp("https://auth.openai.com/email-verification"):
            self._mark_otp_delivery()
            return True
        try:
            if self.send_otp():
                self._mark_otp_delivery()
                return True
        except Exception as e:
            logger.warning(safe_public_error(e, f"send OTP fallback {mode_lc or 'unknown'}"))
        return False

    @staticmethod
    def _default_password_from_email(email: str) -> str:
        pwd = (email or "").replace("@", "")
        if len(pwd) < 8:
            pwd = f"{pwd}2026OpenAI"
        return pwd

    @staticmethod
    def _random_password(length: int = 16) -> str:
        import string
        upper = string.ascii_uppercase
        lower = string.ascii_lowercase
        digits = string.digits
        special = "!@#$%^&*"
        must = [
            random.choice(upper),
            random.choice(lower),
            random.choice(digits),
            random.choice(special),
        ]
        all_chars = upper + lower + digits + special
        rest = random.choices(all_chars, k=length - len(must))
        pwd_list = must + rest
        random.shuffle(pwd_list)
        return "".join(pwd_list)

    def login_password_verify(self, password: str) -> dict:
        """已有账号密码登录一步（/password/verify）。"""
        headers = self._common_headers("https://auth.openai.com/log-in/password")
        headers["Content-Type"] = "application/json"
        if self._last_sentinel_token:
            headers["openai-sentinel-token"] = self._last_sentinel_token
        if getattr(self, "_last_sentinel_so_token", ""):
            headers["openai-sentinel-so-token"] = self._last_sentinel_so_token
        resp = self.session.post(
            "https://auth.openai.com/api/accounts/password/verify",
            headers=headers,
            json={"password": password},
            timeout=30,
        )
        self._trace_http("login_password_verify", resp)
        if resp.status_code != 200:
            raise RuntimeError(safe_response_summary(resp, "password login"))
        try:
            return resp.json()
        except Exception:
            return {}

    # ── Step 7.5: 提交 TOTP 2FA 验证码 ──
    def submit_mfa_totp(self, totp_code: str, challenge_id: str) -> dict:
        """提交 TOTP 2FA 验证码（已有账号登录时，密码验证后进入 mfa-challenge 状态）。

        Args:
            totp_code: 6 位 TOTP 动态码
            challenge_id: 从 continue_url 提取的 challenge ID（如 /mfa-challenge/6a76f2e8...）

        Returns:
            服务端响应 dict，包含 continue_url 指向 callback
        """
        headers = self._common_headers("https://auth.openai.com/mfa-challenge")
        headers["Content-Type"] = "application/json"
        if self._last_sentinel_token:
            headers["openai-sentinel-token"] = self._last_sentinel_token
        if getattr(self, "_last_sentinel_so_token", ""):
            headers["openai-sentinel-so-token"] = self._last_sentinel_so_token

        resp = self.session.post(
            "https://auth.openai.com/api/accounts/mfa/verify",
            headers=headers,
            json={"code": totp_code, "type": "totp", "id": challenge_id},
            timeout=30,
        )
        self._trace_http("submit_mfa_totp", resp)
        if resp.status_code != 200:
            raise RuntimeError(safe_response_summary(resp, "TOTP verification"))
        try:
            return resp.json()
        except Exception:
            return {}

    # ── Step 8: 验证 OTP ──
    def verify_otp(self, otp_code: str) -> dict:
        logger.info("[7/10] 验证 OTP...")
        headers = self._common_headers("https://auth.openai.com/email-verification")
        headers["Content-Type"] = "application/json"
        headers.update(self._access_flow_headers())
        if self._last_sentinel_token:
            headers["openai-sentinel-token"] = self._last_sentinel_token
        if getattr(self, "_last_sentinel_so_token", ""):
            headers["openai-sentinel-so-token"] = self._last_sentinel_so_token
        resp = self.session.post(
            "https://auth.openai.com/api/accounts/email-otp/validate",
            headers=headers,
            json={"code": otp_code},
            timeout=30,
        )
        self._trace_http("validate_email_otp", resp)
        self.record_registration_diagnostic(
            "otp_verify",
            success=resp.status_code == 200,
            http_status=resp.status_code,
        )
        if resp.status_code != 200:
            summary = safe_response_summary(resp, "OTP verification")
            logger.warning(summary)
            raise OtpVerificationError(
                summary,
                error_code=safe_response_error_code(resp),
            )
        logger.info("OTP 验证成功")
        try:
            return resp.json()
        except Exception:
            return {}

    # ── Step 9: 创建账户 ──
    def create_account(self) -> str:
        logger.info("[8/10] 创建账户...")
        # 创建账户前刷新 sentinel token，flow 为 create_account
        if self.result.device_id:
            try:
                from sentinel import get_sentinel_token as _get_st
                sentinel_flow = "oauth_create_account"
                token, so_token = _get_st(self.session, device_id=self.result.device_id,
                                flow=sentinel_flow,
                                **self._sentinel_fp_kwargs())
                self._last_sentinel_token = token or ""
                self._last_sentinel_so_token = so_token or ""
                self.record_registration_diagnostic(
                    "sentinel",
                    flow=sentinel_flow,
                    success=bool(token),
                    token_length=len(token or ""),
                    so_token_present=bool(so_token),
                    so_token_length=len(so_token or ""),
                )
                logger.debug("Sentinel Token 获取成功")
            except RuntimeError:
                raise
            except Exception as e:
                self.record_registration_diagnostic(
                    "sentinel",
                    flow="oauth_create_account",
                    success=False,
                    error_type=type(e).__name__,
                )
                logger.warning(safe_public_error(e, "pre-account sentinel refresh"))
        headers = self._common_headers("https://auth.openai.com/about-you")
        headers["Content-Type"] = "application/json"
        if self._last_sentinel_token:
            headers["openai-sentinel-token"] = self._last_sentinel_token
        if getattr(self, "_last_sentinel_so_token", ""):
            headers["openai-sentinel-so-token"] = self._last_sentinel_so_token
        _FIRST = ["James", "John", "Robert", "Michael", "William", "David", "Richard",
                  "Joseph", "Thomas", "Charles", "Mary", "Patricia", "Jennifer", "Linda",
                  "Elizabeth", "Barbara", "Susan", "Jessica", "Sarah", "Karen"]
        _LAST = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller",
                 "Davis", "Rodriguez", "Martinez", "Wilson", "Anderson", "Taylor", "Thomas"]
        name = f"{random.choice(_FIRST)} {random.choice(_LAST)}"
        birthdate = f"{random.randint(1985, 2000)}-{random.randint(1, 12):02d}-{random.randint(1, 28):02d}"
        resp = self.session.post(
            "https://auth.openai.com/api/accounts/create_account",
            headers=headers,
            json={"name": name, "birthdate": birthdate},
            timeout=30,
        )
        self._trace_http("create_account", resp)
        self.record_registration_diagnostic(
            "account_creation",
            success=resp.status_code == 200,
            http_status=resp.status_code,
        )
        if resp.status_code != 200:
            summary = safe_response_summary(resp, "account creation")
            logger.error(summary)
            raise RuntimeError(summary)
        data = resp.json()
        continue_url = data.get("continue_url", "")
        self._sniff_login_verifier(continue_url, "create_account_continue_url")

        # 尝试 workspace select
        if not continue_url:
            workspace_id = self._extract_workspace_id()
            if workspace_id:
                continue_url = self._workspace_select(workspace_id)

        if not continue_url:
            raise RuntimeError("创建账户后未获取到 continue_url")

        logger.info("账户创建成功")
        return continue_url

    def _extract_workspace_id(self) -> str:
        """从 cookie 中提取 workspace_id"""
        try:
            auth_session = self.session.cookies.get("oai-client-auth-session", "")
            if auth_session:
                parts = auth_session.split(".")
                # 兼容不同 cookie 形态：workspace_id 可能在第 1 段/第 2 段，也可能在 workspaces[0].id
                for idx in range(min(2, len(parts))):
                    segment = (parts[idx] or "").strip()
                    if not segment:
                        continue
                    payload_b64 = segment + "=" * (-len(segment) % 4)
                    decoded = json.loads(base64.urlsafe_b64decode(payload_b64.encode("utf-8")).decode("utf-8"))
                    if not isinstance(decoded, dict):
                        continue
                    wid = (decoded.get("workspace_id", "") or "").strip()
                    if wid:
                        return wid
                    workspaces = decoded.get("workspaces", [])
                    if isinstance(workspaces, list):
                        for it in workspaces:
                            if isinstance(it, dict):
                                wid = (it.get("id", "") or "").strip()
                                if wid:
                                    return wid
        except Exception:
            pass
        return ""

    def _workspace_select(self, workspace_id: str) -> str:
        logger.info("执行 workspace 选择...")
        headers = self._common_headers("https://auth.openai.com/sign-in-with-chatgpt/codex/consent")
        headers["Content-Type"] = "application/json"
        resp = self.session.post(
            "https://auth.openai.com/api/accounts/workspace/select",
            headers=headers,
            json={"workspace_id": workspace_id},
            timeout=30,
        )
        self._trace_http("workspace_select", resp)
        return resp.json().get("continue_url", "") if resp.status_code == 200 else ""

    def _choose_account_select(self, html_text: str, current_url: str) -> str:
        """处理 /choose-an-account 多账号选择页（react-router SSR）。

        HTML 里 streamController.enqueue 注入 `unified_sessions[].id` (us_*) 和
        `session_id` (authsess_*)。这里 regex 抽 us_*，按 react-router action 惯例
        POST 回 /choose-an-account，并 fallback 试几个候选 JSON endpoint。
        返回 next continue_url 或空串。
        """
        m = re.search(r"us_[A-Za-z0-9]{16,}", html_text or "")
        if not m:
            logger.warning("/choose-an-account HTML 里没找到 us_* session id, 跳过")
            return ""
        session_id = m.group(0)
        logger.debug(f"/choose-an-account 选 session_id={session_id}")
        headers = self._common_headers("https://auth.openai.com/choose-an-account")
        headers["Origin"] = "https://auth.openai.com"

        # 真实 endpoint 从 nextStepHandler-*.js 反编译解出：
        #   const {path, method} = r.data.intent === "select"
        #     ? {path: "/session/select", method: "POST"}
        #     : {path: "/session/remove", method: "DELETE"};
        #   fetch(`${authapi_base}/session/select`, {method, body: JSON.stringify({session_id})})
        # 即 POST https://auth.openai.com/api/accounts/session/select JSON {session_id}
        # （intent 决定 path 不进 body；body 只有 session_id 一个字段）
        # 之前直接 POST /choose-an-account 会先经过 react-router action loader 再被
        # nextStepHandler 转发，但 server-side 那一段似乎对 CT/form 字段强敏感，500。
        # 直接命中底层 /api/accounts/session/select 绕开 react-router 层。
        candidates = [
            ("POST", "https://auth.openai.com/api/accounts/session/select",
             {"session_id": session_id}, "json"),
            # 兜底：万一上面被风控，回退到 react-router 路径 + zod schema 字段
            ("POST", "https://auth.openai.com/choose-an-account",
             {"intent": "select", "session_id": session_id}, "form"),
        ]
        for method, url, body, kind in candidates:
            try:
                h = dict(headers)
                if kind == "json":
                    h["Content-Type"] = "application/json"
                    h["Accept"] = "application/json"
                    resp = self.session.post(url, headers=h, json=body, timeout=30)
                else:
                    h["Content-Type"] = "application/x-www-form-urlencoded"
                    h["Accept"] = "application/json, text/html;q=0.9"
                    body_str = "&".join(f"{k}={v}" for k, v in body.items())
                    resp = self.session.post(url, headers=h, data=body_str, timeout=30)
                self._trace_http(f"choose_account_try_{kind}_{url.rsplit('/', 1)[-1][:30]}", resp)
                status = getattr(resp, "status_code", 0)
                loc = (getattr(resp, "headers", {}) or {}).get("Location", "") or \
                      (getattr(resp, "headers", {}) or {}).get("location", "") or ""
                # print 到 stdout 让 webui SSE 能看到每个候选的具体结果
                print(
                    f"[choose-an-account] {method} {url} [{kind}] -> "
                    f"status={status} loc={safe_url(loc)}",
                    flush=True,
                )
                if status in (200, 201, 302, 303):
                    next_url = ""
                    try:
                        j = resp.json() if resp is not None else {}
                        next_url = j.get("continue_url", "") if isinstance(j, dict) else ""
                    except Exception:
                        pass
                    if not next_url and loc:
                        next_url = loc
                    if next_url:
                        logger.debug("choose-an-account 选号成功 endpoint=%s next=%s", url, safe_url(next_url))
                        return next_url
                    # 200 但没 continue_url：可能 set 了 cookie，直接让 caller 重 GET authorize
                    if status == 200:
                        logger.debug(f"choose-an-account POST {url} 200 OK 无 continue_url，假定 cookie 已 set")
                        return current_url  # 让外层重 GET 一次，cookie 已被 server set
            except Exception as e:
                print(
                    f"[choose-an-account] {method} {url} [{kind}] -> "
                    f"{safe_public_error(e, 'choose account')}",
                    flush=True,
                )
                continue
        logger.warning("/choose-an-account 全部候选 endpoint 都失败")
        return ""

    def _normalize_continue_url(self, continue_url: str) -> str:
        """
        标准化 continue_url：
        1) 相对路径 -> 绝对路径
        2) workspace 页面 -> 调用 workspace/select 取下一跳
        """
        if not continue_url:
            return ""
        out = continue_url.strip()
        if out.startswith("/"):
            out = urljoin("https://auth.openai.com", out)
        if "/workspace" in out:
            workspace_id = self._extract_workspace_id() or self._extract_query_first(out, ["workspace_id", "id"])
            if workspace_id:
                logger.info("检测到 workspace 页面，尝试 workspace/select: workspace_id=%s", workspace_id)
                next_url = self._workspace_select(workspace_id)
                if next_url:
                    out = next_url
        return out

    @staticmethod
    def _extract_workspace_id_from_html(html_text: str) -> str:
        """从 workspace 页面 HTML 文本中提取 workspace_id（兜底）。"""
        if not html_text:
            return ""
        try:
            # 先把转义引号还原，便于正则匹配
            text = html_text.replace('\\"', '"')
            patterns = [
                r'workspaces".{0,1600}?"id","([0-9a-fA-F-]{36})"',
                r'"workspace_id"\s*:\s*"([0-9a-fA-F-]{36})"',
                r'"workspaceId"\s*:\s*"([0-9a-fA-F-]{36})"',
            ]
            for p in patterns:
                m = re.search(p, text, flags=re.DOTALL | re.IGNORECASE)
                if m:
                    return (m.group(1) or "").strip()
        except Exception:
            return ""
        return ""

    # ── Step 10: 跟踪重定向链 ──
    def follow_redirect_chain(self, start_url: str) -> tuple[str, str]:
        """手动跟踪重定向，返回 (callback_url, final_url)"""
        logger.info("[9/10] 跟踪重定向链...")
        current_url = start_url
        callback_url = ""
        max_hops = 12
        referer = "https://auth.openai.com/"

        for i in range(max_hops):
            # callback code 是一次性的。若调用方直接传入 callback URL，
            # 此处只捕获并返回，统一留给 _consume_callback_for_session 正式消费一次。
            # 旧逻辑先 GET 再判断 current_url，导致 code 在跟踪阶段被预消费，
            # 随后的正式消费只能拿到失效 code，最终没有 session/access。
            if "/api/auth/callback/openai" in current_url and "code=" in current_url:
                callback_url = current_url
                self._sniff_login_verifier(
                    current_url,
                    f"redirect_hop_{i+1}_callback_url",
                )
                logger.info("捕获 callback URL（未消费）")
                break

            # 逐跳整页导航，头必须像浏览器：同 auth_oauth_init，旧版只发
            # Accept/Referer/UA，缺 client hints 和 Sec-Fetch-*（实测那正是
            # 409 invalid_state 的来源，见 auth_oauth_init docstring）。
            headers = self._navigation_headers()
            headers["Referer"] = referer
            headers.pop("sec-fetch-user", None)   # 302 跟随非用户点击
            # 跨站跳转（chatgpt.com <-> auth.openai.com）标 cross-site，同站标 same-origin
            try:
                headers["sec-fetch-site"] = (
                    "same-origin"
                    if urlparse(current_url).netloc == urlparse(referer).netloc
                    else "cross-site"
                )
            except Exception:
                headers["sec-fetch-site"] = "cross-site"
            resp = self.session.get(
                current_url, headers=headers, timeout=30, allow_redirects=False
            )
            self._trace_http(f"redirect_hop_{i+1}", resp)
            referer = current_url

            # workspace 页面常见为 200，需要主动调 workspace/select 获取下一跳
            if "/workspace" in current_url and resp.status_code == 200:
                workspace_id = self._extract_workspace_id() or self._extract_workspace_id_from_html(resp.text or "")
                if workspace_id:
                    logger.info("workspace 页面提取到 workspace_id=%s，尝试继续授权", workspace_id)
                    next_url = self._workspace_select(workspace_id)
                    if next_url:
                        if next_url.startswith("/"):
                            next_url = urljoin("https://auth.openai.com", next_url)
                        current_url = next_url
                        continue

            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location", "")
                if not location:
                    break
                if location.startswith("/"):
                    parsed = urlparse(current_url)
                    location = f"{parsed.scheme}://{parsed.netloc}{location}"
                # 关键：不要主动 GET callback，避免 code 被服务端回调消费
                if "/api/auth/callback/openai" in location and "code=" in location:
                    callback_url = location
                    current_url = location
                    self._sniff_login_verifier(location, f"redirect_hop_{i+1}_location_callback")
                    logger.info("捕获 callback URL（未消费）")
                    break
                current_url = location
                logger.debug("  重定向 %s: %s", i + 1, safe_url(current_url))
            else:
                break

        # 补一跳首页
        if (not callback_url) and (not current_url.rstrip("/").endswith("chatgpt.com")):
            self.session.get(
                "https://chatgpt.com/",
                headers={"Referer": current_url},
                timeout=30,
            )

        logger.info(f"重定向链完成, callback: {'有' if callback_url else '无'}")
        return callback_url, current_url

    def _reauthorize_for_session(self, original_auth_url: str) -> str | None:
        """已有账号 OTP 验证后，重新发起 authorize 获取 callback URL"""
        logger.info("[9.5/10] 重新 authorize 获取 session ...")
        try:
            # 去掉 prompt=login 参数，利用已有的 auth session cookie
            from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
            parsed = urlparse(original_auth_url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            params.pop("prompt", None)
            # 重新构建 URL
            new_query = urlencode({k: v[0] for k, v in params.items()})
            authorize_url = urlunparse(parsed._replace(query=new_query))

            resp = self.session.get(
                authorize_url,
                allow_redirects=False,
                timeout=15,
            )
            self._trace_http("reauthorize_start", resp)
            logger.info(f"reauthorize status={resp.status_code}")

            # 跟随 redirect chain 找到 callback URL
            current_url = resp.headers.get("Location", "")
            logger.info("reauthorize Location: %s", safe_url(current_url))
            if resp.status_code in (301, 302, 303, 307, 308) and current_url:
                for hop in range(10):
                    logger.debug("reauthorize redirect hop %s: %s", hop + 1, safe_url(current_url))
                    if "code=" in current_url and "state=" in current_url:
                        logger.info("reauthorize: 找到 callback URL")
                        return current_url
                    try:
                        hop_resp = self.session.get(
                            current_url,
                            allow_redirects=False,
                            timeout=15,
                        )
                        self._trace_http(f"reauthorize_hop_{hop+1}", hop_resp)
                        next_loc = hop_resp.headers.get("Location", "")
                        if hop_resp.status_code not in (301, 302, 303, 307, 308) or not next_loc:
                            # 检查最终 URL
                            final_url = str(getattr(hop_resp, 'url', current_url))
                            if "code=" in final_url:
                                return final_url
                            break
                        current_url = next_loc
                        if not current_url.startswith("http"):
                            from urllib.parse import urljoin
                            current_url = urljoin(authorize_url, current_url)
                    except Exception:
                        break
            logger.warning("reauthorize: 未能获取 callback URL")
            return None
        except Exception as e:
            logger.warning(safe_public_error(e, "reauthorize"))
            return None

    # ── Step 11: 获取 session ──
    def _extract_session_cookie(self) -> str:
        """多路兜底提取 __Secure-next-auth.session-token cookie。

        curl_cffi 在某些情况下按 domain 隔离 cookie，session.cookies.get(name) 拿不到，
        所以这里把所有 cookie 都遍历一遍，按名字精确匹配。
        """
        target = "__Secure-next-auth.session-token"
        # 路径1：直接 get
        try:
            v = self.session.cookies.get(target, "")
            if v:
                return v
        except Exception:
            pass
        # 路径2：遍历 jar
        try:
            for c in self.session.cookies:
                name = getattr(c, "name", "") if hasattr(c, "name") else str(c)
                if name == target:
                    val = getattr(c, "value", "") or ""
                    if val:
                        return val
        except Exception:
            pass
        # 路径3：用 _get_cookie_value_by_name（不挑 domain）
        try:
            return self._get_cookie_value_by_name(target)
        except Exception:
            return ""

    def get_auth_session(self) -> tuple[str, str]:
        """获取 session_token 和 access_token。

        session_token 三路兜底（按优先级）：
          1. cookie `__Secure-next-auth.session-token`（NextAuth 数据库 session 策略）
          2. JSON 响应里的 `sessionToken` 字段（NextAuth JWT session 策略，某些路径）
          3. 兼容大小写 / 下划线变体
        access_token 取 JSON 响应里的 `accessToken`。
        """
        first_call = not getattr(self, "_auth_session_fetched", False)
        self._auth_session_fetched = True
        if first_call:
            logger.info("[10/10] 获取认证 Session...")
        headers = self._common_headers("https://chatgpt.com/")
        try:
            session_timeout = max(
                30,
                int(self._get_env("AUTH_SESSION_TIMEOUT", "30")),
            )
        except (TypeError, ValueError):
            session_timeout = 30
        resp = self.session.get(
            "https://chatgpt.com/api/auth/session",
            headers=headers,
            timeout=session_timeout,
        )
        self._trace_http("chatgpt_auth_session", resp)
        self._record_cookie_diagnostic("auth_session_response", http_status=resp.status_code)
        resp.raise_for_status()

        try:
            sess_json = resp.json() if resp is not None else {}
        except Exception:
            sess_json = {}
        if not isinstance(sess_json, dict):
            sess_json = {}

        cookie_st = self._extract_session_cookie()
        json_st = (
            sess_json.get("sessionToken", "")
            or sess_json.get("session_token", "")
            or ""
        )
        session_token = cookie_st or json_st
        access_token = sess_json.get("accessToken", "") or sess_json.get("access_token", "") or ""

        if session_token:
            self.result.session_token = session_token
        if access_token:
            self.result.access_token = access_token
        self.result.cookie_header = self._build_chatgpt_cookie_header()
        self.record_registration_diagnostic(
            "auth_session",
            access_present=bool(access_token),
            session_present=bool(session_token),
            access_length=len(access_token or ""),
            session_length=len(session_token or ""),
            csrf_present=bool(self.result.csrf_token),
            device_id_present=bool(self.result.device_id),
        )

        _log = logger.info if first_call else logger.debug
        _log(f"session: st={'有' if session_token else '无'} at={'有' if access_token else '无'}")
        return session_token, access_token

    def _consume_callback_for_session(self, callback_url: str) -> bool:
        """主动 GET callback URL 让 chatgpt.com NextAuth 设 session cookie。

        协议层 follow_redirect_chain 故意不消费 callback（为后续 OAuth token exchange 留 code），
        但这导致 NextAuth 永远不会写 __Secure-next-auth.session-token cookie。
        在拿不到 session_token 时主动消费一次 callback：跟随到 chatgpt.com 主页，
        服务器会 Set-Cookie session-token。
        """
        if not callback_url or "code=" not in callback_url:
            self.record_registration_diagnostic("callback", captured=False, consumed=False, reason="missing_code")
            return False
        try:
            current = callback_url
            hops = 0
            for hop in range(8):
                hops = hop + 1
                resp = self.session.get(
                    current,
                    headers={
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                        "Referer": "https://auth.openai.com/",
                        "User-Agent": self._ua,
                    },
                    timeout=30,
                    allow_redirects=False,
                )
                self._trace_http(f"consume_callback_hop_{hop+1}", resp)
                if resp.status_code not in (301, 302, 303, 307, 308):
                    break
                loc = (resp.headers.get("Location", "") or "").strip()
                if not loc:
                    break
                if loc.startswith("/"):
                    loc = urljoin(current, loc)
                current = loc
                # 已到 chatgpt.com 主页就够
                parsed = urlparse(current)
                if "chatgpt.com" in (parsed.netloc or "") and "/api/auth/callback" not in current:
                    # 再 GET 一下主页，让 cookie 全部落地
                    try:
                        self.session.get(current, timeout=20, allow_redirects=True)
                    except Exception:
                        pass
                    break
            consumed = bool(self.session.cookies.get("__Secure-next-auth.session-token", ""))
            self.record_registration_diagnostic(
                "callback",
                captured=True,
                consumed=consumed,
                hops=hops,
                final_host=urlparse(current).hostname if current else "",
            )
            self._record_cookie_diagnostic("callback_after")
            return consumed
        except Exception as e:
            logger.warning(safe_public_error(e, "callback consumption"))
            self.record_registration_diagnostic(
                "callback",
                captured=True,
                consumed=False,
                error_type=type(e).__name__,
            )
            return False

    def _establish_auth_session(self, callback_url: str = "") -> bool:
        """建立认证会话，并对 callback/会话读取的瞬时网络失败做有界恢复。

        callback code 可能因为一次网络连接错误没有真正到达服务端。此时
        直接读取 ``/api/auth/session`` 只会得到空会话；第二次消费同一个
        callback 可以恢复这种情况。若 callback 已成功消费，则只重读会话，
        避免无谓地重复使用一次性 code。
        """
        try:
            attempts = max(1, min(3, int(self._get_env("AUTH_SESSION_RETRIES", "2"))))
        except (TypeError, ValueError):
            attempts = 2
        try:
            retry_delay = max(
                0.0,
                min(5.0, float(self._get_env("AUTH_SESSION_RETRY_DELAY", "1"))),
            )
        except (TypeError, ValueError):
            retry_delay = 1.0

        callback_consumed = False
        last_error = None
        for attempt in range(attempts):
            if callback_url and (attempt == 0 or not callback_consumed):
                callback_consumed = self._consume_callback_for_session(callback_url)
                if not callback_consumed:
                    logger.warning(
                        "callback 会话消费未确认，将尝试恢复（第 %s/%s）",
                        attempt + 1,
                        attempts,
                    )

            try:
                self.get_auth_session()
                last_error = None
            except Exception as exc:
                last_error = exc
                logger.warning(
                    safe_public_error(exc, f"auth session read attempt {attempt + 1}")
                )

            if self.result.is_valid():
                self.record_registration_diagnostic(
                    "session_establishment",
                    success=True,
                    attempts=attempt + 1,
                    callback_consumed=callback_consumed,
                )
                return True

            if attempt + 1 < attempts and retry_delay:
                time.sleep(retry_delay)

        if last_error is not None:
            raise last_error
        success = self.result.is_valid()
        self.record_registration_diagnostic(
            "session_establishment",
            success=success,
            attempts=attempts,
            callback_consumed=callback_consumed,
        )
        return success

    # ── 可选: OAuth Token 交换 ──
    def oauth_token_exchange(self, callback_url: str, continue_url: str) -> bool:
        """
        交换 OAuth token（尽力模式）：
        1) 尝试多来源 code_verifier（query/cookie/dump/hydra）
        2) 回退无 verifier
        """
        auth_code = self._extract_query_first(callback_url, ["code"]) or self._extract_query_first(continue_url, ["code"])

        if not auth_code:
            logger.info("缺少 auth_code，跳过 token 交换")
            return False

        verifier_candidates = self._collect_code_verifier_candidates(callback_url, continue_url)
        if not verifier_candidates:
            logger.info("当前未获取到可用 code_verifier，将先尝试无 verifier 交换")
        else:
            show = ", ".join([f"{src}:{len(v)}" for src, v in verifier_candidates[:8]])
            logger.info("code_verifier 候选数=%s 示例=%s", len(verifier_candidates), show)

        logger.info("执行 OAuth Token 交换...")
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
            "Origin": "https://auth.openai.com",
            "Referer": "https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
        }
        base_form = {
            "grant_type": "authorization_code",
            "client_id": self._oauth_client_id or "YOUR_OPENAI_WEB_CLIENT_ID",
            "code": auth_code,
            "redirect_uri": self._oauth_redirect_uri or "https://chatgpt.com/api/auth/callback/openai",
        }
        logger.info(
            "Token 交换参数: client_id=%s redirect_uri=%s",
            base_form["client_id"],
            base_form["redirect_uri"],
        )

        candidates: list[tuple[str, dict]] = []
        if self._oauth_client_secret:
            d = dict(base_form)
            d["client_secret"] = self._oauth_client_secret
            candidates.append(("with_client_secret", d))

        try:
            max_verifier_try = max(1, int(os.getenv("OAUTH_MAX_VERIFIER_TRY", "18")))
        except Exception:
            max_verifier_try = 18

        for src, verifier in verifier_candidates[:max_verifier_try]:
            d = dict(base_form)
            d["code_verifier"] = verifier
            candidates.append((f"with_verifier_{src}", d))
            if self._oauth_client_secret:
                d2 = dict(d)
                d2["client_secret"] = self._oauth_client_secret
                candidates.append((f"with_verifier_{src}_and_client_secret", d2))

        # 一些服务端可能要求额外参数（实验候选）
        audience = self._extract_query_first(self._oauth_auth_url, ["audience"])
        if audience:
            d = dict(base_form)
            d["audience"] = audience
            candidates.append(("without_verifier_with_audience", d))
        if self._oauth_scope:
            d = dict(base_form)
            d["scope"] = self._oauth_scope
            candidates.append(("without_verifier_with_scope", d))

        candidates.append(("without_verifier", dict(base_form)))

        seen_fingerprints: set[str] = set()
        for mode, form in candidates:
            fp = json.dumps(form, sort_keys=True, ensure_ascii=False)
            if fp in seen_fingerprints:
                continue
            seen_fingerprints.add(fp)
            try:
                self._sniff_login_verifier(urlencode(form), f"oauth_token_exchange_{mode}:form")
            except Exception:
                pass
            encoded_form = urlencode(form)
            extra_request = {
                "method": "POST",
                "url": "https://auth.openai.com/oauth/token",
                "body": encoded_form,
                "headers": headers,
            }

            resp = self.session.post(
                "https://auth.openai.com/oauth/token",
                headers=headers,
                data=encoded_form,
                timeout=30,
            )
            self._trace_http(f"oauth_token_exchange_{mode}", resp, extra_request=extra_request)
            if resp.status_code == 200:
                data = resp.json()
                self.result.id_token = data.get("id_token", "")
                self.result.access_token = data.get("access_token", self.result.access_token)
                self.result.refresh_token = data.get("refresh_token", "")
                logger.info(
                    "Token 交换成功(mode=%s): refresh_token=%s",
                    mode,
                    "有" if self.result.refresh_token else "无",
                )
                return True

            logger.warning(
                "Token 交换失败(mode=%s): %s",
                mode,
                safe_response_summary(resp, "OAuth token exchange"),
            )

        return False

    def oauth_secondary_authorize_exchange(self) -> bool:
        """
        二次授权实验：
        - 在当前已登录会话上，重新发起一条带 PKCE 的 authorize
        - 仅提取 callback code，不消费 callback
        - 再走 oauth/token 交换
        """
        logger.info("尝试二次 authorize + PKCE 换 refresh_token ...")
        try:
            csrf = self.get_csrf_token()
            auth_url = self.get_auth_url(csrf)
        except Exception as e:
            logger.warning(safe_public_error(e, "secondary authorize initialization"))
            return False

        try:
            verifier, challenge = self._build_pkce_pair()
            parsed = urlparse(auth_url)
            params = dict(parse_qsl(parsed.query, keep_blank_values=True))
            params["code_challenge"] = challenge
            params["code_challenge_method"] = "S256"
            if not params.get("state"):
                params["state"] = self._b64url_no_pad(os.urandom(16))
            sec_url = urlunparse(parsed._replace(query=urlencode(params)))

            self._manual_login_verifier = verifier
            self._captured_login_verifier = verifier
            self._remember_oauth_params(sec_url)

            current = sec_url
            callback_url = ""
            max_hops = 10
            for i in range(max_hops):
                resp = self.session.get(
                    current,
                    headers={
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                        "Referer": "https://chatgpt.com/",
                        "User-Agent": self._ua,
                    },
                    timeout=30,
                    allow_redirects=False,
                )
                self._trace_http(f"secondary_authorize_hop_{i+1}", resp)

                loc = (resp.headers.get("Location", "") or "").strip()
                if loc and loc.startswith("/"):
                    loc = urljoin(current, loc)

                if loc and "/api/auth/callback/openai" in loc and "code=" in loc:
                    callback_url = loc
                    break
                if resp.status_code not in (301, 302, 303, 307, 308) or not loc:
                    break
                current = loc

            if not callback_url:
                logger.warning("二次 authorize 未捕获 callback code")
                return False

            ok = self.oauth_token_exchange(callback_url, callback_url)
            logger.info("二次 authorize 交换结果: %s", "成功" if ok else "失败")
            return ok
        except Exception as e:
            logger.warning(safe_public_error(e, "secondary authorize exchange"))
            return False

    # ── 完整注册流程 ──
    def run_register(self, mail_provider: MailProvider) -> AuthResult:
        """执行完整注册流程"""
        # AuthFlow 实例可能被外层重试复用；每轮都必须重新判断是否已建立
        # OTP challenge，不能把上一轮的发码状态带进新邮箱/新出口。
        self._otp_challenge_established = False
        self._otp_delivery_requested = False
        # 检查网络
        if not self.check_proxy():
            logger.warning("网络预检查未通过，继续尝试注册链路以获取精确错误...")
        # 缺少初始化 cookie 时，在创建邮箱前停止，避免消耗邮箱。
        if not self.warmup():
            error = RuntimeError(
                "warmup 失败：4 次重试均未拿到 chatgpt.com 的 oai-did cookie，"
                "本轮注册已在初始化阶段停止，"
                "请检查代理后重试"
            )
            # 结构化溯源：safe_public_error 只认异常对象上的属性，registrar
            # 的 classify_error 靠 failure_cause 判 network（号自动回池可重跑）。
            # 固定安全文案保留原因；HTTP 状态只在实际请求日志中记录。
            error.failure_phase = "warmup"
            error.failure_cause = "proxy_warmup_failed"
            error.safe_message = (
                "warmup 失败：连续多次都没拿到 chatgpt.com 的 oai-did cookie，"
                "多为代理出口 IP 不通或被 Cloudflare 拦截，请检测代理连通性后重试"
            )
            raise error

        # 创建邮箱
        email = mail_provider.create_mailbox()
        self.result.email = email

        # 建立协议请求前先记录中转站里已经存在的邮件。否则邮件可能在
        # authorize/continue 建立 OTP challenge 后、正式 wait_for_otp 前到达，
        # 而 wait_for_otp 的首次快照会把这封本轮验证码误标为“旧邮件”，
        # 最终表现为“邮箱已收到，协议一直取不到”。JSON 单码接口的 provider
        # 会自行跳过消费性快照；其他 provider 通过这个可选钩子处理基线。
        prepare_for_otp = getattr(mail_provider, "prepare_for_otp", None)
        if callable(prepare_for_otp):
            prepared_count = prepare_for_otp()
            logger.info(
                "OTP 邮箱基线已建立（注册前已记录 %s 封既有邮件）",
                prepared_count,
            )

        # 登录/注册链路
        csrf_token = self.get_csrf_token()
        auth_url = self.get_auth_url(csrf_token, email=email)
        device_id = self.auth_oauth_init(auth_url)
        sentinel = self.get_sentinel_token(device_id)
        # authorize/continue may itself create the email-OTP challenge and
        # enqueue the first message.  Keep a boundary from before that request
        # so passwordless_login can consume its code without issuing a second
        # send that changes the active challenge.
        authorize_continue_started_at = time.time()
        is_new = self.signup(email, sentinel)

        mode = (self._existing_email_verification_mode or "").lower()
        if (
            not is_new
            and mode == "passwordless_login"
            and not getattr(mail_provider, "accepts_existing_account", False)
        ):
            logger.error(
                "服务端返回 passwordless_login：当前是邮箱验证码登录入口，"
                "不是可设置密码的注册步骤；提交邮箱时服务端可能已经自动发码，"
                "停止本轮且不再调用注册密码接口或重复发码"
            )
            raise RuntimeError(
                "当前邮箱未处于可设置密码的注册步骤；提交邮箱时可能已自动发送登录验证码，"
                "但本轮未保存密码。"
                "请在浏览器中手动从“使用密码”入口完成该半成品账号"
            )
        if not is_new and mode == "passwordless_login":
            logger.info(
                "邮箱 provider=%s 声明接受已有账号，继续 passwordless_login OTP 续接",
                getattr(mail_provider, "kind", "unknown"),
            )

        # 号池邮箱被 OpenAI 标"已有账号" 处理策略:
        #   WEBUI_ALLOW_LOGIN=1 (promo-link 等需要拿 access_token 的模式) → 走 OTP login 拿凭证
        #   WEBUI_ALLOW_LOGIN 未设 (register-only 模式) → fast-fail mark dead 换下一个号
        # 这样 register-only 不被 honeypot 拖死, promo-link 又能复用已存在账号.
        #
        # ⚠️ 这个分支对**所有号池型 provider** 生效（outlook / icloud_relay / 以后新增的），
        #    不是 outlook 专属 —— 日志前缀用 provider 自己的 kind，别写死。
        pool_tag = getattr(mail_provider, "kind", "pool")
        is_pooled_existing = (
            not is_new
            and mode != "passwordless_signup"
            and getattr(mail_provider, "pooled", False)
        )
        if is_pooled_existing:
            _allow_login = self._get_env("WEBUI_ALLOW_LOGIN", "").strip() in (
                "1", "true", "yes",
            )
            if _allow_login:
                logger.info(
                    f"[{pool_tag}] '已有账号' 分支但 WEBUI_ALLOW_LOGIN=1 → 走 OTP login 拿凭证 ({email})"
                )
            else:
                logger.warning(
                    f"[{pool_tag}] '已有账号' 分支检测到号池邮箱 ({email}) → fast-fail mark dead, "
                    f"让外层 register() 自动 claim 下一个号 (设 WEBUI_ALLOW_LOGIN=1 改走 OTP login)"
                )
                try:
                    mail_provider.mark_dead(
                        "OpenAI 识别为已有账号 (接码池二手 / honeypot, 协议层 fast-fail)"
                    )
                except Exception:
                    pass
                raise RuntimeError(
                    f"OpenAI 静默拒绝发 OTP (识别 {email} 为已有账号, {pool_tag} 池 fast-fail)"
                )

        # ⚠️ passwordless_signup **也是新账号**，只是服务端选择了"不设密码直接发码"的注册流程。
        #    signup() 用一个 bool 表达三种服务端状态，把它和"已有账号"压成了同一个 False，
        #    结果新号全部走进下面的 else 分支 —— register_password 从没被调用过，
        #    注册出来的号全是无密码号（只能靠临时邮箱收码登录，域名一失效就永久丢失）。
        #    实测 2026-08-06: 这类号照样能走 POST user/register 设密码并成功。
        if is_new or mode == "passwordless_signup":
            # 新账号：注册密码 → 主动重新发码 → 验证 OTP → 创建账户
            password_registered = self.register_password(email)
            if password_registered:
                # Follow the server's actual post-registration page instead of
                # treating every HTTP 200 as the email_otp_send state.
                registration_page_type = str(
                    getattr(self, "_registration_page_type", "") or ""
                ).strip().lower()
                registration_continue_url = str(
                    getattr(self, "_registration_continue_url", "") or ""
                ).strip().lower()
                otp_sent_at = None
                if (
                    registration_page_type == "email_otp_verification"
                    or "/email-verification" in registration_continue_url
                ):
                    # Entering the verification page only changes the flow state;
                    # it does not prove that a message was delivered.  The first
                    # challenge therefore needs the explicit send endpoint.  Keep
                    # resend_otp() for later invalid/expired-code retries where a
                    # challenge already exists.
                    try:
                        self._send_registration_otp_after_password(
                            mode=mode,
                            referer="https://auth.openai.com/email-verification",
                        )
                    except Exception as e:
                        raise RuntimeError(
                            "密码注册后首次发码请求未被接受"
                        ) from e
                    otp_sent_at = time.time()
                elif (
                    registration_page_type == "email_otp_send"
                    or "/api/accounts/email-otp/send" in registration_continue_url
                ):
                    # The server explicitly asks the client to initiate delivery.
                    try:
                        self._send_registration_otp_after_password(
                            mode=mode,
                            referer="https://auth.openai.com/create-account/password",
                        )
                    except Exception as e:
                        logger.warning(safe_public_error(e, "post-password OTP delivery"))
                        if not self.kickoff_otp_delivery("post_register_password_send_failed"):
                            raise RuntimeError(
                                "密码注册后首次发码请求未被接受"
                            ) from e
                    otp_sent_at = time.time()
                else:
                    raise RuntimeError(
                        "密码注册成功，但服务端返回的下一页无法确认验证码发码状态："
                        f"page_type={registration_page_type or '<empty>'}"
                    )
            else:
                logger.error("注册阶段设置密码失败，停止注册；不允许回退邮箱验证码账号")
                self.fetch_client_auth_session_dump("post_register_password_failed_new")
                raise RuntimeError("注册阶段设置密码失败，已停止；不会继续邮箱验证码流程")

            try:
                otp_timeout = max(10, int(self._get_env("OTP_TIMEOUT", "60")))
            except Exception:
                otp_timeout = 180
            otp_code = self._wait_for_otp_with_one_resend(
                mail_provider,
                email,
                timeout=otp_timeout,
                # authorize/continue may enqueue the first OTP before password
                # registration and the later explicit send complete. The mailbox
                # baseline above makes this earlier strict boundary safe.
                issued_after=authorize_continue_started_at,
                strict_issued_after=self._registration_otp_strict_window(mode),
            )
            try:
                self.verify_otp(otp_code)
                self.fetch_client_auth_session_dump("post_verify_otp_new")
            except RuntimeError as e:
                # 偶发 401 错码，补发一次 OTP 并重试
                if "401" in str(e):
                    logger.warning(safe_public_error(e, "first OTP verification"))
                    otp_sent_at = time.time()
                    if not self.kickoff_otp_delivery("verify_otp_retry_new"):
                        self.send_otp()
                    otp_code = self._wait_for_otp_with_one_resend(
                        mail_provider,
                        email,
                        timeout=otp_timeout,
                        issued_after=otp_sent_at,
                        strict_issued_after=True,
                    )
                    self.verify_otp(otp_code)
                    self.fetch_client_auth_session_dump("post_verify_otp_retry_new")
                else:
                    raise

            try:
                continue_url = self.create_account()
            except Exception as e:
                # registration_disallowed 时尝试 reauthorize 兜底，若仍不可用再抛出
                if self._is_registration_disallowed_error(e):
                    logger.warning("create_account 被拒绝，尝试 reauthorize 兜底获取 session ...")
                    continue_url = self._reauthorize_for_session(auth_url) or ""
                    if not continue_url:
                        raise
                else:
                    raise
        else:
            # 已有账号：直接发 OTP → 验证 → 获取 session
            mode = (self._existing_email_verification_mode or "").lower()
            page_type = (self._existing_page_type or "").lower()
            continue_url = ""

            try:
                otp_timeout = max(10, int(self._get_env("OTP_TIMEOUT", "60")))
            except Exception:
                otp_timeout = 180

            if page_type == "login_password":
                logger.info("已有账号进入 login_password 分支，先走密码校验再 OTP")
                login_password = (os.getenv("LOGIN_PASSWORD", "") or "").strip()
                if not login_password and self._account_callback:
                    # 从数据库加载真实密码
                    try:
                        cred = self._account_callback(email)
                        if cred and cred.get("password"):
                            login_password = cred["password"]
                            logger.info("已从数据库加载密码")
                    except Exception as e:
                        logger.warning(safe_public_error(e, "account callback password load"))
                if not login_password:
                    login_password = self._default_password_from_email(email)
                self.result.password = login_password
                login_resp = self.login_password_verify(login_password)
                login_page_type = self._extract_page_type(login_resp)
                continue_url = self._normalize_continue_url(
                    (login_resp or {}).get("continue_url", "") if isinstance(login_resp, dict) else ""
                )

                # mfa-challenge 分支（密码验证后需要 TOTP 2FA）
                if self._is_mfa_challenge_state(login_page_type, continue_url):
                    totp_secret = (self.result.totp_secret or "").strip()
                    if not totp_secret and self._account_callback:
                        # 从数据库加载凭证
                        try:
                            cred = self._account_callback(email)
                            if cred and cred.get("totp_secret"):
                                totp_secret = cred["totp_secret"]
                                self.result.totp_secret = totp_secret
                                logger.info("已从数据库加载 totp_secret")
                        except Exception as e:
                            logger.warning(safe_public_error(e, "account callback"))
                    if not totp_secret:
                        logger.warning("进入 mfa-challenge 但没有 totp_secret，无法继续")
                    else:
                        challenge_id = continue_url.split("/")[-1] if "/mfa-challenge/" in continue_url else ""
                        if challenge_id:
                            totp_code = _totp_now(totp_secret)
                            logger.info(f"提交 TOTP 码进行 2FA 验证（challenge_id={challenge_id[:16]}...）")
                            mfa_resp = self.submit_mfa_totp(totp_code, challenge_id)
                            continue_url = self._normalize_continue_url(
                                (mfa_resp or {}).get("continue_url", "") if isinstance(mfa_resp, dict) else ""
                            )
                        else:
                            logger.warning("无法从 continue_url 提取 challenge_id")

                # 部分账号密码校验后仍需 email otp（二次校验）
                elif not continue_url or "/email-verification" in continue_url:
                    # password/verify 后推荐使用 resend，而不是 /email-otp/send
                    otp_sent_at = time.time()
                    self.kickoff_otp_delivery("existing_login_password")
                    otp_code = self._wait_for_otp_with_one_resend(
                        mail_provider,
                        email,
                        timeout=otp_timeout,
                        issued_after=otp_sent_at,
                        strict_issued_after=True,
                    )
                    otp_resp = self.verify_otp(otp_code)
                    continue_url = self._normalize_continue_url(
                        (otp_resp or {}).get("continue_url", "") if isinstance(otp_resp, dict) else ""
                    )
            else:
                if mode == "passwordless_login":
                    # authorize/continue 返回 email_otp_verification 时已经建立
                    # challenge，并可能已投递首封验证码。此处再次调用
                    # passwordless/send-otp 会让邮箱里的码与服务端当前 challenge
                    # 错位（实测表现为收码成功但 validate HTTP 403）。先消费隐式
                    # 首封；短窗口超时后 bounded helper 才对同一 challenge resend。
                    self._mark_otp_delivery()
                    otp_sent_at = authorize_continue_started_at
                    logger.info(
                        "passwordless_login 复用 authorize/continue 已建立的 OTP challenge，"
                        "跳过重复 send-otp"
                    )
                elif mode != "passwordless_signup":
                    otp_sent_at = time.time()
                    self.send_otp()
                else:
                    # 某些模式在 /authorize/continue 已触发发码，不要重复 /email-otp/send 以免破坏 state
                    # 默认先尝试 /email-otp/resend 获取新码，失败再回看短窗口
                    forced_resend = self._env_flag("OTP_FORCE_RESEND", "0")
                    if forced_resend and self.kickoff_otp_delivery("existing_forced_resend"):
                        otp_sent_at = time.time()
                        logger.debug(f"已有账号验证码模式={mode}，已主动 resend OTP")
                    else:
                        # 回看短窗口，避免误读上一轮旧验证码
                        otp_sent_at = time.time() - 8
                        logger.info(f"已有账号验证码模式={mode}，跳过额外 send_otp，直接等邮件")

                try:
                    otp_code = self._wait_for_otp_with_one_resend(
                        mail_provider,
                        email,
                        timeout=otp_timeout,
                        issued_after=otp_sent_at,
                        strict_issued_after=True,
                    )
                except TimeoutError:
                    # helper 已经在同一个 OTP_TIMEOUT 预算内完成首轮等待和一次重发；
                    # 这里仅保留号池失败后的标记，不能再套一轮完整等待。
                    if getattr(mail_provider, "exhausted", False):
                        logger.warning(
                            f"[{getattr(mail_provider, 'kind', 'mail')}] "
                            f"收码链路已失效并 mark dead, 已停止重复等待"
                        )
                    if getattr(mail_provider, "pooled", False):
                        try:
                            mail_provider.mark_dead(
                                "OpenAI 静默拒绝发 OTP（'已有账号'但 INBOX 无邮件）"
                            )
                        except Exception:
                            pass
                    raise
                try:
                    otp_resp = self.verify_otp(otp_code)
                    self.fetch_client_auth_session_dump("post_verify_otp_existing")
                except RuntimeError as e:
                    if any(code in str(e) for code in ("401", "409")):
                        logger.warning(safe_public_error(e, "first OTP verification"))
                        otp_sent_at = time.time()
                        if not self.kickoff_otp_delivery("existing_verify_retry"):
                            self.send_otp()
                        otp_code = self._wait_for_otp_with_one_resend(
                            mail_provider,
                            email,
                            timeout=otp_timeout,
                            issued_after=otp_sent_at,
                            strict_issued_after=True,
                        )
                        otp_resp = self.verify_otp(otp_code)
                        self.fetch_client_auth_session_dump("post_verify_otp_retry_existing")
                    else:
                        raise
                continue_url = self._extract_continue_url_from_step(otp_resp)
                continue_url = self._normalize_continue_url(continue_url)
                otp_page_type = self._extract_page_type(otp_resp)

                # 已绑定 2FA 的已有账号会在邮箱 OTP 验证成功后进入
                # mfa-challenge。必须继续提交已保存的 TOTP，不能把 MFA
                # 页面直接交给 redirect chain；否则不会产生 callback/session。
                if self._is_mfa_challenge_state(otp_page_type, continue_url):
                    totp_secret = (self.result.totp_secret or "").strip()
                    if not totp_secret and self._account_callback:
                        try:
                            cred = self._account_callback(email)
                            if cred and cred.get("totp_secret"):
                                totp_secret = str(cred["totp_secret"]).strip()
                                self.result.totp_secret = totp_secret
                                logger.info("邮箱 OTP 后进入 MFA，已从数据库加载 totp_secret")
                        except Exception as e:
                            logger.warning(safe_public_error(e, "account callback MFA load"))
                    if not totp_secret:
                        raise ExistingAccountMfaRecoveryError("missing_local_totp")

                    challenge_id = (
                        continue_url.rstrip("/").split("/")[-1]
                        if "/mfa-challenge/" in continue_url
                        else ""
                    )
                    if not challenge_id:
                        raise RuntimeError("邮箱 OTP 验证后进入 MFA，但无法提取 challenge_id")

                    logger.info(
                        "邮箱 OTP 验证后进入 MFA，提交 TOTP（challenge_id=%s...）",
                        challenge_id[:16],
                    )
                    mfa_resp = self.submit_mfa_totp(
                        _totp_now(totp_secret),
                        challenge_id,
                    )
                    otp_resp = mfa_resp
                    otp_page_type = self._extract_page_type(mfa_resp)
                    continue_url = self._normalize_continue_url(
                        self._extract_continue_url_from_step(mfa_resp)
                    )

                if self._is_add_phone_state(page_type=otp_page_type, continue_url=continue_url):
                    continue_url = self._normalize_continue_url(
                        self._handle_add_phone_verification(continue_url=continue_url)
                    )

            # 某些已有账号在 OTP 后会进入 about-you，需要补一次 create_account
            if continue_url and "/about-you" in continue_url:
                try:
                    continue_url = self.create_account()
                except Exception as e:
                    if self._is_registration_disallowed_error(e):
                        logger.warning("about-you create_account 被拒绝，尝试 reauthorize 兜底获取 session ...")
                        continue_url = self._reauthorize_for_session(auth_url) or ""
                        if continue_url:
                            logger.info("reauthorize 兜底成功，继续后续 session 获取")
                            # 下游会走 follow_redirect_chain + get_auth_session
                            pass
                        else:
                            raise
                    else:
                        logger.warning(safe_public_error(e, "existing account profile creation"))
                        continue_url = ""

            # 若 otp 响应未给可用 continue_url，则回退到 reauthorize
            if not continue_url:
                # auth.openai.com 的 session cookie 已设置，直接拿 code
                continue_url = self._reauthorize_for_session(auth_url)

        if continue_url:
            continue_url = self._normalize_continue_url(continue_url)
            # 关键尝试：在 chatgpt callback 被消费前，先走一次 Codex OAuth（有助于保留 auth.openai 登录态）
            # ⚠️ 挂了 on_session_ready 钩子时**跳过这次抢跑**：钩子（绑 2FA）要等
            #    get_auth_session 拿到 access_token 才能跑，而那步在下面 :callback 之后；
            #    这次抢跑成功的话 Codex 就跑到钩子前面去了，指定的顺序等于没改。
            #    跳过后 Codex 落到后面那个调用点（get_auth_session 之后），顺序才是
            #    创建账户 → 重定向链 → 拿 session → 绑 2FA → Codex 授权 → 接码。
            if (
                (not self.result.refresh_token)
                and self._on_session_ready is None
                and self._env_flag("OAUTH_CODEX_RT_BEFORE_CALLBACK", "1")
            ):
                self.oauth_codex_rt_exchange(mail_provider=mail_provider)
            # 可选：在 callback 被消费前尝试 token 交换（可能影响后续 callback，默认关闭）
            refresh_only_mode = self._env_flag("OAUTH_REFRESH_ONLY", "0")
            pre_exchange_default = "1" if refresh_only_mode else "0"
            pre_exchange = self._env_flag("OAUTH_EXCHANGE_BEFORE_CALLBACK", pre_exchange_default)
            if pre_exchange and not self._env_flag("SKIP_OAUTH_TOKEN_EXCHANGE", "0"):
                self.oauth_token_exchange(continue_url, continue_url)
            callback_url, final_url = self.follow_redirect_chain(continue_url)
            if (not callback_url) and final_url and ("/workspace" in final_url):
                normalized = self._normalize_continue_url(final_url)
                if normalized and normalized != final_url:
                    callback_url, final_url = self.follow_redirect_chain(normalized)
        else:
            callback_url, final_url = None, None

        refresh_only_mode = self._env_flag("OAUTH_REFRESH_ONLY", "0")

        # ─ 关键顺序修复 ─
        # 旧版顺序：get_auth_session → oauth_token_exchange → _consume_callback (兜底)
        # 问题：oauth_token_exchange 直接 POST /oauth/token 用掉了 callback 的 code，
        #       后面 _consume_callback 再 GET callback URL 时 code 已失效 →
        #       NextAuth 拒绝 set __Secure-next-auth.session-token cookie。
        # 新版：先 _consume_callback 让 chatgpt.com NextAuth 自己消费 code 并 set 全套
        #       cookie（含 session-token），然后再 get_auth_session 拿 access_token；
        #       Codex RT exchange 用独立 authorize 链路，跟 chatgpt callback 不冲突。
        if not refresh_only_mode:
            if callback_url:
                logger.debug("消费 callback 触发 NextAuth Set-Cookie (session-token)")
            self._establish_auth_session(callback_url)

        # ── 钩子：session 到手、Codex 授权之前 ──
        # 主人指定的顺序是「注册完 → 绑 2FA → Codex 授权 → 接码」。这里是唯一同时满足
        # 「已经有 access_token」和「Codex 还没跑」的位置，所以插在这。
        # 失败绝不能拖垮已注册成功的号 —— 异常吞掉，继续往下走 Codex。
        if self._on_session_ready is not None and self.result.access_token:
            try:
                self._on_session_ready(self, self.result.access_token)
            except Exception as e:
                logger.warning(safe_public_error(e, "session ready callback"))

        # Codex OAuth refresh_token 交换（独立 authorize 链路，不依赖上面 callback 的 code）
        if callback_url or continue_url:
            self.fetch_client_auth_session_dump("pre_oauth_exchange_register")
            # 注意：oauth_token_exchange(callback_url) 会和 NextAuth 抢同一个 code，
            # 默认禁用避免冲突；只有用户显式 SET OAUTH_TOKEN_EXCHANGE_FROM_CALLBACK=1
            # 才尝试（极少需要，access_token 已通过 NextAuth callback 拿到）。
            if self._env_flag("OAUTH_TOKEN_EXCHANGE_FROM_CALLBACK", "0") \
                    and not self._env_flag("SKIP_OAUTH_TOKEN_EXCHANGE", "0"):
                self.oauth_token_exchange(callback_url or "", continue_url or "")
            if (not self.result.refresh_token) and self._env_flag("OAUTH_CODEX_RT_EXCHANGE", "1"):
                self.oauth_codex_rt_exchange(mail_provider=mail_provider)
            if (not self.result.refresh_token) and self._env_flag("OAUTH_SECONDARY_AUTHORIZE_EXCHANGE", "0"):
                self.oauth_secondary_authorize_exchange()
            # 最终再拉一次 session（Codex 流程可能更新 cookie/access_token）
            if not refresh_only_mode:
                self.get_auth_session()

        if refresh_only_mode:
            if not (self.result.refresh_token or self.result.access_token):
                raise RuntimeError("流程完成但未获取 refresh_token/access_token")
        elif not self.result.is_valid():
            raise AuthSessionMissingError()

        logger.info("注册流程完成!")
        return self.result

    def verify_existing_password(self, email: str, password: str) -> dict:
        """Verify one existing-account password and stop before OTP/MFA/session."""
        normalized = (email or "").strip()
        candidate = password if isinstance(password, str) else ""
        if not normalized:
            raise RuntimeError("密码验证缺少邮箱")
        if not candidate or not candidate.strip():
            raise RuntimeError("密码验证缺少密码")

        if not run_verification_step('network_precheck', self.check_proxy):
            logger.warning("网络预检查未通过，继续尝试密码验证以获取精确错误...")
        if not run_verification_step('warmup', self.warmup):
            raise PasswordVerificationError('warmup')

        self._is_existing_account = True
        self._password_registered_in_run = False
        self._password_verified_in_run = False
        self.result.email = normalized

        csrf_token = run_verification_step('csrf', self.get_csrf_token)
        auth_url = run_verification_step('auth_url', self.get_auth_url, csrf_token, email=normalized)
        device_id = run_verification_step('oauth_init', self.auth_oauth_init, auth_url)
        sentinel = run_verification_step('security_check', self.get_sentinel_token, device_id)
        login_step = run_verification_step(
            'identify_account', self.authorize_continue,
            email=normalized,
            sentinel_token=sentinel,
            screen_hint="login",
            referer="https://auth.openai.com/log-in",
            trace_step="authorize_continue_password_reset_verify",
        )
        if not isinstance(login_step, dict):
            raise PasswordVerificationError('identify_account', reason='invalid_response')
        page_type = (self._extract_page_type(login_step) or "").lower()
        continue_url = self._normalize_continue_url(
            self._extract_continue_url_from_step(login_step)
        )

        password_entry = (
            page_type == "login_password"
            or "/log-in/password" in (continue_url or "").lower()
        )
        email_otp_entry = (
            page_type == "email_otp_verification"
            or "/email-verification" in (continue_url or "").lower()
        )
        if email_otp_entry and not password_entry:
            password_page_url = (
                "https://auth.openai.com/log-in/password?"
                + urlencode({"email": normalized})
            )
            password_page = run_verification_step(
                'password_entry', self.session.get,
                password_page_url,
                headers=self._common_headers(
                    "https://auth.openai.com/log-in/password"
                ),
                timeout=30,
            )
            self._trace_http(
                "open_login_password_for_reset_verification", password_page
            )
            if getattr(password_page, "status_code", 0) >= 400:
                raise PasswordVerificationError(
                    'password_entry', http_status=password_page.status_code
                )
            password_entry = True

        if not password_entry:
            raise PasswordVerificationError('password_entry', reason='entry_unavailable')

        verified_step = run_verification_step('password_check', self.login_password_verify, candidate)
        if not isinstance(verified_step, dict):
            raise PasswordVerificationError('password_check', reason='invalid_response')
        self._password_verified_in_run = True
        return {"ok": True}

    # ── 传统 forgot-password 协议流程 ────────────────────────────────
    def _password_reset_cancelled(self, cancel_event=None) -> None:
        if cancel_event is not None and cancel_event.is_set():
            raise PasswordResetProtocolError("cancelled", "cancelled")

    @staticmethod
    def _password_reset_auth_url(value: str, *, allowed_paths: set[str], phase: str) -> str:
        """只接受 auth.openai.com 下的官方重置页面，拒绝 auth/error 等伪成功。"""
        raw = str(value or "").strip()
        try:
            parsed = urlparse(raw)
        except Exception:
            parsed = urlparse("")
        path = (parsed.path or "").rstrip("/")
        if parsed.scheme != "https" or parsed.netloc.lower() != "auth.openai.com" or path not in allowed_paths:
            raise PasswordResetProtocolError(phase, "invalid_reset_state")
        return raw

    def _password_reset_response_json(self, resp, phase: str) -> dict:
        status = int(getattr(resp, "status_code", 0) or 0)
        response_metadata = safe_auth_response_metadata(resp)
        self._password_reset_last_response_metadata = response_metadata
        self.record_registration_diagnostic("password_reset_http", phase=phase, **response_metadata)
        if status != 200:
            error = PasswordResetProtocolError(
                phase,
                "upstream_http_error",
                error_code=safe_response_error_code(resp),
                http_status=status,
            )
            for key in (
                "error_type", "error_code_source", "error_code_state", "upstream_error_present",
            ):
                if key in response_metadata:
                    setattr(error, key, response_metadata[key])
            raise error
        try:
            data = resp.json()
        except Exception as exc:
            raise PasswordResetProtocolError(phase, "invalid_json") from exc
        if not isinstance(data, dict):
            raise PasswordResetProtocolError(phase, "invalid_response")
        return data

    def send_password_reset_otp(self) -> bool:
        """按官方 reset-password 页面发送传统重置验证码。

        该接口是 POST /password/send-otp，依赖当前 auth session 中的 username，
        不使用 passwordless/send-otp，也不重放已提交的请求。
        """
        endpoint = "https://auth.openai.com/api/accounts/password/send-otp"
        headers = self._common_headers("https://auth.openai.com/reset-password")
        headers["Content-Type"] = "application/json"
        headers.update(self._access_flow_headers())
        resp = self.session.post(endpoint, headers=headers, timeout=30, allow_redirects=False)
        self._trace_http("password_reset_send_otp", resp)
        status = int(getattr(resp, "status_code", 0) or 0)
        response_url = str(getattr(resp, "url", "") or "")
        location = str((getattr(resp, "headers", {}) or {}).get("Location") or "")
        actual_path = urlparse(response_url).path.rstrip("/") if response_url else ""
        response_metadata = safe_auth_response_metadata(resp)
        self._password_reset_last_response_metadata = response_metadata
        if status != 200 or actual_path not in {"", "/api/accounts/password/send-otp"} or location:
            error_code = safe_response_error_code(resp)
            self.record_registration_diagnostic(
                "password_reset_otp_send",
                success=False,
                **response_metadata,
                location_present=bool(location),
            )
            error = PasswordResetProtocolError(
                "otp_send",
                "otp_delivery_rejected",
                error_code=error_code,
                http_status=status,
            )
            for key in (
                "error_type", "error_code_source", "error_code_state", "upstream_error_present",
            ):
                if key in response_metadata:
                    setattr(error, key, response_metadata[key])
            raise error
        self._otp_delivery_requested = True
        self._otp_challenge_established = True
        self.record_registration_diagnostic("password_reset_otp_send", success=True, http_status=status)
        return True

    def validate_password_reset_otp(self, otp_code: str) -> dict:
        """用官方 email_otp_validate Sentinel 校验本轮重置验证码。"""
        code = str(otp_code or "").strip()
        if not re.fullmatch(r"\d{6}", code):
            raise PasswordResetProtocolError("otp_validate", "invalid_otp_format")
        sentinel = self.get_sentinel_token(self.result.device_id, flow="email_otp_validate")
        headers = self._common_headers("https://auth.openai.com/email-verification")
        headers["Content-Type"] = "application/json"
        headers.update(self._access_flow_headers())
        if sentinel:
            headers["openai-sentinel-token"] = sentinel
        if getattr(self, "_last_sentinel_so_token", ""):
            headers["openai-sentinel-so-token"] = self._last_sentinel_so_token
        endpoint = "https://auth.openai.com/api/accounts/email-otp/validate"
        resp = self.session.post(endpoint, headers=headers, json={"code": code}, timeout=30, allow_redirects=False)
        self._trace_http("password_reset_validate_otp", resp)
        data = self._password_reset_response_json(resp, "otp_validate")
        page_type = self._extract_page_type(data)
        continue_url = self._normalize_continue_url(self._extract_continue_url_from_step(data))
        if page_type != "reset_password_new_password" and not continue_url:
            raise PasswordResetProtocolError("otp_validate", "missing_new_password_state")
        if continue_url:
            self._password_reset_auth_url(
                continue_url,
                allowed_paths={"/reset-password/new-password", "/reset-password/success"},
                phase="otp_validate",
            )
        self.record_registration_diagnostic(
            "password_reset_otp_validate",
            success=True,
            http_status=200,
            page_type=page_type,
            continue_path=urlparse(continue_url).path if continue_url else "",
        )
        return data

    def submit_password_reset(self, new_password: str) -> dict:
        """提交新密码并要求官方 reset-password/success 证据。"""
        password = str(new_password or "")
        if len(password) < 12:
            raise PasswordResetProtocolError("password_submit", "password_too_short")
        sentinel = self.get_sentinel_token(self.result.device_id, flow="password_reset")
        headers = self._common_headers("https://auth.openai.com/reset-password/new-password")
        headers["Content-Type"] = "application/json"
        headers.update(self._access_flow_headers())
        if sentinel:
            headers["openai-sentinel-token"] = sentinel
        if getattr(self, "_last_sentinel_so_token", ""):
            headers["openai-sentinel-so-token"] = self._last_sentinel_so_token
        endpoint = "https://auth.openai.com/api/accounts/password/reset"
        resp = self.session.post(
            endpoint,
            headers=headers,
            json={"password": password},
            timeout=30,
            allow_redirects=False,
        )
        self._trace_http("password_reset_submit", resp)
        data = self._password_reset_response_json(resp, "password_submit")
        page_type = self._extract_page_type(data)
        continue_url = self._normalize_continue_url(self._extract_continue_url_from_step(data))
        success = page_type == "reset_password_success"
        if continue_url:
            self._password_reset_auth_url(
                continue_url,
                allowed_paths={"/reset-password/success"},
                phase="password_submit",
            )
            success = True
        if not success:
            raise PasswordResetProtocolError("password_submit", "missing_reset_success")
        self.record_registration_diagnostic(
            "password_reset_submit",
            success=True,
            http_status=200,
            page_type=page_type,
            continue_path=urlparse(continue_url).path if continue_url else "",
        )
        return {"success": True, "page_type": page_type, "continue_url": continue_url}

    def run_protocol_password_reset(
        self,
        mail_provider: MailProvider,
        email: str,
        new_password: str,
        otp_timeout: int = 180,
        cancel_event=None,
        progress_callback=None,
    ) -> dict:
        """同一 auth session 完成传统官网密码重置，不走浏览器/Roxy。"""
        normalized = (email or "").strip().lower()
        if not normalized:
            raise PasswordResetProtocolError("starting", "missing_email")
        self._is_existing_account = True
        self.result.email = normalized
        self._password_reset_cancel_event = cancel_event
        # A POST can already have reached the provider when the transport
        # breaks. Do not replay OTP or password mutations on the same lease;
        # the outer worker may switch endpoint only before otp_send begins.
        if isinstance(self.session, _TlsRetrySession):
            self.session._disable_post_retries = True
        else:
            # requests fallback also retries POSTs in its HTTPAdapter by
            # default. This session belongs to one reset attempt only.
            import requests
            from urllib3.util.retry import Retry
            if isinstance(self.session, requests.Session):
                for adapter in self.session.adapters.values():
                    adapter.max_retries = Retry(total=0, redirect=0)

        def phase(name: str, message: str, *, check_cancel: bool = True) -> None:
            if check_cancel:
                self._password_reset_cancelled(cancel_event)
            self._password_reset_phase = name
            self._password_reset_last_response_metadata = {}
            if callable(progress_callback):
                progress_callback(name, message)

        phase("protocol_start", "正在建立协议认证会话")
        phase("proxy_check", "正在检查当前代理连通性")
        if not self.check_proxy():
            logger.warning("网络预检查未通过，继续尝试协议重置以获取精确错误...")
        phase("warmup", "正在建立初始认证状态")
        if not self.warmup():
            raise PasswordResetProtocolError("warmup", "proxy_warmup_failed")
        phase("csrf", "正在获取认证初始化状态")
        csrf = self.get_csrf_token()
        phase("auth_url", "正在获取授权地址")
        auth_url = self.get_auth_url(csrf, email=normalized)
        phase("oauth_init", "正在初始化授权会话")
        device_id = self.auth_oauth_init(auth_url)
        phase("sentinel", "正在准备授权请求")
        sentinel = self.get_sentinel_token(device_id, flow="authorize_continue")
        phase("identify_account", "正在识别已有账号")
        step = self.authorize_continue(
            email=normalized,
            sentinel_token=sentinel,
            screen_hint="login",
            referer="https://auth.openai.com/log-in",
            trace_step="authorize_continue_password_reset",
        )
        page_type = self._extract_page_type(step).lower()
        continue_url = self._normalize_continue_url(self._extract_continue_url_from_step(step))
        if page_type not in {"login_password", "email_otp_verification"} and "/log-in/" not in continue_url:
            raise PasswordResetProtocolError("identify_account", "invalid_login_state")
        # The official reset route establishes server-side reset state before
        # its form action POSTs /api/accounts/password/send-otp. Calling the
        # API immediately after authorize/continue can otherwise return 400
        # invalid_request despite a valid login state.
        phase("reset_page", "正在进入官网重置密码流程")
        reset_page = self.session.get(
            "https://auth.openai.com/reset-password",
            headers=self._navigation_headers(),
            timeout=30,
            allow_redirects=True,
        )
        self._trace_http("open_password_reset_page", reset_page)
        reset_status = int(getattr(reset_page, "status_code", 0) or 0)
        reset_url = str(getattr(reset_page, "url", "") or "")
        reset_path = urlparse(reset_url).path.rstrip("/") if reset_url else ""
        self.record_registration_diagnostic("password_reset_http", phase="reset_page", **safe_auth_response_metadata(reset_page))
        if reset_status >= 400:
            raise PasswordResetProtocolError(
                "reset_page",
                "upstream_http_error",
                error_code=safe_response_error_code(reset_page),
                http_status=reset_status,
            )
        if reset_path and reset_path != "/reset-password":
            raise PasswordResetProtocolError("reset_page", "invalid_reset_state")
        self.record_registration_diagnostic(
            "password_reset_page",
            success=True,
            http_status=reset_status,
            response_path=reset_path or "/reset-password",
        )
        phase("otp_send", "正在发送密码重置验证码")
        prepare = getattr(mail_provider, "prepare_for_otp", None)
        if callable(prepare):
            prepare()
        issued_after = time.time()
        self.send_password_reset_otp()
        phase("otp_wait", "正在等待邮箱验证码")
        wait_kwargs = {
            "timeout": max(int(otp_timeout), 1),
            "issued_after": issued_after,
            "strict_issued_after": True,
        }
        try:
            if "cancel_event" in inspect.signature(mail_provider.wait_for_otp).parameters:
                wait_kwargs["cancel_event"] = cancel_event
        except (TypeError, ValueError):
            pass
        otp = mail_provider.wait_for_otp(normalized, **wait_kwargs)
        self._password_reset_cancelled(cancel_event)
        phase("otp_validate", "正在校验邮箱验证码")
        self.validate_password_reset_otp(otp)
        phase("password_submit", "正在提交随机新密码")
        self.submit_password_reset(new_password)
        # Once the remote password POST returned the official success state,
        # do not let a late cancellation discard the local persistence step.
        phase("success", "官网已确认密码重置成功", check_cancel=False)
        return {"success": True, "password_set": True}


    # ── 纯协议已有账号登录流程（目标：拿 callback/session/refresh） ──
    def run_protocol_login(
        self,
        mail_provider: MailProvider,
        email: str,
        password: str = '',
        allow_registration_fallback: bool = True,
        require_password_registration: bool = False,
        allow_email_otp_after_password: bool = False,
        prefer_email_otp_without_password: bool = False,
    ) -> AuthResult:
        """
        纯协议登录（不创建随机邮箱）：
        - 适配 passwordless / login_password 两类已有账号入口
        - 可配合 OAUTH_EXCHANGE_BEFORE_CALLBACK / OAUTH_REFRESH_ONLY 尝试优先拿 refresh_token
        """
        if not (email or "").strip():
            raise RuntimeError("run_protocol_login 缺少邮箱")

        if not self.check_proxy():
            logger.warning("网络预检查未通过，继续尝试登录链路以获取精确错误...")
        # 同 run_register：没 oai-did 就走不通 authorize 链，早失败早换 IP。
        # 这里不花钱建邮箱，但报错说清原因，省得当成"密码错"排查。
        if not self.warmup():
            error = RuntimeError(
                "warmup 失败：4 次重试均未拿到 chatgpt.com 的 oai-did cookie，"
                "本轮登录已在初始化阶段停止，"
                "请检查代理后重试"
            )
            # 同 run_register：结构化溯源 + 自家安全文案，防脱敏层吞掉原因。
            error.failure_phase = "warmup"
            error.failure_cause = "proxy_warmup_failed"
            error.safe_message = (
                "warmup 失败：连续多次都没拿到 chatgpt.com 的 oai-did cookie，"
                "多为代理出口 IP 不通或被 Cloudflare 拦截，请检测代理连通性后重试"
            )
            raise error

        # run_protocol_login 的语义即"登录已有账号"（docstring 明写）。kickoff_otp_delivery
        # 依据 _is_existing_account 选 resend vs send_passwordless_otp 分支；落到 send
        # 分支会把 server-side state 弄坏 → 之后 IMAP 抓到的 OTP X 已失效 → verify 401
        # wrong_email_otp_code。这里入口统一 set True，覆盖 passwordless 这类 page_type
        # 不在 ("login_password","email_otp_verification") 集合的情况；signup() 回退
        # 路径会基于 OpenAI 真实响应再次覆盖（True/False），无副作用。
        self._is_existing_account = True
        self._password_registered_in_run = False
        self._password_verified_in_run = False
        self._otp_challenge_established = False
        self._otp_delivery_requested = False
        self._authorization_failure_reason = ""

        email = email.strip()
        self.result.email = email
        supplied_password = (password or "").strip()
        login_password = supplied_password or self._default_password_from_email(email)
        self.result.password = login_password

        csrf_token = self.get_csrf_token()
        auth_url = self.get_auth_url(csrf_token, email=email)
        device_id = self.auth_oauth_init(auth_url)
        sentinel = self.get_sentinel_token(device_id)

        continue_url = ""
        try:
            otp_timeout = max(10, int(self._get_env("OTP_TIMEOUT", "60")))
        except Exception:
            otp_timeout = 180

        page_type = ""
        mode = ""
        email_otp_required_by_login_entry = False
        profile_completed_after_password = False
        profile_identity_otp_sent_at = None
        passwordless_otp_sent_at = None
        prepare_for_otp = getattr(mail_provider, "prepare_for_otp", None)
        prefer_login_screen_first = str(
            os.getenv("LOCALAUTH_EXISTING_LOGIN_USE_LOGIN_HINT", "1")
        ).lower() in ("1", "true", "yes", "on")

        if prefer_login_screen_first:
            try:
                logger.info("已有账号协议登录：优先走 login screen_hint 探测 password/otp 分支")
                login_step = self.authorize_continue(
                    email=email,
                    sentinel_token=sentinel,
                    screen_hint="login",
                    referer="https://auth.openai.com/log-in",
                    trace_step="authorize_continue_login_protocol",
                )
                page_type = (self._extract_page_type(login_step) or "").lower()
                continue_url = self._normalize_continue_url(
                    self._extract_continue_url_from_step(login_step)
                )
                page = (login_step.get("page") or {}) if isinstance(login_step, dict) else {}
                payload = (page.get("payload") or {}) if isinstance(page, dict) else {}
                mode = (payload.get("email_verification_mode", "") or "").lower()
                self._existing_page_type = page_type
                self._existing_email_verification_mode = mode

                if page_type == "login_password" or "/log-in/password" in (continue_url or ""):
                    if prefer_email_otp_without_password:
                        logger.info("按恢复策略切换到一次性验证码登录")
                        if callable(prepare_for_otp):
                            prepare_for_otp()
                        passwordless_otp_sent_at = time.time()
                        if not self.send_passwordless_otp(
                            "https://auth.openai.com/log-in/password"
                        ):
                            raise RuntimeError("一次性验证码发码请求未被接受")
                        page_type = "email_otp_verification"
                        continue_url = "https://auth.openai.com/email-verification"
                        email_otp_required_by_login_entry = True
                        self._existing_page_type = page_type
                        self._existing_email_verification_mode = "passwordless_login"
                    else:
                        logger.info("登录分支: login_password -> password/verify")
                    # 命中已有账号 password 路径：标记之，让 kickoff_otp_delivery 走 resend
                    # 分支（避免 send_passwordless_otp 把 state 弄坏 → wrong_email_otp_code）
                        self._is_existing_account = True
                        login_resp = self.login_password_verify(login_password)
                        self._password_verified_in_run = True
                        page_type = (self._extract_page_type(login_resp) or "").lower()
                        continue_url = self._normalize_continue_url(
                            self._extract_continue_url_from_step(login_resp)
                        )

                    # mfa-challenge 分支（密码验证后需要 TOTP 2FA）
                    if self._is_mfa_challenge_state(page_type, continue_url):
                        totp_secret = (self.result.totp_secret or "").strip()
                        if not totp_secret and self._account_callback:
                            # 从数据库加载凭证
                            try:
                                cred = self._account_callback(email)
                                if cred and cred.get("totp_secret"):
                                    totp_secret = cred["totp_secret"]
                                    self.result.totp_secret = totp_secret
                                    logger.info("已从数据库加载 totp_secret")
                            except Exception as e:
                                logger.warning(safe_public_error(e, "account callback"))
                        if not totp_secret:
                            logger.warning("进入 mfa-challenge 但没有 totp_secret，无法继续")
                        else:
                            challenge_id = continue_url.split("/")[-1] if "/mfa-challenge/" in continue_url else ""
                            if challenge_id:
                                totp_code = _totp_now(totp_secret)
                                logger.info(f"提交 TOTP 码进行 2FA 验证（challenge_id={challenge_id[:16]}...）")
                                mfa_resp = self.submit_mfa_totp(totp_code, challenge_id)
                                page_type = (self._extract_page_type(mfa_resp) or "").lower()
                                continue_url = self._normalize_continue_url(
                                    self._extract_continue_url_from_step(mfa_resp)
                                )
                            else:
                                logger.warning("无法从 continue_url 提取 challenge_id")

                elif page_type == "email_otp_verification" or "/email-verification" in (continue_url or ""):
                    # 只要调用方明确允许“邮箱验证码入口 -> 密码页”切换，
                    # 就应先尝试密码验证；不能把它错误地限制在
                    # allow_registration_fallback=False 的分支里。
                    # 重新授权场景通常同时开启 registration fallback，
                    # 旧条件因此会直接跳到 signup 探测并误报“未进入可设置密码阶段”。
                    if prefer_email_otp_without_password:
                        logger.info("按恢复策略保留已有账号邮箱验证码入口")
                        email_otp_required_by_login_entry = True
                        self._is_existing_account = True
                    elif allow_email_otp_after_password:
                        logger.info(
                            "登录入口默认显示邮箱验证码，主动切换到密码页并先验证密码"
                        )
                        password_page_url = (
                            "https://auth.openai.com/log-in/password?"
                            + urlencode({"email": email})
                        )
                        password_page = self.session.get(
                            password_page_url,
                            headers=self._common_headers(
                                "https://auth.openai.com/log-in/password"
                            ),
                            timeout=30,
                        )
                        self._trace_http("open_login_password_from_email_otp", password_page)
                        login_resp = self.login_password_verify(login_password)
                        self._password_verified_in_run = True
                        page_type = (self._extract_page_type(login_resp) or "").lower()
                        continue_url = self._normalize_continue_url(
                            self._extract_continue_url_from_step(login_resp)
                        )
                        logger.info(
                            "密码验证通过，继续处理服务端返回的下一步骤"
                        )
                        logger.info(
                            "密码验证响应状态: page_type=%s continue_url=%s",
                            page_type or "(empty)",
                            safe_url(continue_url) or "(empty)",
                        )
                    elif not allow_registration_fallback:
                        raise RuntimeError(
                            "严格密码登录模式拒绝邮箱验证码登录：本次未完成密码验证"
                        )
                    password_about_you = (
                        "/about-you" in (continue_url or "").lower()
                        or page_type in ("create_account", "about_you", "about-you")
                    )
                    password_callback_ready = (
                        page_type in ("external_url", "callback")
                        or "/api/auth/callback/" in (continue_url or "").lower()
                        or "/auth/callback" in (continue_url or "").lower()
                    )
                    if password_about_you:
                        logger.info("密码验证后进入 about-you，直接完成姓名/出生日期资料")
                        if callable(prepare_for_otp):
                            prepare_for_otp()
                        profile_identity_otp_sent_at = time.time()
                        continue_url = self._normalize_continue_url(self.create_account())
                        profile_completed_after_password = True
                        page_type = ""
                        self._existing_page_type = ""
                    elif password_callback_ready:
                        logger.info("密码验证已返回 callback，跳过邮箱 OTP 并继续获取 Session")
                        email_otp_required_by_login_entry = False
                        self._existing_page_type = ""
                        self._existing_email_verification_mode = ""
                    elif require_password_registration and not self._password_verified_in_run:
                        logger.info(
                            "登录入口只给邮箱验证码，当前要求注册阶段设置密码，改走 signup 探测"
                        )
                        continue_url = ""
                        page_type = ""
                        mode = ""
                    else:
                        logger.info("登录分支: email_otp_verification")
                        # 仅当密码验证后仍未进入 about-you 且服务端仍需 OTP 时保留该状态。
                        email_otp_required_by_login_entry = True
                        self._is_existing_account = True
                else:
                    logger.info(
                        "login screen_hint 未直接命中已有账号完成态: page_type=%s continue_url=%s",
                        page_type or "(empty)",
                        safe_url(continue_url) or "(empty)",
                    )
            except AuthorizeRateLimitError:
                # 当前出口 IP 已被限流；切到 signup 只会立刻重复撞同一接口。
                raise
            except Exception as e:
                if not allow_registration_fallback:
                    raise
                logger.warning(safe_public_error(e, "login screen hint probe"))
                continue_url = ""
                page_type = ""
                mode = ""

        if not continue_url and page_type not in ("login_password", "email_otp_verification"):
            is_new = self.signup(email, sentinel)
            page_type = (self._existing_page_type or "").lower()
            mode = (self._existing_email_verification_mode or "").lower()
            if is_new or mode == "passwordless_signup":
                if not allow_registration_fallback:
                    raise RuntimeError('\u4e25\u683c\u767b\u5f55\u6a21\u5f0f\u62d2\u7edd\u6ce8\u518c\u65b0\u8d26\u53f7')
                logger.warning("目标邮箱仍在注册阶段，先设置密码再验证邮箱")
                if not self.register_password(email):
                    raise RuntimeError("注册阶段设置密码失败，拒绝继续邮箱验证码流程")
                otp_sent_at = time.time()
                self.send_otp()
                otp_code = self._wait_for_otp_with_one_resend(
                    mail_provider,
                    email,
                    timeout=otp_timeout,
                    issued_after=otp_sent_at,
                    strict_issued_after=True,
                )
                self.verify_otp(otp_code)
                continue_url = self.create_account()
                profile_completed_after_password = True
                page_type = ""
                mode = ""
                self._existing_page_type = ""
                self._existing_email_verification_mode = ""
            else:
                if require_password_registration:
                    raise RuntimeError(
                        "账号未进入可设置密码的注册阶段，拒绝邮箱验证码登录"
                    )
        else:
            page_type = "" if profile_completed_after_password else (page_type or self._existing_page_type or "").lower()
            mode = "" if profile_completed_after_password else (mode or self._existing_email_verification_mode or "").lower()

        logger.info(
            "OTP 决策: entry_required=%s page_type=%s continue_url=%s",
            email_otp_required_by_login_entry,
            page_type or "(empty)",
            safe_url(continue_url) or "(empty)",
        )

        verify_identity_required = "/verify-your-identity" in (continue_url or "").lower()

        if (
            ((not profile_completed_after_password) or verify_identity_required)
            and (
                email_otp_required_by_login_entry
                or not continue_url
                or page_type == "email_otp_verification"
                or "/email-verification" in continue_url
                or verify_identity_required
            )
        ):
            # 仍需 OTP：优先 resend 获取新码
            if verify_identity_required and profile_identity_otp_sent_at is not None:
                logger.info("资料提交后进入身份邮箱验证，先打开身份页再等待验证码")
                # The provider returned a browser continuation.  Navigating to it is
                # the state transition that creates the identity challenge; waiting
                # for mail without opening the page leaves no challenge-specific code.
                otp_sent_at = time.time()
                identity_page = self.session.get(
                    continue_url,
                    headers=self._common_headers("https://auth.openai.com/about-you"),
                    timeout=30,
                    allow_redirects=False,
                )
                self._trace_http("open_verify_identity", identity_page)
                if int(getattr(identity_page, "status_code", 200) or 200) >= 400:
                    raise RuntimeError(
                        "打开身份邮箱验证页失败: "
                        f"HTTP {getattr(identity_page, 'status_code', 0)}"
                    )
                # The mailbox was snapshotted before create_account. Do not read it
                # again here: the single-code relay consumes the current code on read.
                # The relay receives this cutoff too, so an older challenge cannot be
                # marked as served before client-side validation.
                strict_otp_window = True
            else:
                if passwordless_otp_sent_at is not None:
                    otp_sent_at = passwordless_otp_sent_at
                    logger.info("一次性验证码已请求，直接等待本轮邮件")
                else:
                    if callable(prepare_for_otp):
                        prepare_for_otp()
                    otp_sent_at = time.time()
                    resend_ok = self.kickoff_otp_delivery("protocol_need_otp")
                    if not resend_ok and mode not in ("passwordless_signup", "passwordless_login"):
                        self.send_otp()
                        otp_sent_at = time.time()
                strict_otp_window = True

            otp_code = self._wait_for_otp_with_one_resend(
                mail_provider,
                email,
                timeout=otp_timeout,
                issued_after=otp_sent_at,
                strict_issued_after=strict_otp_window,
            )
            try:
                otp_resp = self.verify_otp(otp_code)
                self.fetch_client_auth_session_dump("post_verify_otp_protocol")
            except RuntimeError as e:
                if any(code in str(e) for code in ("401", "409")):
                    logger.warning(safe_public_error(e, "first OTP verification"))
                    if callable(prepare_for_otp):
                        prepare_for_otp()
                    otp_sent_at = time.time()
                    if not self.kickoff_otp_delivery("protocol_verify_retry"):
                        self.send_otp()
                    otp_code = self._wait_for_otp_with_one_resend(
                        mail_provider,
                        email,
                        timeout=otp_timeout,
                        issued_after=otp_sent_at,
                        strict_issued_after=True,
                    )
                    otp_resp = self.verify_otp(otp_code)
                    self.fetch_client_auth_session_dump("post_verify_otp_retry_protocol")
                else:
                    raise
            otp_page_type = (self._extract_page_type(otp_resp) or "").strip().lower()
            continue_url = self._extract_continue_url_from_step(otp_resp)
            continue_url = self._normalize_continue_url(continue_url)

            # A password can already exist while the profile is still unfinished.
            # After password + email OTP, OpenAI then returns the about-you/create_account
            # step. Complete that step before attempting OAuth/session recovery.
            if (
                "/about-you" in (continue_url or "").lower()
                or otp_page_type in ("create_account", "about_you", "about-you")
            ):
                logger.info("密码和邮箱验证码均已通过，继续完成姓名/出生日期资料")
                continue_url = self._normalize_continue_url(self.create_account())
                otp_page_type = ""

            if self._is_add_phone_state(page_type=otp_page_type, continue_url=continue_url):
                continue_url = self._normalize_continue_url(
                    self._handle_add_phone_verification(continue_url=continue_url)
                )

        continue_url = self._normalize_continue_url(continue_url)
        # 某些边缘态 OTP 后未返回 callback，回退 reauthorize
        if not continue_url:
            continue_url = self._reauthorize_for_session(auth_url) or ""

        refresh_only_mode = self._env_flag("OAUTH_REFRESH_ONLY", "0")
        callback_url = ""
        if continue_url:
            continue_url = self._normalize_continue_url(continue_url)
            if (not self.result.refresh_token) and self._env_flag("OAUTH_CODEX_RT_BEFORE_CALLBACK", "1"):
                self.oauth_codex_rt_exchange(mail_provider=mail_provider)
            pre_exchange_default = "1" if refresh_only_mode else "0"
            pre_exchange = self._env_flag("OAUTH_EXCHANGE_BEFORE_CALLBACK", pre_exchange_default)
            if pre_exchange:
                self.oauth_token_exchange(continue_url, continue_url)
            callback_url, final_url = self.follow_redirect_chain(continue_url)
            if (not callback_url) and final_url and ("/workspace" in final_url):
                normalized = self._normalize_continue_url(final_url)
                if normalized and normalized != final_url:
                    callback_url, final_url = self.follow_redirect_chain(normalized)

        if (not refresh_only_mode) and callback_url:
            logger.debug("Consuming callback before reading the NextAuth session")
            self._consume_callback_for_session(callback_url)

        if not refresh_only_mode:
            self.get_auth_session()

        if callback_url or continue_url:
            self.fetch_client_auth_session_dump("pre_oauth_exchange_protocol")
            if self._env_flag("OAUTH_TOKEN_EXCHANGE_FROM_CALLBACK", "0") \
                    and not self._env_flag("SKIP_OAUTH_TOKEN_EXCHANGE", "0"):
                self.oauth_token_exchange(callback_url or "", continue_url or "")
            if (not self.result.refresh_token) and self._env_flag("OAUTH_CODEX_RT_EXCHANGE", "1"):
                self.oauth_codex_rt_exchange(mail_provider=mail_provider)
            if (not self.result.refresh_token) and self._env_flag("OAUTH_SECONDARY_AUTHORIZE_EXCHANGE", "0"):
                self.oauth_secondary_authorize_exchange()
            if not refresh_only_mode:
                self.get_auth_session()

        if refresh_only_mode:
            if not (self.result.refresh_token or self.result.access_token):
                failure_reason = getattr(self, "_authorization_failure_reason", "").strip()
                if failure_reason:
                    raise RuntimeError(
                        f"{failure_reason}，因此未拿到 refresh_token/access_token"
                    )
                raise RuntimeError("协议登录完成，但未拿到 refresh_token/access_token")
        elif not self.result.is_valid():
            failure_reason = getattr(self, "_authorization_failure_reason", "").strip()
            if failure_reason:
                raise RuntimeError(
                    f"{failure_reason}，因此未拿到有效 session/access token"
                )
            raise RuntimeError("协议登录完成，但未拿到有效 session/access token")

        logger.info("纯协议登录流程完成")
        return self.result

    # ── 从已有凭证初始化 ──
    def from_existing_credentials(
        self, session_token: str, access_token: str, device_id: str
    ) -> AuthResult:
        """使用已有凭证（跳过注册）"""
        self.result.device_id = device_id or str(uuid.uuid4())
        self.session.cookies.set("oai-did", self.result.device_id, domain=".chatgpt.com")
        detected_email = ""

        # 如果有 session_token, 用它刷新 access_token (旧 access_token 可能已过期)
        if session_token:
            self.session.cookies.set(
                "__Secure-next-auth.session-token",
                session_token,
                domain=".chatgpt.com",
            )
            logger.info("使用 session_token 刷新 access_token...")
            try:
                headers = self._common_headers("https://chatgpt.com/")
                resp = self.session.get(
                    "https://chatgpt.com/api/auth/session",
                    headers=headers,
                    timeout=30,
                )
                session_data = resp.json() if resp is not None else {}
                new_access_token = session_data.get("accessToken", "")
                user_obj = session_data.get("user", {}) if isinstance(session_data, dict) else {}
                if isinstance(user_obj, dict):
                    detected_email = detected_email or (user_obj.get("email", "") or "")
                new_session_token = self.session.cookies.get("__Secure-next-auth.session-token", "")
                if new_access_token:
                    access_token = new_access_token
                    logger.info("access_token 刷新成功")
                else:
                    logger.warning(f"access_token 刷新失败 (status={resp.status_code}), 使用原 token")
                if new_session_token:
                    session_token = new_session_token
            except Exception as e:
                logger.warning(safe_public_error(e, "access token refresh"))
        elif access_token:
            # 没有 session_token, 尝试通过 access_token 获取
            logger.info("未提供 session_token, 尝试通过 access_token 获取...")
            try:
                headers = self._common_headers("https://chatgpt.com/")
                headers["Authorization"] = f"Bearer {access_token}"
                resp = self.session.get(
                    "https://chatgpt.com/api/auth/session",
                    headers=headers,
                    timeout=30,
                )
                session_data = resp.json() if resp is not None else {}
                user_obj = session_data.get("user", {}) if isinstance(session_data, dict) else {}
                if isinstance(user_obj, dict):
                    detected_email = detected_email or (user_obj.get("email", "") or "")
                session_token = self.session.cookies.get("__Secure-next-auth.session-token", "")
                if session_token:
                    logger.info("通过 access_token 获取 session_token 成功")
                else:
                    logger.warning("未能获取 session_token, 可能需要手动提供")
            except Exception as e:
                logger.warning(safe_public_error(e, "session token retrieval"))

        self.result.access_token = access_token
        self.result.session_token = session_token
        if session_token:
            self.session.cookies.set(
                "__Secure-next-auth.session-token",
                session_token,
                domain=".chatgpt.com",
            )
        self.result.cookie_header = self._build_chatgpt_cookie_header()

        # 回填 email（skip-register 模式下常用于账单 email）
        if not detected_email and access_token and access_token.count(".") >= 2:
            try:
                payload_b64 = access_token.split(".")[1]
                payload_b64 += "=" * (-len(payload_b64) % 4)
                payload = json.loads(base64.urlsafe_b64decode(payload_b64.encode("utf-8")).decode("utf-8"))
                prof = payload.get("https://api.openai.com/profile", {}) if isinstance(payload, dict) else {}
                if isinstance(prof, dict):
                    detected_email = detected_email or (prof.get("email", "") or "")
            except Exception:
                pass
        self.result.email = detected_email or ""
        logger.info("使用已有凭证初始化完成")
        return self.result
