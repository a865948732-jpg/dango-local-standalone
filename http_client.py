"""
HTTP 客户端 - 使用 curl_cffi 实现 TLS 指纹模拟
支持 Cloudflare 绕过，降级到 requests
"""
import logging
import json
import random
import re
import time
from typing import Optional

logger = logging.getLogger(__name__)

# 尝试使用 curl_cffi（推荐，自带 TLS 指纹模拟）
try:
    from curl_cffi.requests import Session as CffiSession

    _HAS_CFFI = True
    logger.debug("curl_cffi 可用，使用 TLS 指纹模拟")
except ImportError:
    _HAS_CFFI = False
    logger.debug("curl_cffi 不可用，降级到 requests")

import requests
from safe_diagnostics import safe_url, safe_http_transport_metadata
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# 通用 UA（fallback，优先使用 fingerprint.generate_fingerprint() 生成的值）
USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15"
)

# TLS 握手瞬断的识别标记（与 AuthFlow._is_tls_error 保持同一套口径）
_TLS_ERROR_MARKERS = ("curl: (35)", "tls connect error", "openssl_internal", "sslerror")

# 代理瞬断：住宅代理/中转链路对「连接代理本身」的秒级抖动（2026-09-26
# as.proxy001.com:7878 实测：几分钟内 warmup 通、提交邮箱又 ProxyError）。
# curl_cffi 与 requests 对这类失败抛的异常类名都叫 ProxyError。此时请求还没
# 离开本机（连代理都没连上），服务端不可能收到，原 session 重试与 TLS 瞬断
# 同级别安全，不会造成重复提交。
_PROXY_ERROR_KIND_MARKERS = ("proxyerror",)


def _is_tls_handshake_error(exc: Exception) -> bool:
    msg = str(exc).lower()
    return any(m in msg for m in _TLS_ERROR_MARKERS)


def _is_transient_link_error(exc: Exception) -> bool:
    """链路级瞬断：TLS 握手被掐断，或代理连接本身失败。

    共同点：请求根本没有送达上游（连代理都没出去），所以原 session 重试
    不会造成服务端重复处理；实测这两类瞬断原 session 重试一次即恢复。
    """
    if _is_tls_handshake_error(exc):
        return True
    kind = type(exc).__name__.lower()
    return any(m in kind for m in _PROXY_ERROR_KIND_MARKERS)


# 链路/网络类异常的宽口径判定：供 sentinel 等调用方区分「网络问题（带真因
# 上抛、判 network）」与「PoW/JS 计算问题」。比 _is_transient_link_error 宽：
# 额外覆盖 curl (56) 连接被对端关闭、curl (28)/(7) 等连接层失败——这些**不
# 适合在 http_client 层无差别重试**（POST 响应中途断开时重试有重复提交风险），
# 但应当作为网络错误向上传递，而不是被 catch-all 吞成「token 缺失」。
_NETWORK_LINK_MARKERS = _TLS_ERROR_MARKERS + (
    "curl: (56)", "curl: (28)", "curl: (7)",
    "connection closed", "connection reset", "connection aborted",
    "remote disconnected",
)


def _is_network_link_error(exc: Exception) -> bool:
    """宽口径网络链路异常（用于分类/上抛判定，不用于自动重试）。"""
    if _is_transient_link_error(exc):
        return True
    msg = str(exc).lower()
    return any(m in msg for m in _NETWORK_LINK_MARKERS)


class _TlsRetrySession:
    """给 session 的 get/post 套一层 TLS 瞬断重试，其余属性原样透传。

    ── 为什么要有这东西 ──
    代理链路会偶发 `curl: (35) TLS connect error ... OPENSSL_internal`，
    连 HTTP 请求都没发出去就炸。2026-08-10 实测（148 轮扫描）：

        发生率            5.4%（8/148）
        与指纹的关系      无 —— chrome146/142/136、safari18_0/15_3、firefox133 都中过
        与域名的关系      无 —— chatgpt.com 3/25、auth.openai.com 1/25，
                          且见过同一轮两个域一起炸（那一路出口链路整个坏了）

    换句话说这是**链路级瞬断**，不是风控、不是指纹问题，摘掉任何一个指纹都没用。

    ── 为什么必须原 session 重试，不能重建 ──
    warmup 那处的重试是重建 session（换出口 IP），因为那时还没 cookie。
    但链路中后段（auth_oauth_init / sentinel / authorize_continue …）session 里
    已经装着 warmup 种的 oai-did 和 csrf，**一重建就全丢，直接变 409 invalid_state**
    —— 那正是上一轮刚修好的病。所以这里只重试，绝不碰 session。

    实测原 session 重试的效果（8 次 TLS35 事件全部捕获后立即重试）：

        恢复 8/8，全部**第 1 次重试就成功**，恢复后 oai-did 仍在 8/8

    ── 为什么包在 session 层，而不是逐个调用点加 try ──
    这个错能打在链上**任意一步**。主人 2026-08-10 那批 10 个号的两次失败就分别
    炸在 `[3/10] auth_oauth_init` 和 `[4/10] sentinel`（后者还被 sentinel_quickjs
    的 catch-all 吞成 "QuickJS 失败/主 token 缺失"，真因全被掩盖）。auth_flow 里
    有 35 处 session.get/post，且 sentinel.py 是直接拿 session 对象自己发请求的，
    逐点打补丁既治不完也漏得到 —— 包在出口这一层才是一次覆盖全部。

    ── 透传安全性（已实测）──
    全项目在 session 上访问的非 get/post 属性只有 cookies(20处) / trust_env(3) /
    proxies(3) / mount(2) / headers(1)，实测包装后全部行为一致：
    cookies.get_dict() / cookies.get() / cookies.jar / 迭代 / __setattr__ 透传均 OK。
    （注：迭代 session.cookies 产出的是 str 而非 Cookie 对象、拿不到 .name，
    这是 curl_cffi **原生行为**，包装前后一致，与本类无关。）
    """

    def __init__(self, inner, retries: int = 3, backoff: float = 1.5):
        object.__setattr__(self, "_inner", inner)
        object.__setattr__(self, "_retries", max(0, int(retries)))
        object.__setattr__(self, "_backoff", float(backoff))
        object.__setattr__(self, "_disable_post_retries", False)

    # 除 get/post 外的一切读写都直达真 session
    def __getattr__(self, name):
        return getattr(object.__getattribute__(self, "_inner"), name)

    def __setattr__(self, name, value):
        if name == "_disable_post_retries":
            object.__setattr__(self, name, bool(value))
            return
        setattr(object.__getattribute__(self, "_inner"), name, value)

    def __iter__(self):
        return iter(object.__getattribute__(self, "_inner"))

    def _call_with_retry(self, method: str, *args, **kwargs):
        import time

        inner = object.__getattribute__(self, "_inner")
        retries = object.__getattribute__(self, "_retries")
        backoff = object.__getattribute__(self, "_backoff")
        fn = getattr(inner, method)
        if method == "post" and object.__getattribute__(self, "_disable_post_retries"):
            return fn(*args, **kwargs)

        for attempt in range(retries + 1):
            try:
                return fn(*args, **kwargs)
            except Exception as e:
                # 只兜链路瞬断（TLS 被掐 / 连代理失败）：HTTP 错误码、超时、
                # 业务异常一律原样抛，免得把"服务端明确拒绝"也变成重试，
                # 反而更像异常流量。
                if not _is_transient_link_error(e) or attempt >= retries:
                    raise
                wait = backoff * (attempt + 1)
                url = args[0] if args else kwargs.get("url", "?")
                reason = "TLS 瞬断" if _is_tls_handshake_error(e) else "代理瞬断"
                logger.warning(
                    "%s，%.1fs 后原 session 重试 (%d/%d): %s",
                    reason, wait, attempt + 1, retries, safe_url(url),
                )
                time.sleep(wait)

    def get(self, *args, **kwargs):
        return self._call_with_retry("get", *args, **kwargs)

    def get_authorization_init(self, url, *, cancel_event=None, diagnostic_callback=None, **kwargs):
        """密码重置授权 GET：同一会话最多 3 次调用，含退避共用 60 秒预算。

        直接调用底层 GET，避免与旧 TLS 重试叠加；HTTP 响应原样交给业务层。
        此接口不用于发码或密码提交，不更换代理、cookie 或 TLS 配置。
        """
        inner = object.__getattribute__(self, "_inner")
        backoff = max(0.0, object.__getattribute__(self, "_backoff"))
        started = time.monotonic()
        deadline = started + 60.0

        def check_cancel():
            if cancel_event is not None and cancel_event.is_set():
                error = RuntimeError("password reset cancelled")
                error.failure_phase = "cancelled"
                error.failure_cause = "cancelled"
                raise error

        def record(fields):
            logger.info("%s", json.dumps(dict(event="password_reset_transport", v=1, **fields), sort_keys=True))
            if callable(diagnostic_callback):
                diagnostic_callback("password_reset_transport", **fields)

        for attempt in range(1, 4):
            check_cancel()
            request_kwargs = dict(kwargs)
            request_kwargs["timeout"] = min(float(kwargs.get("timeout", 30)), deadline - time.monotonic())
            try:
                response = inner.get(url, **request_kwargs)
            except Exception as error:
                facts = safe_http_transport_metadata(error)
                elapsed_ms = min(180000, max(0, int((time.monotonic() - started) * 1000)))
                error.failure_phase = "oauth_init"
                error.transport_attempts = attempt
                error.transport_elapsed_ms = elapsed_ms
                retryable = facts.get("transport_code") in {5, 6, 7, 16, 18, 28, 35, 52, 55, 56, 92} or (
                    "transport_code" not in facts and facts.get("transport_reason") in {"connection_error", "proxy_error"}
                )
                wait = backoff * attempt
                retry = retryable and attempt < 3 and time.monotonic() + wait < deadline
                record(dict(facts, phase="oauth_init", success=False, retry_scheduled=retry,
                            transport_attempts=attempt, transport_elapsed_ms=elapsed_ms))
                check_cancel()
                if not retry:
                    raise
                if cancel_event is not None:
                    cancel_event.wait(wait)
                else:
                    time.sleep(wait)
                check_cancel()
                if time.monotonic() >= deadline:
                    raise
            else:
                fields = dict(phase="oauth_init", success=True, retry_scheduled=False,
                              transport_attempts=attempt,
                              transport_elapsed_ms=min(180000, max(0, int((time.monotonic() - started) * 1000))))
                status = getattr(response, "status_code", None)
                if type(status) is int and 100 <= status <= 599:
                    fields["http_status"] = status
                record(fields)
                check_cancel()
                return response

    def post(self, *args, **kwargs):
        return self._call_with_retry("post", *args, **kwargs)

    def put(self, *args, **kwargs):
        return self._call_with_retry("put", *args, **kwargs)


def rotate_proxy_session_id(proxy: Optional[str]) -> Optional[str]:
    """轮换住宅代理的会话 ID：把代理串用户名里的 ``ssid_<数字>`` 换成新随机数。

    为什么需要：warmup 撞 403 时会重建 session 换出口，但「固定会话」型住宅
    代理（用户名带 ssid_XXX，如 as.proxy001.com）新 session 拿到的仍是**同一
    个出口 IP** —— IP 已被目标站 Cloudflare 拉黑时，换多少次指纹都没用
    （2026-09-26 实测：原 ssid 连续 403/连接失败，换 ssid 立刻 200 过 CF）。
    轮换 ssid 即换出口 IP。不含 ssid_ 模式的代理原样返回，完全不受影响。
    """
    if not proxy:
        return proxy
    return re.sub(
        r"(ssid_)(\d+)",
        lambda m: f"{m.group(1)}{random.randint(10_000_000, 99_999_999)}",
        proxy,
        count=1,
    )


def create_http_session(
    proxy: Optional[str] = None,
    impersonate: str = "safari18_0",
    user_agent: Optional[str] = None,
):
    """
    创建 HTTP 会话。优先使用 curl_cffi 模拟浏览器 TLS 指纹，
    不可用时降级到 requests。
    """
    if _HAS_CFFI:
        session = CffiSession(impersonate=impersonate)
        # 使用显式配置，避免被系统 HTTP(S)_PROXY 隐式污染。
        session.trust_env = False
        if proxy:
            # curl_cffi 在 SOCKS 代理下建议使用 socks5h，让 DNS 走代理端解析。
            # 这能减少本地 DNS/链路导致的 TLS 握手异常。
            normalized_proxy = proxy
            if proxy.startswith("socks5://"):
                normalized_proxy = "socks5h://" + proxy[len("socks5://"):]
                logger.info("代理协议已标准化: socks5:// -> socks5h://")
            session.proxies = {"https": normalized_proxy, "http": normalized_proxy}
        else:
            # 显式设置空代理，覆盖系统环境变量 (trust_env=False 对 libcurl 不够)
            session.proxies = {"https": "", "http": ""}
        # 代理链路 5.4% 偶发 TLS 瞬断，原 session 重试实测 8/8 一次即恢复。
        # 包在这里才能同时覆盖 auth_flow 的 35 处调用和 sentinel（它直接拿 session 自己发请求）。
        return _TlsRetrySession(session)
    else:
        session = requests.Session()
        session.trust_env = False
        retry = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "POST"],
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        if proxy:
            session.proxies = {"https": proxy, "http": proxy}
        session.headers["User-Agent"] = user_agent or USER_AGENT
        return session
