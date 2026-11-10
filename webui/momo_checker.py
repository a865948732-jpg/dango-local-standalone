"""MoMo payment-method and zero-price trial eligibility checker.

The checker intentionally stops before creating a Stripe PaymentMethod or
confirming a payment.  It only creates the checkout context, applies the
trial promotion, and verifies the final payment methods and amount.
"""
from __future__ import annotations

import os
import random
import re
import sys
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit


APP_ROOT = Path(__file__).resolve().parent
DEFAULT_SOURCE_ROOT = APP_ROOT.parent
MAX_PROXY_LENGTH = 1024
MAX_TOKEN_LENGTH = 20_000
MAX_PROXY_POOL_SIZE = 200


class MomoCheckInputError(ValueError):
    """Raised for malformed local API input."""


class ProxyPoolSelector:
    """Select a proxy from an in-memory pool without persisting credentials."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._cursors: dict[tuple[str, tuple[str, ...]], int] = {}

    def select(self, name: str, pool: list[str], strategy: str) -> str:
        if not pool:
            return ""
        if strategy == "random":
            return random.choice(pool)
        key = (name, tuple(pool))
        with self._lock:
            cursor = self._cursors.get(key, 0)
            self._cursors[key] = (cursor + 1) % len(pool)
        return pool[cursor % len(pool)]


PROXY_POOL_SELECTOR = ProxyPoolSelector()


def _source_root() -> Path:
    configured = str(os.environ.get("MOMO_CHECKOUT_SOURCE_ROOT") or "").strip()
    return Path(configured).expanduser().resolve() if configured else DEFAULT_SOURCE_ROOT


def _ensure_source_import_path() -> Path:
    root = _source_root()
    if not (root / "standalone_core" / "momo_extract.py").is_file():
        raise RuntimeError(
            "MOMO_SOURCE_NOT_FOUND: 未找到现有 MoMo 检测核心；"
            "请设置 MOMO_CHECKOUT_SOURCE_ROOT 指向包含 standalone_core 的项目目录。"
        )
    root_text = str(root)
    if root_text not in sys.path:
        sys.path.insert(0, root_text)
    return root


def _momo_extract_module() -> Any:
    """Import the optional checkout adapter only when a check actually runs."""

    _ensure_source_import_path()
    from standalone_core import momo_extract

    return momo_extract


def load_momo_core() -> Any:
    module = _momo_extract_module()
    loader = getattr(module, "_load_core", None)
    if not callable(loader):
        raise RuntimeError("MOMO_CORE_LOADER_MISSING: MoMo 检测核心缺少加载入口")
    return loader()


def resolve_momo_fingerprint(*args: Any, **kwargs: Any) -> dict[str, Any]:
    module = _momo_extract_module()
    resolver = getattr(module, "resolve_momo_fingerprint", None)
    if not callable(resolver):
        raise RuntimeError("MOMO_FINGERPRINT_RESOLVER_MISSING: MoMo 检测核心缺少指纹入口")
    return resolver(*args, **kwargs)


ProgressCallback = Callable[[str, str], None]


def _text(value: Any) -> str:
    return str(value or "").strip()


def _safe_text(value: Any, limit: int = 220) -> str:
    return re.sub(r"\s+", " ", _text(value))[:limit]


def _mask_proxy(value: str) -> str:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return "已配置代理"
    host = parsed.hostname or ""
    if not host:
        return "已配置代理"
    if parsed.port:
        host = f"{host}:{parsed.port}"
    return f"{parsed.scheme}://***@{host}" if (parsed.username or parsed.password) else f"{parsed.scheme}://{host}"


def _normalize_methods(payload: Any, core: Any) -> list[str]:
    collector = getattr(core, "opll_collect_payment_method_types", None)
    raw_methods = collector(payload) if callable(collector) else []
    methods: list[str] = []
    for value in raw_methods if isinstance(raw_methods, list) else []:
        method = _text(value).lower()
        if method and method not in methods:
            methods.append(method)
    return methods[:20]


def _explicit_zero(value: Any, source: Any) -> bool:
    source_text = _text(source).lower()
    if source_text in {"", "fallback_zero", "missing_payload"}:
        return False
    text = _text(value)
    if not text:
        return False
    try:
        return float(text) == 0.0
    except (TypeError, ValueError):
        return text in {"0", "0.0", "0.00"}


def _amount_snapshot(payload: Any, core: Any) -> tuple[str, str]:
    reader = getattr(core, "opll_stripe_amount_info", None)
    if not callable(reader):
        return "", "missing_amount_reader"
    amount, source = reader(payload)
    return _safe_text(amount, 48), _safe_text(source, 100)


def _checkout_kind(checkout: dict[str, Any]) -> str:
    checkout_id = _text(checkout.get("checkout_id") or checkout.get("cs_id"))
    if checkout_id.startswith("oaics_"):
        return "oaics"
    if checkout_id.startswith("cs_"):
        return "stripe_checkout"
    return "unknown"


def _validate_proxy(value: Any, label: str) -> str:
    proxy = _text(value)
    if not proxy:
        raise MomoCheckInputError(f"{label}不能为空")
    if len(proxy) > MAX_PROXY_LENGTH:
        raise MomoCheckInputError(f"{label}长度超过限制")
    if "://" not in proxy:
        proxy = f"http://{proxy}"
    try:
        parsed = urlsplit(proxy)
    except ValueError as exc:
        raise MomoCheckInputError(f"{label}格式无效") from exc
    if parsed.scheme.lower() not in {"http", "https", "socks4", "socks4a", "socks5", "socks5h"} or not parsed.hostname:
        raise MomoCheckInputError(f"{label}格式无效，例如 user:pass@host:port 或 http://user:pass@host:port")
    try:
        port = parsed.port
    except ValueError as exc:
        raise MomoCheckInputError(f"{label}端口无效") from exc
    if port is None:
        raise MomoCheckInputError(f"{label}缺少端口")
    return proxy


def _proxy_pool_items(value: Any, label: str) -> list[str]:
    if isinstance(value, list):
        candidates = [str(item) for item in value]
    else:
        candidates = re.split(r"[\r\n]+", _text(value))
    pool: list[str] = []
    for candidate in candidates:
        candidate = candidate.strip()
        if not candidate:
            continue
        proxy = _validate_proxy(candidate, label)
        if proxy not in pool:
            pool.append(proxy)
    if len(pool) > MAX_PROXY_POOL_SIZE:
        raise MomoCheckInputError(f"{label}最多支持 {MAX_PROXY_POOL_SIZE} 条代理")
    return pool


def _validate_payload(payload: Any) -> dict[str, str]:
    if not isinstance(payload, dict):
        raise MomoCheckInputError("请求体必须是 JSON 对象")
    token = _text(payload.get("access_token"))
    if not token:
        raise MomoCheckInputError("请输入 Access Token")
    if len(token) > MAX_TOKEN_LENGTH:
        raise MomoCheckInputError("Access Token 长度超过限制")
    payment_pool = _proxy_pool_items(
        payload.get("payment_proxy_pool") if "payment_proxy_pool" in payload else payload.get("payment_proxy"),
        "代理池 1",
    )
    if not payment_pool:
        raise MomoCheckInputError("代理池 1至少需要填写一条 VN 代理")
    promo_pool = _proxy_pool_items(
        payload.get("promo_proxy_pool") if "promo_proxy_pool" in payload else payload.get("promo_proxy"),
        "代理池 2",
    )
    proxy_strategy = _text(payload.get("proxy_strategy")).lower() or "round_robin"
    if proxy_strategy not in {"round_robin", "random"}:
        raise MomoCheckInputError("代理选择策略只能是 round_robin 或 random")
    payment_proxy = PROXY_POOL_SELECTOR.select("payment", payment_pool, proxy_strategy)
    promo_follows_payment = not promo_pool
    promo_proxy = payment_proxy if promo_follows_payment else PROXY_POOL_SELECTOR.select("promo", promo_pool, proxy_strategy)
    fingerprint_mode = _text(payload.get("fingerprint_mode")).lower() or "sticky"
    if fingerprint_mode not in {"sticky", "rotate"}:
        raise MomoCheckInputError("指纹模式只能是 sticky 或 rotate")
    return {
        "access_token": token,
        "payment_proxy": payment_proxy,
        "promo_proxy": promo_proxy,
        "payment_pool_size": str(len(payment_pool)),
        "promo_pool_size": str(len(promo_pool) or len(payment_pool)),
        "promo_follows_payment": "true" if promo_follows_payment else "false",
        "proxy_strategy": proxy_strategy,
        "email": _text(payload.get("email"))[:254],
        "cookie": _text(payload.get("chatgpt_cookie"))[:16_000],
        "account_id": _text(payload.get("account_id"))[:320],
        "fingerprint_mode": fingerprint_mode,
    }


def _error_code(exc: Exception) -> str:
    if isinstance(exc, MomoCheckInputError):
        return "MOMO_INPUT_INVALID"
    code = _safe_text(getattr(exc, "code", ""), 80)
    if code:
        return code
    text = _safe_text(exc).lower()
    if "unusual activity" in text:
        return "UPSTREAM_UNUSUAL_ACTIVITY"
    if "http 401" in text or "http 403" in text:
        return "AUTH_OR_RISK_BLOCKED"
    if "timeout" in text:
        return "UPSTREAM_TIMEOUT"
    return "MOMO_CHECK_FAILED"


def _error_message(exc: Exception) -> str:
    message = _safe_text(getattr(exc, "message", "") or str(exc), 420)
    if not message:
        return "上游未返回可用的错误详情"
    return re.sub(
        r"(?i)(bearer\s+)[^\s,;]+",
        r"\1***",
        message,
    )


def _local_fixture_enabled() -> bool:
    return _text(os.environ.get("MOMO_CHECK_LOCAL_FIXTURE")).lower() in {"1", "true", "yes"}


def _local_fixture_result(values: dict[str, str]) -> dict[str, Any]:
    """Return a deterministic, explicitly-labelled result for local UI checks."""

    requested = _text(os.environ.get("MOMO_CHECK_LOCAL_FIXTURE_RESULT")).lower()
    result = requested if requested in {"eligible", "ineligible"} else "eligible"
    reason_codes = [] if result == "eligible" else ["MOMO_METHOD_UNAVAILABLE"]
    return {
        "ok": True,
        "result": result,
        "checked_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "context": {
            "mode": "local_fixture",
            "billing_country": "VN",
            "currency": "VND",
            "checkout_kind": "fixture",
            "fingerprint_mode": values["fingerprint_mode"],
        },
        "routing": {
            "strategy": values["proxy_strategy"],
            "payment_pool_size": int(values["payment_pool_size"]),
            "promo_pool_size": int(values["promo_pool_size"]),
            "promo_follows_payment": values["promo_follows_payment"] == "true",
            "payment_proxy": _mask_proxy(values["payment_proxy"]),
            "promo_proxy": _mask_proxy(values["promo_proxy"]),
        },
        "momo": {"available": result == "eligible", "payment_methods": ["momo", "card"]},
        "zero_trial": {
            "eligible": result == "eligible",
            "amount": "0" if result == "eligible" else "10",
            "amount_source": "local_fixture",
            "verified_at": "local_fixture",
        },
        "reason_codes": reason_codes,
        "diagnostics": ["LOCAL_FIXTURE"],
        "steps": [
            {
                "key": "fixture",
                "label": "本地合成检测",
                "status": "done",
                "detail": "未发起外部请求",
            }
        ],
    }


class MomoTrialChecker:
    """Runs the read-only portion of the existing VN MoMo checkout flow."""

    def __init__(
        self,
        *,
        core_loader: Callable[[], Any] | None = None,
        fingerprint_resolver: Callable[..., dict[str, Any]] | None = None,
    ) -> None:
        self._core_loader = core_loader or load_momo_core
        self._fingerprint_resolver = fingerprint_resolver or resolve_momo_fingerprint

    def _fingerprint(self, values: dict[str, str]) -> dict[str, Any]:
        fingerprint = self._fingerprint_resolver(
            values["access_token"],
            account_id=values["account_id"] or values["email"],
            mode=values["fingerprint_mode"],
            attempt=1,
        )
        if not isinstance(fingerprint, dict):
            raise RuntimeError("MOMO_FINGERPRINT_INVALID: 指纹服务未返回对象")
        result = dict(fingerprint)
        result.setdefault("mode", values["fingerprint_mode"])
        return result

    @staticmethod
    def _billing_profile(core: Any, email: str) -> dict[str, Any]:
        generator = getattr(core, "opll_generate_vn_profile", None)
        if callable(generator):
            try:
                billing = generator(email)
            except TypeError:
                billing = generator()
        else:
            fallback = getattr(core, "opll_billing_for_country", None)
            billing = fallback("VN") if callable(fallback) else {}
        if not isinstance(billing, dict):
            raise RuntimeError("MOMO_BILLING_INVALID: 未生成有效越南账单资料")
        billing = dict(billing)
        billing["country"] = "VN"
        billing.setdefault("currency", "VND")
        if email:
            billing["email"] = email
        return billing

    @staticmethod
    def _sentinel_profile(fingerprint: dict[str, Any], flow: str) -> dict[str, Any]:
        def field(*names: str, default: str) -> str:
            for name in names:
                value = _text(fingerprint.get(name))
                if value:
                    return value
            return default

        return {
            "flow": flow,
            "page_url": "https://chatgpt.com/?promo_campaign=plus-1-month-free",
            "language": field("oai_language", "language", default="vi-VN"),
            "timezone": field("timezone", default="Asia/Ho_Chi_Minh"),
            "cores": int(float(field("cores", default="8") or 8)),
        }

    @staticmethod
    def _fingerprint_summary(fingerprint: dict[str, Any]) -> str:
        return _safe_text(
            fingerprint.get("summary") or fingerprint.get("name") or fingerprint.get("fingerprint_id"),
            120,
        )

    @staticmethod
    def _stage(stages: list[dict[str, str]], callback: ProgressCallback | None, key: str, label: str, detail: str = "") -> None:
        item = {"key": key, "label": label, "status": "done", "detail": _safe_text(detail, 180)}
        stages.append(item)
        if callback:
            callback(label, item["detail"])

    def check(self, payload: Any, *, progress: ProgressCallback | None = None) -> dict[str, Any]:
        """Check MoMo exposure and final zero-price evidence without payment confirmation."""

        stages: list[dict[str, str]] = []
        chatgpt: Any = None
        stripe: Any = None
        try:
            values = _validate_payload(payload)
            if _local_fixture_enabled():
                return _local_fixture_result(values)
            core = self._core_loader()
            fingerprint = self._fingerprint(values)
            device_id = _text(fingerprint.get("device_id"))
            billing = self._billing_profile(core, values["email"])
            self._stage(
                stages,
                progress,
                "fingerprint",
                "绑定越南指纹会话",
                f"模式={_text(fingerprint.get('mode')) or values['fingerprint_mode']}；代理={_mask_proxy(values['payment_proxy'])}",
            )

            session_builder = getattr(core, "opll_build_chatgpt_session", None)
            if not callable(session_builder):
                raise RuntimeError("MOMO_CORE_SESSION_MISSING: 缺少 ChatGPT 会话构建函数")
            chatgpt = session_builder(
                values["access_token"],
                values["payment_proxy"],
                chatgpt_cookie=values["cookie"],
                fingerprint_profile=fingerprint,
                device_id=device_id,
                oai_context=True,
            )
            create_checkout = getattr(core, "opll_create_checkout", None)
            if not callable(create_checkout):
                raise RuntimeError("MOMO_CORE_CHECKOUT_MISSING: 缺少 checkout 创建函数")
            checkout = create_checkout(
                values["access_token"],
                "VN",
                "VND",
                values["payment_proxy"],
                checkout_ui_mode="custom",
                require_stripe_session=False,
                preferred_processor_entity="",
                promo_campaign_id="plus-1-month-free",
                billing_profile=billing,
                chatgpt_cookie=values["cookie"],
                fingerprint_profile=fingerprint,
                device_id=device_id,
                oai_context=True,
                chatgpt=chatgpt,
                include_full_profile=False,
                sentinel_profile=self._sentinel_profile(fingerprint, "chatgpt_checkout"),
            )
            if not isinstance(checkout, dict):
                raise RuntimeError("MOMO_CHECKOUT_RESPONSE_INVALID: checkout 响应不是对象")
            checkout = dict(checkout)
            checkout["billing_country"] = "VN"
            checkout["currency"] = "VND"
            kind = _checkout_kind(checkout)
            raw_checkout = checkout.get("raw_checkout") if isinstance(checkout.get("raw_checkout"), dict) else {}
            methods = _normalize_methods(raw_checkout, core)
            self._stage(
                stages,
                progress,
                "checkout",
                "创建 VN MoMo Checkout",
                f"checkout={kind}；初始支付方式={','.join(methods) or '-'}",
            )

            amount = ""
            amount_source = ""
            amount_stage = ""
            if kind == "oaics":
                if "momo" in methods:
                    stripe_builder = getattr(core, "opll_build_stripe_session", None)
                    elements_builder = getattr(core, "opll_stripe_create_momo_elements_session", None)
                    if not callable(stripe_builder) or not callable(elements_builder):
                        raise RuntimeError("MOMO_OAICS_ELEMENTS_MISSING: 缺少 OAICS Elements 检测函数")
                    stripe = stripe_builder(
                        values["payment_proxy"],
                        fingerprint_profile=fingerprint,
                        device_id=device_id,
                    )
                    elements = elements_builder(
                        stripe,
                        checkout,
                        payment_locale="vi-VN",
                        browser_timezone="Asia/Saigon",
                    )
                    methods = _normalize_methods(elements, core) or methods
                    self._stage(
                        stages,
                        progress,
                        "payment_method",
                        "检测 Stripe Elements 中的 MoMo",
                        f"支付方式={','.join(methods) or '-'}",
                    )
                else:
                    self._stage(stages, progress, "payment_method", "检测 Checkout 中的 MoMo", "Checkout 未公布 MoMo")

                taxes_reader = getattr(core, "opll_chatgpt_checkout_taxes", None)
                if not callable(taxes_reader):
                    raise RuntimeError("MOMO_TAXES_MISSING: 缺少 Checkout 税区检测函数")
                taxes = taxes_reader(
                    "",
                    checkout,
                    values["payment_proxy"],
                    billing_profile=billing,
                    fingerprint_profile=fingerprint,
                    device_id=device_id,
                    oai_context=True,
                    chatgpt=chatgpt,
                )
                amount, amount_source = _amount_snapshot(taxes, core)
                amount_stage = "checkout/taxes"
                self._stage(
                    stages,
                    progress,
                    "zero_trial",
                    "检测越南账单后的 0 元资格",
                    f"amount={amount or '-'}；source={amount_source or '-'}",
                )
            else:
                promotion = getattr(core, "opll_chatgpt_checkout_update_promotion", None)
                if not callable(promotion):
                    raise RuntimeError("MOMO_PROMOTION_MISSING: 缺少试用优惠检测函数")
                promotion(
                    values["access_token"],
                    checkout,
                    values["promo_proxy"],
                    chatgpt_cookie=values["cookie"],
                    normalize_vn=True,
                    billing_profile=billing,
                    include_full_profile=True,
                    include_promo=True,
                    checkout_ui_mode=str(checkout.get("checkout_ui_mode") or "custom"),
                    fingerprint_profile=fingerprint,
                    device_id=device_id,
                    extra_payload={"subscription_data": {"trial_period_days": 30}},
                )
                self._stage(
                    stages,
                    progress,
                    "promotion",
                    "应用 1 个月试用优惠",
                    f"优惠更新代理={_mask_proxy(values['promo_proxy'])}",
                )

                stripe_builder = getattr(core, "opll_build_stripe_session", None)
                stripe_init = getattr(core, "opll_stripe_init", None)
                if not callable(stripe_builder) or not callable(stripe_init):
                    raise RuntimeError("MOMO_STRIPE_INIT_MISSING: 缺少 Stripe 支付页检测函数")
                stripe = stripe_builder(
                    values["payment_proxy"],
                    fingerprint_profile=fingerprint,
                    device_id=device_id,
                )
                init_payload = stripe_init(
                    _text(checkout.get("cs_id")),
                    "VN",
                    "VND",
                    values["payment_proxy"],
                    payment_locale="vi",
                    stripe=stripe,
                    checkout=checkout,
                    browser_timezone="Asia/Ho_Chi_Minh",
                    saved_payment_method_mode="never",
                )
                if not isinstance(init_payload, dict):
                    raise RuntimeError("MOMO_STRIPE_INIT_INVALID: Stripe 支付页响应不是对象")
                methods = _normalize_methods(init_payload, core)
                amount, amount_source = _amount_snapshot(init_payload, core)
                amount_stage = "stripe_init"
                self._stage(
                    stages,
                    progress,
                    "payment_method",
                    "检测 Stripe 支付页中的 MoMo",
                    f"支付方式={','.join(methods) or '-'}；amount={amount or '-'}",
                )

                tax_updater = getattr(core, "opll_stripe_update_tax_region", None)
                context_builder = getattr(core, "opll_stripe_context", None)
                stripe_key = getattr(core, "opll_stripe_key_for_checkout", None)
                if callable(tax_updater) and callable(context_builder) and callable(stripe_key):
                    context = context_builder(
                        init_payload,
                        "vi",
                        {
                            "browser_timezone": "Asia/Ho_Chi_Minh",
                            "saved_payment_method_mode": "never",
                            "fingerprint_profile": fingerprint,
                            "device_id": device_id,
                        },
                    )
                    context["currency"] = "vnd"
                    tax_payload = tax_updater(
                        stripe,
                        _text(checkout.get("cs_id")),
                        stripe_key(checkout),
                        context,
                        billing,
                        payment_locale="vi",
                        browser_timezone="Asia/Ho_Chi_Minh",
                        saved_payment_method_mode="never",
                    )
                    if isinstance(tax_payload, dict) and tax_payload:
                        updated_methods = _normalize_methods(tax_payload, core)
                        updated_amount, updated_source = _amount_snapshot(tax_payload, core)
                        has_state = bool(updated_methods or updated_source not in {"", "fallback_zero", "missing_payload"})
                        if has_state:
                            methods = updated_methods or methods
                            amount, amount_source = updated_amount, updated_source
                            amount_stage = "stripe_tax_region"
                    self._stage(
                        stages,
                        progress,
                        "zero_trial",
                        "复核越南税区后的 0 元资格",
                        f"amount={amount or '-'}；source={amount_source or '-'}",
                    )
                else:
                    self._stage(
                        stages,
                        progress,
                        "zero_trial",
                        "检测试用后的 0 元资格",
                        f"amount={amount or '-'}；source={amount_source or '-'}",
                    )

            momo_available = "momo" in methods
            zero_eligible = _explicit_zero(amount, amount_source)
            reason_codes: list[str] = []
            if not momo_available:
                reason_codes.append("MOMO_METHOD_UNAVAILABLE")
            if not zero_eligible:
                reason_codes.append("MOMO_AMOUNT_NONZERO")
            result = "eligible" if not reason_codes else "ineligible"
            return {
                "ok": True,
                "result": result,
                "checked_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                "context": {
                    "billing_country": "VN",
                    "currency": "VND",
                    "checkout_kind": kind,
                    "fingerprint_mode": _text(fingerprint.get("mode")) or values["fingerprint_mode"],
                    "fingerprint_summary": self._fingerprint_summary(fingerprint),
                },
                "routing": {
                    "strategy": values["proxy_strategy"],
                    "payment_pool_size": int(values["payment_pool_size"]),
                    "promo_pool_size": int(values["promo_pool_size"]),
                    "promo_follows_payment": values["promo_follows_payment"] == "true",
                    "payment_proxy": _mask_proxy(values["payment_proxy"]),
                    "promo_proxy": _mask_proxy(values["promo_proxy"]),
                },
                "momo": {
                    "available": momo_available,
                    "payment_methods": methods,
                },
                "zero_trial": {
                    "eligible": zero_eligible,
                    "amount": amount,
                    "amount_source": amount_source,
                    "verified_at": amount_stage,
                },
                "reason_codes": reason_codes,
                "steps": stages,
            }
        except Exception as exc:  # noqa: BLE001
            return {
                "ok": False,
                "result": "error",
                "checked_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                "error": {
                    "code": _error_code(exc),
                    "message": _error_message(exc),
                },
                "steps": stages,
            }
        finally:
            for session in (stripe, chatgpt):
                closer = getattr(session, "close", None)
                if callable(closer):
                    try:
                        closer()
                    except Exception:
                        pass


def source_status() -> dict[str, Any]:
    """Return non-sensitive dependency status for the health endpoint."""

    root = _source_root()
    ready = (root / "standalone_core" / "momo_extract.py").is_file()
    return {
        "ready": ready,
        "source_ready": ready,
        "code": "READY" if ready else "MOMO_SOURCE_NOT_FOUND",
        "message": "MoMo 检测核心已就绪" if ready else "缺少 standalone_core/momo_extract.py",
        "source_root": str(root),
        "checked_at": int(time.time()),
    }


MAX_BATCH_ITEMS = 20


def _batch_tokens(payload: Any) -> list[str]:
    if not isinstance(payload, dict):
        raise MomoCheckInputError("请求体必须是 JSON 对象")
    raw_tokens = payload.get("access_tokens")
    candidates = raw_tokens if isinstance(raw_tokens, list) else str(raw_tokens or "").splitlines()
    tokens: list[str] = []
    for candidate in candidates:
        token = str(candidate or "").strip()
        if not token:
            continue
        if len(token) > MAX_TOKEN_LENGTH:
            raise MomoCheckInputError("单个 Access Token 长度超过限制")
        if token not in tokens:
            tokens.append(token)
    if not tokens:
        raise MomoCheckInputError("批量模式至少需要填写一个 Access Token")
    if len(tokens) > MAX_BATCH_ITEMS:
        raise MomoCheckInputError(f"批量模式最多支持 {MAX_BATCH_ITEMS} 个 Access Token")
    return tokens


def _public_batch_item(index: int, result: dict[str, Any]) -> dict[str, Any]:
    return {
        "index": index,
        "ok": bool(result.get("ok")),
        "result": result.get("result", "error"),
        "context": result.get("context", {}),
        "routing": result.get("routing", {}),
        "momo": result.get("momo", {}),
        "zero_trial": result.get("zero_trial", {}),
        "reason_codes": result.get("reason_codes", []),
        "error": result.get("error"),
        "steps": result.get("steps", []),
    }


def run_batch_check(payload: Any, checker: MomoTrialChecker | None = None) -> dict[str, Any]:
    """Run a bounded serial batch without returning any Access Token."""

    tokens = _batch_tokens(payload)
    active_checker = checker or MomoTrialChecker()
    base_payload = dict(payload)
    base_payload.pop("access_tokens", None)
    base_payload.pop("access_token", None)
    items: list[dict[str, Any]] = []
    for index, token in enumerate(tokens, start=1):
        item_payload = dict(base_payload)
        item_payload["access_token"] = token
        try:
            item_result = active_checker.check(item_payload)
        except MomoCheckInputError as exc:
            item_result = {
                "ok": False,
                "result": "error",
                "error": {"code": "INVALID_INPUT", "message": str(exc)},
                "steps": [],
            }
        except Exception:
            item_result = {
                "ok": False,
                "result": "error",
                "error": {"code": "BATCH_ITEM_FAILED", "message": "该条检测发生未分类异常"},
                "steps": [],
            }
        items.append(_public_batch_item(index, item_result))
    summary = {
        "eligible": sum(item["result"] == "eligible" for item in items),
        "ineligible": sum(item["result"] == "ineligible" for item in items),
        "error": sum(item["result"] == "error" for item in items),
    }
    return {
        "ok": True,
        "result": "batch",
        "total": len(items),
        "completed": len(items),
        "summary": summary,
        "items": items,
    }
