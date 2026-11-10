"""Minimal VN/VND MoMo eligibility checkout adapter.

This module deliberately stops before PaymentMethod creation and payment
confirmation.  It only creates/updates checkout context and reads payment-page
methods and amount evidence.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
import uuid
from typing import Any, Iterable

from http_client import create_http_session


CHATGPT_ORIGIN = "https://chatgpt.com"
CHECKOUT_URL = f"{CHATGPT_ORIGIN}/backend-api/payments/checkout"
CHECKOUT_UPDATE_URL = f"{CHATGPT_ORIGIN}/backend-api/payments/checkout/update"
CHECKOUT_TAXES_URL = f"{CHATGPT_ORIGIN}/backend-api/payments/checkout/taxes"
STRIPE_API = "https://api.stripe.com/v1/payment_pages"
PROMO_ID = "plus-1-month-free"
STRIPE_VERSION = "2025-03-31.basil; checkout_server_update_beta=v1; checkout_manual_approval_preview=v1"
DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/136.0.0.0 Safari/537.36"
)


class MoMoExtractError(RuntimeError):
    """Stable, sanitized adapter failure exposed to the WebUI."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        status_code: int | None = None,
        request_id: str = "",
    ) -> None:
        self.code = str(code or "MOMO_CHECK_FAILED")[:80]
        self.message = str(message or "上游请求失败")[:500]
        self.status_code = status_code
        self.request_id = str(request_id or "")[:160]
        super().__init__(self.message)


def _load_core() -> Any:
    return sys.modules[__name__]


def _text(value: Any) -> str:
    return str(value or "").strip()


def _stable_uuid(seed: str) -> str:
    digest = hashlib.sha256(seed.encode("utf-8", errors="ignore")).hexdigest()
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"momo-vn:{digest}"))


def resolve_momo_fingerprint(
    access_token: str,
    *,
    account_id: str = "",
    mode: str = "sticky",
    attempt: int = 1,
    **_: Any,
) -> dict[str, Any]:
    selected_mode = _text(mode).lower() or "sticky"
    if selected_mode not in {"sticky", "rotate"}:
        selected_mode = "sticky"
    identity = _text(account_id) or _text(access_token)
    if selected_mode == "rotate":
        fingerprint_id = str(uuid.uuid4())
        device_id = str(uuid.uuid4())
    else:
        fingerprint_id = _stable_uuid(f"fingerprint:{identity}")
        device_id = _stable_uuid(f"device:{identity}")
    return {
        "fingerprint_id": fingerprint_id,
        "device_id": device_id,
        "mode": selected_mode,
        "attempt": max(1, int(attempt or 1)),
        "country": "VN",
        "currency": "VND",
        "language": "vi-VN",
        "oai_language": "vi-VN",
        "timezone": "Asia/Ho_Chi_Minh",
        "cores": 8,
        "user_agent": DEFAULT_UA,
        "summary": "VN Chrome 136 / vi-VN",
    }


def opll_generate_vn_profile(email: str = "") -> dict[str, Any]:
    profile = {
        "name": "Nguyen Van An",
        "line1": "1 Nguyen Hue",
        "line2": "",
        "city": "Ho Chi Minh City",
        "state": "Ho Chi Minh",
        "postal_code": "700000",
        "country": "VN",
        "currency": "VND",
    }
    if _text(email):
        profile["email"] = _text(email)[:254]
    return profile


def opll_billing_for_country(country: str = "VN") -> dict[str, Any]:
    profile = opll_generate_vn_profile()
    profile["country"] = "VN" if _text(country).upper() != "VN" else _text(country).upper()
    return profile


def _fingerprint_headers(profile: dict[str, Any] | None, device_id: str = "") -> dict[str, str]:
    fingerprint = profile if isinstance(profile, dict) else {}
    resolved_device = _text(device_id) or _text(fingerprint.get("device_id"))
    headers = {
        "User-Agent": _text(fingerprint.get("user_agent")) or DEFAULT_UA,
        "Accept-Language": _text(fingerprint.get("oai_language") or fingerprint.get("language")) or "vi-VN",
    }
    if resolved_device:
        headers["oai-device-id"] = resolved_device
    return headers


def _chatgpt_headers(
    access_token: str,
    *,
    fingerprint_profile: dict[str, Any] | None = None,
    device_id: str = "",
    referer: str = f"{CHATGPT_ORIGIN}/?promo_campaign={PROMO_ID}",
    target_path: str = "/backend-api/payments/checkout",
) -> dict[str, str]:
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Origin": CHATGPT_ORIGIN,
        "Referer": referer,
        "Authorization": f"Bearer {_text(access_token)}",
        "x-openai-target-path": target_path,
        "x-openai-target-route": target_path,
    }
    headers.update(_fingerprint_headers(fingerprint_profile, device_id))
    return headers


def _cookie_header(cookie: str) -> str:
    return "; ".join(part.strip() for part in _text(cookie).split(";") if "=" in part)


def opll_build_chatgpt_session(
    access_token: str,
    proxy: str,
    *,
    chatgpt_cookie: str = "",
    fingerprint_profile: dict[str, Any] | None = None,
    device_id: str = "",
    **_: Any,
) -> Any:
    fingerprint = fingerprint_profile if isinstance(fingerprint_profile, dict) else {}
    session = create_http_session(
        _text(proxy),
        impersonate="chrome136",
        user_agent=_text(fingerprint.get("user_agent")) or DEFAULT_UA,
    )
    headers = _chatgpt_headers(
        access_token,
        fingerprint_profile=fingerprint,
        device_id=device_id,
    )
    cookie = _cookie_header(chatgpt_cookie)
    if cookie:
        headers["Cookie"] = cookie
    session.headers.update(headers)
    return session


def opll_build_stripe_session(
    proxy: str,
    *,
    fingerprint_profile: dict[str, Any] | None = None,
    device_id: str = "",
    **_: Any,
) -> Any:
    fingerprint = fingerprint_profile if isinstance(fingerprint_profile, dict) else {}
    session = create_http_session(
        _text(proxy),
        impersonate="chrome136",
        user_agent=_text(fingerprint.get("user_agent")) or DEFAULT_UA,
    )
    session.headers.update(
        {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": "https://js.stripe.com",
            "Referer": "https://js.stripe.com/",
            **_fingerprint_headers(fingerprint, device_id),
        }
    )
    return session


def _redact(value: Any, secrets: Iterable[str] = ()) -> str:
    text = re.sub(r"\s+", " ", _text(value))
    for secret in secrets:
        secret_text = _text(secret)
        if secret_text:
            text = text.replace(secret_text, "***")
    patterns = (
        (r"(?i)(bearer\s+)[^\s,;]+", r"\1***"),
        (r"(?i)(client_secret\s*[=:]\s*)[^\s,;]+", r"\1***"),
        (r"(?i)(publishable_key\s*[=:]\s*)[^\s,;]+", r"\1***"),
        (r"\bpk_(?:live|test)_[A-Za-z0-9_]+", "pk_***"),
        (r"\bcs_(?:live|test|secret)_[A-Za-z0-9_]+", "cs_***"),
        (r"(?i)(cookie\s*[=:]\s*)[^\s,;]+", r"\1***"),
    )
    for pattern, replacement in patterns:
        text = re.sub(pattern, replacement, text)
    return text[:420]


def _response_json(
    response: Any,
    code_prefix: str,
    *,
    secrets: Iterable[str] = (),
) -> dict[str, Any]:
    status = int(getattr(response, "status_code", 0) or 0)
    headers = getattr(response, "headers", {}) or {}
    request_id = _text(headers.get("x-request-id") if hasattr(headers, "get") else "")
    if status >= 400:
        detail = _redact(getattr(response, "text", ""), secrets)
        is_checkout_unusual_activity = (
            code_prefix == "MOMO_CHECKOUT"
            and status == 400
            and "our systems have detected unusual activity" in detail.casefold()
        )
        if is_checkout_unusual_activity:
            message = "上游暂时拒绝 Checkout：检测到异常活动，请稍后通过常规 ChatGPT 结账流程重新验证"
            if request_id:
                message += f"；request_id={request_id}"
            raise MoMoExtractError(
                "MOMO_CHECKOUT_UNUSUAL_ACTIVITY",
                message,
                status_code=status,
                request_id=request_id,
            )

        message = f"上游返回 HTTP {status}"
        if request_id:
            message += f"；request_id={request_id}"
        if detail:
            message += f"；detail={detail}"
        raise MoMoExtractError(
            f"{code_prefix}_HTTP_{status}",
            message,
            status_code=status,
            request_id=request_id,
        )
    try:
        payload = response.json()
    except Exception as exc:
        raise MoMoExtractError(f"{code_prefix}_JSON_INVALID", "上游响应不是有效 JSON") from exc
    if not isinstance(payload, dict):
        raise MoMoExtractError(f"{code_prefix}_RESPONSE_INVALID", "上游响应不是对象")
    return payload


def _checkout_payload(
    *,
    checkout_ui_mode: str,
    promo_campaign_id: str,
    billing_profile: dict[str, Any] | None,
) -> dict[str, Any]:
    billing = dict(billing_profile or {})
    billing["country"] = "VN"
    billing["currency"] = "VND"
    body: dict[str, Any] = {
        "entry_point": "all_plans_pricing_modal",
        "plan_name": "chatgptplusplan",
        "price_interval": "month",
        "seat_quantity": 1,
        "checkout_ui_mode": _text(checkout_ui_mode) or "custom",
        "billing_details": billing,
        "cancel_url": f"{CHATGPT_ORIGIN}/",
        "promo_campaign": {
            "promo_campaign_id": _text(promo_campaign_id) or PROMO_ID,
            "is_coupon_from_query_param": False,
        },
    }
    return body


def _processor_entity(payload: dict[str, Any]) -> str:
    for node in (payload, payload.get("checkout_session"), payload.get("session"), payload.get("data")):
        if isinstance(node, dict):
            value = _text(node.get("processor_entity") or node.get("processorEntity"))
            if value:
                return value
    return "openai_llc"


def opll_create_checkout(
    access_token: str,
    country: str,
    currency: str,
    proxy: str,
    *,
    checkout_ui_mode: str = "custom",
    promo_campaign_id: str = PROMO_ID,
    billing_profile: dict[str, Any] | None = None,
    chatgpt_cookie: str = "",
    fingerprint_profile: dict[str, Any] | None = None,
    device_id: str = "",
    chatgpt: Any = None,
    **_: Any,
) -> dict[str, Any]:
    own_session = chatgpt is None
    session = chatgpt or opll_build_chatgpt_session(
        access_token,
        proxy,
        chatgpt_cookie=chatgpt_cookie,
        fingerprint_profile=fingerprint_profile,
        device_id=device_id,
    )
    headers = _chatgpt_headers(
        access_token,
        fingerprint_profile=fingerprint_profile,
        device_id=device_id,
    )
    cookie = _cookie_header(chatgpt_cookie)
    if cookie:
        headers["Cookie"] = cookie
    body = _checkout_payload(
        checkout_ui_mode=checkout_ui_mode,
        promo_campaign_id=promo_campaign_id,
        billing_profile=billing_profile,
    )
    try:
        response = session.post(CHECKOUT_URL, headers=headers, json=body, timeout=30)
        raw = _response_json(
            response,
            "MOMO_CHECKOUT",
            secrets=(access_token, chatgpt_cookie),
        )
    finally:
        if own_session:
            close = getattr(session, "close", None)
            if callable(close):
                close()
    checkout_id = _text(
        raw.get("checkout_session_id")
        or raw.get("session_id")
        or raw.get("checkout_id")
        or raw.get("id")
    )
    if not checkout_id.startswith(("cs_", "oaics_")):
        raise MoMoExtractError("MOMO_CHECKOUT_ID_MISSING", "checkout 响应缺少有效会话 ID")
    publishable_key = _text(
        raw.get("stripe_publishable_key")
        or raw.get("publishable_key")
        or raw.get("publishableKey")
        or raw.get("stripePublishableKey")
        or raw.get("key")
    )
    return {
        "checkout_id": checkout_id,
        "cs_id": checkout_id if checkout_id.startswith("cs_") else "",
        "oaics_id": checkout_id if checkout_id.startswith("oaics_") else "",
        "processor_entity": _processor_entity(raw),
        "checkout_ui_mode": _text(raw.get("checkout_ui_mode")) or _text(checkout_ui_mode) or "custom",
        "billing_country": "VN",
        "currency": "VND",
        "publishable_key": publishable_key,
        "stripe_publishable_key": publishable_key,
        "raw_checkout": raw,
    }


def opll_chatgpt_checkout_update_promotion(
    access_token: str,
    checkout: dict[str, Any],
    proxy: str,
    *,
    chatgpt_cookie: str = "",
    billing_profile: dict[str, Any] | None = None,
    checkout_ui_mode: str = "custom",
    fingerprint_profile: dict[str, Any] | None = None,
    device_id: str = "",
    extra_payload: dict[str, Any] | None = None,
    **_: Any,
) -> dict[str, Any]:
    checkout_id = _text(checkout.get("cs_id") or checkout.get("checkout_id"))
    if not checkout_id.startswith("cs_"):
        raise MoMoExtractError("MOMO_PROMOTION_CHECKOUT_INVALID", "优惠更新缺少 Stripe checkout ID")
    entity = _text(checkout.get("processor_entity")) or "openai_llc"
    body: dict[str, Any] = {
        "checkout_session_id": checkout_id,
        "processor_entity": entity,
        "plan_name": "chatgptplusplan",
        "price_interval": "month",
        "seat_quantity": 1,
        "checkout_ui_mode": _text(checkout_ui_mode) or "custom",
        "billing_details": {"country": "VN", "currency": "VND"},
        "promo_campaign": {
            "promo_campaign_id": PROMO_ID,
            "is_coupon_from_query_param": False,
        },
    }
    if isinstance(extra_payload, dict):
        for key, value in extra_payload.items():
            if key not in {"payment_method", "payment_method_data", "confirm", "confirmation_token"}:
                body[key] = value
    session = opll_build_chatgpt_session(
        access_token,
        proxy,
        chatgpt_cookie=chatgpt_cookie,
        fingerprint_profile=fingerprint_profile,
        device_id=device_id,
    )
    path = "/backend-api/payments/checkout/update"
    headers = _chatgpt_headers(
        access_token,
        fingerprint_profile=fingerprint_profile,
        device_id=device_id,
        referer=f"{CHATGPT_ORIGIN}/checkout/{entity}/{checkout_id}",
        target_path=path,
    )
    try:
        response = session.post(CHECKOUT_UPDATE_URL, headers=headers, json=body, timeout=30)
        return _response_json(
            response,
            "MOMO_PROMOTION",
            secrets=(access_token, chatgpt_cookie, opll_stripe_key_for_checkout(checkout)),
        )
    finally:
        close = getattr(session, "close", None)
        if callable(close):
            close()


def opll_stripe_key_for_checkout(checkout: dict[str, Any]) -> str:
    raw = checkout.get("raw_checkout") if isinstance(checkout.get("raw_checkout"), dict) else {}
    return _text(
        checkout.get("stripe_publishable_key")
        or checkout.get("publishable_key")
        or raw.get("stripe_publishable_key")
        or raw.get("publishable_key")
        or raw.get("publishableKey")
        or raw.get("key")
    )


def opll_stripe_init(
    checkout_session_id: str,
    country: str,
    currency: str,
    proxy: str,
    *,
    payment_locale: str = "vi",
    stripe: Any = None,
    checkout: dict[str, Any] | None = None,
    browser_timezone: str = "Asia/Ho_Chi_Minh",
    saved_payment_method_mode: str = "never",
    **_: Any,
) -> dict[str, Any]:
    cs_id = _text(checkout_session_id)
    if not cs_id.startswith("cs_"):
        raise MoMoExtractError("MOMO_STRIPE_CHECKOUT_INVALID", "Stripe init 缺少有效 checkout ID")
    key = opll_stripe_key_for_checkout(checkout or {})
    if not key:
        raise MoMoExtractError("MOMO_STRIPE_KEY_MISSING", "checkout 响应缺少 Stripe publishable key")
    own_session = stripe is None
    session = stripe or opll_build_stripe_session(proxy)
    form = {
        "browser_locale": _text(payment_locale) or "vi",
        "browser_timezone": _text(browser_timezone) or "Asia/Ho_Chi_Minh",
        "elements_session_client[elements_init_source]": "custom_checkout",
        "elements_session_client[referrer_host]": "chatgpt.com",
        "elements_session_client[stripe_js_id]": str(uuid.uuid4()),
        "elements_session_client[locale]": _text(payment_locale) or "vi",
        "elements_session_client[is_aggregation_expected]": "false",
        "elements_options_client[saved_payment_method][enable_save]": _text(saved_payment_method_mode) or "never",
        "elements_options_client[saved_payment_method][enable_redisplay]": "never",
        "key": key,
        "_stripe_version": STRIPE_VERSION,
    }
    try:
        response = session.post(f"{STRIPE_API}/{cs_id}/init", data=form, timeout=30)
        return _response_json(response, "MOMO_STRIPE_INIT", secrets=(key,))
    finally:
        if own_session:
            close = getattr(session, "close", None)
            if callable(close):
                close()


def opll_collect_payment_method_types(payload: Any) -> list[str]:
    found: list[str] = []

    def add(values: Any) -> None:
        if not isinstance(values, list):
            return
        for value in values:
            method = _text(value).lower()
            if method and method not in found:
                found.append(method)

    def walk(node: Any, depth: int = 0) -> None:
        if depth > 8:
            return
        if isinstance(node, dict):
            for key, value in node.items():
                key_text = _text(key).lower()
                if key_text in {
                    "payment_method_types",
                    "paymentmethodtypes",
                    "supported_payment_method_types",
                }:
                    add(value)
                elif isinstance(value, (dict, list)):
                    walk(value, depth + 1)
        elif isinstance(node, list):
            for item in node:
                walk(item, depth + 1)

    walk(payload)
    return found[:20]


def opll_stripe_amount_info(payload: Any) -> tuple[str, str]:
    if not isinstance(payload, dict):
        return "", "missing_payload"
    candidates: tuple[tuple[str, ...], ...] = (
        ("total_summary", "due"),
        ("invoice", "amount_due"),
        ("amount_total",),
        ("elements_options", "amount"),
        ("amount",),
    )
    for path in candidates:
        node: Any = payload
        for part in path:
            if not isinstance(node, dict) or part not in node:
                node = None
                break
            node = node[part]
        if node is not None:
            return _text(node) or "0", ".".join(path)
    for container in ("session", "checkout_session", "data"):
        nested = payload.get(container)
        if isinstance(nested, dict):
            amount, source = opll_stripe_amount_info(nested)
            if source not in {"missing_payload", "fallback_zero"}:
                return amount, f"{container}.{source}"
    return "", "missing_payload"


def opll_stripe_context(
    init_payload: dict[str, Any],
    payment_locale: str,
    options: dict[str, Any] | None = None,
) -> dict[str, Any]:
    opts = dict(options or {})
    context = {
        "browser_locale": _text(payment_locale) or "vi",
        "browser_timezone": _text(opts.get("browser_timezone")) or "Asia/Ho_Chi_Minh",
        "saved_payment_method_mode": _text(opts.get("saved_payment_method_mode")) or "never",
        "stripe_js_id": str(uuid.uuid4()),
        "currency": "vnd",
    }
    context["payment_method_types"] = opll_collect_payment_method_types(init_payload)
    return context


def opll_stripe_update_tax_region(
    stripe: Any,
    checkout_session_id: str,
    publishable_key: str,
    context: dict[str, Any],
    billing_profile: dict[str, Any],
    *,
    payment_locale: str = "vi",
    browser_timezone: str = "Asia/Ho_Chi_Minh",
    saved_payment_method_mode: str = "never",
    **_: Any,
) -> dict[str, Any]:
    cs_id = _text(checkout_session_id)
    key = _text(publishable_key)
    if not cs_id.startswith("cs_"):
        raise MoMoExtractError("MOMO_STRIPE_CHECKOUT_INVALID", "税区更新缺少有效 checkout ID")
    if not key:
        raise MoMoExtractError("MOMO_STRIPE_KEY_MISSING", "税区更新缺少 Stripe publishable key")
    billing = dict(billing_profile or {})
    billing["country"] = "VN"
    form = {
        "key": key,
        "_stripe_version": STRIPE_VERSION,
        "browser_locale": _text(payment_locale) or "vi",
        "browser_timezone": _text(browser_timezone) or "Asia/Ho_Chi_Minh",
        "elements_options_client[saved_payment_method][enable_save]": _text(saved_payment_method_mode) or "never",
        "elements_options_client[saved_payment_method][enable_redisplay]": "never",
        "billing_address_collection[name]": _text(billing.get("name")),
        "billing_address_collection[address][line1]": _text(billing.get("line1")),
        "billing_address_collection[address][line2]": _text(billing.get("line2")),
        "billing_address_collection[address][city]": _text(billing.get("city")),
        "billing_address_collection[address][state]": _text(billing.get("state")),
        "billing_address_collection[address][postal_code]": _text(billing.get("postal_code")),
        "billing_address_collection[address][country]": "VN",
    }
    stripe_js_id = _text((context or {}).get("stripe_js_id"))
    if stripe_js_id:
        form["elements_session_client[stripe_js_id]"] = stripe_js_id
    response = stripe.post(f"{STRIPE_API}/{cs_id}", data=form, timeout=30)
    return _response_json(response, "MOMO_STRIPE_TAX_REGION", secrets=(key,))


def opll_stripe_create_momo_elements_session(
    stripe: Any,
    checkout: dict[str, Any],
    **_: Any,
) -> dict[str, Any]:
    raw = checkout.get("raw_checkout") if isinstance(checkout.get("raw_checkout"), dict) else {}
    for key in ("elements_session", "elements", "payment_method_configuration"):
        value = raw.get(key)
        if isinstance(value, dict):
            return value
    return raw


def opll_chatgpt_checkout_taxes(
    access_token: str,
    checkout: dict[str, Any],
    proxy: str,
    *,
    billing_profile: dict[str, Any] | None = None,
    fingerprint_profile: dict[str, Any] | None = None,
    device_id: str = "",
    chatgpt: Any = None,
    **_: Any,
) -> dict[str, Any]:
    checkout_id = _text(checkout.get("checkout_id") or checkout.get("oaics_id") or checkout.get("cs_id"))
    if not checkout_id:
        raise MoMoExtractError("MOMO_TAXES_CHECKOUT_INVALID", "税区检测缺少 checkout ID")
    own_session = chatgpt is None
    session = chatgpt or opll_build_chatgpt_session(
        access_token,
        proxy,
        fingerprint_profile=fingerprint_profile,
        device_id=device_id,
    )
    path = "/backend-api/payments/checkout/taxes"
    headers = _chatgpt_headers(
        access_token,
        fingerprint_profile=fingerprint_profile,
        device_id=device_id,
        target_path=path,
    )
    body = {
        "checkout_session_id": checkout_id,
        "billing_details": {**dict(billing_profile or {}), "country": "VN", "currency": "VND"},
    }
    try:
        response = session.post(CHECKOUT_TAXES_URL, headers=headers, json=body, timeout=30)
        return _response_json(response, "MOMO_TAXES", secrets=(access_token,))
    finally:
        if own_session:
            close = getattr(session, "close", None)
            if callable(close):
                close()
