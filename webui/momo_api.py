"""FastAPI integration for the optional MoMo eligibility checker."""
from __future__ import annotations

import logging
from typing import Any, Callable, Literal
from urllib.parse import urlsplit

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from safe_diagnostics import sanitize_text

from . import db
logger = logging.getLogger("webui.momo")


from .momo_checker import (
    MAX_BATCH_ITEMS,
    MAX_TOKEN_LENGTH,
    MomoCheckInputError,
    MomoTrialChecker,
    run_batch_check,
    source_status,
)


class MomoCommonRequest(BaseModel):
    source: Literal["manual", "registered"] = "manual"
    payment_proxy_pool: str | list[str] = ""
    promo_proxy_pool: str | list[str] = ""
    proxy_strategy: Literal["round_robin", "random"] = "round_robin"
    fingerprint_mode: Literal["sticky", "rotate"] = "sticky"


class MomoCheckRequest(MomoCommonRequest):
    access_token: str = ""
    emails: list[str] = Field(default_factory=list)


class MomoBatchCheckRequest(MomoCommonRequest):
    access_tokens: Any = Field(default_factory=list)
    emails: list[str] = Field(default_factory=list)


CheckerFactory = Callable[[], MomoTrialChecker]
StatusReader = Callable[[], dict[str, Any]]


def _request_data(request: BaseModel) -> dict[str, Any]:
    dumper = getattr(request, "model_dump", None)
    return dumper() if callable(dumper) else request.dict()


def _common_payload(request: MomoCommonRequest) -> dict[str, Any]:
    data = _request_data(request)
    return {
        "payment_proxy_pool": data.get("payment_proxy_pool", ""),
        "promo_proxy_pool": data.get("promo_proxy_pool", ""),
        "proxy_strategy": data.get("proxy_strategy", "round_robin"),
        "fingerprint_mode": data.get("fingerprint_mode", "sticky"),
    }


def _normalize_emails(values: list[str]) -> list[str]:
    emails: list[str] = []
    for value in values:
        email = str(value or "").strip().lower()
        if email and email not in emails:
            emails.append(email)
    if not emails:
        raise HTTPException(400, "至少选择一个注册账号")
    if len(emails) > MAX_BATCH_ITEMS:
        raise HTTPException(400, f"批量模式最多支持 {MAX_BATCH_ITEMS} 个账号")
    return emails


def _registered_error(email: str, code: str, message: str) -> dict[str, Any]:
    return {
        "ok": False,
        "result": "error",
        "email": email,
        "label": email,
        "error": {"code": code, "message": message},
        "failure_stage": "credentials",
        "steps": [],
    }


def _registered_checkout_cookie(row: dict[str, Any]) -> str:
    """Build the server-side checkout cookie without exposing it to the client."""

    session_name = "__Secure-next-auth.session-token"
    session_token = str(row.get("session_token") or "").strip()
    cookie_parts: list[str] = []
    seen: set[str] = set()
    for raw_part in str(row.get("cookie_header") or "").replace("\r", "").replace("\n", "").split(";"):
        part = raw_part.strip()
        if "=" not in part:
            continue
        name, _separator, value = part.partition("=")
        name = name.strip()
        value = value.strip()
        if not name or not value or name == session_name or name in seen:
            continue
        seen.add(name)
        cookie_parts.append(f"{name}={value}")
    if session_token:
        cookie_parts.append(f"{session_name}={session_token}")
    return "; ".join(cookie_parts)


def _registered_token(
    db_module: Any,
    email: str,
) -> tuple[str | None, str, dict[str, Any] | None]:
    row = db_module.get_registered(email)
    if not row:
        return None, "", _registered_error(
            email,
            "REGISTERED_ACCOUNT_NOT_FOUND",
            f"未找到已注册账号: {email}",
        )
    token = str(row.get("access_token") or "").strip()
    if not token:
        return None, "", _registered_error(
            email,
            "REGISTERED_TOKEN_MISSING",
            f"注册账号缺少 Access Token: {email}",
        )
    if len(token) > MAX_TOKEN_LENGTH:
        return None, "", _registered_error(
            email,
            "REGISTERED_TOKEN_INVALID",
            f"注册账号 Access Token 长度超过限制: {email}",
        )
    return token, _registered_checkout_cookie(row), None


def _mask_proxy(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        parsed = urlsplit(text)
    except ValueError:
        return "已配置代理"
    host = parsed.hostname or ""
    if not host:
        return "已配置代理"
    if parsed.port:
        host = f"{host}:{parsed.port}"
    scheme = parsed.scheme or "proxy"
    return f"{scheme}://***@{host}" if (parsed.username or parsed.password) else f"{scheme}://{host}"


def _pick(mapping: Any, keys: tuple[str, ...]) -> dict[str, Any]:
    if not isinstance(mapping, dict):
        return {}
    return {key: mapping[key] for key in keys if key in mapping}


def _failure_stage(result: Any) -> str:
    raw = result if isinstance(result, dict) else {}
    explicit = str(raw.get("failure_stage") or "").strip()
    if explicit:
        return explicit[:80]

    error = raw.get("error") if isinstance(raw.get("error"), dict) else {}
    code = str(error.get("code") or "").strip().upper()
    prefix_stages = (
        ("REGISTERED_", "credentials"),
        ("MOMO_INPUT_", "input"),
        ("MOMO_CORE_", "core"),
        ("MOMO_FINGERPRINT_", "fingerprint"),
        ("MOMO_BILLING_", "billing"),
        ("MOMO_CHECKOUT_", "checkout"),
        ("MOMO_OAICS_", "payment_method"),
        ("MOMO_PROMOTION_", "promotion"),
        ("MOMO_STRIPE_TAX_REGION_", "stripe_tax_region"),
        ("MOMO_STRIPE_INIT_", "stripe_init"),
        ("MOMO_STRIPE_CHECKOUT_", "stripe_init"),
        ("MOMO_STRIPE_KEY_", "stripe_init"),
        ("MOMO_TAXES_", "zero_trial"),
    )
    for prefix, stage in prefix_stages:
        if code.startswith(prefix):
            return stage

    steps = [step for step in list(raw.get("steps") or []) if isinstance(step, dict)]
    for step in reversed(steps):
        if str(step.get("status") or "").lower() in {"error", "failed"}:
            return str(step.get("key") or "unknown")[:80]
    if not steps:
        return "unknown" if code else ""

    last = str(steps[-1].get("key") or "").strip()
    next_stage = {
        "fingerprint": "checkout",
        "checkout": "promotion",
        "promotion": "stripe_init",
        "payment_method": "stripe_tax_region",
        "tax_region": "zero_trial",
        "stripe_tax_region": "zero_trial",
    }
    return next_stage.get(last, last or "unknown")


def _safe_log_text(value: Any, limit: int = 120) -> str:
    sanitized = sanitize_text(value)
    return " ".join(str(sanitized or "").split())[:limit] or "-"


def _log_batch_diagnostics(source: str, items: list[dict[str, Any]]) -> None:
    failed = [item for item in items if item.get("result") == "error"]
    if not failed:
        logger.info("[momo] batch source=%s completed=%s errors=0", source, len(items))
        return
    details: list[str] = []
    for item in failed:
        error = item.get("error") if isinstance(item.get("error"), dict) else {}
        details.append(
            "#%s label=%s code=%s stage=%s message=%s"
            % (
                item.get("index", "?"),
                _safe_log_text(item.get("label")),
                _safe_log_text(error.get("code") or "CHECK_FAILED", 80),
                _safe_log_text(item.get("failure_stage") or "unknown", 80),
                _safe_log_text(error.get("message") or "-", 420),
            )
        )
    logger.warning(
        "[momo] batch source=%s errors=%s/%s details=%s",
        source,
        len(failed),
        len(items),
        "; ".join(details),
    )


def _public_result(
    result: Any,
    *,
    label: str,
    email: str | None = None,
    index: int | None = None,
) -> dict[str, Any]:
    raw = result if isinstance(result, dict) else {}
    routing = _pick(
        raw.get("routing"),
        (
            "strategy",
            "payment_pool_size",
            "promo_pool_size",
            "promo_follows_payment",
            "payment_proxy",
            "promo_proxy",
        ),
    )
    for key in ("payment_proxy", "promo_proxy"):
        if key in routing:
            routing[key] = _mask_proxy(routing[key])
    momo = _pick(raw.get("momo"), ("available", "payment_methods", "methods"))
    if "payment_methods" not in momo and "methods" in momo:
        momo["payment_methods"] = momo.pop("methods")
    public = {
        "ok": bool(raw.get("ok")),
        "result": str(raw.get("result") or "error"),
        "label": label,
        "checked_at": raw.get("checked_at"),
        "context": _pick(
            raw.get("context"),
            (
                "billing_country",
                "currency",
                "checkout_kind",
                "mode",
                "fingerprint_mode",
                "fingerprint_summary",
            ),
        ),
        "routing": routing,
        "momo": momo,
        "zero_trial": _pick(
            raw.get("zero_trial"),
            ("eligible", "amount", "amount_source", "verified_at"),
        ),
        "reason_codes": list(raw.get("reason_codes") or [])[:20],
        "steps": [
            _pick(step, ("key", "label", "status", "detail"))
            for step in list(raw.get("steps") or [])[:30]
            if isinstance(step, dict)
        ],
    }
    error = raw.get("error")
    if isinstance(error, dict):
        public["error"] = _pick(error, ("code", "message"))
    elif error:
        public["error"] = {"code": "CHECK_FAILED", "message": "检测失败"}
    if public["result"] == "error":
        public["failure_stage"] = _failure_stage(raw)
    if email is not None:
        public["email"] = email
    if index is not None:
        public["index"] = index
    return public


def _unexpected_result(
    *,
    label: str,
    email: str | None = None,
    index: int | None = None,
    exc: Exception | None = None,
) -> dict[str, Any]:
    exception_type = type(exc).__name__ if exc is not None else "UnknownError"
    logger.warning(
        "[momo] unexpected item label=%s index=%s exception_type=%s",
        _safe_log_text(label),
        index if index is not None else "-",
        _safe_log_text(exception_type, 80),
    )
    return _public_result(
        {
            "ok": False,
            "result": "error",
            "error": {"code": "MOMO_CHECK_FAILED", "message": "该条检测发生未分类异常"},
            "steps": [],
        },
        label=label,
        email=email,
        index=index,
    )


def _pool_for_result(result: dict[str, Any]) -> tuple[str, str]:
    status = str(result.get("result") or "").strip().lower()
    if status == "eligible":
        return "momo", ""
    if status == "ineligible":
        return "upi", ""
    error = result.get("error") if isinstance(result.get("error"), dict) else {}
    return "pending", str(error.get("code") or "MOMO_CHECK_FAILED")[:120]


def _annotate_registered_pool(
    db_module: Any,
    email: str,
    result: dict[str, Any],
) -> dict[str, Any]:
    pool, error_code = _pool_for_result(result)
    updated = False
    updater = getattr(db_module, "update_registered_pool", None)
    if callable(updater):
        try:
            updated = bool(
                updater(
                    email,
                    pool,
                    source="momo_check",
                    error_code=error_code,
                )
            )
        except Exception:
            logger.warning(
                "[momo] pool update failed label=%s pool=%s",
                _safe_log_text(email),
                pool,
            )
    result["pool"] = pool
    result["pool_updated"] = updated
    return result


def _summary(items: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "eligible": sum(item.get("result") == "eligible" for item in items),
        "ineligible": sum(item.get("result") == "ineligible" for item in items),
        "error": sum(item.get("result") == "error" for item in items),
    }


def _batch_response(source: str, items: list[dict[str, Any]]) -> dict[str, Any]:
    _log_batch_diagnostics(source, items)
    return {
        "ok": True,
        "result": "batch",
        "total": len(items),
        "completed": len(items),
        "summary": _summary(items),
        "items": items,
    }


def create_momo_router(
    db_module: Any,
    *,
    checker_factory: CheckerFactory = MomoTrialChecker,
    status_reader: StatusReader = source_status,
) -> APIRouter:
    router = APIRouter(prefix="/api/momo", tags=["momo"])

    @router.get("/health")
    def health() -> dict[str, Any]:
        return {"ok": True, **status_reader()}

    @router.post("/check")
    def check(request: MomoCheckRequest) -> dict[str, Any]:
        common = _common_payload(request)
        checker = checker_factory()
        if request.source == "registered":
            emails = _normalize_emails(request.emails)
            if len(emails) != 1:
                raise HTTPException(400, "单条检测只能选择一个注册账号")
            email = emails[0]
            token, checkout_cookie, error = _registered_token(db_module, email)
            if error:
                return _annotate_registered_pool(db_module, email, error)
            payload = {
                **common,
                "access_token": token,
                "chatgpt_cookie": checkout_cookie,
                "email": email,
                "account_id": email,
            }
            try:
                return _annotate_registered_pool(
                    db_module,
                    email,
                    _public_result(checker.check(payload), label=email, email=email),
                )
            except Exception as exc:
                return _annotate_registered_pool(
                    db_module,
                    email,
                    _unexpected_result(label=email, email=email, exc=exc),
                )

        token = str(request.access_token or "").strip()
        if not token:
            raise HTTPException(400, "Access Token 不能为空")
        if len(token) > MAX_TOKEN_LENGTH:
            raise HTTPException(400, "Access Token 长度超过限制")
        try:
            return _public_result(
                checker.check({**common, "access_token": token}),
                label="手动 Token",
            )
        except Exception as exc:
            return _unexpected_result(label="手动 Token", exc=exc)

    @router.post("/batch-check")
    def batch_check(request: MomoBatchCheckRequest) -> dict[str, Any]:
        common = _common_payload(request)
        checker = checker_factory()
        if request.source == "registered":
            emails = _normalize_emails(request.emails)
            items: list[dict[str, Any]] = []
            for index, email in enumerate(emails, start=1):
                token, checkout_cookie, error = _registered_token(db_module, email)
                if error:
                    error["index"] = index
                    items.append(_annotate_registered_pool(db_module, email, error))
                    continue
                payload = {
                    **common,
                    "access_token": token,
                    "chatgpt_cookie": checkout_cookie,
                    "email": email,
                    "account_id": email,
                }
                try:
                    result = checker.check(payload)
                    items.append(_annotate_registered_pool(
                        db_module,
                        email,
                        _public_result(result, label=email, email=email, index=index),
                    ))
                except Exception as exc:
                    items.append(_annotate_registered_pool(
                        db_module,
                        email,
                        _unexpected_result(label=email, email=email, index=index, exc=exc),
                    ))
            return _batch_response("registered", items)

        try:
            raw = run_batch_check(
                {**common, "access_tokens": request.access_tokens},
                checker=checker,
            )
        except MomoCheckInputError as exc:
            raise HTTPException(400, str(exc)) from exc
        items = [
            _public_result(item, label=f"手动 Token #{index}", index=index)
            for index, item in enumerate(raw.get("items") or [], start=1)
        ]
        return _batch_response("manual", items)

    return router


router = create_momo_router(db)
