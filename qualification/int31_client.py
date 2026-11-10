"""Client for int31.space's public checkout-capability task API."""
from __future__ import annotations

import re
import time
from decimal import Decimal, InvalidOperation
from typing import Any, Callable
from urllib.parse import quote, urljoin, urlparse

import requests


BASE_URL = "https://int31.space"
CREATE_PATH = "/public/api/checkout-capabilities"
PENDING_STATUSES = {"QUEUED", "RUNNING"}
FAILED_STATUSES = {"FAILED", "CANCELED", "UNAVAILABLE"}
TERMINAL_STATUSES = {"SUCCEEDED", *FAILED_STATUSES}


class Int31Error(RuntimeError):
    """Base error for the public checkout-capability API."""


class Int31HTTPError(Int31Error):
    """The public API returned a non-success HTTP response."""

    def __init__(self, message: str, *, status_code: int = 0, retry_after: float = 0):
        super().__init__(message)
        self.status_code = status_code
        self.retry_after = min(60.0, max(0.0, retry_after))


class Int31TaskError(Int31Error):
    """The remote task reached a failed terminal status."""


class Int31TimeoutError(Int31Error):
    """The remote task did not reach a terminal status in time."""


def normalize_proxy_url(value: str) -> str:
    proxy = str(value or "").strip()
    if not proxy:
        raise ValueError("proxyUrl is required")
    if "://" not in proxy:
        fields = proxy.split(":")
        if len(fields) == 4:
            host, port, user, password = fields
            proxy = f"http://{quote(user, safe='')}:{quote(password, safe='')}@{host}:{port}"
        else:
            proxy = "http://" + proxy
    if not re.match(r"^(https?|socks5h?)://[^\s]+$", proxy, re.I):
        raise ValueError("proxyUrl format is invalid")
    return proxy


class Int31CheckoutClient:
    def __init__(
        self,
        *,
        session: Any | None = None,
        base_url: str = BASE_URL,
        poll_interval: float = 1.0,
        timeout: float = 240.0,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.session = session or requests.Session()
        self.base_url = base_url.rstrip("/")
        self.poll_interval = max(0.0, float(poll_interval))
        self.timeout = max(0.1, float(timeout))
        self.sleep = sleep
        self.monotonic = monotonic

    @property
    def create_url(self) -> str:
        return self.base_url + CREATE_PATH

    def check(self, access_token: str, proxy_url: str, targets: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        token = str(access_token or "").strip()
        if not token:
            raise ValueError("accessToken is required")
        proxy = normalize_proxy_url(proxy_url)
        request_timeout = min(30.0, self.timeout)
        response = self.session.post(
            self.create_url,
            json={"accessToken": token, "proxyUrl": proxy},
            timeout=request_timeout,
        )
        task = self._payload(response)
        started = self.monotonic()
        while str(task.get("status") or "").upper() in PENDING_STATUSES:
            task_id = str(task.get("taskId") or "").strip()
            if self.monotonic() - started >= self.timeout:
                raise Int31TimeoutError(f"int31 task {task_id or 'unknown'} timed out")
            self.sleep(self.poll_interval)
            status_url = self._status_url(task)
            task = self._payload(self.session.get(status_url, timeout=request_timeout))
        return self._normalize_terminal(task, targets=targets)

    def _payload(self, response: Any) -> dict[str, Any]:
        status_code = int(getattr(response, "status_code", 0) or 0)
        if status_code < 200 or status_code >= 300:
            headers = getattr(response, "headers", {}) or {}
            try:
                retry_after = float(headers.get("Retry-After", 0))
            except (TypeError, ValueError):
                retry_after = 0
            raise Int31HTTPError(f"int31 checkout-capabilities HTTP {status_code or 'error'}", status_code=status_code, retry_after=retry_after)
        try:
            payload = response.json()
        except Exception as exc:
            raise Int31HTTPError("int31 checkout-capabilities returned invalid JSON") from exc
        if not isinstance(payload, dict):
            raise Int31HTTPError("int31 checkout-capabilities returned invalid JSON")
        return payload

    def _status_url(self, task: dict[str, Any]) -> str:
        task_id = str(task.get("taskId") or "").strip()
        raw = str(task.get("statusUrl") or "").strip()
        if not raw and task_id:
            raw = f"{CREATE_PATH}/{task_id}"
        parsed = urlparse(raw)
        if parsed.scheme or parsed.netloc or not raw.startswith(CREATE_PATH + "/"):
            raise Int31TaskError(f"int31 task {task_id or 'unknown'} returned invalid statusUrl")
        return urljoin(self.base_url + "/", raw.lstrip("/"))

    def _normalize_terminal(self, task: dict[str, Any], targets: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        status = str(task.get("status") or "").upper()
        task_id = str(task.get("taskId") or "").strip()
        if status in FAILED_STATUSES:
            failure = str(task.get("failureType") or "unknown failure")
            raise Int31TaskError(f"int31 task {task_id or 'unknown'} {status}: {failure}")
        if status != "SUCCEEDED":
            raise Int31TaskError(f"int31 task {task_id or 'unknown'} returned unknown status {status or 'EMPTY'}")
        raw_result = task.get("result")
        if not isinstance(raw_result, dict):
            raise Int31TaskError(f"int31 task {task_id or 'unknown'} SUCCEEDED without result")

        methods = sorted({
            str(method).strip().lower()
            for method in raw_result.get("paymentMethodTypes") or []
            if str(method).strip()
        })
        backend = str(raw_result.get("checkoutBackend") or "")
        processor = str(raw_result.get("processorEntity") or "")
        country = str(raw_result.get("providerCountry") or "").upper()
        currency = str(raw_result.get("currency") or "").upper()
        amount_minor = raw_result.get("amountMinor")
        # A boolean, omitted field or unparseable amount is not zero-price evidence.
        try:
            amount = Decimal(str(amount_minor)) if not isinstance(amount_minor, bool) else None
            amount_known = amount is not None and amount.is_finite() and amount >= 0
        except (InvalidOperation, ValueError):
            amount, amount_known = None, False
        is_free_trial = bool(amount_known and amount == 0)
        methods_text = ", ".join(methods) if methods else "(none)"

        selected = list(targets or [])
        if not selected:
            selected = [{
                "preset": "momo_vn",
                "channel": "momo",
                "country": country or "VN",
                "currency": currency or "VND",
                "label": "越南 MoMo",
            }]

        regions = []
        for entry in selected:
            preset = str(entry.get("preset") or entry.get("name") or "momo_vn")
            channel = str(entry.get("channel") or preset).strip().lower()
            label = str(entry.get("label") or entry.get("name") or preset)
            has_channel = channel in methods
            # Qualified only when the target channel exists AND checkout amount is a free trial (0).
            requested_country = str(entry.get("country") or "").upper()
            requested_currency = str(entry.get("currency") or "").upper()
            reasons = []
            if not has_channel:
                reasons.append("CHANNEL_UNAVAILABLE")
            if not amount_known:
                reasons.append("AMOUNT_UNKNOWN")
            elif not is_free_trial:
                reasons.append("AMOUNT_NONZERO")
            if requested_country and country != requested_country:
                reasons.append("COUNTRY_MISMATCH" if country else "COUNTRY_UNKNOWN")
            if requested_currency and currency != requested_currency:
                reasons.append("CURRENCY_MISMATCH" if currency else "CURRENCY_UNKNOWN")
            hit = not reasons
            if hit:
                evidence = f"int31 published {channel} with free trial 0; available: {methods_text}"
            elif has_channel and not is_free_trial:
                evidence = f"int31 published {channel} but amount {amount_minor} is not free trial; available: {methods_text}"
            elif has_channel:
                evidence = f"int31 published {channel} but checkout country/currency does not match target; available: {methods_text}"
            else:
                evidence = f"int31 missing {channel}; available: {methods_text}"
            regions.append({
                "preset": preset,
                "name": label,
                "channel": channel,
                "qualified": hit,
                "country": country,
                "currency": currency,
                "requested_country": requested_country,
                "requested_currency": requested_currency,
                "reason_codes": reasons,
                "checkout_backend": backend,
                "processor_entity": processor,
                "payment_method_types": methods,
                "amount_minor": amount_minor,
                "is_free_trial": is_free_trial,
                "evidence": evidence,
            })

        qualified = any(row["qualified"] for row in regions)
        evidence = (
            f"int31 matched selected channels; available: {methods_text}"
            if qualified else
            f"int31 selected targets did not satisfy channel, zero amount and region; available: {methods_text}"
        )
        return {
            "qualified": qualified,
            "result": "eligible" if qualified else "ineligible",
            "reason_codes": sorted({code for row in regions for code in row["reason_codes"]}) if not qualified else [],
            "available_channels": methods,
            "regions": regions,
            "email": str(task.get("email") or ""),
            "task_id": task_id,
            "checkout_backend": backend,
            "processor_entity": processor,
            "provider_country": country,
            "currency": currency,
            "amount_minor": amount_minor,
            "is_free_trial": is_free_trial,
            "payment_method_types": methods,
            "evidence": evidence,
        }


def check_checkout_capabilities(
    access_token: str,
    proxy_url: str,
    targets: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return Int31CheckoutClient().check(access_token, proxy_url, targets=targets)
