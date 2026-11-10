"""Receive-API mail adapter for rebind account reauthorization only."""
from __future__ import annotations

import json
import time
from datetime import datetime
from typing import Any, Optional
from urllib.parse import urlparse

import requests

from mail_providers.base import MailProvider, extract_otp


class RebindApiMailProvider(MailProvider):
    """Read OTP codes from the URL stored in the dedicated rebind mailbox pool."""

    kind = "rebind_api"
    display_name = "换绑邮箱收信 API"
    pooled = False
    ephemeral = False
    accepts_existing_account = True

    def __init__(self, email: str, mail_api: str):
        self.email = (email or "").strip().lower()
        self.mail_api = (mail_api or "").strip()
        parsed = urlparse(self.mail_api)
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("换绑邮箱收信 API 必须是 HTTP/HTTPS 地址")

    @classmethod
    def from_config(cls, settings: dict, account: Optional[dict] = None):
        account = account or {}
        return cls(str(account.get("email") or ""), str(account.get("mail_api") or ""))

    def create_mailbox(self) -> str:
        return self.email

    @staticmethod
    def _parse_time(value: Any) -> float | None:
        if value in (None, ""):
            return None
        if isinstance(value, (int, float)):
            timestamp = float(value)
            return timestamp / 1000.0 if timestamp > 1e12 else timestamp
        text = str(value).strip()
        if not text:
            return None
        if text.isdigit():
            return RebindApiMailProvider._parse_time(int(text))
        try:
            if text.endswith("Z"):
                text = text[:-1] + "+00:00"
            return datetime.fromisoformat(text).timestamp()
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _candidates(payload: Any) -> list[dict]:
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]
        if not isinstance(payload, dict):
            return []
        for key in ("data", "mail", "mails", "items", "result", "messages", "list"):
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
            if isinstance(value, dict):
                return [value]
        return [payload]

    def _fetch_latest_otp(self, issued_after: float | None) -> str:
        response = requests.get(self.mail_api, timeout=20)
        response.raise_for_status()
        raw = response.text or ""
        try:
            payload: Any = response.json()
        except (ValueError, json.JSONDecodeError):
            payload = raw
        if isinstance(payload, (dict, list)):
            for item in self._candidates(payload):
                received_at = next(
                    (self._parse_time(item.get(key)) for key in (
                        "time", "timestamp", "created_at", "date", "received_at", "ts"
                    ) if self._parse_time(item.get(key)) is not None),
                    None,
                )
                if issued_after is not None and received_at is not None and received_at + 1 < issued_after:
                    continue
                blob = " ".join(str(item.get(key) or "") for key in (
                    "code", "otp", "subject", "title", "content", "body", "text", "html", "message"
                ))
                code = extract_otp(blob or str(item))
                if code:
                    return code
            return extract_otp(raw) or ""
        return extract_otp(str(payload)) or ""

    def wait_for_otp(
        self,
        email_addr: str,
        timeout: int = 120,
        issued_after: Optional[float] = None,
        strict_issued_after: bool = False,
        allow_recent_snapshot_fallback: bool = False,
    ) -> str:
        deadline = time.time() + max(5, int(timeout))
        last_error = ""
        while time.time() < deadline:
            try:
                code = self._fetch_latest_otp(issued_after)
                if code:
                    return code
            except Exception as exc:  # network/provider error; retry until timeout
                last_error = str(exc)
            time.sleep(2.5)
        suffix = f" ({last_error})" if last_error else ""
        raise TimeoutError(f"{int(timeout)} 秒内未从换绑邮箱收信 API 取得验证码{suffix}")
