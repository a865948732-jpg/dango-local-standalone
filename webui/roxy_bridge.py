"""Roxy browser bridge owned by repo_0810.

The subprocess receives no mailbox identity or credential in argv.  The owning
registration worker passes a one-shot JSON request over stdin and serves OTP
from the already-created repo_0810 MailProvider over a nonce-protected loopback
callback.  The worker may use Roxy/Profile browser code, but it never imports or
writes the historical project's mailbox, job, or account stores.
"""
from __future__ import annotations

import json
import hashlib
import inspect
import logging
import os
import re
import secrets
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from safe_diagnostics import (
    safe_otp_failure_metadata, safe_public_error, safe_traceback_summary, sanitize_text,
    safe_roxy_create_rejection, safe_roxy_rejection_metadata,
    safe_proxy_probe_metadata,
)
from .roxy_settings import read_settings, settings_path, create_profile_payload, proxy_info_from_url

ROOT = Path(__file__).resolve().parents[1]
WORKER = ROOT / "webui" / "roxy_worker.py"
ROXY_API_BASE = os.getenv("ROXY_API_BASE", "http://127.0.0.1:50000").rstrip("/")
ROXY_WORKSPACE_ID = int(os.getenv("ROXY_WORKSPACE_ID") or 0)
ROXY_PROJECT_ID = int(os.getenv("ROXY_PROJECT_ID") or 0)
if settings_path().is_file():
    _initial_settings = read_settings()
    ROXY_API_BASE = _initial_settings.api_base
    ROXY_WORKSPACE_ID = int(_initial_settings.workspace_id)
    ROXY_PROJECT_ID = int(_initial_settings.project_id)
_ROXY_PREFERRED_MODULE_SETTING = "roxy_preferred_module_id"
_ROXY_PREFERRED_EGRESS_TAG_SETTING = "roxy_preferred_egress_ip_tag"
_ROXY_PREFERRED_MODULE_ENV = "REPO0810_ROXY_PREFERRED_MODULE_ID"
_ROXY_PREFERRED_EGRESS_TAG_ENV = "REPO0810_ROXY_PREFERRED_EGRESS_IP_TAG"
_CREATE_PROFILE_LOCK = threading.Lock()
_ROXY_PROXY_CHECK_MAX_AGE_SECONDS = 5 * 60
_ROXY_PROXY_DETECTION_SUCCESS_TTL_SECONDS = 5 * 60
_ROXY_PROXY_DETECTION_FAILURE_TTL_SECONDS = 60
_ROXY_PROXY_DETECTION_CACHE_LOCK = threading.Lock()
_ROXY_PROXY_DETECTION_CACHE: dict[str, tuple[float, dict | None]] = {}
_ROXY_PROXY_DETECTION_REFRESH_LOCK = threading.Lock()
_ROXY_EGRESS_CAPACITY_MAX_ATTEMPTS = 3
_ROXY_EGRESS_CAPACITY_RETRY_DELAY_SECONDS = 0.25

_WORKER_STDERR_MAX_BYTES = 32 * 1024
_WORKER_STDERR_SUMMARY_MAX_CHARS = 180
_WORKER_EXCEPTION_RE = re.compile(
    r"(?im)^\s*(?:[A-Za-z_][A-Za-z0-9_]*\.)*"
    r"([A-Za-z_][A-Za-z0-9_]*(?:Error|Exception|Timeout|Interrupt|Exit))"
    r"\s*(?::\s*(.*?))?\s*$"
)
_WORKER_SAFE_STDERR_RE = re.compile(
    r"(?i)(?:error|exception|failed|failure|invalid|timeout|timed\s+out|"
    r"proxy|network|connection|http|module|selenium|profile|session|"
    r"auth|otp|password|roxy|startup|import)"
)


class RoxyWorkerBoundaryError(RuntimeError):
    """Secret-free diagnostics for failures between worker and bridge."""

    def __init__(
        self,
        message: str,
        *,
        failure_phase: str = "worker_preflight",
        exception_type: str = "Error",
        page_state: dict | None = None,
    ):
        self.failure_phase = failure_phase
        self.exception_type = exception_type
        self.page_state = dict(page_state) if isinstance(page_state, dict) else {}
        super().__init__(message)


class RoxyStartupError(RuntimeError):
    """Compiler-owned startup reason without proxy or upstream response text."""

    def __init__(self, message: str, *, phase: str, cause: str,
                 original: BaseException | None = None, api_code: object = None,
                 rejection: dict | None = None, http_status: object = None,
                 proxy_probe: dict | None = None):
        self.failure_phase = phase
        self.failure_cause = cause
        self.exception_type = type(original).__name__ if original else "RuntimeError"
        self.safe_message = message
        self.page_state = {}
        self.proxy_probe = safe_proxy_probe_metadata(proxy_probe)
        if self.proxy_probe:
            self.page_state["proxy_probe"] = self.proxy_probe
            self.exception_type = self.proxy_probe.get("exception_type", self.exception_type)
            if http_status is None:
                http_status = self.proxy_probe.get("http_status")
        self.roxy_rejection = safe_roxy_rejection_metadata(rejection)
        if type(http_status) is int and 100 <= http_status <= 599:
            self.http_status = http_status
        code = self.roxy_rejection.get("roxy_code") or safe_roxy_create_rejection({"code": api_code}).get("roxy_code")
        if code:
            self.page_state["roxy_api_code"] = code
            self.safe_message += f" (Roxy code={code})"
        if self.roxy_rejection:
            self.page_state["roxy_rejection"] = self.roxy_rejection
        if cause == "roxy_daily_quota":
            self.page_state["roxy_profile_creation_blocked"] = "daily_quota"
        super().__init__(message)


class RoxyEgressHealthCheckError(RuntimeError):
    """The Roxy health boundary was unavailable, so capacity is unknown."""

    def __init__(self):
        super().__init__("Roxy 健康出口检查暂时不可用，请稍后重试")


class RoxyProfileQuotaError(RuntimeError):
    """Roxy refused Profile creation because the workspace quota is exhausted."""

    def __init__(self, message: str, *, code: object = None, api_message: str = "",
                 rejection: dict | None = None):
        self.roxy_rejection = safe_roxy_rejection_metadata(rejection) or safe_roxy_create_rejection(
            {"code": code, "msg": api_message},
        )
        self.code = self.roxy_rejection.get("roxy_code", "")
        self.api_message = "窗口单日创建次数已经超出"
        self.failure_phase = "create_profile"
        self.failure_cause = "roxy_daily_quota"
        self.exception_type = "RuntimeError"
        self.safe_message = "Roxy 每日窗口创建额度已用尽"
        self.page_state = {
            "roxy_rejection": self.roxy_rejection,
            "roxy_api_code": self.code,
            "roxy_profile_creation_blocked": "daily_quota",
        }
        super().__init__(self.safe_message)


def _is_roxy_profile_quota_error(code: object, message: object) -> bool:
    """Return whether a create response is a hard quota stop, not a bad egress.

    Roxy uses code 416 for the workspace's daily Profile-create limit.  The
    message check keeps this compatible with deployments that omit/serialize
    the numeric code differently while avoiding retries against every healthy
    proxy module when the limit is already global to the workspace.
    """
    normalized_code = str(code or "").strip().lower()
    normalized_message = str(message or "").strip().lower()
    return normalized_code == "416" or "窗口单日创建次数已经超出" in normalized_message


def _read_worker_output(stream, process_value=None) -> bytes:
    """Read bounded bytes from CompletedProcess or the temporary output file."""
    value = process_value
    if isinstance(value, str):
        value = value.encode("utf-8", errors="replace")
    if isinstance(value, (bytes, bytearray)) and value:
        return bytes(value)[:_WORKER_STDERR_MAX_BYTES]
    try:
        stream.seek(0)
        return bytes(stream.read(_WORKER_STDERR_MAX_BYTES) or b"")
    except Exception:
        return b""


def _worker_exception_type(stderr: str) -> str:
    match = _WORKER_EXCEPTION_RE.search(stderr or "")
    if match:
        return match.group(1)
    # A process can terminate while printing only the exception name. Keep a
    # conservative suffix allow-list instead of exposing arbitrary stderr text.
    for token in re.findall(r"\b[A-Za-z_][A-Za-z0-9_]{0,79}\b", stderr or ""):
        if re.search(r"(?:Error|Exception|Timeout|Interrupt|Exit)$", token):
            return token
    return "Error"


def _worker_stderr_summary(stderr: bytes) -> str:
    """Return a short allow-listed, credential-redacted stderr summary."""
    decoded = bytes(stderr or b"").decode("utf-8", errors="replace")
    if not decoded:
        return ""
    sanitized = sanitize_text(decoded)
    # Do not persist traceback paths or long opaque values even when a line did
    # not label them as a credential.
    sanitized = re.sub(r"\b[A-Za-z0-9+/=_-]{24,}\b", "[VALUE]", sanitized)
    lines: list[str] = []
    for raw_line in sanitized.splitlines():
        line = re.sub(r"\s+", " ", raw_line).strip()
        if not line or line.startswith("Traceback (most recent call last):"):
            continue
        if re.match(r'^File "[^\"]+", line \d+', line):
            continue
        if not _WORKER_SAFE_STDERR_RE.search(line) and "[REDACTED]" not in line:
            continue
        if line not in lines:
            lines.append(line[:120])
        if len(lines) >= 3:
            break
    return " | ".join(lines)[:_WORKER_STDERR_SUMMARY_MAX_CHARS]


def _worker_boundary_state(proc, stderr: bytes, reason: str) -> tuple[str, dict]:
    """Build structured diagnostics for missing or malformed worker output."""
    stderr_text = bytes(stderr or b"").decode("utf-8", errors="replace")
    exception_type = _worker_exception_type(stderr_text)
    state: dict[str, Any] = {
        "worker_exit_code": getattr(proc, "returncode", None),
        "worker_exception": exception_type,
        "worker_boundary_reason": reason,
    }
    summary = _worker_stderr_summary(stderr)
    if summary:
        state["worker_stderr_summary"] = summary
    return exception_type, state


class RoxyProfileLease:
    def __init__(self, pool, slot: dict):
        self._pool = pool
        self._slot = slot
        self._released = False

    @property
    def profile_id(self) -> str:
        return str(self._slot.get("profile_id") or "")

    def bind_profile(self, profile_id: str) -> None:
        self._slot["profile_id"] = str(profile_id or "")

    def retire(self) -> None:
        """Do not return this Profile to the reusable pool after this run."""
        self._pool._retire(self._slot)

    def retain_window(self) -> None:
        with self._pool._condition:
            self._slot["retained_window"] = True

    def release(self) -> None:
        if self._released:
            return
        self._released = True
        self._pool._release(self._slot)


class RoxyProfilePool:
    """Bounded FIFO slots: at most five Roxy windows, then reuse."""

    def __init__(self, max_size: int = 5):
        self.max_size = min(5, max(1, int(max_size)))
        self._condition = threading.Condition()
        self._slots: list[dict] = []
        self._seeded = False

    @property
    def slot_count(self) -> int:
        with self._condition:
            return len(self._slots)

    @property
    def profile_ids(self) -> list[str]:
        with self._condition:
            return [str(slot.get("profile_id") or "") for slot in self._slots]

    @property
    def retained_profile_ids(self) -> list[str]:
        with self._condition:
            return [str(slot.get("profile_id") or "") for slot in self._slots
                    if slot.get("retained_window")]

    def release_closed_retained(self, idle_profile_ids: list[str]) -> None:
        with self._condition:
            self._slots = [slot for slot in self._slots
                           if not (slot.get("retained_window")
                                   and slot.get("profile_id") in idle_profile_ids)]
            self._condition.notify_all()

    def status(self) -> dict:
        with self._condition:
            return {
                "capacity": self.max_size,
                "slots": len(self._slots),
                "in_use": sum(1 for slot in self._slots if slot.get("busy")),
            }

    def seed_profiles(self, profile_ids: list[str]) -> None:
        with self._condition:
            if self._seeded:
                return
            known = {str(slot.get("profile_id") or "") for slot in self._slots}
            for raw in profile_ids:
                profile_id = str(raw or "")
                if not profile_id or profile_id in known:
                    continue
                if len(self._slots) >= self.max_size:
                    break
                self._slots.append({"busy": False, "profile_id": profile_id})
                known.add(profile_id)
            self._seeded = True

    def sync_profiles(
        self,
        profile_ids: list[str],
        *,
        preferred_profile_ids: list[str] | None = None,
    ) -> None:
        """Reconcile reusable idle slots with Roxy's current profile list."""
        current = []
        for raw in profile_ids:
            profile_id = str(raw or "").strip()
            if profile_id and profile_id not in current:
                current.append(profile_id)
        current_set = set(current)
        with self._condition:
            # Busy slots belong to active tasks and must not be disturbed even
            # though Roxy reports their windows as open. Idle slots are valid
            # only while their Profile still appears in the current idle list.
            self._slots = [
                slot for slot in self._slots
                if slot["busy"] or slot.get("retained_window")
                or (
                    str(slot.get("profile_id") or "")
                    and str(slot.get("profile_id") or "") in current_set
                )
            ]
            known = {str(slot.get("profile_id") or "") for slot in self._slots}
            for profile_id in current:
                if profile_id in known or len(self._slots) >= self.max_size:
                    continue
                self._slots.append({"busy": False, "profile_id": profile_id})
                known.add(profile_id)
            preferred = [
                str(profile_id or "").strip()
                for profile_id in (preferred_profile_ids or [])
                if str(profile_id or "").strip()
            ]
            if preferred:
                preferred_rank = {profile_id: index for index, profile_id in enumerate(preferred)}
                idle_positions = [
                    index for index, slot in enumerate(self._slots) if not slot["busy"]
                ]
                idle_slots = [self._slots[index] for index in idle_positions]
                idle_slots = [
                    slot
                    for _index, slot in sorted(
                        enumerate(idle_slots),
                        key=lambda item: (
                            preferred_rank.get(
                                str(item[1].get("profile_id") or ""),
                                len(preferred_rank) + item[0],
                            ),
                            item[0],
                        ),
                    )
                ]
                for index, slot in zip(idle_positions, idle_slots):
                    self._slots[index] = slot
            self._seeded = True
            self._condition.notify_all()

    def acquire(
        self,
        timeout: float | None = None,
        *,
        exclude_profile_id: str = "",
        required_profile_id: str = "",
        allow_existing_profile: bool = True,
    ) -> RoxyProfileLease:
        excluded = str(exclude_profile_id or "")
        required = str(required_profile_id or "")
        deadline = None if timeout is None else time.monotonic() + max(0, timeout)
        with self._condition:
            while True:
                if required:
                    required_slot = next(
                        (
                            slot for slot in self._slots
                            if str(slot.get("profile_id") or "") == required
                        ),
                        None,
                    )
                    if required_slot is None:
                        if len(self._slots) >= self.max_size:
                            raise RuntimeError("指定的 Roxy Profile 不在五窗口池中")
                        required_slot = {"busy": False, "profile_id": required}
                        self._slots.append(required_slot)
                    if not required_slot["busy"]:
                        required_slot["busy"] = True
                        return RoxyProfileLease(self, required_slot)
                    remaining = None if deadline is None else deadline - time.monotonic()
                    if remaining is not None and remaining <= 0:
                        raise TimeoutError("等待指定 Roxy Profile 槽位超时")
                    self._condition.wait(remaining)
                    continue
                if not allow_existing_profile:
                    # A system-direct task must let the worker create an
                    # unbound Profile. Drop idle bound slots here (and again
                    # after every wake-up) so a concurrently released proxy
                    # Profile can never be mistaken for a direct one.
                    self._slots = [
                        slot
                        for slot in self._slots
                        if slot["busy"] or slot.get("retained_window") or not str(slot.get("profile_id") or "")
                    ]
                for slot in self._slots:
                    profile_id = str(slot.get("profile_id") or "")
                    if (
                        not slot["busy"]
                        and not slot.get("retained_window")
                        and profile_id != excluded
                        and (allow_existing_profile or not profile_id)
                    ):
                        slot["busy"] = True
                        return RoxyProfileLease(self, slot)
                if len(self._slots) < self.max_size:
                    slot = {"busy": True, "profile_id": ""}
                    self._slots.append(slot)
                    return RoxyProfileLease(self, slot)
                if all(slot.get("retained_window") for slot in self._slots):
                    raise RuntimeError("保留的 Roxy 窗口已占满容量，请先手动关闭窗口")
                remaining = None if deadline is None else deadline - time.monotonic()
                if remaining is not None and remaining <= 0:
                    raise TimeoutError("等待 Roxy 窗口槽位超时")
                self._condition.wait(remaining)

    def _release(self, slot: dict) -> None:
        with self._condition:
            if slot.get("retired"):
                try:
                    self._slots.remove(slot)
                except ValueError:
                    pass
                self._condition.notify_all()
                return
            slot["busy"] = False
            self._condition.notify()

    def _retire(self, slot: dict) -> None:
        with self._condition:
            slot["retired"] = True


PROFILE_POOL = RoxyProfilePool(max_size=(read_settings().max_windows if settings_path().is_file()
                                      else int(os.getenv("REPO0810_ROXY_MAX_WINDOWS", "5"))))


class RoxyEgressLease:
    def __init__(self, pool, egress_tag: str):
        self._pool = pool
        self._egress_tag = egress_tag
        self._released = False

    @property
    def egress_tag(self) -> str:
        return self._egress_tag

    def release(self) -> None:
        if self._released:
            return
        self._released = True
        self._pool._release(self._egress_tag)


class RoxyEgressPool:
    """Process-wide exclusive ownership keyed by one-way Roxy egress tags."""

    def __init__(self):
        self._condition = threading.Condition()
        self._in_use: set[str] = set()

    def acquire_any(
        self,
        egress_tags: list[str],
        timeout: float | None = None,
    ) -> RoxyEgressLease:
        normalized = list(dict.fromkeys(
            str(tag or "").strip() for tag in egress_tags if str(tag or "").strip()
        ))
        if not normalized:
            raise RuntimeError("Roxy Profile 缺少可验证出口，不能建立独占 lease")
        deadline = None if timeout is None else time.monotonic() + max(0.0, timeout)
        with self._condition:
            while True:
                available = next(
                    (tag for tag in normalized if tag not in self._in_use),
                    "",
                )
                if available:
                    self._in_use.add(available)
                    return RoxyEgressLease(self, available)
                remaining = None if deadline is None else deadline - time.monotonic()
                if remaining is not None and remaining <= 0:
                    raise TimeoutError("等待 Roxy 独占出口超时")
                self._condition.wait(remaining)

    def acquire(self, egress_tag: str, timeout: float | None = None) -> RoxyEgressLease:
        return self.acquire_any([egress_tag], timeout=timeout)

    def _release(self, egress_tag: str) -> None:
        with self._condition:
            self._in_use.discard(egress_tag)
            self._condition.notify_all()


ROXY_EGRESS_POOL = RoxyEgressPool()


def _existing_roxy_profile_ids(*, strict_idle: bool = False) -> list[str]:
    try:
        import requests

        response = requests.get(
            ROXY_API_BASE + "/browser/list",
            params={
                "workspaceId": ROXY_WORKSPACE_ID,
                "page": 1,
                "pageSize": 100 if strict_idle else PROFILE_POOL.max_size,
            },
            timeout=20,
        )
        if strict_idle:
            response.raise_for_status()
        payload = response.json()
        if strict_idle and payload.get("code") not in (0, 200, "0", "200"):
            return []
        rows = ((payload.get("data") or {}).get("rows") or [])
        idle_statuses = {"0", "false", "closed"} if strict_idle else {"", "0", "false", "closed"}
        return [
            str(row.get("dirId") or "")
            for row in rows
            if row.get("dirId")
            and str(row.get("openStatus") if row.get("openStatus") is not None else "")
            .strip()
            .lower() in idle_statuses
        ]
    except Exception:
        return []


def _saved_roxy_preference() -> dict[str, str]:
    """Read the persisted fast-egress preference without exposing credentials."""
    module_id = str(os.getenv(_ROXY_PREFERRED_MODULE_ENV) or "").strip()
    ip_tag = str(os.getenv(_ROXY_PREFERRED_EGRESS_TAG_ENV) or "").strip()
    try:
        from . import db

        module_id = module_id or str(
            db.get_setting(_ROXY_PREFERRED_MODULE_SETTING, "")
        ).strip()
        ip_tag = ip_tag or str(
            db.get_setting(_ROXY_PREFERRED_EGRESS_TAG_SETTING, "")
        ).strip()
    except Exception:
        # Preference is an optimization only. A missing/unavailable settings
        # store must never prevent fallback to another healthy Roxy module.
        pass
    return {"module_id": module_id, "ip_tag": ip_tag}


def _roxy_profile_ip_tags(profile_ids: list[str]) -> dict[str, str]:
    """Return one-way egress tags for requested Profiles; never expose IPs."""
    wanted = {str(profile_id or "").strip() for profile_id in profile_ids}
    wanted.discard("")
    if not wanted:
        return {}
    try:
        import requests

        payload = requests.get(
            ROXY_API_BASE + "/browser/list",
            params={
                "workspaceId": ROXY_WORKSPACE_ID,
                "page": 1,
                "pageSize": 100,
            },
            timeout=20,
        ).json()
        tags: dict[str, str] = {}
        for row in ((payload.get("data") or {}).get("rows") or []):
            profile_id = str(row.get("dirId") or "").strip()
            if profile_id not in wanted:
                continue
            raw_ip = str(((row.get("proxyInfo") or {}).get("lastIp") or "")).strip()
            if raw_ip:
                tags[profile_id] = hashlib.sha256(raw_ip.encode("utf-8")).hexdigest()
        return tags
    except Exception:
        return {}


def _delete_roxy_profile(profile_id: str) -> None:
    """Delete one Roxy Profile, closing a hard-timed-out window when necessary."""
    profile_id = str(profile_id or "").strip()
    if not profile_id:
        return
    import requests
    preferences = read_settings()

    def delete_once() -> dict:
        response = requests.post(
            ROXY_API_BASE + preferences.delete_path,
            json={"workspaceId": ROXY_WORKSPACE_ID, "dirIds": [profile_id]},
            timeout=30,
        )
        response.raise_for_status()
        return response.json()

    payload = delete_once()
    if payload.get("code") in (None, 0, 200, "0", "200"):
        return

    # A process-level deadline exits before the worker's browser cleanup can
    # run. Close only this exact failed Profile, then retry its deletion once.
    response = requests.post(
        ROXY_API_BASE + preferences.close_path,
        json={"workspaceId": ROXY_WORKSPACE_ID, "dirId": profile_id},
        timeout=30,
    )
    response.raise_for_status()
    close_payload = response.json()
    if close_payload.get("code") not in (None, 0, 200, "0", "200"):
        raise RuntimeError(
            close_payload.get("msg")
            or close_payload.get("message")
            or "Roxy 关闭失败 Profile 窗口失败"
        )
    time.sleep(1)
    payload = delete_once()
    if payload.get("code") not in (None, 0, 200, "0", "200"):
        raise RuntimeError(payload.get("msg") or payload.get("message") or "Roxy 删除 Profile 失败")


def _finish_owned_profile(profile_id: str, preferences) -> None:
    if not profile_id or preferences.keep_browser_open:
        return
    import requests
    response = requests.post(
        ROXY_API_BASE + preferences.close_path,
        json={"workspaceId": ROXY_WORKSPACE_ID, "dirId": profile_id}, timeout=30,
    )
    response.raise_for_status()
    payload = response.json()
    if payload.get("code") not in (None, 0, 200, "0", "200"):
        raise RuntimeError("Roxy 本次环境关闭失败")
    if preferences.delete_after_run:
        _delete_roxy_profile(profile_id)


def refresh_retained_profile_slots() -> None:
    if PROFILE_POOL.retained_profile_ids:
        PROFILE_POOL.release_closed_retained(_existing_roxy_profile_ids(strict_idle=True))


def _probe_custom_proxy_with_recovery(proxy: str):
    from .proxy_screening import _probe
    transient = {'peer_disconnected', 'connection_reset', 'connection_aborted'}
    for attempt in range(1, 4):
        result = _probe(proxy)
        if result.ok:
            return result
        details = safe_proxy_probe_metadata(getattr(result, 'diagnostics', None))
        if details:
            details['attempt_count'] = attempt
            result.diagnostics = details
        if (attempt == 3 or details.get('stage') != 'request'
                or details.get('transport_reason') not in transient):
            return result
        logging.getLogger(__name__).warning(
            '[Roxy proxy] 出口查询连接中断 (%s)，同一代理 %.1f 秒后重试 (%d/3)',
            details['transport_reason'], 0.5 * attempt, attempt + 1,
        )
        time.sleep(0.5 * attempt)


def _custom_proxy_ip_tag(proxy: str, options: dict) -> str:
    import ipaddress
    screening = options.get("proxy_screening") or {}
    if isinstance(screening, dict) and screening.get("accepted") and screening.get("ip"):
        raw_ip = str(screening["ip"])
    else:
        first, second = _probe_custom_proxy_with_recovery(proxy), _probe_custom_proxy_with_recovery(proxy)
        if not first.ok or not second.ok:
            failed = first if not first.ok else second
            code = getattr(failed, "error_code", "")
            diagnostics = safe_proxy_probe_metadata(getattr(failed, "diagnostics", None))
            if diagnostics:
                diagnostics["pass_index"] = 1 if not first.ok else 2
            reasons = {
                "proxy_auth_failed": "Roxy 代理连接或认证失败",
                "proxy_connect_timeout": "Roxy 代理连接超时",
                "intel_conflict": "Roxy 代理出口情报不一致",
                "exit_lookup_failed": "Roxy 代理出口 IP 查询失败",
            }
            cause = code if code in reasons else "proxy_probe_failed"
            raise RoxyStartupError(reasons.get(code, "Roxy 代理出口检查失败"),
                                   phase="proxy_check", cause=cause, proxy_probe=diagnostics)
        if not first.ip or first.ip != second.ip:
            raise RoxyStartupError("Roxy 两次代理检测的出口 IP 不一致或缺失",
                                   phase="proxy_check", cause="proxy_exit_unstable")
        raw_ip = second.ip
    try:
        normalized = str(ipaddress.ip_address(raw_ip))
    except ValueError as exc:
        raise RoxyStartupError("Roxy 内置代理缺少有效出口 IP",
                               phase="proxy_check", cause="proxy_exit_invalid", original=exc) from exc
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _create_custom_roxy_profile(proxy: str, *, preferences) -> str:
    import requests
    body = create_profile_payload(
        ROXY_WORKSPACE_ID, ROXY_PROJECT_ID, proxy_info_from_url(proxy) if proxy else None,
        settings=preferences,
    )
    try:
        with _CREATE_PROFILE_LOCK:
            response = requests.post(ROXY_API_BASE + "/browser/create", json=body, timeout=30)
            response.raise_for_status()
            payload = response.json()
    except requests.exceptions.JSONDecodeError as exc:
        raise RoxyStartupError("Roxy 环境创建返回数据无效",
                               phase="create_profile", cause="roxy_api_invalid_response", original=exc) from exc
    except requests.RequestException as exc:
        raise RoxyStartupError("Roxy 本机环境创建请求失败",
                               phase="create_profile", cause="roxy_api_transport_failed", original=exc,
                               http_status=getattr(getattr(exc, "response", None), "status_code", None)) from exc
    except (ValueError, TypeError) as exc:
        raise RoxyStartupError("Roxy 环境创建返回数据无效",
                               phase="create_profile", cause="roxy_api_invalid_response", original=exc) from exc
    if not isinstance(payload, dict):
        raise RoxyStartupError("Roxy 环境创建返回数据无效",
                               phase="create_profile", cause="roxy_api_invalid_response")
    if payload.get("code") not in (None, 0, 200, "0", "200"):
        rejection = safe_roxy_create_rejection(payload, getattr(response, "status_code", None))
        if rejection["reason"] == "daily_quota":
            raise RoxyStartupError("Roxy 每日窗口创建额度已用尽",
                                   phase="create_profile", cause="roxy_daily_quota", rejection=rejection)
        raise RoxyStartupError("Roxy 拒绝创建本次环境",
                               phase="create_profile", cause="roxy_api_rejected", rejection=rejection)
    profile_id = _first_roxy_value(payload.get("data"), {"dirId", "id", "profileId", "profile_id"})
    if not profile_id:
        raise RoxyStartupError("Roxy 创建环境后未返回 dirId",
                               phase="create_profile", cause="roxy_profile_id_missing")
    return profile_id


def _reconcile_idle_roxy_profiles(
    retired_profile_ids: set[str],
    retired_ip_tags: set[str],
) -> tuple[list[str], dict[str, str]]:
    """Delete retired idle Profiles before they consume Roxy's physical quota."""
    with _CREATE_PROFILE_LOCK:
        profile_ids = _existing_roxy_profile_ids()
        profile_ip_tags = _roxy_profile_ip_tags(profile_ids)
        usable: list[str] = []
        for profile_id in profile_ids:
            ip_tag = profile_ip_tags.get(profile_id, "")
            if profile_id in retired_profile_ids or ip_tag in retired_ip_tags:
                _delete_roxy_profile(profile_id)
                continue
            usable.append(profile_id)
        return usable, {
            profile_id: profile_ip_tags[profile_id]
            for profile_id in usable
            if profile_id in profile_ip_tags
        }


def _first_roxy_value(payload: object, names: set[str]) -> str:
    if isinstance(payload, dict):
        for key, value in payload.items():
            if key in names and value not in (None, ""):
                return str(value)
            nested = _first_roxy_value(value, names)
            if nested:
                return nested
    elif isinstance(payload, list):
        for value in payload:
            nested = _first_roxy_value(value, names)
            if nested:
                return nested
    return ""


def _is_roxy_proxy_check_fresh(raw_check_time: object) -> bool:
    text = str(raw_check_time or "").strip()
    if not text:
        return False
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return False
    if parsed.tzinfo is None:
        now = datetime.now()
    else:
        parsed = parsed.astimezone(timezone.utc)
        now = datetime.now(timezone.utc)
    return (now - parsed).total_seconds() <= _ROXY_PROXY_CHECK_MAX_AGE_SECONDS


def _live_detect_roxy_proxy_module(
    module_id: object,
    *,
    force_refresh: bool = False,
) -> dict | None:
    import requests

    cache_key = str(module_id)
    now = time.monotonic()
    with _ROXY_PROXY_DETECTION_CACHE_LOCK:
        if force_refresh:
            _ROXY_PROXY_DETECTION_CACHE.pop(cache_key, None)
        else:
            cached = _ROXY_PROXY_DETECTION_CACHE.get(cache_key)
            if cached and cached[0] > now:
                return dict(cached[1]) if cached[1] else None
            if cached:
                _ROXY_PROXY_DETECTION_CACHE.pop(cache_key, None)

    detected = None
    try:
        response = requests.post(
            ROXY_API_BASE + "/proxy/detect",
            json={"workspaceId": ROXY_WORKSPACE_ID, "id": module_id},
            timeout=20,
        )
        response.raise_for_status()
        payload = response.json()
        if payload.get("code") in (None, 0, 200, "0", "200"):
            raw_ip = _first_roxy_value(
                payload.get("data") or {},
                {"ip", "lastIp", "publicIp", "public_ip"},
            ).strip()
            if raw_ip:
                detected = {
                    "module_id": module_id,
                    "ip_tag": hashlib.sha256(raw_ip.encode("utf-8")).hexdigest(),
                }
    except Exception:
        detected = None

    ttl = (
        _ROXY_PROXY_DETECTION_SUCCESS_TTL_SECONDS
        if detected
        else _ROXY_PROXY_DETECTION_FAILURE_TTL_SECONDS
    )
    with _ROXY_PROXY_DETECTION_CACHE_LOCK:
        _ROXY_PROXY_DETECTION_CACHE[cache_key] = (
            time.monotonic() + ttl,
            dict(detected) if detected else None,
        )
    return detected


def _live_detect_roxy_proxy_modules(
    module_ids: list[object],
    *,
    force_refresh: bool = False,
) -> list[dict]:
    from functools import partial
    from concurrent.futures import ThreadPoolExecutor

    unique_module_ids = list(dict.fromkeys(module_ids))
    if not unique_module_ids:
        return []
    # Registration workers can reach this boundary together. One batch owns
    # the refresh while the others wait and then reuse its short-lived cache.
    with _ROXY_PROXY_DETECTION_REFRESH_LOCK:
        with ThreadPoolExecutor(
            max_workers=min(5, len(unique_module_ids))
        ) as executor:
            detected = executor.map(
                partial(
                    _live_detect_roxy_proxy_module,
                    force_refresh=force_refresh,
                ),
                unique_module_ids,
            )
            return [item for item in detected if item]


def _eligible_roxy_proxy_modules(
    excluded_ip_tags: set[str] | None = None,
    *,
    refresh_stale: bool = True,
    force_refresh: bool = False,
    _return_diagnostics: bool = False,
) -> list[dict] | tuple[list[dict], dict[str, object]]:
    """Return healthy Roxy proxy modules without exposing their credentials."""
    excluded = {str(tag or "").strip() for tag in (excluded_ip_tags or set())}
    excluded.discard("")
    import requests

    response = requests.get(
        ROXY_API_BASE + "/proxy/list",
        params={
            "workspaceId": ROXY_WORKSPACE_ID,
            "page": 1,
            "pageSize": 100,
        },
        timeout=20,
    )
    response.raise_for_status()
    payload = response.json()
    if payload.get("code") not in (None, 0, 200, "0", "200"):
        raise RuntimeError(payload.get("msg") or payload.get("message") or "Roxy 代理列表读取失败")
    eligible = []
    stale_module_ids = []
    rows = ((payload.get("data") or {}).get("rows") or [])
    for row in rows:
        module_id = row.get("id")
        if not _is_roxy_proxy_check_fresh(row.get("checkTime")):
            if refresh_stale and module_id not in (None, ""):
                stale_module_ids.append(module_id)
            continue
        raw_ip = str(row.get("lastIp") or "").strip()
        ip_tag = hashlib.sha256(raw_ip.encode("utf-8")).hexdigest() if raw_ip else ""
        if (
            module_id not in (None, "")
            and int(row.get("checkStatus") or 0) == 1
            and ip_tag
            and ip_tag not in excluded
        ):
            eligible.append({"module_id": module_id, "ip_tag": ip_tag})
    detected_rows = _live_detect_roxy_proxy_modules(
        stale_module_ids,
        force_refresh=force_refresh,
    )
    for detected in detected_rows:
        if detected["ip_tag"] not in excluded:
            eligible.append(detected)
    diagnostics = {
        "listed_count": len(rows),
        "stale_module_count": len(set(str(item) for item in stale_module_ids)),
        "detected_module_count": len({str(item.get("module_id")) for item in detected_rows}),
        "health_check_failed": bool(
            refresh_stale
            and stale_module_ids
            and len(detected_rows)
            < len(set(str(item) for item in stale_module_ids))
        ),
    }
    if _return_diagnostics:
        return eligible, diagnostics
    return eligible


def available_roxy_egress_capacity(
    *,
    retired_profile_ids: set[str] | None = None,
    retired_ip_tags: set[str] | None = None,
    refresh_stale: bool = True,
) -> int:
    """Count currently verified module egresses, bounded by the Profile pool."""
    # A Profile's lastIp is historical metadata, not a live health signal.
    # Keep this argument for callers that manage Profile retirement separately,
    # but never turn an idle Profile's stale IP into healthy capacity here.
    del retired_profile_ids
    retired_egresses = {
        str(tag or "").strip() for tag in (retired_ip_tags or set())
    }
    last_error: BaseException | None = None
    for attempt in range(_ROXY_EGRESS_CAPACITY_MAX_ATTEMPTS):
        try:
            checked = _eligible_roxy_proxy_modules(
                retired_egresses,
                refresh_stale=refresh_stale,
                force_refresh=bool(refresh_stale and attempt > 0),
                _return_diagnostics=True,
            )
        except Exception as exc:  # noqa: BLE001 - health boundary is retried
            last_error = exc
        else:
            if (
                isinstance(checked, tuple)
                and len(checked) == 2
                and isinstance(checked[1], dict)
            ):
                eligible, diagnostics = checked
            else:
                # Keep compatibility with callers/tests that replace the
                # private selector with its historical list-only contract.
                eligible = checked
                diagnostics = {}
            module_egresses = {
                str(item.get("ip_tag") or "").strip()
                for item in eligible
                if isinstance(item, dict) and str(item.get("ip_tag") or "").strip()
            }
            if module_egresses:
                return min(PROFILE_POOL.max_size, len(module_egresses))
            if not diagnostics.get("health_check_failed"):
                return 0
            last_error = RoxyEgressHealthCheckError()

        if attempt + 1 < _ROXY_EGRESS_CAPACITY_MAX_ATTEMPTS:
            time.sleep(_ROXY_EGRESS_CAPACITY_RETRY_DELAY_SECONDS)

    if isinstance(last_error, RoxyEgressHealthCheckError):
        raise last_error
    raise RoxyEgressHealthCheckError() from last_error


def _create_roxy_profile(
    *,
    excluded_ip_tags: set[str] | None = None,
    reserve_egress: bool = False,
    preferred_module_id: object | None = None,
) -> tuple[str, str] | tuple[str, str, RoxyEgressLease]:
    """Create an idle Profile bound to a healthy, non-exhausted proxy module."""
    import requests

    # Roxy's local API accepts only one create operation at a time.  Serialize
    # the complete select/create boundary so startup workers cannot trigger a
    # profile-creation storm and fail before a browser ever opens.
    with _CREATE_PROFILE_LOCK:
        eligible = _eligible_roxy_proxy_modules(excluded_ip_tags)
        if not eligible:
            raise RuntimeError("Roxy 没有未超限且检测正常的代理可用于新窗口")
        saved_preference = _saved_roxy_preference()
        preferred_module = str(
            preferred_module_id
            if preferred_module_id is not None
            else saved_preference.get("module_id")
            or ""
        ).strip()
        remaining = list(eligible)
        last_error = "Roxy 创建 Profile 失败"
        while remaining:
            preferred = next(
                (
                    item
                    for item in remaining
                    if str(item.get("module_id") or "").strip() == preferred_module
                ),
                None,
            ) or secrets.choice(remaining)
            preferred_tag = str(preferred.get("ip_tag") or "").strip()
            candidate_tags = [preferred_tag]
            candidate_tags.extend(
                str(item.get("ip_tag") or "").strip()
                for item in remaining
                if str(item.get("ip_tag") or "").strip() != preferred_tag
            )
            egress_lease = (
                ROXY_EGRESS_POOL.acquire_any(candidate_tags, timeout=600)
                if reserve_egress
                else None
            )
            selected_tag = (
                egress_lease.egress_tag if egress_lease is not None else preferred_tag
            )
            selected = next(
                item
                for item in remaining
                if str(item.get("ip_tag") or "").strip() == selected_tag
            )
            remaining = [
                item for item in remaining
                if str(item.get("ip_tag") or "").strip() != selected_tag
            ]
            profile_id = ""
            keep_egress_lease = False
            try:
                response = requests.post(
                    ROXY_API_BASE + "/browser/create",
                    json=create_profile_payload(
                        ROXY_WORKSPACE_ID, ROXY_PROJECT_ID,
                        {"moduleId": selected["module_id"]},
                    ),
                    timeout=30,
                )
                response.raise_for_status()
                payload = response.json()
                if payload.get("code") not in (None, 0, 200, "0", "200"):
                    rejection = safe_roxy_create_rejection(payload, getattr(response, "status_code", None))
                    if rejection["reason"] == "daily_quota":
                        # This limit is workspace-wide. Rotating through other
                        # healthy modules cannot help and would only burn more
                        # request time while producing the same failure.
                        raise RoxyProfileQuotaError(
                            "Roxy 每日窗口创建额度已用尽", rejection=rejection,
                        )
                    last_error = RoxyStartupError(
                        "Roxy 拒绝创建本次环境", phase="create_profile",
                        cause="roxy_api_rejected", rejection=rejection,
                    )
                    continue
                profile_id = _first_roxy_value(
                    payload, {"dirId", "profileId", "profile_id"}
                )
                if not profile_id:
                    last_error = "Roxy 创建 Profile 后未返回 dirId"
                    continue

                # The selected proxy's last known egress is already verified by
                # Roxy. The list endpoint can lag briefly after create, so use the
                # selected one-way tag until the new Profile row catches up.
                ip_tag = (
                    _roxy_profile_ip_tags([profile_id]).get(profile_id)
                    or selected_tag
                )
                if egress_lease is not None and ip_tag != egress_lease.egress_tag:
                    if ip_tag in (excluded_ip_tags or set()):
                        last_error = "Roxy 新建 Profile 实际出口已达到使用上限"
                        _delete_roxy_profile(profile_id)
                        profile_id = ""
                        continue
                    try:
                        actual_lease = ROXY_EGRESS_POOL.acquire(ip_tag, timeout=0)
                    except (RuntimeError, TimeoutError):
                        last_error = "Roxy 新建 Profile 实际出口正被其他任务占用"
                        _delete_roxy_profile(profile_id)
                        profile_id = ""
                        continue
                    egress_lease.release()
                    egress_lease = actual_lease
                if egress_lease is not None:
                    keep_egress_lease = True
                    return profile_id, ip_tag, egress_lease
                return profile_id, ip_tag
            except RoxyProfileQuotaError:
                # A workspace-wide quota cannot be recovered by trying the
                # remaining modules. Preserve the typed error for the caller.
                raise
            except Exception as exc:
                # Preserve the legacy RuntimeError classification while retaining
                # fixed transport evidence; never use the exception's raw text.
                message = "Roxy 创建 Profile 失败"
                if isinstance(exc, requests.Timeout):
                    message += " (timeout)"
                elif isinstance(exc, requests.ConnectionError):
                    message += " (connection)"
                last_error = RoxyStartupError(message, phase="create_profile", cause=(
                    "roxy_api_invalid_response" if isinstance(exc, (ValueError, TypeError))
                    else "roxy_api_transport_failed" if isinstance(exc, requests.RequestException)
                    else "roxy_api_invalid_response"
                ), http_status=getattr(getattr(exc, "response", None), "status_code", None))
                kind = type(exc).__name__
                if kind in {"HTTPError", "JSONDecodeError", "ReadTimeout", "ConnectTimeout", "Timeout",
                            "ConnectionError", "ProxyError", "SSLError", "ValueError", "TypeError"}:
                    last_error.page_state["roxy_transport_exception"] = kind
                last_error.__cause__ = exc
                if profile_id:
                    try:
                        _delete_roxy_profile(profile_id)
                    except Exception:
                        pass
            finally:
                if egress_lease is not None and not keep_egress_lease:
                    egress_lease.release()
        if isinstance(last_error, RoxyStartupError):
            raise last_error
        raise RuntimeError(last_error)


def run_browser_password_reset(
    *,
    account: dict,
    options: dict,
    mail_provider,
    progress_callback=None,
    profile_reserver=None,
    profile_retirer=None,
    retired_profile_ids: set[str] | None = None,
    retired_ip_tags: set[str] | None = None,
) -> dict[str, Any]:
    """Run the independent Roxy forgot-password operation."""
    reset_options = dict(options or {})
    reset_options["operation"] = "password_reset"
    return run_browser_registration(
        account=account,
        options=reset_options,
        mail_provider=mail_provider,
        progress_callback=progress_callback,
        profile_reserver=profile_reserver,
        profile_retirer=profile_retirer,
        retired_profile_ids=retired_profile_ids,
        retired_ip_tags=retired_ip_tags,
    )


def build_worker_command() -> list[str]:
    configured = str(os.getenv("REPO0810_ROXY_PYTHON") or "").strip()
    python = Path(configured) if configured else Path(sys.executable)
    # Isolated mode ignores PYTHONUTF8; select UTF-8 explicitly so redirected
    # JSON output can carry non-GBK page text on Windows without losing results.
    return [str(python), "-I", "-X", "utf8", str(WORKER)]


def _state_has_http_500(state: dict) -> bool:
    """Recognize a 500 response even when the auth URL is still present."""
    if not isinstance(state, dict):
        return False
    if state.get("route_error_500") is True or state.get("http_status_500") is True:
        return True
    evidence = " ".join(
        str(state.get(key) or "")
        for key in (
            "title",
            "status_text",
            "chrome_error_code",
            "chrome_error_text",
            "alert_text",
            "error",
        )
    ).strip().lower()
    if not re.search(r"\b500\b", evidence):
        return False
    return bool(re.search(
        r"internal\s+server\s+error|route\s+error|http\s+error|server\s+error",
        evidence,
    ) or re.fullmatch(r"\s*500\s*", evidence))


def _is_profile_fatal_result(result: dict) -> bool:
    """Recognize a browser/Profile failure that requires a fresh egress."""
    if not isinstance(result, dict) or result.get("success"):
        return False
    # Replacing the Profile cannot make an already-sent email arrive. Once the
    # browser has reached the mailbox wait, restarting would only repeat the
    # completed signup/password path and consume the same OTP budget again.
    if str(result.get("failure_phase") or "").strip().lower() == "otp_wait":
        return False
    state = result.get("page_state")
    if not isinstance(state, dict):
        state = {}
    if (
        str(result.get("failure_phase") or "").strip().lower() == "open_profile"
        and str(result.get("exception_type") or "").strip()
        == "SessionNotCreatedException"
    ):
        return True
    page_url = str(state.get("url") or "").strip().lower()
    if page_url.startswith("chrome-error://chromewebdata/"):
        return True
    if (
        page_url == "about:blank"
        and str(result.get("failure_phase") or "").strip().lower() == "browser_prepare"
        and str(result.get("exception_type") or "").strip() == "TimeoutException"
    ):
        return True
    if (
        str(result.get("failure_phase") or "").strip().lower()
        == "browser_prepare"
        and str(state.get("auth_preflight_stage") or "").strip().lower()
        in {"timeout", "network", "http_error", "invalid_result"}
    ):
        return True
    if _state_has_http_500(state):
        return True
    evidence = " ".join(str(value or "") for value in (
        result.get("error"),
        state.get("chrome_error_code"),
        state.get("chrome_error_text"),
        state.get("alert_text"),
    )).lower()
    return (
        "http error 500" in evidence
        or (
            "route error" in evidence
            and ("500" in evidence or "internal server error" in evidence)
        )
    )


def _should_retire_profile_without_retry(result: dict) -> bool:
    """Drop a failed Profile once replay could resubmit an identity or OTP."""
    if not isinstance(result, dict) or result.get("success"):
        return False
    phase = str(result.get("failure_phase") or "").strip().lower()
    return phase in {
        "email_submit",
        "password_route",
        "password_submit",
        "otp",
        "otp_wait",
        "otp_submit",
        "profile",
        "session",
    }


def _should_retire_egress_without_retry(result: dict) -> bool:
    """Quarantine an egress only when the failed page carries concrete evidence."""
    if not isinstance(result, dict) or result.get("success"):
        return False
    state = result.get("page_state")
    if not isinstance(state, dict):
        state = {}
    page_url = str(state.get("url") or "").strip().lower()
    if page_url.startswith("chrome-error://chromewebdata/"):
        return True
    if _state_has_http_500(state):
        return True
    if (
        str(result.get("failure_phase") or "").strip().lower() == "email_submit"
        and str(result.get("exception_type") or "").strip()
        == "EmailSubmitHardTimeout"
        and str(state.get("email_submit_stage") or "").strip().lower()
        == "timeout"
    ):
        return True
    evidence = " ".join(
        str(value or "")
        for value in (
            result.get("error"),
            state.get("chrome_error_code"),
            state.get("chrome_error_text"),
            state.get("alert_text"),
        )
    ).lower()
    return "http error 500" in evidence or (
        "route error" in evidence
        and ("500" in evidence or "internal server error" in evidence)
    )


class OtpCallbackServer:
    def __init__(
        self,
        mail_provider,
        email: str,
        *,
        timeout: int = 80,
        progress_callback=None,
    ):
        self.mail_provider = mail_provider
        self.email = (email or "").strip().lower()
        self.timeout = max(10, int(timeout or 80))
        self.progress_callback = progress_callback
        self._otp_wait_started_at: float | None = None
        self._otp_wait_lock = threading.Lock()
        self._active_otp_waits: list[tuple[float | None, threading.Event]] = []
        self.nonce = secrets.token_urlsafe(24)
        self.progress_nonce = secrets.token_urlsafe(24)
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.url = ""
        self.progress_url = ""

    def _next_otp_wait_timeout(self) -> int:
        now = time.monotonic()
        if self._otp_wait_started_at is None:
            self._otp_wait_started_at = now
        remaining = self.timeout - (now - self._otp_wait_started_at)
        if remaining <= 0:
            raise TimeoutError(f"OTP 总等待预算已耗尽（{self.timeout}s）")
        return max(1, int(remaining + 0.999))

    def _notify_progress(self, phase: str) -> None:
        if self.progress_callback is None:
            return
        try:
            self.progress_callback(phase)
        except Exception:
            # Observability is best-effort; it must never break OTP delivery.
            return

    def _register_otp_wait(self, issued_after) -> threading.Event:
        """Register one callback wait and cancel older timestamped waits.

        The browser starts a fresh callback request after clicking resend.  A
        provider that is still polling for the first request must stop before
        it can consume the newly delivered code; otherwise the two waits race
        against the same mailbox state.
        """
        try:
            current_ts = float(issued_after) if issued_after is not None else None
        except (TypeError, ValueError):
            current_ts = None
        wait_cancel_event = threading.Event()
        with self._otp_wait_lock:
            if current_ts is not None:
                for previous_ts, previous_event in self._active_otp_waits:
                    if previous_ts is None or current_ts > previous_ts:
                        previous_event.set()
            self._active_otp_waits.append((current_ts, wait_cancel_event))
        return wait_cancel_event

    def _unregister_otp_wait(self, wait_cancel_event: threading.Event) -> None:
        with self._otp_wait_lock:
            self._active_otp_waits = [
                (issued_after, event)
                for issued_after, event in self._active_otp_waits
                if event is not wait_cancel_event
            ]

    def _cancel_active_otp_waits(self) -> None:
        """Stop provider polling before the callback server is torn down."""
        with self._otp_wait_lock:
            active_events = [event for _issued_after, event in self._active_otp_waits]
        for event in active_events:
            event.set()

    @staticmethod
    def _wait_supports_cancel_event(wait_for_otp) -> bool:
        try:
            parameters = inspect.signature(wait_for_otp).parameters.values()
        except (TypeError, ValueError):
            return False
        return any(
            parameter.name == "cancel_event"
            or parameter.kind is inspect.Parameter.VAR_KEYWORD
            for parameter in parameters
        )

    def _wait_for_otp_with_budget(self, issued_after, cancel_event):
        """Keep early mailbox timeouts inside the original callback budget."""
        wait_for_otp = self.mail_provider.wait_for_otp
        supports_cancel = self._wait_supports_cancel_event(wait_for_otp)
        last_timeout = None
        while True:
            if cancel_event.is_set():
                raise RuntimeError("OTP wait cancelled")
            try:
                wait_timeout = self._next_otp_wait_timeout()
            except TimeoutError:
                if last_timeout is not None:
                    raise last_timeout
                raise
            wait_kwargs = {
                "timeout": wait_timeout,
                "issued_after": issued_after,
                "strict_issued_after": True,
            }
            if supports_cancel:
                wait_kwargs["cancel_event"] = cancel_event
            try:
                return wait_for_otp(self.email, **wait_kwargs)
            except TimeoutError as exc:
                last_timeout = exc
                # A provider/transport can time out before its allotted wait.
                # Do not restart registration, resend mail, or reset the deadline.
                if getattr(exc, "fatal", False):
                    raise
                remaining = self.timeout - (
                    time.monotonic() - self._otp_wait_started_at
                )
                if remaining <= 0:
                    raise
                if cancel_event.wait(min(1.0, remaining)):
                    raise RuntimeError("OTP wait cancelled") from exc

    def __enter__(self):
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, _format, *_args):
                return

            def _send_json(self, status: int, body: bytes) -> None:
                try:
                    self.send_response(status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                except (
                    BrokenPipeError,
                    ConnectionAbortedError,
                    ConnectionResetError,
                ):
                    # The browser may close the callback connection after its
                    # task has already failed.  There is no response to send
                    # in that case, and it must not become a server traceback.
                    return

            def do_POST(self):
                if self.path not in {"/otp", "/progress"}:
                    self.send_error(404)
                    return
                wait_cancel_event = None
                try:
                    length = int(self.headers.get("Content-Length") or 0)
                    payload = json.loads(self.rfile.read(length) or b"{}")
                    if self.path == "/progress":
                        if not secrets.compare_digest(
                            str(payload.get("nonce") or ""), owner.progress_nonce
                        ):
                            raise PermissionError("invalid progress nonce")
                        phase = str(payload.get("phase") or "").strip().lower()
                        if phase not in {
                            "open_profile", "browser_prepare", "email_submit",
                            "password_route", "password_submit", "otp", "otp_wait",
                            "otp_submit", "otp_submitted", "profile", "session",
                            "browser_complete", "password_reset_prepare",
                            "password_reset_email", "password_reset_entry",
                            "password_reset_otp_wait", "password_reset_otp_submit",
                            "password_reset_submit", "password_reset_complete",
                        }:
                            raise ValueError("invalid progress phase")
                        owner._notify_progress(phase)
                        body = json.dumps({"ok": True}).encode("utf-8")
                        self._send_json(200, body)
                        return
                    if not secrets.compare_digest(str(payload.get("nonce") or ""), owner.nonce):
                        raise PermissionError("invalid callback nonce")
                    wait_cancel_event = owner._register_otp_wait(
                        payload.get("issued_after")
                    )
                    with owner._otp_wait_lock:
                        if not wait_cancel_event.is_set():
                            owner._notify_progress("waiting_otp")
                    otp = owner._wait_for_otp_with_budget(
                        payload.get("issued_after"), wait_cancel_event
                    )
                    with owner._otp_wait_lock:
                        if wait_cancel_event.is_set():
                            raise RuntimeError("OTP wait cancelled")
                        owner._notify_progress("otp_received")
                    body = json.dumps({"ok": True, "otp": str(otp)}).encode("utf-8")
                    status = 200
                except Exception as exc:
                    # Superseding or stopping a wait is not a mailbox failure.
                    # A late old callback must not overwrite newer progress.
                    with owner._otp_wait_lock:
                        if wait_cancel_event is None or not wait_cancel_event.is_set():
                            owner._notify_progress("otp_failed")
                    otp_failure = safe_otp_failure_metadata(exc)
                    otp_failure["failure_locations"] = safe_traceback_summary(exc, {
                        str(Path(__file__).resolve()),
                        str(ROOT / "mail_providers" / "icloud_relay.py"),
                    })
                    if owner._otp_wait_started_at is not None:
                        diagnostics = dict(otp_failure.get("otp_wait_diagnostics", {}))
                        diagnostics.update({
                            "callback_budget_seconds": owner.timeout,
                            "callback_elapsed_seconds": max(
                                0.0, time.monotonic() - owner._otp_wait_started_at,
                            ),
                        })
                        otp_failure["otp_wait_diagnostics"] = diagnostics
                    otp_failure = safe_otp_failure_metadata(otp_failure)
                    public_error = RuntimeError("OTP callback failed")
                    public_error.failure_phase = "otp_wait"
                    for key, value in otp_failure.items():
                        setattr(public_error, key, value)
                    body = json.dumps({
                        "ok": False,
                        "error": safe_public_error(public_error, "OTP callback"),
                        "otp_failure": otp_failure,
                    }).encode("utf-8")
                    status = 504
                finally:
                    if wait_cancel_event is not None:
                        owner._unregister_otp_wait(wait_cancel_event)
                self._send_json(status, body)

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self._server.server_port}/otp"
        self.progress_url = f"http://127.0.0.1:{self._server.server_port}/progress"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, _exc_type, _exc, _tb):
        self._cancel_active_otp_waits()
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2)


def run_browser_registration(
    *,
    account: dict,
    options: dict,
    mail_provider,
    name: str = "",
    birthday: str = "",
    progress_callback=None,
    profile_reserver=None,
    profile_retirer=None,
    retired_profile_ids: set[str] | None = None,
    retired_ip_tags: set[str] | None = None,
) -> dict[str, Any]:
    email = (account.get("email") or "").strip().lower()
    if not email:
        raise ValueError("Roxy 注册缺少目标邮箱")

    def notify_progress(phase):
        if progress_callback:
            try:
                progress_callback(phase)
            except Exception:
                pass

    preferences = read_settings()
    timeout = max(10, int((options or {}).get("otp_timeout") or preferences.otp_timeout))
    system_direct = bool((options or {}).get("roxy_system_direct"))
    use_proxy_pool = bool((options or {}).get("roxy_use_proxy_pool", preferences.use_proxy_pool))
    fresh_profile = preferences.one_profile_per_account or use_proxy_pool or system_direct
    refresh_retained_profile_slots()
    run_proxy = str((options or {}).get("proxy") or "").strip()
    if use_proxy_pool and (not run_proxy or system_direct):
        raise ValueError("Roxy 内置代理已启用，本次任务必须提供独占代理资源")
    if use_proxy_pool:
        proxy_info_from_url(run_proxy)
        # Requests can mistake a scheme-less proxy username for the URL scheme.
        if "://" not in run_proxy:
            run_proxy = "http://" + run_proxy
    retired = {str(profile_id or "").strip() for profile_id in (retired_profile_ids or set())}
    retired.discard("")
    exhausted_ip_tags = {str(tag or "").strip() for tag in (retired_ip_tags or set())}
    exhausted_ip_tags.discard("")
    explicit_profile_id = str((options or {}).get("roxy_profile_id") or preferences.profile_id).strip()
    if fresh_profile and explicit_profile_id:
        raise ValueError("本次 Roxy 模式要求创建新环境，不能指定固定 Profile")
    if explicit_profile_id and explicit_profile_id in retired:
        raise RuntimeError("指定 Roxy Profile 已达到使用上限，不能继续复用")

    if fresh_profile:
        profile_ids, profile_ip_tags = [], {}
    elif profile_reserver and not explicit_profile_id:
        profile_ids, profile_ip_tags = _reconcile_idle_roxy_profiles(
            retired,
            exhausted_ip_tags,
        )
    else:
        profile_ids = [
            profile_id
            for profile_id in _existing_roxy_profile_ids()
            if profile_id not in retired
        ]
        profile_ip_tags = {}
    if explicit_profile_id and explicit_profile_id not in profile_ids:
        profile_ids.append(explicit_profile_id)
    saved_preference = _saved_roxy_preference()
    preferred_profile_ids = [
        profile_id
        for profile_id in profile_ids
        if saved_preference.get("ip_tag")
        and profile_ip_tags.get(profile_id) == saved_preference["ip_tag"]
    ]
    PROFILE_POOL.sync_profiles(
        profile_ids,
        preferred_profile_ids=preferred_profile_ids,
    )
    if profile_reserver and explicit_profile_id:
        profile_ip_tags = _roxy_profile_ip_tags(profile_ids)
    base_request = {
        "email": email,
        "operation": str((options or {}).get("operation") or "registration"),
        "password": str((options or {}).get("candidate_password") or ""),
        "candidate_password_verified": bool(
            (options or {}).get("candidate_password_verified")
        ),
        "name": name,
        "birthday": birthday,
        "otp_timeout": timeout,
        "proxy": run_proxy,
        "keep_browser_open": preferences.keep_browser_open,
        "profile_id": explicit_profile_id,
        "native_pointer_submit": bool((options or {}).get("native_pointer_submit")),
        "trusted_keyboard_submit": bool(
            (options or {}).get("trusted_keyboard_submit", True)
        ),
        "async_email_submit": bool((options or {}).get("async_email_submit")),
        "auth_entry_preflight": True,
        # WebDriver's script/page timeouts can be ignored by a wedged renderer.
        # The isolated worker therefore owns a process-level deadline covering
        # login navigation and the anonymous NextAuth preflight.
        "browser_prepare_hard_timeout": 35 if system_direct else 65,
        "email_submit_hard_timeout": 120,
    }
    with OtpCallbackServer(
        mail_provider,
        email,
        timeout=timeout,
        progress_callback=progress_callback,
    ) as callback:
        skipped_profiles = 0
        max_skips = PROFILE_POOL.max_size + 1
        profile_fatal_retries = 0
        while True:
            lease = PROFILE_POOL.acquire(
                # Queue wait is independent from mailbox OTP timeout. A sixth
                # account waits for one of the five browser stages to finish.
                timeout=600,
                required_profile_id=base_request["profile_id"],
                allow_existing_profile=not fresh_profile,
            )
            egress_lease = None
            owned_profile_id = ""
            result = None
            try:
                request = dict(base_request)
                if not request["profile_id"]:
                    if lease.profile_id:
                        request["profile_id"] = lease.profile_id
                    elif use_proxy_pool or system_direct:
                        if use_proxy_pool:
                            notify_progress("proxy_check")
                        ip_tag = (_custom_proxy_ip_tag(run_proxy, options or {})
                                  if use_proxy_pool else "roxy-system-direct")
                        if ip_tag in exhausted_ip_tags:
                            raise RoxyStartupError("Roxy 内置代理出口已达到使用上限",
                                                   phase="proxy_check", cause="proxy_exit_exhausted")
                        egress_lease = ROXY_EGRESS_POOL.acquire(ip_tag, timeout=600)
                        notify_progress("create_profile")
                        owned_profile_id = _create_custom_roxy_profile(run_proxy, preferences=preferences)
                        lease.bind_profile(owned_profile_id)
                        request["profile_id"] = owned_profile_id
                        profile_ip_tags[owned_profile_id] = ip_tag
                    elif profile_reserver or fresh_profile:
                        try:
                            created_profile = _create_roxy_profile(
                                excluded_ip_tags=exhausted_ip_tags,
                                reserve_egress=True,
                            )
                        except RoxyProfileQuotaError as exc:
                            # Return a structured terminal result.  The caller
                            # can show the authoritative Roxy code/message and
                            # retry later, but must not enter the browser worker
                            # or rotate through the same impossible quota.
                            return {
                                "success": False,
                                "email": email,
                                "profile_id": "",
                                "failure_phase": "open_profile",
                                "exception_type": type(exc).__name__,
                                "error": str(exc),
                                "page_state": exc.page_state,
                            }
                        if len(created_profile) == 3:
                            profile_id, ip_tag, egress_lease = created_profile
                        else:
                            profile_id, ip_tag = created_profile
                        lease.bind_profile(profile_id)
                        owned_profile_id = profile_id
                        request["profile_id"] = profile_id
                        profile_ip_tags[profile_id] = ip_tag
                    else:
                        request["profile_id"] = lease.profile_id

                retirement_required = False
                profile_id = str(request["profile_id"] or "")
                if profile_reserver and profile_id:
                    ip_tag = profile_ip_tags.get(profile_id, "")
                    if not ip_tag:
                        if explicit_profile_id:
                            raise RuntimeError("指定 Roxy Profile 缺少可验证出口 IP")
                        try:
                            _delete_roxy_profile(profile_id)
                        finally:
                            lease.retire()
                        skipped_profiles += 1
                        if skipped_profiles >= max_skips:
                            raise RuntimeError("没有可验证出口 IP 的 Roxy Profile 可用")
                        continue

                    if egress_lease is None:
                        egress_lease = ROXY_EGRESS_POOL.acquire(ip_tag, timeout=600)
                    if fresh_profile:
                        notify_progress("reserve_profile")
                    reservation = profile_reserver(profile_id, ip_tag) or {}
                    if not reservation.get("allowed"):
                        if fresh_profile:
                            raise RoxyStartupError("本次 Roxy 环境或出口 IP 已达到使用上限",
                                                   phase="reserve_profile", cause="proxy_exit_exhausted")
                        if explicit_profile_id:
                            raise RuntimeError("指定 Roxy Profile 或其出口 IP 已达到使用上限")
                        try:
                            _delete_roxy_profile(profile_id)
                        finally:
                            lease.retire()
                        exhausted_ip_tags.add(ip_tag)
                        skipped_profiles += 1
                        if skipped_profiles >= max_skips:
                            raise RuntimeError("没有未超限出口 IP 的 Roxy Profile 可用")
                        continue
                    retirement_required = bool(reservation.get("retire_profile"))
                elif system_direct and egress_lease is None:
                    egress_lease = ROXY_EGRESS_POOL.acquire(
                        "roxy-system-direct", timeout=600
                    )

                request["otp_callback"] = callback.url
                request["otp_nonce"] = callback.nonce
                request["progress_callback"] = callback.progress_url
                request["progress_nonce"] = callback.progress_nonce
                # Do not use PIPE/capture_output here. Roxy-launched browser
                # descendants can inherit the pipe handle, so communicate()
                # keeps waiting for EOF after the isolated worker has already
                # hit its hard deadline and exited. A seekable file lets
                # subprocess.run wait only for the direct worker process.
                with tempfile.TemporaryFile() as worker_stdout, tempfile.TemporaryFile() as worker_stderr:
                    proc = subprocess.run(
                        build_worker_command(),
                        input=json.dumps(request).encode("utf-8"),
                        text=False,
                        stdout=worker_stdout,
                        stderr=worker_stderr,
                        cwd=str(ROOT),
                        env={**os.environ, "PYTHONUTF8": "1"},
                        timeout=max(180, timeout + 420),
                        check=False,
                    )
                    raw_stdout = _read_worker_output(
                        worker_stdout,
                        getattr(proc, "stdout", None),
                    )
                    raw_stderr = _read_worker_output(
                        worker_stderr,
                        getattr(proc, "stderr", None),
                    )
                stdout = (raw_stdout or b"").decode("utf-8", errors="replace")
                lines = [line.strip() for line in stdout.splitlines() if line.strip()]
                if not lines:
                    exception_type, page_state = _worker_boundary_state(
                        proc,
                        raw_stderr,
                        "missing_stdout",
                    )
                    raise RoxyWorkerBoundaryError(
                        f"Roxy worker 未返回结果（exit={proc.returncode}）",
                        exception_type=exception_type,
                        page_state=page_state,
                    )
                try:
                    result = json.loads(lines[-1])
                except json.JSONDecodeError as exc:
                    exception_type, page_state = _worker_boundary_state(
                        proc,
                        raw_stderr,
                        "invalid_json",
                    )
                    raise RoxyWorkerBoundaryError(
                        "Roxy worker 返回了无效 JSON",
                        exception_type=exception_type,
                        page_state=page_state,
                    ) from exc
                if not isinstance(result, dict):
                    exception_type, page_state = _worker_boundary_state(
                        proc,
                        raw_stderr,
                        "invalid_result",
                    )
                    raise RoxyWorkerBoundaryError(
                        "Roxy worker 返回结构无效",
                        exception_type=exception_type,
                        page_state=page_state,
                    )
                profile_id = str(result.get("profile_id") or request["profile_id"] or "")
                if profile_id:
                    lease.bind_profile(profile_id)

                if fresh_profile:
                    if (_should_retire_egress_without_retry(result) or _is_profile_fatal_result(result)):
                        ip_tag = profile_ip_tags.get(profile_id, "")
                        if profile_retirer and ip_tag:
                            try:
                                profile_retirer(profile_id, ip_tag)
                            except Exception as exc:
                                result["egress_retirement_error"] = safe_public_error(exc, "Roxy egress retirement")
                    return result

                if _should_retire_profile_without_retry(result):
                    ip_tag = profile_ip_tags.get(profile_id, "")
                    if (
                        _should_retire_egress_without_retry(result)
                        and profile_retirer
                        and profile_id
                        and ip_tag
                    ):
                        try:
                            profile_retirer(profile_id, ip_tag)
                        except Exception as exc:
                            result["egress_retirement_error"] = safe_public_error(
                                exc, "Roxy disconnected egress retirement"
                            )
                    try:
                        _delete_roxy_profile(profile_id)
                    except Exception as exc:
                        result["profile_retirement_error"] = safe_public_error(
                            exc, "Roxy disconnected Profile deletion"
                        )
                    finally:
                        lease.retire()
                    return result

                if _is_profile_fatal_result(result):
                    ip_tag = profile_ip_tags.get(profile_id, "")
                    if ip_tag:
                        exhausted_ip_tags.add(ip_tag)
                    state = result.get("page_state")
                    if not isinstance(state, dict):
                        state = {}
                    auth_preflight_failed = bool(
                        str(state.get("auth_preflight_stage") or "").strip().lower()
                        in {"timeout", "network", "http_error", "invalid_result"}
                    )
                    fatal_before_email = (
                        str(result.get("failure_phase") or "").strip().lower()
                        == "browser_prepare"
                    )
                    if fatal_before_email and profile_retirer and profile_id and ip_tag:
                        try:
                            profile_retirer(profile_id, ip_tag)
                        except Exception as exc:
                            result["egress_retirement_error"] = safe_public_error(
                                exc, "Roxy browser-prepare egress retirement"
                            )
                    if explicit_profile_id:
                        result["profile_fatal_retry_required"] = True
                        return result
                    try:
                        _delete_roxy_profile(profile_id)
                    except Exception as exc:
                        result["profile_retirement_error"] = safe_public_error(
                            exc, "Roxy fatal Profile deletion"
                        )
                        return result
                    finally:
                        lease.retire()
                    retry_limit = max_skips - 1 if auth_preflight_failed else 1
                    if profile_fatal_retries < retry_limit:
                        profile_fatal_retries += 1
                        continue
                    result["profile_fatal_retry_exhausted"] = True
                    return result

                if retirement_required:
                    lease.retire()
                    if not explicit_profile_id:
                        try:
                            _delete_roxy_profile(profile_id)
                        except Exception as exc:
                            result["profile_retirement_error"] = safe_public_error(
                                exc, "Roxy Profile retirement"
                            )
                    else:
                        result["profile_retirement_required"] = True
                return result
            finally:
                if fresh_profile:
                    if preferences.keep_browser_open and owned_profile_id:
                        lease.retain_window()
                    else:
                        lease.retire()
                    if owned_profile_id:
                        try:
                            _finish_owned_profile(owned_profile_id, preferences)
                        except Exception as exc:
                            if result is not None:
                                result["profile_cleanup_error"] = safe_public_error(exc, "Roxy owned Profile cleanup")
                            else:
                                import logging
                                logging.getLogger("webui.roxy").warning(
                                    "%s", safe_public_error(exc, "Roxy owned Profile cleanup")
                                )
                if egress_lease is not None:
                    egress_lease.release()
                lease.release()
