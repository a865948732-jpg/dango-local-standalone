"""One-shot Roxy browser worker for repo_0810.

This process has no access to repo_0810's database and does not import the
historical registration service.  It receives one request on stdin, asks the
owning repo for OTP over a nonce-protected loopback callback, and emits one JSON
result on stdout.
"""
from __future__ import annotations

import base64
import json
import logging
import os
import random
import re
import secrets
import string
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import requests
from safe_diagnostics import safe_otp_failure_metadata, safe_public_error, safe_traceback_summary, safe_url
from webui.roxy_config import require_roxy_configuration
from webui.roxy_settings import read_settings, settings_path, create_profile_payload, proxy_info_from_url

ROXY_API_BASE = os.getenv("ROXY_API_BASE", "http://127.0.0.1:50000").rstrip("/")
ROXY_WORKSPACE_ID = int(os.getenv("ROXY_WORKSPACE_ID") or 0)
ROXY_PROJECT_ID = int(os.getenv("ROXY_PROJECT_ID") or 0)
if settings_path().is_file():
    _initial_settings = read_settings()
    ROXY_API_BASE = _initial_settings.api_base
    ROXY_WORKSPACE_ID = int(_initial_settings.workspace_id)
    ROXY_PROJECT_ID = int(_initial_settings.project_id)
ROXY_TIMEOUT = 90
_KEY_ENTER = "\ue007"
_KEY_BACKSPACE = "\ue003"
_KEY_CONTROL = "\ue009"
_KEY_COMMAND = "\ue03d"
_TRUSTED_KEYBOARD_INPUT_STAGES = {
    "select_existing", "clear_existing", "type_value", "readback", "value_not_stable",
}
_EMAIL_SUBMIT_STAGES = {
    "input_wait",
    "email_fill",
    "initial_submit",
    "initial_transition_wait",
    "stop_loading",
    "same_form_recovery",
    "post_recovery_wait",
    "legacy_entry",
}
_EMAIL_SUBMIT_TRACE_STAGES = {
    "before_initial_submit",
    "after_initial_submit",
    "initial_wait_done",
    "after_stop_loading",
    "recovery_result",
    "recovery_wait_done",
}
_EMAIL_SUBMIT_TRACE_STATES = {
    "password", "login_password", "otp", "logged_in", "route_error_500",
    "password_error", "loading", "email_page", "unknown", "browser_error",
    "auth_callback_error",
}
_EMAIL_SUBMIT_CLICK_MODES = {
    "async_dom_click", "cdp_pointer", "keyboard_enter",
    "webdriver_fallback_overlay",
}
_EMAIL_INPUT_SELECTORS = [
    "input[type=email]",
    "input[name=email]",
    "input[name=username]",
    "input[autocomplete=email]",
    "input[autocomplete*=email]",
]
_EMAIL_INPUT_SELECTOR_QUERY = ", ".join(_EMAIL_INPUT_SELECTORS)
_NEW_PASSWORD_INPUT_SELECTORS = [
    "input[autocomplete*=new-password]",
    "input[name=new-password]",
    "input[type=password]",
]
_NEW_PASSWORD_INPUT_SELECTOR_QUERY = ", ".join(_NEW_PASSWORD_INPUT_SELECTORS)


class TrustedKeyboardInputError(RuntimeError):
    def __init__(self, stage: str, input_diagnostics: list[dict] | None = None):
        normalized = str(stage or "").strip().lower()
        if normalized not in _TRUSTED_KEYBOARD_INPUT_STAGES:
            normalized = "readback"
        self.password_input_stage = normalized
        self.input_diagnostics = list(input_diagnostics or [])
        super().__init__(f"trusted keyboard input failed at {normalized}")


class AuthEntryPreflightError(RuntimeError):
    def __init__(self, stage: str):
        normalized = str(stage or "").strip().lower()
        if normalized not in {"timeout", "network", "http_error", "invalid_result"}:
            normalized = "invalid_result"
        self.auth_preflight_stage = normalized
        super().__init__(f"auth entry preflight failed at {normalized}")


class EmailFormReadinessError(RuntimeError):
    def __init__(self, diagnostics: dict | None = None):
        bounded = dict(diagnostics or {})
        if "signature" in bounded:
            bounded["signature"] = str(bounded.get("signature") or "")[:240]
        self.email_form_diagnostics = bounded
        super().__init__("邮箱页面尚未加载稳定，拒绝提前输入")


class RoxyPasswordResetError(RuntimeError):
    """Structured failure for the independent browser password-reset flow."""

    def __init__(self, message: str, *, phase: str, cause: str):
        self.failure_phase = str(phase or "password_reset")
        self.failure_cause = str(cause or "password_reset_failed")
        super().__init__(message)


def _arm_process_deadline(
    seconds: float,
    failure_result: dict,
    *,
    exit_func=None,
) -> threading.Event:
    """Force this isolated worker to stop even when WebDriver never returns."""
    cancelled = threading.Event()
    hard_exit = exit_func or os._exit
    delay = max(0.01, float(seconds))

    def watchdog() -> None:
        if cancelled.wait(delay):
            return
        try:
            # The bridge parses the final non-empty stdout line as JSON. Keep
            # this bounded result free of account credentials and page text.
            print(
                json.dumps(failure_result, ensure_ascii=False, separators=(",", ":")),
                flush=True,
            )
        finally:
            hard_exit(124)

    threading.Thread(
        target=watchdog,
        name="roxy-browser-prepare-deadline",
        daemon=True,
    ).start()
    return cancelled


@contextmanager
def _webdriver_command_timeout(
    driver,
    seconds: float,
    *,
    keep_on_error: bool = False,
):
    """Bound each ChromeDriver HTTP command inside a nominal phase deadline."""
    executor = getattr(driver, "command_executor", None)
    client_config = getattr(executor, "_client_config", None)
    if client_config is None:
        yield
        return
    try:
        previous = client_config.timeout
        client_config.timeout = max(1.0, float(seconds))
    except Exception:
        yield
        return
    try:
        yield
    except BaseException:
        if not keep_on_error:
            client_config.timeout = previous
        raise
    else:
        client_config.timeout = previous


def _http(
    method: str,
    path: str,
    body: dict | None = None,
    *,
    params: dict | None = None,
) -> dict:
    response = requests.request(
        method,
        ROXY_API_BASE + path,
        params=params or None,
        json=body,
        timeout=ROXY_TIMEOUT,
    )
    response.raise_for_status()
    payload = response.json()
    if payload.get("code") not in (None, 0, 200, "0", "200"):
        raise RuntimeError(payload.get("msg") or payload.get("message") or "Roxy API failed")
    return payload


def _first(payload, names):
    if isinstance(payload, dict):
        for key, value in payload.items():
            if key in names and value not in (None, ""):
                return str(value)
            found = _first(value, names)
            if found:
                return found
    elif isinstance(payload, list):
        for value in payload:
            found = _first(value, names)
            if found:
                return found
    return ""


def _password() -> str:
    groups = [
        "ABCDEFGHJKLMNPQRSTUVWXYZ",
        "abcdefghjkmnpqrstuvwxyz",
        "23456789",
        "!@#$%^&*?_-+=",
    ]
    chars = [secrets.choice(group) for group in groups]
    all_chars = "".join(groups)
    chars.extend(secrets.choice(all_chars) for _ in range(10))
    random.SystemRandom().shuffle(chars)
    return "".join(chars)


def _password_for_request(req: dict) -> str:
    saved = str((req or {}).get("password") or "").strip()
    return saved or _password()


def _report_progress(req: dict, phase: str) -> None:
    """Best-effort, secret-free phase reporting to the owning repo_0810 run."""
    callback = str((req or {}).get("progress_callback") or "")
    nonce = str((req or {}).get("progress_nonce") or "")
    if not callback.startswith("http://127.0.0.1:") or not nonce:
        return
    try:
        body = json.dumps({"nonce": nonce, "phase": phase}).encode("utf-8")
        request = urllib.request.Request(
            callback,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=2) as response:
            response.read()
    except Exception:
        # Observability must never alter the registration state machine.
        return


def _profile_name() -> str:
    return f"repo0810-roxy-{int(time.time() * 1000)}-{secrets.token_hex(2)}"


@dataclass
class OpenedProfile:
    profile_id: str
    debugger_address: str
    driver_path: str


def _profile_is_confirmed_idle(profile_id: str) -> bool:
    """Read only Roxy's authoritative list after an ambiguous open timeout."""
    normalized = str(profile_id or "").strip()
    if not normalized:
        return False
    try:
        payload = _http(
            "GET",
            "/browser/list",
            params={"workspaceId": ROXY_WORKSPACE_ID, "page": 1, "pageSize": 100},
        )
        for row in ((payload.get("data") or {}).get("rows") or []):
            if str(row.get("dirId") or "").strip() != normalized:
                continue
            open_status = row.get("openStatus")
            if open_status is None:
                return False
            return str(open_status).strip().lower() in {"0", "false", "closed"}
    except Exception:
        return False
    return False


def _open_profile_request(profile_id: str) -> dict:
    preferences = read_settings()
    return _http("POST", preferences.open_path, {
        "workspaceId": ROXY_WORKSPACE_ID,
        "dirId": int(profile_id) if profile_id.isdigit() else profile_id,
        "args": [],
        "forceOpen": True,
        "headless": preferences.headless,
    })


def _create_open_profile(proxy: str = "", profile_id: str = "") -> OpenedProfile:
    profile_id = str(profile_id or "").strip()
    if profile_id:
        created = {"code": 0, "data": {"dirId": profile_id}}
    else:
        body = create_profile_payload(
            ROXY_WORKSPACE_ID, ROXY_PROJECT_ID,
            proxy_info_from_url(proxy) if proxy else None,
        )
        created = _http("POST", "/browser/create", body)
        profile_id = _first(created, {"dirId", "id", "profileId", "profile_id"})
        if not profile_id:
            raise RuntimeError("Roxy 创建 Profile 后未返回 dirId")
    try:
        try:
            opened = _open_profile_request(profile_id)
        except requests.exceptions.ReadTimeout:
            # Only an authoritative idle state permits the one open retry.
            if not _profile_is_confirmed_idle(profile_id):
                raise
            time.sleep(1)
            opened = _open_profile_request(profile_id)
        debugger = _first(opened, {
            "debuggerAddress", "debugger_address", "debugger", "http",
            "debuggingPortUrl", "remoteDebuggingAddress",
        })
        driver_path = _first(opened, {"driver", "driverPath", "driver_path"})
        if not debugger:
            raise RuntimeError("Roxy 打开 Profile 后未返回 debuggerAddress")
        return OpenedProfile(profile_id, debugger, driver_path)
    except Exception as exc:
        exc.roxy_profile_id = profile_id
        raise


def _cleanup(opened: OpenedProfile | None) -> None:
    if not opened:
        return
    try:
        _http("POST", read_settings().close_path, {
            "workspaceId": ROXY_WORKSPACE_ID,
            "dirId": int(opened.profile_id) if opened.profile_id.isdigit() else opened.profile_id,
        })
    except Exception:
        pass


def _driver(opened: OpenedProfile):
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service

    options = Options()
    options.page_load_strategy = "eager"
    options.add_experimental_option("debuggerAddress", opened.debugger_address)
    if opened.driver_path:
        driver = webdriver.Chrome(service=Service(opened.driver_path), options=options)
    else:
        driver = webdriver.Chrome(options=options)
    return driver


def _reset_profile_auth_state(driver) -> None:
    """Clear OpenAI/ChatGPT auth state before assigning a slot to a new identity."""
    try:
        driver.execute_cdp_cmd("Network.enable", {})
        driver.execute_cdp_cmd("Network.clearBrowserCookies", {})
        driver.execute_cdp_cmd("Network.clearBrowserCache", {})
        for origin in ("https://chatgpt.com", "https://auth.openai.com"):
            driver.execute_cdp_cmd("Storage.clearDataForOrigin", {
                "origin": origin,
                "storageTypes": "all",
            })
    except Exception as exc:
        raise RuntimeError(f"Roxy Profile 复用前清理认证状态失败：{exc}") from exc


def _clear_profile_auth_state(driver) -> None:
    """Clear this task Profile's auth/cache state before the window is closed."""
    try:
        driver.execute_cdp_cmd("Network.enable", {})
        driver.execute_cdp_cmd("Network.clearBrowserCookies", {})
        driver.execute_cdp_cmd("Network.clearBrowserCache", {})
        for origin in ("https://chatgpt.com", "https://auth.openai.com"):
            driver.execute_cdp_cmd("Storage.clearDataForOrigin", {
                "origin": origin,
                "storageTypes": "all",
            })
    except Exception as exc:
        raise RuntimeError(f"Roxy Profile 任务结束清理认证缓存失败：{exc}") from exc


def _visible(driver, selector: str):
    try:
        elements = driver.find_elements("css selector", selector) or []
    except Exception:
        return None
    try:
        iterator = iter(elements)
    except TypeError:
        return None
    for element in iterator:
        try:
            if element.is_displayed() and element.is_enabled():
                return element
        except Exception:
            pass
    return None


def _poll_until(
    probe,
    is_ready,
    *,
    timeout: float,
    interval: float = 0.25,
    clock=None,
    sleeper=None,
):
    clock = clock or time.monotonic
    sleeper = sleeper or time.sleep
    deadline = clock() + max(0.0, float(timeout))
    last = probe()
    while not is_ready(last):
        remaining = deadline - clock()
        if remaining <= 0:
            break
        sleeper(min(max(0.01, float(interval)), remaining))
        last = probe()
    return last


def _wait_any(driver, selectors: list[str], timeout: int = 45):
    def probe():
        for selector in selectors:
            element = _visible(driver, selector)
            if element is not None:
                return selector, element
        return "", None

    return _poll_until(
        probe,
        lambda result: result[1] is not None,
        timeout=timeout,
        interval=0.25,
    )


def _wait_for_stable_email_form(driver, timeout: int = 10) -> dict:
    """Wait until the loaded email form is complete and stable before editing it."""
    stable_signature = ""
    stable_samples = 0
    sample_count = 0
    ready_samples = 0
    signature_changes = 0
    allow_interactive = (
        getattr(driver, "_repo0810_auth_load_stopped", False) is True
    )

    def probe() -> dict:
        nonlocal stable_signature, stable_samples
        nonlocal sample_count, ready_samples, signature_changes
        snapshot = driver.execute_script(r"""
            // repo0810EmailFormReadiness
            const visible = element => {
                if (!element || !element.isConnected || element.disabled || element.readOnly) {
                    return false;
                }
                const style = getComputedStyle(element);
                if (style.display === 'none' || style.visibility === 'hidden') return false;
                const rect = element.getBoundingClientRect();
                return rect.width > 0 && rect.height > 0;
            };
            const input = [...document.querySelectorAll(
                String(arguments[0] || '')
            )].find(visible) || null;
            const scope = input && (input.form || input.closest('form') || document);
            const submit = scope && [...scope.querySelectorAll(
                'button[type=submit], input[type=submit]'
            )].find(element => visible(element) &&
                String(element.getAttribute('aria-disabled') || '').toLowerCase() !== 'true') || null;
            const busy = !!(scope && [...scope.querySelectorAll(
                '[aria-busy="true"], [data-loading="true"]'
            )].some(visible));
            const readyState = String(document.readyState || '');
            const ready = ['interactive', 'complete'].includes(readyState) &&
                !!input && !!submit && !busy;
            const geometry = element => {
                if (!element) return '';
                const rect = element.getBoundingClientRect();
                return [
                    Math.round(rect.left), Math.round(rect.top),
                    Math.round(rect.width), Math.round(rect.height),
                ].join(',');
            };
            return {
                ready,
                ready_state: readyState,
                has_input: !!input,
                has_submit: !!submit,
                busy,
                signature: ready ? [
                    String(location.origin || ''), String(location.pathname || ''),
                    geometry(input), geometry(submit),
                    String(submit.tagName || '').toLowerCase(),
                    String(submit.getAttribute('type') || '').toLowerCase(),
                ].join('|') : '',
            };
        """, _EMAIL_INPUT_SELECTOR_QUERY) or {}
        sample_count += 1
        ready_state = (
            str(snapshot.get("ready_state") or "").strip().lower()
            if isinstance(snapshot, dict)
            else ""
        )
        ready_state_allowed = ready_state == "complete" or (
            allow_interactive and ready_state == "interactive"
        )
        structurally_ready = (
            isinstance(snapshot, dict)
            and ready_state_allowed
            and snapshot.get("has_input") is True
            and snapshot.get("has_submit") is True
            and snapshot.get("busy") is False
        )
        snapshot_reports_ready = (
            isinstance(snapshot, dict)
            and ready_state_allowed
            and snapshot.get("ready") is True
        )
        if (
            not isinstance(snapshot, dict)
            or (not snapshot_reports_ready and not structurally_ready)
        ):
            stable_signature = ""
            stable_samples = 0
            result = dict(snapshot) if isinstance(snapshot, dict) else {}
            result["ready"] = False
            result["stable"] = False
            result["stable_samples"] = 0
            result["sample_count"] = sample_count
            result["ready_samples"] = ready_samples
            result["signature_changes"] = signature_changes
            return result
        ready_samples += 1
        signature = str(snapshot.get("signature") or "")
        if not signature:
            stable_signature = ""
            stable_samples = 0
            result = dict(snapshot)
            result["ready"] = False
            result["stable"] = False
            result["stable_samples"] = 0
            result["sample_count"] = sample_count
            result["ready_samples"] = ready_samples
            result["signature_changes"] = signature_changes
            return result
        if signature == stable_signature:
            stable_samples += 1
        else:
            if stable_signature:
                signature_changes += 1
            stable_signature = signature
            stable_samples = 1
        result = dict(snapshot)
        result["ready"] = True
        result["stable"] = stable_samples >= 2
        result["stable_samples"] = stable_samples
        result["sample_count"] = sample_count
        result["ready_samples"] = ready_samples
        result["signature_changes"] = signature_changes
        return result

    result = _poll_until(
        probe,
        lambda snapshot: isinstance(snapshot, dict) and snapshot.get("stable") is True,
        timeout=max(1, int(timeout)),
        interval=0.25,
    )
    return dict(result) if isinstance(result, dict) else {
        "ready": False,
        "stable": False,
        "stable_samples": 0,
        "sample_count": sample_count,
        "ready_samples": ready_samples,
        "signature_changes": signature_changes,
    }


def _wait_for_stable_password_form(driver, timeout: int = 30) -> dict:
    """Wait for the mounted password form to remain usable before typing."""
    stable_signature = ""
    stable_samples = 0
    sample_count = 0

    def probe() -> dict:
        nonlocal stable_signature, stable_samples, sample_count
        snapshot = driver.execute_script(r"""
            // repo0810PasswordFormReadiness
            const visible = element => {
                if (!element || !element.isConnected) return false;
                const style = getComputedStyle(element);
                if (style.display === 'none' || style.visibility === 'hidden' ||
                    Number(style.opacity || 1) === 0) return false;
                const rect = element.getBoundingClientRect();
                return rect.width > 0 && rect.height > 0;
            };
            const usable = element => visible(element) && !element.disabled &&
                !element.readOnly &&
                String(element.getAttribute('aria-disabled') || '').toLowerCase() !== 'true';
            const input = [...document.querySelectorAll(String(arguments[0] || ''))]
                .find(usable) || null;
            const scope = input && (input.form || input.closest('form') || document);
            const submit = scope && [...scope.querySelectorAll(
                'button[type=submit], input[type=submit]'
            )].find(usable) || null;
            const busySelectors = [
                '[aria-busy="true"]',
                '[data-loading="true"]',
                '[role="progressbar"]',
                '[aria-label*="loading" i]',
                '[data-testid*="loading" i]',
                '[data-testid*="spinner" i]',
                'svg[class*="animate-spin" i]',
                '[class~="spinner"]',
                '[class~="loading"]',
            ].join(',');
            const busy = [...document.querySelectorAll(busySelectors)].some(visible);
            const readyState = String(document.readyState || '');
            const ready = readyState === 'complete' && !!input && !!submit && !busy;
            const geometry = element => {
                if (!element) return '';
                const rect = element.getBoundingClientRect();
                return [
                    Math.round(rect.left), Math.round(rect.top),
                    Math.round(rect.width), Math.round(rect.height),
                ].join(',');
            };
            return {
                ready,
                ready_state: readyState,
                has_input: !!input,
                has_submit: !!submit,
                busy,
                signature: ready ? [
                    String(location.origin || ''), String(location.pathname || ''),
                    geometry(input), geometry(submit),
                    String(input.getAttribute('name') || '').toLowerCase(),
                    String(input.getAttribute('autocomplete') || '').toLowerCase(),
                    String(submit.tagName || '').toLowerCase(),
                    String(submit.getAttribute('type') || '').toLowerCase(),
                ].join('|') : '',
            };
        """, _NEW_PASSWORD_INPUT_SELECTOR_QUERY) or {}
        sample_count += 1
        if not isinstance(snapshot, dict) or snapshot.get("ready") is not True:
            stable_signature = ""
            stable_samples = 0
            result = dict(snapshot) if isinstance(snapshot, dict) else {}
            result["stable"] = False
            result["stable_samples"] = 0
            result["sample_count"] = sample_count
            return result
        signature = str(snapshot.get("signature") or "")
        if not signature:
            stable_signature = ""
            stable_samples = 0
        elif signature == stable_signature:
            stable_samples += 1
        else:
            stable_signature = signature
            stable_samples = 1
        result = dict(snapshot)
        result["stable"] = stable_samples >= 2
        result["stable_samples"] = stable_samples
        result["sample_count"] = sample_count
        return result

    result = _poll_until(
        probe,
        lambda snapshot: isinstance(snapshot, dict) and snapshot.get("stable") is True,
        timeout=max(1, int(timeout)),
        interval=0.25,
    )
    return dict(result) if isinstance(result, dict) else {
        "ready": False,
        "stable": False,
        "stable_samples": 0,
        "sample_count": sample_count,
    }


def _set_text(element, value: str) -> None:
    try:
        element.click()
        element.clear()
        element.send_keys(value)
        return
    except Exception:
        # Overlays/animated labels may intercept the physical click even though
        # the React-controlled input is ready. The verified wrapper below will
        # use the native value setter and dispatch input/change events.
        return


def _is_password_field(element) -> bool:
    try:
        field_type = str(element.get_attribute("type") or "").strip().lower()
        autocomplete = str(element.get_attribute("autocomplete") or "").strip().lower()
        name = str(element.get_attribute("name") or "").strip().lower()
        return field_type == "password" or "password" in autocomplete or "password" in name
    except Exception:
        return False


def _trusted_keyboard_input_snapshot(driver, element, stage: str) -> dict:
    """Capture secret-free evidence about the real password input boundary."""
    try:
        result = driver.execute_script(r"""
            // repo0810PasswordInputDiagnostics
            const el = arguments[0];
            const stage = String(arguments[1] || '');
            const key = '__repo0810PasswordInputDiagnostics';
            if (!el[key]) {
              const counts = {
                keydown_count: 0, trusted_keydown_count: 0,
                beforeinput_count: 0, trusted_beforeinput_count: 0,
                input_count: 0, trusted_input_count: 0,
                change_count: 0, focus_count: 0, blur_count: 0,
                last_input_type: '',
              };
              const count = (name, trustedName) => event => {
                counts[name] += 1;
                if (trustedName && event.isTrusted) counts[trustedName] += 1;
                if (event.inputType) counts.last_input_type = String(event.inputType).slice(0, 40);
              };
              el.addEventListener('keydown', count('keydown_count', 'trusted_keydown_count'), true);
              el.addEventListener('beforeinput', count('beforeinput_count', 'trusted_beforeinput_count'), true);
              el.addEventListener('input', count('input_count', 'trusted_input_count'), true);
              el.addEventListener('change', count('change_count'), true);
              el.addEventListener('focus', count('focus_count'), true);
              el.addEventListener('blur', count('blur_count'), true);
              el[key] = counts;
            }
            const counts = el[key];
            return {
              stage,
              connected: !!el.isConnected,
              active: document.activeElement === el,
              disabled: !!el.disabled,
              read_only: !!el.readOnly,
              dom_value_length: String(el.value || '').length,
              attribute_value_length: String(el.getAttribute('value') || '').length,
              keydown_count: counts.keydown_count,
              trusted_keydown_count: counts.trusted_keydown_count,
              beforeinput_count: counts.beforeinput_count,
              trusted_beforeinput_count: counts.trusted_beforeinput_count,
              input_count: counts.input_count,
              trusted_input_count: counts.trusted_input_count,
              change_count: counts.change_count,
              focus_count: counts.focus_count,
              blur_count: counts.blur_count,
              last_input_type: counts.last_input_type,
            };
        """, element, str(stage or "")) or {}
        return result if isinstance(result, dict) else {"stage": str(stage or "")}
    except Exception as exc:
        return {"stage": str(stage or ""), "snapshot_error": type(exc).__name__}


def _try_atomic_cdp_password_insert(driver, element, value: str, modifier: str):
    """Reacquire the current React field and atomically insert trusted text."""
    dispatch = getattr(driver, "execute_cdp_cmd", None)
    if not callable(dispatch):
        return False, element
    _, current = _wait_any(
        driver,
        [
            "input[autocomplete=new-password]",
            "input[autocomplete=current-password]",
            "input[name=password]",
            "input[type=password]",
        ],
        timeout=2,
    )
    if current is None:
        return False, element
    try:
        current.click()
    except Exception:
        pass
    try:
        driver.execute_script(
            "arguments[0].focus({preventScroll:true});",
            current,
        )
    except Exception:
        pass
    try:
        current.send_keys(modifier, "a")
        current.send_keys(_KEY_BACKSPACE)
        dispatch("Input.insertText", {"text": value})
        time.sleep(0.1)
        return str(current.get_attribute("value") or "") == value, current
    except Exception:
        return False, current


def _set_text_with_trusted_keyboard(driver, element, value: str) -> None:
    """Use WebDriver's native key path for controlled password fields."""
    input_diagnostics = [
        _trusted_keyboard_input_snapshot(driver, element, "before")
    ]
    try:
        platform = str(driver.execute_script(
            "return navigator.userAgentData?.platform || navigator.platform || '';"
        ) or "").lower()
    except Exception:
        platform = ""
    modifier = _KEY_COMMAND if "mac" in platform else _KEY_CONTROL
    try:
        # Preserve the real interaction boundary used by the last successful
        # Roxy runs. React's controlled password input may ignore key events
        # until it has received an actual click/focus transition.
        element.click()
    except Exception:
        # Animated labels can transiently intercept the click. The focused
        # element Send Keys fallback below remains bounded and verified.
        pass
    try:
        # RoxyChrome 151 can acknowledge Element Send Keys without moving DOM
        # focus to a freshly mounted React password input. Focus the same field
        # first; the actual value still travels only through trusted key events.
        driver.execute_script(
            "arguments[0].focus({preventScroll:true}); "
            "return document.activeElement === arguments[0];",
            element,
        )
    except Exception:
        # Standard WebDriver implementations focus on Element Send Keys. Keep
        # that proven path when the optional DOM focus command is unavailable.
        pass
    try:
        # Keep the proven element Send Keys path first. If React remounts the
        # field while these per-key events are in flight, the bounded CDP
        # fallback below reacquires the current field and inserts atomically.
        element.send_keys(modifier, "a")
    except Exception as exc:
        raise TrustedKeyboardInputError("select_existing") from exc
    try:
        element.send_keys(_KEY_BACKSPACE)
    except Exception as exc:
        raise TrustedKeyboardInputError("clear_existing") from exc
    try:
        element.send_keys(value)
    except Exception as exc:
        raise TrustedKeyboardInputError("type_value") from exc
    time.sleep(0.25)
    deadline = time.monotonic() + 2.0
    while True:
        try:
            observed = str(element.get_attribute("value") or "")
        except Exception as exc:
            raise TrustedKeyboardInputError("readback") from exc
        if observed == value:
            return
        if time.monotonic() >= deadline:
            input_diagnostics.append(
                _trusted_keyboard_input_snapshot(driver, element, "after")
            )
            inserted, current = _try_atomic_cdp_password_insert(
                driver, element, value, modifier
            )
            if inserted:
                input_diagnostics.append(
                    _trusted_keyboard_input_snapshot(
                        driver, current, "cdp_after"
                    )
                )
                driver._repo0810_password_input_diagnostics = input_diagnostics
                return
            if current is not element:
                input_diagnostics.append(
                    _trusted_keyboard_input_snapshot(
                        driver, current, "cdp_after"
                    )
                )
            driver._repo0810_password_input_diagnostics = input_diagnostics
            raise TrustedKeyboardInputError(
                "value_not_stable", input_diagnostics=input_diagnostics
            )
        time.sleep(0.05)


def _set_text_verified(driver, element, value: str) -> None:
    """Write through React's native setter first; use WebDriver only as fallback."""
    if (
        getattr(driver, "_repo0810_trusted_keyboard_submit_enabled", False) is True
        and _is_password_field(element)
    ):
        _set_text_with_trusted_keyboard(driver, element, value)
        return
    driver.execute_script(r"""
        const el = arguments[0], value = arguments[1];
        const descriptor = Object.getOwnPropertyDescriptor(
            el.tagName === 'TEXTAREA' ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype,
            'value'
        );
        if (descriptor && descriptor.set) descriptor.set.call(el, value);
        else el.value = value;
        el.dispatchEvent(new Event('input', {bubbles:true}));
        el.dispatchEvent(new Event('change', {bubbles:true}));
    """, element, value)

    def read_value() -> str:
        return str(element.get_attribute("value") or "")

    deadline = time.monotonic() + 0.5

    def wait_for_stable(current: str) -> str:
        if current == value:
            return current
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return current
        return _poll_until(
            read_value,
            lambda observed: observed == value,
            timeout=remaining,
            interval=0.05,
        )

    current = read_value()
    current = wait_for_stable(current)
    if current != value:
        _set_text(element, value)
        current = read_value()
        current = wait_for_stable(current)
    if current != value:
        raise RuntimeError("React 输入框未稳定保存目标值，拒绝提交")


def _capture_submit_target_metadata(driver, target) -> dict:
    """Return bounded non-secret metadata for the one target we will submit."""
    script = r"""
        const x = arguments[0];
        return {
            tag: String(x.tagName || '').toLowerCase(),
            type: String(x.getAttribute('type') || '').toLowerCase(),
            name: String(x.getAttribute('name') || '').slice(0, 48),
            value: String(x.getAttribute('value') || '').slice(0, 72),
            href_path: (() => { try { return new URL(x.href || '', location.href).pathname; } catch (_) { return ''; } })(),
            testid: String(x.getAttribute('data-testid') || '').slice(0, 48),
        };
    """
    try:
        captured = driver.execute_script(script, target)
        return captured if isinstance(captured, dict) else {}
    except Exception:
        return {}


def _click_submit_target(driver, target) -> None:
    """Deliver one opt-in native click, or one WebDriver fallback, and record it."""
    metadata = _capture_submit_target_metadata(driver, target)
    pointer_dispatch = _native_pointer_click(driver, target)
    if pointer_dispatch in {"dispatched", "uncertain"}:
        metadata["click_mode"] = "cdp_pointer"
        metadata["pointer_dispatch"] = pointer_dispatch
        hit = str(getattr(driver, "_repo0810_last_pointer_hit", "") or "").lower()
        if hit in {"target", "descendant", "iframe", "other", "none"}:
            metadata["pointer_hit"] = hit
    else:
        # Never send a second submit after a pointer sequence. A fallback is
        # allowed only when the native path refused before dispatching a click.
        hit = str(getattr(driver, "_repo0810_last_pointer_hit", "") or "").lower()
        if hit in {"iframe", "other", "none"}:
            metadata["pointer_hit"] = hit
            metadata["click_mode"] = "webdriver_fallback_overlay"
        target.click()
    if metadata:
        driver._repo0810_last_submit_target = metadata


def _click_email_submit(driver, input_element) -> None:
    """Submit a visible email form exactly once without password-flow filtering."""
    if getattr(driver, "_repo0810_async_email_submit_enabled", False) is True:
        # Do selection and scheduling in one renderer round-trip. Returning a
        # WebElement to Python and then calling ``.click()`` lets a React rerender
        # stale the target, and ChromeDriver can wait for navigation instead of
        # returning from the click command. This request-scoped variant queues
        # exactly one local form-button click after WebDriver has returned.
        scheduled = driver.execute_script(r"""
            const input = arguments[0];
            const scope = input.form || input.closest('form') || document;
            const visible = x => !!(x && (x.offsetWidth || x.offsetHeight ||
                x.getClientRects().length));
            const target = [...scope.querySelectorAll('button[type=submit],input[type=submit]')]
              .find(x => visible(x) && !x.disabled &&
                  String(x.getAttribute('aria-disabled') || '').toLowerCase() !== 'true') || null;
            if (!target) return {ok: false, reason: 'missing_submit'};
            const submitTarget = {
                tag: String(target.tagName || '').toLowerCase(),
                type: String(target.getAttribute('type') || '').toLowerCase(),
                name: String(target.getAttribute('name') || '').slice(0, 48),
                value: String(target.getAttribute('value') || '').slice(0, 72),
                testid: String(target.getAttribute('data-testid') || '').slice(0, 48),
            };
            setTimeout(() => {
                try { target.click(); } catch (_) {}
            }, 80);
            return {ok: true, submit_target: submitTarget};
        """, input_element) or {}
        if not isinstance(scheduled, dict) or scheduled.get("ok") is not True:
            raw_reason = (
                str(scheduled.get("reason") or "")
                if isinstance(scheduled, dict)
                else ""
            ).strip().lower()
            reason = (
                raw_reason
                if re.fullmatch(r"[a-z][a-z0-9_]{0,31}", raw_reason)
                else "unknown"
            )
            raise RuntimeError(f"异步邮箱提交准备失败：reason={reason}")
        metadata = scheduled.get("submit_target")
        if not isinstance(metadata, dict):
            metadata = {}
        metadata = dict(metadata)
        metadata["click_mode"] = "async_dom_click"
        driver._repo0810_last_submit_target = metadata
        return

    target = driver.execute_script(r"""
        const input = arguments[0];
        const scope = input.form || input.closest('form') || document;
        const visible = x => !!(x && (x.offsetWidth || x.offsetHeight ||
            x.getClientRects().length));
        return [...scope.querySelectorAll('button[type=submit],input[type=submit]')]
          .find(x => visible(x) && !x.disabled &&
              String(x.getAttribute('aria-disabled') || '').toLowerCase() !== 'true') || null;
    """, input_element)
    if target is None:
        raise RuntimeError("本地邮箱表单没有可用提交按钮")
    _click_submit_target(driver, target)


def _native_pointer_click(driver, element) -> str:
    """Return whether one CDP click was dispatched, uncertain, or not dispatched."""
    if getattr(driver, "_repo0810_native_pointer_enabled", False) is not True:
        return "not_dispatched"
    dispatch = getattr(driver, "execute_cdp_cmd", None)
    if not callable(dispatch):
        return "not_dispatched"
    try:
        driver.execute_script(
            "arguments[0].scrollIntoView({block:'center', inline:'center'});",
            element,
        )
        point = driver.execute_script(r"""
            const el = arguments[0];
            const rect = el.getBoundingClientRect();
            const x = rect.left + rect.width / 2;
            const y = rect.top + rect.height / 2;
            const hit = document.elementFromPoint(x, y);
            let hitKind = 'none';
            if (hit === el) hitKind = 'target';
            else if (hit && el.contains(hit)) hitKind = 'descendant';
            else if (hit && (String(hit.tagName || '').toLowerCase() === 'iframe' || hit.closest?.('iframe'))) hitKind = 'iframe';
            else if (hit) hitKind = 'other';
            return {x, y, hit: hitKind};
        """, element)
        if not isinstance(point, dict):
            return "not_dispatched"
        x = float(point.get("x") or 0)
        y = float(point.get("y") or 0)
        if x <= 0 or y <= 0:
            return "not_dispatched"
        hit = str(point.get("hit") or "").lower()
        if hit in {"target", "descendant", "iframe", "other", "none"}:
            driver._repo0810_last_pointer_hit = hit
        if hit not in {"target", "descendant"}:
            return "not_dispatched"
        dispatch("Input.dispatchMouseEvent", {"type": "mouseMoved", "x": x, "y": y})
        time.sleep(0.05)
    except Exception:
        return "not_dispatched"
    try:
        dispatch(
            "Input.dispatchMouseEvent",
            {"type": "mousePressed", "x": x, "y": y, "button": "left", "clickCount": 1},
        )
        time.sleep(0.05)
        dispatch(
            "Input.dispatchMouseEvent",
            {"type": "mouseReleased", "x": x, "y": y, "button": "left", "clickCount": 1},
        )
    except Exception:
        # Once mousePressed has been handed to the transport, a timeout cannot
        # tell us whether Chrome received it. Never issue a second synchronous
        # WebDriver click; the existing post-submit state wait/recovery decides
        # whether the page advanced.
        return "uncertain"
    return "dispatched"


def _click_submit(driver, input_element, timeout: int = 10) -> None:
    if (
        getattr(driver, "_repo0810_trusted_keyboard_submit_enabled", False) is True
        and _is_password_field(input_element)
    ):
        try:
            input_element.send_keys(_KEY_ENTER)
        except Exception as exc:
            raise RuntimeError("可信键盘提交无法发送 Enter") from exc
        driver._repo0810_last_submit_target = {
            "type": "keyboard",
            "click_mode": "keyboard_enter",
        }
        return
    _click_submit_button(driver, input_element, timeout=timeout)


def _click_submit_button(driver, input_element, timeout: int = 10) -> None:
    """Click one enabled non-passwordless submit button for stall recovery."""
    end = time.time() + max(1, int(timeout))
    script = r"""
        const input = arguments[0];
        const scope = input.form || input.closest('form') || document;
        const visible = x => !!(x && (x.offsetWidth || x.offsetHeight ||
            x.getClientRects().length));
        const isPasswordlessIntent = x => {
            const metadata = [
                x.getAttribute('name'), x.getAttribute('value'),
                x.getAttribute('data-testid'), x.getAttribute('data-dd-action-name'),
                x.getAttribute('aria-label'), x.textContent,
            ].filter(Boolean).join(' ').toLowerCase();
            return /passwordless_signup_send_otp|passwordless|one-time|otp|email\s*code/.test(metadata);
        };
        return [...scope.querySelectorAll('button[type=submit],input[type=submit]')]
            .find(x => visible(x) && !x.disabled &&
                String(x.getAttribute('aria-disabled') || '').toLowerCase() !== 'true' &&
                !isPasswordlessIntent(x)) || null;
    """
    while time.time() < end:
        submit = driver.execute_script(script, input_element)
        if submit is not None:
            _click_submit_target(driver, submit)
            return
        time.sleep(0.25)
    raise RuntimeError("密码页提交按钮未在时限内变为可用")


def _recover_email_submit_via_request_submit(driver, email: str) -> dict:
    """Queue one normal click on the current form; never force a disabled form."""
    try:
        result = driver.execute_script(r"""
            const email = String(arguments[0] || '').trim();
            const selector = String(arguments[1] || '');
            const outcome = state => { window.__repo0810EmailRecoveryState = state; };
            const rendered = el => !!(el && el.isConnected &&
                (el.offsetWidth || el.offsetHeight || el.getClientRects().length) &&
                getComputedStyle(el).visibility !== 'hidden' &&
                getComputedStyle(el).display !== 'none');
            const visible = el => rendered(el) && !el.disabled && !el.readOnly;
            const currentForm = () => {
                const input = [...document.querySelectorAll(selector)].find(visible);
                if (!input) return {reason: 'missing_email_input'};
                const form = input.form || input.closest('form');
                if (!form || !form.isConnected) return {reason: 'missing_form'};
                const busy = '[aria-busy="true"], [data-loading="true"]';
                if (form.closest(busy) || [...form.querySelectorAll(busy)].some(rendered)) {
                    return {reason: 'page_busy'};
                }
                const submit = [...form.querySelectorAll('button[type="submit"],input[type="submit"]')]
                    .find(el => visible(el) &&
                        String(el.getAttribute('aria-disabled') || '').toLowerCase() !== 'true');
                if (!submit) return {reason: 'missing_submit'};
                return {input, form, submit};
            };
            const initial = currentForm();
            if (initial.reason) {
                outcome(initial.reason);
                return {ok: false, reason: initial.reason, scheduled: false};
            }
            const input = initial.input;
            const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
            if (setter) setter.call(input, email);
            else input.value = email;
            input.dispatchEvent(new InputEvent('input', {
                bubbles: true,
                inputType: 'insertText',
                data: email,
            }));
            input.dispatchEvent(new Event('change', {bubbles: true}));
            outcome('queued');
            setTimeout(() => {
                try {
                    // React can replace the input/form during the event or delay.
                    // Never click detached controls or overwrite a changed identity.
                    const current = currentForm();
                    if (current.reason) { outcome(current.reason); return; }
                    if (current.input.value !== email) { outcome('input_changed'); return; }
                    if ([...current.form.elements].some(el =>
                        el.willValidate && el.validity && !el.validity.valid)) {
                        outcome('form_invalid');
                        return;
                    }
                    const observed = () => outcome('submit_observed');
                    current.form.addEventListener('submit', observed, true);
                    try {
                        outcome('click_dispatched');
                        current.submit.click();
                    } finally {
                        current.form.removeEventListener('submit', observed, true);
                    }
                } catch (_) { outcome('dispatch_exception'); }
            }, 80);
            return {
                ok: true,
                reason: 'request_submit_recovery',
                scheduled: true,
                has_form: true,
                has_submit: true,
            };
        """, email, _EMAIL_INPUT_SELECTOR_QUERY) or {}
        if isinstance(result, dict):
            return result
    except Exception:
        return {"ok": False, "reason": "webdriver_error"}
    return {"ok": False, "reason": "invalid_result"}


def _recover_email_submit_via_native_form(driver, email: str) -> dict:
    """Bypass a stalled frontend handler with the form's native navigation."""
    try:
        result = driver.execute_script(r"""
            const email = String(arguments[0] || '').trim();
            const visible = el => !!(el && (el.offsetWidth || el.offsetHeight ||
                el.getClientRects().length) && getComputedStyle(el).visibility !== 'hidden' &&
                getComputedStyle(el).display !== 'none' && !el.disabled && !el.readOnly);
            const input = [...document.querySelectorAll(
                String(arguments[1] || '')
            )].find(visible);
            if (!input) return {ok: false, reason: 'missing_email_input'};
            const form = input.closest('form');
            if (!form) return {ok: false, reason: 'missing_form'};
            let action;
            try {
                action = new URL(form.action || location.href, location.href);
            } catch (_) {
                return {ok: false, reason: 'invalid_form_action'};
            }
            if (action.origin !== location.origin) {
                return {ok: false, reason: 'cross_origin_form'};
            }
            const setter = Object.getOwnPropertyDescriptor(
                HTMLInputElement.prototype, 'value'
            )?.set;
            if (setter) setter.call(input, email);
            else input.value = email;
            input.dispatchEvent(new InputEvent('input', {
                bubbles: true,
                inputType: 'insertText',
                data: email,
            }));
            input.dispatchEvent(new Event('change', {bubbles: true}));
            if (!input.checkValidity() || !form.checkValidity()) {
                return {ok: false, reason: 'invalid_form'};
            }
            setTimeout(() => {
                try {
                    HTMLFormElement.prototype.submit.call(form);
                } catch (_) {}
            }, 0);
            return {
                ok: true,
                reason: 'native_form_navigation',
                method: String(form.method || 'get').toLowerCase(),
                action_path: action.pathname,
            };
        """, email, _EMAIL_INPUT_SELECTOR_QUERY) or {}
        if isinstance(result, dict):
            return result
    except Exception as exc:
        return {"ok": False, "reason": f"{type(exc).__name__}: {exc}"}
    return {"ok": False, "reason": f"invalid_result:{type(result).__name__}"}


def _has_access_token(driver) -> bool:
    try:
        host = urllib.parse.urlsplit(
            str(getattr(driver, "current_url", "") or "")
        ).hostname or ""
        if host.lower() not in {"chatgpt.com", "www.chatgpt.com"}:
            return False
        session = driver.execute_async_script("""
            const done = arguments[0];
            fetch('/api/auth/session', {credentials:'include'})
              .then(r => r.json()).then(done).catch(() => done({}));
        """) or {}
        return bool(session.get("accessToken"))
    except Exception:
        return False


def _state_has_http_500(state: dict) -> bool:
    """Recognize a 500 page even when the browser URL still looks like login."""
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


def _post_email_page_state(driver) -> dict:
    script = r"""
        const visible = el => !!(el && (el.offsetWidth || el.offsetHeight ||
            el.getClientRects().length) && !el.disabled && !el.readOnly);
        const visibleText = el => !!(el && (el.offsetWidth || el.offsetHeight ||
            el.getClientRects().length));
        const bodyText = String(document.body?.innerText || '').replace(/\s+/g, ' ').toLowerCase();
        const scrubStatus = value => String(value || '')
            .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, '[EMAIL]')
            .replace(/https?:\/\/[^\s"<>]+/gi, '[URL]')
            .replace(/\b\d{5,}\b/g, '[NUMBER]')
            .replace(/\s+/g, ' ').trim().slice(0, 160);
        const title = scrubStatus(document.title);
        const statusText = scrubStatus(document.body?.innerText || '');
        const errorText = [...document.querySelectorAll(
            '[role="alert"], [aria-live="assertive"], [data-testid*="error"], p'
        )]
            .filter(visibleText)
            .map(el => String(el.innerText || el.textContent || '').replace(/\s+/g, ' ').toLowerCase())
            .join(' ');
        const submitButtons = [...document.querySelectorAll(
            'button[type=submit], input[type=submit]'
        )].filter(visibleText);
        const statusEvidence = (title + ' ' + statusText).toLowerCase();
        const httpStatus500 = /\b500\b/.test(statusEvidence)
            && (/internal\s+server\s+error|route\s+error|http\s+error|server\s+error/.test(statusEvidence)
                || /^\s*500\s*$/.test(statusEvidence));
        const routeError500 = httpStatus500
            || /route error\s*\(\s*500(?:\s+internal server error)?\s*\)/.test(bodyText)
            || (/500\s+internal server error/.test(bodyText) && /istrusted/.test(bodyText));
        return {
          url: location.href,
          title: title,
          status_text: statusText,
          http_status_500: httpStatus500,
          inputs: [...document.querySelectorAll('input')]
            .filter(visible)
            .map(el => ({
              type: el.type || '',
              name: el.name || '',
              autocomplete: el.autocomplete || '',
              inputmode: el.inputMode || '',
            })),
          password_error: /incorrect password|invalid password|wrong password|password is incorrect|密码错误|密码不正确|パスワードが違います/.test(
            bodyText + ' ' + errorText
          ),
          submit_disabled: submitButtons.some(el => !!el.disabled ||
            String(el.getAttribute('aria-disabled') || '').toLowerCase() === 'true'),
          page_busy: [...document.querySelectorAll('[aria-busy="true"], [data-loading="true"]')]
            .some(visibleText),
          route_error_500: routeError500,
        };
    """
    try:
        dispatch = getattr(driver, "execute_cdp_cmd", None)
        if callable(dispatch):
            payload = dispatch(
                "Runtime.evaluate",
                {
                    "expression": "(() => {\n" + script + "\n})()",
                    "returnByValue": True,
                },
            )
            if isinstance(payload, dict):
                remote = payload.get("result")
                if isinstance(remote, dict) and isinstance(remote.get("value"), dict):
                    return remote["value"]
        state = driver.execute_script(script) or {}
        if isinstance(state, dict):
            return state
    except Exception:
        pass
    return {"url": str(getattr(driver, "current_url", "") or ""), "inputs": []}


def _safe_email_submit_snapshot(
    driver,
    stage: str,
    *,
    state: str = "",
    started_at: float | None = None,
    recovery: dict | None = None,
) -> dict:
    """Return one bounded, credential-free email transition checkpoint."""
    normalized_stage = str(stage or "").strip().lower()
    if normalized_stage not in _EMAIL_SUBMIT_TRACE_STAGES:
        return {}
    snapshot = {"stage": normalized_stage}
    page_state = _post_email_page_state(driver)
    if not isinstance(page_state, dict):
        page_state = {}
    normalized_state = str(state or "").strip().lower()
    if normalized_state in _EMAIL_SUBMIT_TRACE_STATES:
        snapshot["state"] = normalized_state
    url = safe_url(page_state.get("url") or getattr(driver, "current_url", ""))
    if url:
        snapshot["url"] = url
    inputs = page_state.get("inputs") or []
    snapshot["has_email_input"] = any(
        isinstance(item, dict) and (
            str(item.get("type") or "").strip().lower() == "email"
            or str(item.get("name") or "").strip().lower() == "email"
            or "email" in str(item.get("autocomplete") or "").strip().lower()
        )
        for item in inputs
    )
    for key in ("submit_disabled", "page_busy"):
        if isinstance(page_state.get(key), bool):
            snapshot[key] = page_state[key]
    if normalized_stage == "after_initial_submit":
        target = getattr(driver, "_repo0810_last_submit_target", None)
        if isinstance(target, dict):
            click_mode = str(target.get("click_mode") or "").strip().lower()
            if click_mode in _EMAIL_SUBMIT_CLICK_MODES:
                snapshot["click_mode"] = click_mode
    if started_at is not None:
        try:
            snapshot["elapsed_ms"] = min(
                999999,
                max(0, int(round((time.monotonic() - float(started_at)) * 1000))),
            )
        except (TypeError, ValueError):
            pass
    if isinstance(recovery, dict):
        if isinstance(recovery.get("ok"), bool):
            snapshot["recovery_ok"] = recovery["ok"]
        raw_reason = str(recovery.get("reason") or "").strip().lower()
        snapshot["recovery_reason"] = (
            raw_reason
            if re.fullmatch(r"[a-z][a-z0-9_]{0,31}", raw_reason)
            else "unknown"
        )
        for source in ("has_form", "has_submit"):
            if isinstance(recovery.get(source), bool):
                snapshot[source] = recovery[source]
    return snapshot


def _classify_post_email_state(driver) -> str:
    state = _post_email_page_state(driver)
    raw_url = str(state.get("url") or getattr(driver, "current_url", "") or "")
    url = raw_url.lower()
    inputs = state.get("inputs") or []
    if _auth_callback_error_state(raw_url):
        return "auth_callback_error"
    if url.startswith("chrome-error://chromewebdata/"):
        return "browser_error"
    if _state_has_http_500(state):
        return "route_error_500"
    if state.get("password_error"):
        return "password_error"
    attrs = " ".join(
        " ".join(str(item.get(key) or "") for key in (
            "type", "name", "autocomplete", "inputmode"
        ))
        for item in inputs
    ).lower()
    has_current_password_input = any(
        str(item.get("autocomplete") or "").lower() == "current-password"
        or str(item.get("type") or "").lower() == "password"
        for item in inputs
    )
    if "/log-in/password" in url:
        if state.get("submit_disabled") or state.get("page_busy"):
            return "loading"
        if not has_current_password_input:
            return "login_password_shell"
        return "login_password"
    if "/auth/login" in url and not inputs:
        # A live run proved this URL can remain a blank, still-loading document
        # for minutes.  A password route requires an actual password input;
        # URL alone is not evidence that the current-password page mounted.
        return "loading"
    if "email-verification" in url or any(
        marker in attrs for marker in ("one-time-code", " otp", " code", "numeric")
    ):
        return "otp"
    password_route = any(route in url for route in (
        "/create-account/password", "/signup/password", "/u/signup/password"
    ))
    has_new_password_input = any(
        str(item.get("autocomplete") or "").lower() == "new-password"
        or str(item.get("type") or "").lower() == "password"
        for item in inputs
    )
    if password_route:
        if state.get("submit_disabled") or state.get("page_busy"):
            return "loading"
        if not has_new_password_input:
            return "password_shell"
        return "password"
    if has_new_password_input:
        return "password"
    if any(
        str(item.get("autocomplete") or "").lower() == "current-password"
        for item in inputs
    ):
        return "login_password"
    if any(
        str(item.get("type") or "").lower() == "email"
        or str(item.get("name") or "").lower() == "email"
        for item in inputs
    ):
        return "email_page"
    try:
        parsed = urllib.parse.urlsplit(url)
    except Exception:
        parsed = None
    if (
        parsed is not None
        and (parsed.hostname or "").lower() in {"chatgpt.com", "www.chatgpt.com"}
        and not (parsed.path or "").startswith("/auth/")
        and _has_access_token(driver)
    ):
        return "logged_in"
    return "unknown"


def _wait_post_email_state(driver, timeout: int = 40) -> str:
    return _poll_until(
        lambda: _classify_post_email_state(driver),
        lambda state: state in {
            "password", "login_password", "otp", "logged_in", "route_error_500",
            "auth_callback_error", "browser_error",
        },
        timeout=max(1, int(timeout)),
        interval=0.25,
    )


class RoxyEmailSubmitError(RuntimeError):
    """Terminal email failure with fixed text and allowlisted diagnostics."""

    def __init__(self, state: str, url: str):
        self.failure_phase = "email_submit"
        self.failure_cause = {
            "auth_callback_error": "auth_callback_error",
            "browser_error": "browser_transport_error",
            "route_error_500": "auth_route_error_500",
        }[state]
        self.safe_message = {
            "auth_callback_error": "Email authentication ended on /auth/error",
            "browser_error": "Email authentication browser transport failed",
            "route_error_500": "Email authentication returned HTTP 500",
        }[state]
        self.email_submit_diagnostics = {"email_submit_reason": self.failure_cause}
        code = _auth_callback_error_state(url).get("auth_error_code")
        if state == "auth_callback_error" and code:
            self.email_submit_diagnostics["auth_error_code"] = code
        super().__init__(self.safe_message)


def _raise_email_terminal_error(driver, state: str) -> None:
    url = str(getattr(driver, "current_url", "") or "")
    # Navigation can complete between the classifier sample and recovery.
    if _auth_callback_error_state(url):
        state = "auth_callback_error"
    elif url.lower().startswith("chrome-error://chromewebdata/"):
        state = "browser_error"
    if state in {"auth_callback_error", "browser_error", "route_error_500"}:
        raise RoxyEmailSubmitError(state, url)


def _wait_post_email_with_single_recovery(driver, email: str, timeout: int = 40) -> str:
    state = _wait_post_email_state(driver, timeout=timeout)
    if state not in {"email_page", "loading", "unknown"}:
        return state
    for attempt in (1, 2):
        _, email_input = _wait_any(
            driver,
            _EMAIL_INPUT_SELECTORS,
            timeout=5,
        )
        if email_input is None:
            return state
        if attempt == 1:
            _set_text_verified(driver, email_input, email)
            _click_submit(driver, email_input)
        else:
            _recover_email_submit_via_request_submit(driver, email)
        state = _wait_post_email_state(driver, timeout=max(4, min(20, timeout)))
        if state in {"password", "login_password", "otp", "logged_in"}:
            return state
        if state in {"email_page", "loading", "unknown"} and attempt == 2:
            break
        if state in {"email_page", "loading", "unknown"}:
            time.sleep(0.6)
    return state


def _password_reset_page_state(driver) -> dict:
    """Collect bounded, secret-free state for the password-reset route."""
    try:
        state = driver.execute_script(r"""
            const visible = el => !!(el && (el.offsetWidth || el.offsetHeight ||
              el.getClientRects().length) && getComputedStyle(el).display !== 'none' &&
              getComputedStyle(el).visibility !== 'hidden');
            const scrub = value => String(value || '').replace(/\s+/g, ' ').trim().slice(0, 180);
            const inputs = [...document.querySelectorAll('input')].filter(visible).map(el => ({
              type: String(el.type || '').toLowerCase(),
              name: String(el.name || '').toLowerCase(),
              autocomplete: String(el.autocomplete || '').toLowerCase(),
              disabled: !!el.disabled,
            }));
            const controls = [...document.querySelectorAll('button,a,[role=button],[role=link]')]
              .filter(visible).slice(0, 20).map(el => scrub([
                el.innerText, el.textContent, el.getAttribute('aria-label'),
                el.getAttribute('href'), el.getAttribute('data-testid'),
              ].filter(Boolean).join(' ')));
            return {
              url: location.href,
              body_text: scrub(document.body?.innerText || ''),
              inputs,
              controls,
            };
        """) or {}
        return state if isinstance(state, dict) else {}
    except Exception as exc:
        return {"snapshot_error": type(exc).__name__}


def _classify_password_reset_state(driver) -> str:
    """Classify only states that are sufficient for the reset state machine."""
    state = _password_reset_page_state(driver)
    url = str(state.get("url") or getattr(driver, "current_url", "") or "").lower()
    body = str(state.get("body_text") or "").lower()
    if url.startswith("chrome-error://"):
        return "browser_error"
    if any(marker in body or marker in url for marker in (
        "password has been reset", "password reset successful", "password updated",
        "密码已重置", "密码更新成功",
    )):
        return "success"
    inputs = state.get("inputs") if isinstance(state.get("inputs"), list) else []
    normalized = [item for item in inputs if isinstance(item, dict) and not item.get("disabled")]
    has_otp = any(
        str(item.get("autocomplete") or "") in {"one-time-code", "sms-otp"}
        or any(marker in str(item.get(key) or "") for marker in ("otp", "verification", "code"))
        for item in normalized
        for key in ("name", "type")
    )
    if has_otp or "email-verification" in url or "verify-code" in url:
        return "otp"
    password_fields = [
        item for item in normalized
        if str(item.get("type") or "") == "password"
        or "new-password" in str(item.get("autocomplete") or "")
    ]
    if password_fields:
        return "new_password"
    if any(
        str(item.get("type") or "") == "email"
        or "email" in str(item.get("name") or "")
        for item in normalized
    ):
        return "reset_email"
    if "password" in url or "forgot" in url or "reset" in url:
        return "reset_shell"
    return "unknown"


def _click_password_reset_entry(driver, timeout: int = 20) -> bool:
    """Click a visible, explicitly labelled forgot-password control once."""
    script = r"""
        const visible = el => !!(el && (el.offsetWidth || el.offsetHeight ||
          el.getClientRects().length) && !el.disabled &&
          String(el.getAttribute('aria-disabled') || '').toLowerCase() !== 'true');
        const label = el => [el.innerText, el.textContent, el.getAttribute('aria-label'),
          el.getAttribute('title'), el.getAttribute('data-testid'), el.getAttribute('href')]
          .filter(Boolean).join(' ').replace(/\s+/g, '').toLowerCase();
        const target = [...document.querySelectorAll(
          'a,button,[role=button],[role=link],input[type=button],input[type=submit]'
        )].filter(visible).find(el => {
          const text = label(el);
          return /forgotpassword|resetpassword|forgottenpassword|忘记密码|重置密码|パスワードを忘れた/.test(text);
        });
        if (!target) return false;
        target.click();
        return true;
    """
    deadline = time.monotonic() + max(1, int(timeout))
    while time.monotonic() < deadline:
        try:
            if bool(driver.execute_script(script)):
                return True
        except Exception:
            pass
        time.sleep(0.25)
    return False


def _wait_password_reset_state(driver, timeout: int = 30) -> str:
    return _poll_until(
        lambda: _classify_password_reset_state(driver),
        lambda state: state in {"otp", "new_password", "reset_email", "success", "browser_error"},
        timeout=max(1, int(timeout)),
        interval=0.25,
    )


def _submit_password_reset_email(driver, email: str, timeout: int = 30) -> str:
    _, element = _wait_any(driver, _EMAIL_INPUT_SELECTORS, timeout=min(15, timeout))
    if element is None:
        raise RoxyPasswordResetError(
            "密码找回页面没有邮箱输入框", phase="password_reset_email", cause="email_input_missing"
        )
    _set_text_verified(driver, element, email)
    _click_submit_button(driver, element, timeout=min(10, timeout))
    return _wait_password_reset_state(driver, timeout=timeout)


def _submit_password_reset_new_password(driver, password: str, timeout: int = 45) -> str:
    _, first = _wait_any(driver, _NEW_PASSWORD_INPUT_SELECTORS, timeout=min(20, timeout))
    if first is None:
        raise RoxyPasswordResetError(
            "密码找回页面没有新密码输入框", phase="password_reset_submit", cause="new_password_input_missing"
        )
    fields = driver.execute_script(r"""
        const visible = el => !!(el && (el.offsetWidth || el.offsetHeight || el.getClientRects().length) &&
          !el.disabled && getComputedStyle(el).display !== 'none' && getComputedStyle(el).visibility !== 'hidden');
        return [...document.querySelectorAll('input[type=password], input[autocomplete*=new-password]')]
          .filter(visible);
    """) or [first]
    for field in fields[:2]:
        _set_text_verified(driver, field, password)
    _click_submit_button(driver, first, timeout=min(10, timeout))
    state = _wait_password_reset_state(driver, timeout=timeout)
    if state != "success":
        raise RoxyPasswordResetError(
            "提交新密码后未出现明确成功状态",
            phase="password_reset_submit",
            cause="success_state_missing",
        )
    return state


def _run_password_reset_flow(driver, req: dict, password: str) -> dict:
    """Drive the official forgot-password flow; never fall back to login success."""
    email = str(req.get("email") or "").strip().lower()
    callback = str(req.get("otp_callback") or "")
    nonce = str(req.get("otp_nonce") or "")
    timeout = max(10, min(600, int(req.get("otp_timeout") or 180)))
    _report_progress(req, "password_reset_prepare")
    _open_auth_login_page(driver, timeout=45)
    _assert_auth_entry_ready(driver, "", timeout=10)
    _report_progress(req, "password_reset_email")
    state = _wait_post_email_with_single_recovery(driver, email, timeout=60)
    if state == "browser_error":
        raise RoxyPasswordResetError("密码找回入口浏览器加载失败", phase="password_reset_email", cause="browser_error")
    if state not in {"login_password", "password"}:
        raise RoxyPasswordResetError(
            "提交邮箱后未进入登录密码页，无法安全点击找回密码",
            phase="password_reset_email",
            cause="password_route_missing",
        )
    _report_progress(req, "password_reset_entry")
    if not _click_password_reset_entry(driver, timeout=20):
        raise RoxyPasswordResetError(
            "登录页没有明确的忘记密码入口",
            phase="password_reset_entry",
            cause="reset_entry_missing",
        )
    state = _wait_password_reset_state(driver, timeout=30)
    if state == "reset_email":
        state = _submit_password_reset_email(driver, email, timeout=30)
    if state == "otp":
        _report_progress(req, "password_reset_otp_wait")
        _wait_for_otp_input_with_recovery(driver, timeout=20)
        code = _otp_with_one_resend(driver, callback, nonce, time.time(), timeout)
        _report_progress(req, "password_reset_otp_submit")
        _submit_otp_with_one_invalid_retry(driver, code, callback, nonce, timeout=timeout)
        state = _wait_password_reset_state(driver, timeout=30)
    if state == "new_password":
        _report_progress(req, "password_reset_submit")
        _submit_password_reset_new_password(driver, password, timeout=45)
    elif state != "success":
        raise RoxyPasswordResetError(
            "密码找回流程需要邮件链接或未识别的验证方式，已停止",
            phase="password_reset_otp_wait",
            cause="reset_link_or_unknown_challenge",
        )
    _report_progress(req, "password_reset_complete")
    return {
        "success": True,
        "operation": "password_reset",
        "email": email,
        "password": password,
        "password_set": True,
        "password_verified": True,
        "profile_id": str(getattr(driver, "_repo0810_profile_id", "") or ""),
    }


def _wait_password_route_after_otp_click(driver, timeout: int = 20) -> str:
    return _poll_until(
        lambda: _classify_post_email_state(driver),
        lambda state: (
            state in {"password", "login_password", "logged_in"}
            or state not in {"otp", "email_page", "unknown", "loading"}
        ),
        timeout=max(1, int(timeout)),
        interval=0.25,
    )


def _switch_otp_to_password(
    driver,
    timeout: int = 20,
    email: str = "",
    *,
    allow_login_fallback: bool = True,
) -> str:
    selector_script = r"""
        const visible = el => !!(el && (el.offsetWidth || el.offsetHeight ||
            el.getClientRects().length) && !el.disabled &&
            String(el.getAttribute('aria-disabled') || '').toLowerCase() !== 'true');
        const candidates = [...document.querySelectorAll(
            'a,button,[role=button],[role=link],input[type=button],input[type=submit]'
        )].filter(visible);
        const target = candidates.find(el => {
            const text = [
                el.innerText,
                el.textContent,
                el.getAttribute('aria-label'),
                el.getAttribute('title'),
                el.getAttribute('data-testid'),
                el.getAttribute('data-dd-action-name'),
                el.getAttribute('value'),
            ].filter(Boolean).join(' ').replace(/\s+/g, '').toLowerCase();
            const href = String(el.getAttribute('href') || '').toLowerCase();
            return text.includes('使用密码继续')
              || text.includes('使用密码')
              || text.includes('continuewithpassword')
              || text.includes('usepassword')
              || text.includes('パスワードで続行')
              || text.includes('パスワードを使用')
              || href.includes('/password');
        });
        if (!target) return false;
        target.click();
        return true;
    """
    clicked = False
    end = time.time() + max(1, int(timeout))
    while time.time() < end and not clicked:
        clicked = bool(driver.execute_script(selector_script))
        if not clicked:
            time.sleep(0.5)
    if not clicked:
        if not allow_login_fallback:
            # Do not navigate away from an already-issued OTP challenge. A
            # direct create-account/password navigation creates a second auth
            # challenge and can leave two OTP pages in the same Profile.
            return "otp"
        normalized = str(email or "").strip().lower()
        if normalized:
            driver.get(
                "https://auth.openai.com/log-in/password?"
                + urllib.parse.urlencode({"email": normalized})
            )
            state = _wait_post_email_state(driver, timeout=timeout)
            if state == "login_password":
                return state
        return "otp"
    return _wait_password_route_after_otp_click(driver, timeout=timeout)


def _switch_login_password_to_otp(driver, timeout: int = 20) -> str:
    """Choose the provider's email-code continuation without submitting a password."""
    try:
        previous_script_timeout = getattr(
            getattr(driver, "timeouts", None), "script", None
        )
    except Exception:
        previous_script_timeout = None
    try:
        driver.set_script_timeout(max(1, min(3, int(timeout))))
        clicked = bool(driver.execute_script(r"""
        const visible = el => !!(el && (el.offsetWidth || el.offsetHeight ||
            el.getClientRects().length) && !el.disabled && !el.readOnly);
        const label = el => ([
            el.innerText,
            el.textContent,
            el.getAttribute('aria-label'),
            el.getAttribute('title'),
            el.value,
            el.getAttribute('data-testid'),
            el.getAttribute('name'),
            el.getAttribute('id'),
        ].filter(Boolean).join(' ')
          .replace(/\s+/g, '')
          .toLowerCase());
        const attr = el => ([
            el.getAttribute('name') || '',
            el.getAttribute('value') || '',
            el.getAttribute('data-action') || '',
            el.getAttribute('data-dd-action-name') || '',
        ].join(' ').toLowerCase());
        const href = x => String(x.getAttribute('href') || '').toLowerCase();
        const direct = [...document.querySelectorAll(
            'a,button,input[type=button],input[type=submit],[role=button]'
        )]
          .filter(visible)
          .find(el => {
            const txt = label(el);
            const a = attr(el);
            const h = href(el);
            return txt.includes('continuewithemail')
              || txt.includes('continuewithemailcode')
              || txt.includes('useemailcode')
              || txt.includes('emailcode')
              || txt.includes('emailverification')
              || txt.includes('useemail')
              || txt.includes('使用邮箱验证码')
              || txt.includes('使用验证码')
              || txt.includes('邮箱验证码')
              || txt.includes('通过电子邮件继续')
              || txt.includes('メールコード')
              || txt.includes('validate')
              || txt.includes('intent')
              || a.includes('email')
              || h.includes('/email-verification')
              || h.includes('email-otp')
              || h.includes('one-time-code');
          }) || null;
        if (direct) {
            direct.click();
            return true;
        }
        for (const form of [...document.querySelectorAll('form')]) {
            const formInputs = [...form.querySelectorAll('input')].filter(visible);
            const hasPassword = formInputs.some(el => String(el.type || '').toLowerCase() === 'password');
            const hasEmail = formInputs.some(el => String(el.type || '').toLowerCase() === 'email');
            const submit = [...form.querySelectorAll('input[type=submit],button[type=submit]')]
              .find(el => visible(el) && !String(el.getAttribute('name') || '').toLowerCase().includes('password'));
            if (submit && (hasPassword || hasEmail)) {
                submit.click();
                return true;
            }
        }
        return false;
        """))
        if not clicked:
            return _classify_post_email_state(driver)
        return _wait_post_email_state(driver, timeout=timeout)
    except Exception:
        # The atomic click may interrupt the command as the document unloads.
        # Observe the bounded destination state instead of clicking again.
        return _wait_post_email_state(driver, timeout=timeout)
    finally:
        try:
            restore = (
                float(previous_script_timeout)
                if isinstance(previous_script_timeout, (int, float))
                else ROXY_TIMEOUT
            )
            driver.set_script_timeout(restore)
        except Exception:
            pass


def _safe_password_transition_snapshot(driver, stage: str) -> dict:
    """Capture a bounded, secret-free state vector around one password submit."""
    if stage not in {"pre", "post", "before_refresh", "after_refresh"}:
        return {}
    snapshot: dict = {"s": stage}
    try:
        observed = driver.execute_script(r"""
            const visible = el => !!(el && (el.offsetWidth || el.offsetHeight ||
                el.getClientRects().length));
            const inputs = [...document.querySelectorAll('input')].filter(visible);
            const passwordInputs = inputs.filter(el =>
                String(el.type || '').toLowerCase() === 'password' ||
                String(el.autocomplete || '').toLowerCase() === 'new-password'
            );
            const submits = [...document.querySelectorAll('button[type=submit],input[type=submit]')]
                .filter(visible);
            const alerts = [...document.querySelectorAll(
                '[role="alert"], [aria-live="assertive"], [data-testid*="error"]'
            )].filter(visible);
            const busy = [...document.querySelectorAll('[aria-busy="true"], [data-loading="true"]')]
                .some(visible);
            const frameHosts = [...document.querySelectorAll('iframe')].map(frame => {
                try { return new URL(frame.getAttribute('src') || '', location.href).hostname.toLowerCase(); }
                catch (_) { return ''; }
            }).filter(Boolean);
            const frameCategory = (() => {
                if (frameHosts.some(host => host.includes('arkoselabs'))) return 'arkose';
                if (frameHosts.some(host => host.includes('cloudflare') || host.includes('turnstile'))) return 'cloudflare';
                if (frameHosts.some(host => host.includes('hcaptcha') || host.includes('recaptcha') || host.includes('captcha'))) return 'captcha';
                if (frameHosts.some(host => host.includes('challenge'))) return 'challenge';
                return frameHosts.length ? 'other' : 'none';
            })();
            return {
                r: String(document.readyState || ''),
                i: inputs.length,
                p: passwordInputs.length,
                v: passwordInputs.filter(el => String(el.value || '').length > 0).length,
                u: submits.length,
                d: submits.length > 0 && submits.every(el =>
                    !!el.disabled || String(el.getAttribute('aria-disabled') || '').toLowerCase() === 'true'
                ),
                b: busy,
                a: alerts.length > 0,
                f: window.frames.length,
                q: frameCategory,
            };
        """) or {}
        if not isinstance(observed, dict):
            observed = {}
        ready = str(observed.get("r") or "").lower()
        if ready in {"loading", "interactive", "complete"}:
            snapshot["r"] = ready
        challenge = str(observed.get("q") or "").lower()
        if challenge in {"none", "other", "captcha", "cloudflare", "arkose", "challenge"}:
            snapshot["q"] = challenge
        for key in ("i", "p", "v", "u", "f"):
            try:
                snapshot[key] = min(99, max(0, int(observed.get(key) or 0)))
            except (TypeError, ValueError):
                pass
        for key in ("d", "b", "a"):
            if isinstance(observed.get(key), bool):
                snapshot[key] = observed[key]
    except Exception as exc:
        snapshot["e"] = type(exc).__name__
    try:
        snapshot["w"] = min(99, max(0, len(driver.window_handles)))
    except Exception:
        pass
    return snapshot


def _wait_password_transition(
    driver,
    *,
    current_state: str,
    timeout: int,
) -> str:
    transitional = {
            "password", "password_shell", "login_password", "login_password_shell",
            "loading", "email_page", "unknown"
    }
    return _poll_until(
        lambda: _classify_post_email_state(driver),
        lambda state: state not in transitional,
        timeout=max(1, int(timeout)),
        interval=0.25,
    )


def _submit_password_and_wait(
    driver,
    element,
    timeout: int = 90,
    current_state: str = "password",
    transition_trace: list[dict] | None = None,
    password: str = "",
) -> str:
    # Probe early for a stalled SPA, then reserve the remaining bounded budget
    # for one same-window refresh and, if React cleared the field, one refilled
    # button submission.
    def snapshot(stage: str) -> None:
        if transition_trace is None or len(transition_trace) >= 4:
            return
        item = _safe_password_transition_snapshot(driver, stage)
        if isinstance(item, dict) and item.get("s") == stage:
            transition_trace.append(item)

    budget = min(90, max(1, int(timeout)))
    remaining_budget = budget
    initial_budget = min(8, remaining_budget)
    snapshot("pre")
    _click_submit(driver, element)
    snapshot("post")
    state = _wait_password_transition(
        driver,
        current_state=current_state,
        timeout=initial_budget,
    )
    remaining_budget -= initial_budget
    if state in {"otp", "logged_in", "password_error"}:
        return state

    transitional = {
        "password", "password_shell", "login_password", "login_password_shell",
        "loading", "email_page", "unknown"
    }
    if state not in transitional:
        return state

    # Live failures show the trusted Enter path can leave an enabled password
    # form unchanged without an error or busy marker.  Reuse the already-filled
    # value and click the real enabled form button once before refreshing.
    password_stall_states = {
        "password", "password_shell", "login_password", "login_password_shell"
    }
    if state in password_stall_states and remaining_budget > 0:
        button_budget = min(10, remaining_budget)
        _click_submit_button(
            driver,
            element,
            timeout=min(5, button_budget),
        )
        state = _wait_password_transition(
            driver,
            current_state=state,
            timeout=button_budget,
        )
        remaining_budget -= button_budget
        if state in {"otp", "logged_in", "password_error"}:
            return state
        if state not in transitional:
            return state

    if state == "loading" and remaining_budget > 0:
        loading_budget = min(15, remaining_budget)
        state = _wait_password_transition(
            driver,
            current_state=state,
            timeout=loading_budget,
        )
        remaining_budget -= loading_budget
        if state in {"otp", "logged_in", "password_error"}:
            return state
        if state not in transitional:
            return state

    if remaining_budget <= 0:
        return state

    snapshot("before_refresh")
    driver.refresh()
    snapshot("after_refresh")
    state = _classify_post_email_state(driver)
    if state in {"otp", "logged_in", "password_error"}:
        return state
    if state not in transitional:
        return state
    if state in password_stall_states and password:
        selectors = (
            [
                "input[autocomplete*=current-password]",
                "input[name=current-password]",
                "input[type=password]",
            ]
            if current_state.startswith("login_password")
            else [
                "input[autocomplete*=new-password]",
                "input[name=new-password]",
                "input[type=password]",
            ]
        )
        _, refreshed_element = _wait_any(
            driver,
            selectors,
            timeout=min(10, remaining_budget),
        )
        if refreshed_element is not None:
            _set_text_verified(driver, refreshed_element, password)
            _click_submit_button(
                driver,
                refreshed_element,
                timeout=min(5, remaining_budget),
            )
            return _wait_password_transition(
                driver,
                current_state=state,
                timeout=remaining_budget,
            )
    return _wait_password_transition(
        driver,
        current_state=state,
        timeout=remaining_budget,
    )


def _continue_existing_password_login(
    driver,
    password: str,
    timeout: int = 90,
    transition_trace: list[dict] | None = None,
) -> str:
    selectors = [
        "input[autocomplete*=current-password]",
        "input[name=current-password]",
        "input[type=password]",
    ]
    budget = max(1, int(timeout))
    shell_state = _classify_post_email_state(driver)
    is_login_shell = shell_state in {"login_password", "login_password_shell"}
    first_wait = min(20, budget) if is_login_shell else budget
    _, element = _wait_any(driver, selectors, timeout=first_wait)
    if element is None and is_login_shell and first_wait < budget:
        # Reuse the historical same-window shell recovery pattern: one refresh
        # can remount a delayed auth form, but must never create a new challenge.
        driver.refresh()
        time.sleep(1)
        _, element = _wait_any(
            driver,
            selectors,
            timeout=max(1, budget - first_wait - 1),
        )
    if element is None:
        raise RuntimeError("已有账号密码页没有可用密码输入框")
    _set_text_verified(driver, element, password)
    return _submit_password_and_wait(
        driver,
        element,
        timeout=timeout,
        current_state="login_password",
        transition_trace=transition_trace,
        password=password,
    )


def _resolve_existing_login_password(
    driver,
    password: str,
    *,
    candidate_password_verified: bool,
    timeout: int = 90,
) -> tuple[str, bool]:
    """Recover an existing identity without treating an unverified candidate as a password."""
    if not candidate_password_verified:
        return (
            _switch_login_password_to_otp(
                driver,
                timeout=min(20, max(1, int(timeout))),
            ),
            False,
        )
    state = _continue_existing_password_login(driver, password, timeout=timeout)
    accepted = state in {"otp", "logged_in"}
    return state, accepted


def _submit_signup_password(
    driver,
    element,
    password: str,
    timeout: int = 90,
    transition_trace: list[dict] | None = None,
) -> tuple[str, float]:
    readiness_timeout = min(30, max(10, int(timeout) // 3))
    readiness = _wait_for_stable_password_form(
        driver,
        timeout=readiness_timeout,
    )
    if readiness.get("stable") is not True:
        raise RuntimeError("密码页面尚未加载稳定，拒绝提前输入")
    # The input that first made the route classifiable may be replaced while
    # the React tree hydrates. Re-acquire the mounted field after stability is
    # proven, and only then start the password submission clock.
    _, element = _wait_any(
        driver,
        _NEW_PASSWORD_INPUT_SELECTORS,
        timeout=2,
    )
    if element is None:
        raise RuntimeError("密码页面稳定后输入框已失效，拒绝提前输入")
    _set_text_verified(driver, element, password)
    issued_after = time.time()
    state = _submit_password_and_wait(
        driver,
        element,
        timeout=timeout,
        current_state="password",
        transition_trace=transition_trace,
        password=password,
    )
    return state, issued_after


def _submit_email_with_validated_legacy(
    driver,
    email: str,
    *,
    legacy_module=None,
    stage_callback=None,
    transition_trace: list[dict] | None = None,
    email_form_timeout: int = 120,
) -> str:
    trace_started_at = time.monotonic()

    def mark(stage: str) -> None:
        if callable(stage_callback) and stage in _EMAIL_SUBMIT_STAGES:
            stage_callback(stage)

    def trace(stage: str, *, state: str = "", recovery: dict | None = None) -> None:
        if not isinstance(transition_trace, list) or len(transition_trace) >= 6:
            return
        snapshot = _safe_email_submit_snapshot(
            driver,
            stage,
            state=state,
            started_at=trace_started_at,
            recovery=recovery,
        )
        if snapshot:
            transition_trace.append(snapshot)

    def is_auth_email_entry() -> bool:
        try:
            parsed = urllib.parse.urlsplit(
                str(getattr(driver, "current_url", "") or "")
            )
        except Exception:
            return False
        host = (parsed.hostname or "").lower()
        path = (parsed.path or "/").lower()
        if host in {"chatgpt.com", "www.chatgpt.com"}:
            return path.startswith("/auth/")
        if host != "auth.openai.com":
            return False
        # These routes have already passed the email-entry boundary. Preserve
        # their existing OTP/password handling instead of waiting for an email
        # field that must not reappear.
        return not any(marker in path for marker in (
            "/email-verification",
            "/log-in/password",
            "/create-account/password",
            "/signup/password",
            "/u/signup/password",
            "/about-you",
        ))

    # When the form is visible, or the browser is still on an authentication
    # entry route whose form is mounting late, repo_0810 owns the exact identity
    # write/submit boundary. The historical helper retries typing internally,
    # which can write into an incomplete React tree.
    mark("input_wait")
    _raise_email_terminal_error(driver, "unknown")
    _, email_input = _wait_any(
        driver,
        _EMAIL_INPUT_SELECTORS,
        timeout=5,
    )
    if email_input is not None or is_auth_email_entry():
        try:
            form_timeout = max(10, min(180, int(email_form_timeout)))
        except (TypeError, ValueError):
            form_timeout = 120
        readiness = _wait_for_stable_email_form(driver, timeout=form_timeout)
        form_is_stable = readiness is True or (
            isinstance(readiness, dict) and readiness.get("stable") is True
        )
        if not form_is_stable:
            # Never hand an unstable/remounting React form to the historical
            # helper: it retries typing internally and can reproduce the exact
            # early-email-input race this readiness gate exists to prevent.
            raise EmailFormReadinessError(readiness)
        # The early visible element can be replaced while the React tree
        # finishes loading. Re-acquire it only after the form is stable so we
        # never type into a detached pre-render node.
        _, email_input = _wait_any(
            driver,
            _EMAIL_INPUT_SELECTORS,
            timeout=2,
        )
        if email_input is None:
            raise RuntimeError("邮箱页面稳定后输入框已失效，拒绝提前输入")
        mark("email_fill")
        _set_text_verified(driver, email_input, email)
        trace("before_initial_submit", state="email_page")
        mark("initial_submit")
        _click_email_submit(driver, email_input)
        trace("after_initial_submit", state="email_page")
        # Keep the same observation window used by the last proven-successful
        # path. Real successful runs needed 15-78 seconds to leave this phase;
        # forcing a native form navigation after six seconds interrupted that
        # valid transition and left Chrome on a blank /auth/login document.
        mark("initial_transition_wait")
        state = _wait_post_email_state(driver, timeout=40)
        trace("initial_wait_done", state=state)
        _raise_email_terminal_error(driver, state)
        if state in {"password", "login_password", "otp", "logged_in"}:
            return state
        if state == "loading":
            mark("stop_loading")
            try:
                driver.execute_cdp_cmd("Page.stopLoading", {})
            except Exception as exc:
                raise RuntimeError(
                    "邮箱提交后的空白文档无法停止加载"
                ) from exc
            trace("after_stop_loading", state=state)

        _raise_email_terminal_error(driver, state)

        # Reuse the historical path that replaced browser-internal NextAuth
        # fetches in Roxy/Chrome 150: refill the same controlled input and issue
        # one requestSubmit-style recovery.  The retired async fetch can lose
        # its WebDriver callback during navigation and block until script or
        # process timeout.
        mark("same_form_recovery")
        recovered = _recover_email_submit_via_request_submit(driver, email)
        trace("recovery_result", state=state, recovery=recovered)
        if not isinstance(recovered, dict) or not recovered.get("ok"):
            # The original UI submit can still commit while the bounded
            # recovery command reports that the form disappeared. Trust the
            # browser-state classifier before rejecting that navigation race.
            mark("post_recovery_wait")
            state = _wait_post_email_state(driver, timeout=40)
            trace("recovery_wait_done", state=state)
            _raise_email_terminal_error(driver, state)
            if state in {"password", "login_password", "otp", "logged_in"}:
                return state
            raw_reason = str(
                recovered.get("reason") if isinstance(recovered, dict) else ""
            ).strip().lower()
            reason = (
                raw_reason
                if re.fullmatch(r"[a-z][a-z0-9_]{0,31}", raw_reason)
                else "unknown"
            )
            raise RuntimeError(
                f"邮箱同页补交失败：reason={reason}"
            )
        mark("post_recovery_wait")
        state = _wait_post_email_state(driver, timeout=40)
        trace("recovery_wait_done", state=state)
        _raise_email_terminal_error(driver, state)
        if state in {"password", "login_password", "otp", "logged_in"}:
            return state
        raise RuntimeError(f"邮箱同页补交后未进入下一步：{state}")

    # Only non-form entry/welcome pages use the historical navigation helper.
    mark("legacy_entry")
    legacy_module = _legacy_module(legacy_module)
    try:
        state = legacy_module._submit_email_and_wait_next(driver, email, attempts=3)
        _raise_email_terminal_error(driver, state)
        return state
    except RuntimeError as exc:
        _raise_email_terminal_error(driver, "unknown")
        url = str(getattr(driver, "current_url", "") or "").lower()
        if "登录密码页" in str(exc) or "/log-in/password" in url:
            return "login_password"
        current_state = _classify_post_email_state(driver)
        _raise_email_terminal_error(driver, current_state)
        if current_state in {"password", "login_password", "otp", "logged_in"}:
            return current_state
        raise


def _legacy_module(legacy_module=None):
    if legacy_module is None:
        legacy_root = require_roxy_configuration().legacy_root
        if str(legacy_root) not in sys.path:
            sys.path.insert(0, str(legacy_root))
        from core import roxy_registration as legacy_module

    original = legacy_module._has_access_token
    if not getattr(original, "__dict__", {}).get("_repo0810_same_origin_guard"):
        def same_origin_access_token_probe(driver):
            try:
                host = urllib.parse.urlsplit(
                    str(getattr(driver, "current_url", "") or "")
                ).hostname or ""
            except Exception:
                host = ""
            if host.lower() not in {"chatgpt.com", "www.chatgpt.com"}:
                return False
            return bool(original(driver))

        same_origin_access_token_probe._repo0810_same_origin_guard = True
        legacy_module._has_access_token = same_origin_access_token_probe
    return legacy_module


def _require_valid_otp_code(code: object) -> str:
    """Reject empty or partial mailbox codes before touching the browser form."""
    normalized = str(code or "").strip()
    if not re.fullmatch(r"\d{6}", normalized):
        raise RuntimeError("邮箱验证码尚未完整获取，已跳过提交")
    return normalized


def _wait_for_otp_input_with_recovery(driver, timeout: int = 20):
    """Recover only a persistently blank verification document, within one budget."""
    deadline = time.monotonic() + max(1, min(600, int(timeout)))
    blank_since = None
    refreshed = 0
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError("邮箱验证码页没有可用验证码输入框")
        with _webdriver_command_timeout(driver, min(5, remaining), keep_on_error=True):
            # Probe split OTP fields in one command so per-element checks
            # cannot multiply the remaining WebDriver time budget.
            element = driver.execute_script(r"""
                // repo0810OtpInputReadiness
                const usable = element => {
                    if (!element.isConnected || element.matches(':disabled') || element.readOnly ||
                        String(element.getAttribute('aria-disabled') || '').toLowerCase() === 'true') {
                        return false;
                    }
                    const style = getComputedStyle(element);
                    if (style.display === 'none' || style.visibility === 'hidden') return false;
                    const rect = element.getBoundingClientRect();
                    return rect.width > 0 && rect.height > 0;
                };
                return [...document.querySelectorAll(
                    'input[inputmode=numeric], input[autocomplete=one-time-code], input[name=code]'
                )].find(usable) || null;
            """)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError("邮箱验证码页没有可用验证码输入框")
        if element is not None:
            return element
        with _webdriver_command_timeout(driver, min(5, remaining), keep_on_error=True):
            state = _safe_page_state(driver)
        now = time.monotonic()
        remaining = deadline - now
        if remaining <= 0:
            raise RuntimeError("邮箱验证码页没有可用验证码输入框")
        if state.get("snapshot_error"):
            raise RuntimeError("OTP 页面状态不可读，已停止输入恢复")
        if state.get("route_error_500") or _state_has_http_500(state):
            raise RuntimeError("OTP 页面返回 HTTP 500，已停止输入恢复")
        parsed = urllib.parse.urlsplit(str(state.get("url") or ""))
        if state.get("chrome_error_code") or parsed.scheme == "chrome-error":
            raise RuntimeError("OTP 浏览器网络错误，已停止输入恢复")
        blank = (
            parsed.scheme == "https"
            and (parsed.hostname or "").lower() in {"auth.openai.com", "chatgpt.com"}
            and parsed.path.rstrip("/") == "/email-verification"
            and isinstance(state.get("inputs"), list) and not state["inputs"]
            and isinstance(state.get("buttons"), list) and not state["buttons"]
            and not state.get("page_busy")
            and not str(state.get("status_text") or "").strip()
            and not str(state.get("alert_text") or "").strip()
        )
        if not blank:
            blank_since = None
        elif blank_since is None:
            blank_since = now
        elif now - blank_since >= 6 and refreshed < 2:
            with _webdriver_command_timeout(driver, min(5, remaining), keep_on_error=True):
                driver.refresh()
            refreshed += 1
            blank_since = None
            continue
        time.sleep(min(0.25, remaining))


def _submit_otp_with_validated_legacy(
    driver,
    code: str,
    *,
    timeout: int = 120,
    legacy_module=None,
) -> None:
    code = _require_valid_otp_code(code)
    legacy_module = _legacy_module(legacy_module)
    try:
        submit_timeout = max(10, min(600, int(timeout)))
    except (TypeError, ValueError):
        submit_timeout = 120
    auto_submit_grace = min(10, submit_timeout)
    legacy_module._clear_otp_inputs(driver)
    legacy_module._type_otp(driver, code)
    # OpenAI can auto-submit as soon as the final OTP digit is entered. Reuse
    # the same accepted-transition detector before attempting a second submit.
    # Give the SPA a short stabilization window first; two seconds was too
    # short when the verification page was still rerendering after the last
    # digit, which led to an unnecessary click/cleanup race.
    outcome = legacy_module._wait_after_email_otp_submit(
        driver, timeout=auto_submit_grace
    )
    if outcome == "accepted":
        return
    if outcome == "route_error":
        raise RuntimeError(f"邮箱 OTP 未被服务端接受：{outcome}")
    if outcome == "invalid":
        # The legacy detector also returns invalid when an untouched form
        # merely times out. Require actual rejection before skipping its submit.
        state = legacy_module._email_otp_page_state(driver)
        if not isinstance(state, dict) or state.get("error"):
            raise RuntimeError("邮箱 OTP 自动提交观察状态不可读，已停止")
        inputs = state.get("inputs")
        if not isinstance(inputs, list):
            raise RuntimeError("邮箱 OTP 自动提交观察状态不可读，已停止")
        if state.get("errors") or any(
            isinstance(item, dict)
            and str(item.get("ariaInvalid") or "").lower() == "true"
            for item in inputs
        ):
            raise RuntimeError("邮箱 OTP 未被服务端接受：invalid")
        if not legacy_module._is_email_verification_page(driver):
            observed = _safe_page_state(driver)
            if (
                observed.get("snapshot_error") or observed.get("chrome_error_code")
                or observed.get("route_error_500") or _state_has_http_500(observed)
            ):
                raise RuntimeError("邮箱 OTP 跳转状态不可用，已停止")
            parsed = urllib.parse.urlsplit(str(observed.get("url") or ""))
            if parsed.scheme == "https":
                host = (parsed.hostname or "").lower()
                if host == "auth.openai.com" and parsed.path.rstrip("/") in {
                    "/about-you", "/profile", "/signup/profile", "/create-account/profile",
                }:
                    return
                if host in {"chatgpt.com", "www.chatgpt.com"} and legacy_module._has_access_token(driver):
                    return
            raise RuntimeError("邮箱 OTP 尚无可信的成功跳转，已停止")
        has_otp_input = any(
            isinstance(item, dict) and any(token in " ".join(
                str(item.get(key) or "")
                for key in ("name", "id", "autocomplete", "inputmode")
            ).lower() for token in ("one-time-code", "otp", "code", "numeric", "tel"))
            for item in inputs
        )
        if not has_otp_input:
            raise RuntimeError("邮箱 OTP 表单尚未就绪，已停止提交")
    # Keep the historical click helper here. It owns the page's React timing
    # and was the known-good path before the strict live-button probe was
    # introduced; the latter can reject a button during a short rerender.
    legacy_module._click_continue(driver)
    outcome = legacy_module._wait_after_email_otp_submit(
        driver, timeout=submit_timeout
    )
    if outcome == "accepted":
        return
    if outcome in {"invalid", "route_error"}:
        raise RuntimeError(f"邮箱 OTP 未被服务端接受：{outcome}")

    # One bounded same-window recovery: refresh, restore the same OTP (the SPA
    # clears the field on reload), submit once more, then stop. Each post-submit
    # state wait uses the caller's OTP timeout so a late mailbox/browser update
    # cannot close the window after the short historical 20-second limit.
    driver.refresh()
    time.sleep(min(2, submit_timeout))
    if not legacy_module._is_email_verification_page(driver):
        return
    legacy_module._clear_otp_inputs(driver)
    legacy_module._type_otp(driver, code)
    legacy_module._click_continue(driver)
    outcome = legacy_module._wait_after_email_otp_submit(
        driver, timeout=submit_timeout
    )
    if outcome == "accepted":
        return
    raise RuntimeError(f"邮箱 OTP 同窗刷新续接未完成：{outcome}")


def _click_otp_submit_stable(driver, timeout: int = 20) -> None:
    """Click the enabled submit in the live OTP form through the validated pointer path."""
    _, otp_input = _wait_any(driver, [
        "input[inputmode=numeric]",
        "input[autocomplete=one-time-code]",
        "input[name=code]",
    ], timeout=max(1, min(10, int(timeout))))
    if otp_input is None:
        raise RuntimeError("邮箱验证码页没有可用验证码输入框")
    otp_ready = _poll_until(
        lambda: bool(driver.execute_script(r"""
            const input = arguments[0];
            const scope = input.form || input.closest('form') || document;
            const visible = x => !!(x && (x.offsetWidth || x.offsetHeight ||
                x.getClientRects().length));
            const values = [...scope.querySelectorAll(
              'input[inputmode=numeric], input[autocomplete=one-time-code], input[name=code]'
            )].filter(visible).map(x => String(x.value || '').trim());
            return values.some(value => /^\d{6}$/.test(value)) ||
              (values.length > 1 && /^\d{6}$/.test(values.join('')));
        """, otp_input)),
        bool,
        timeout=max(1, int(timeout)),
        interval=0.25,
    )
    if not otp_ready:
        raise RuntimeError("邮箱验证码尚未完整获取，已跳过提交")
    target = _poll_until(
        lambda: driver.execute_script(r"""
            const input = arguments[0];
            const scope = input.form || input.closest('form') || document;
            const visible = x => !!(x && (x.offsetWidth || x.offsetHeight ||
                x.getClientRects().length));
            return [...scope.querySelectorAll('button[type=submit],input[type=submit]')]
              .find(x => visible(x) && !x.disabled &&
                  String(x.getAttribute('aria-disabled') || '').toLowerCase() !== 'true') || null;
        """, otp_input),
        lambda element: element is not None,
        timeout=max(1, int(timeout)),
        interval=0.25,
    )
    if target is None:
        raise RuntimeError("邮箱验证码页没有可用提交按钮")
    _click_submit_target(driver, target)


def _click_resend_email_otp_stable(driver, timeout: int = 20) -> None:
    """Find and click resend atomically in-page so React cannot stale the handle."""
    clicked = _poll_until(
        lambda: bool(driver.execute_script(r"""
            const visible = el => !!(el && (el.offsetWidth || el.offsetHeight || el.getClientRects().length));
            const enabled = el => !el.disabled && String(el.getAttribute('aria-disabled') || '').toLowerCase() !== 'true';
            const candidates = [...document.querySelectorAll('button,a,[role=button],[role=link],input[type=button],input[type=submit]')]
              .filter(el => visible(el) && enabled(el));
            const target = candidates.find(el => {
              const name = String(el.getAttribute('name') || '').toLowerCase();
              const value = String(el.getAttribute('value') || '').toLowerCase();
              const attrs = [el.id, name, value, el.getAttribute('data-dd-action-name'), el.getAttribute('aria-label'), el.getAttribute('title'), el.getAttribute('data-testid')]
                .join(' ').toLowerCase();
              if (name === 'intent' && value === 'resend') return true;
              if (/resend|send.*new|new.*code|again/.test(attrs)) return true;
              return /resend|send\s+(?:a\s+)?new\s+code|send\s+again|重新发送|重发|再次发送|再送信|新しい|届かない/.test((el.innerText || el.textContent || '').toLowerCase());
            });
            if (!target) return false;
            target.click();
            return true;
        """)),
        bool,
        timeout=max(1, int(timeout)),
        interval=0.25,
    )
    if not clicked:
        raise RuntimeError("找不到可点击的重新发送验证码按钮")


def _submit_otp_with_one_invalid_retry(
    driver,
    code: str,
    callback_url: str,
    nonce: str,
    *,
    timeout: int = 60,
    legacy_module=None,
) -> None:
    legacy_module = _legacy_module(legacy_module)
    try:
        _submit_otp_with_validated_legacy(
            driver,
            code,
            timeout=timeout,
            legacy_module=legacy_module,
        )
        return
    except RuntimeError as exc:
        message = str(exc).lower()
        retryable = "invalid" in message or "unknown" in message
        if not retryable:
            raise
    if bool(getattr(code, "resend_used", False)):
        raise RuntimeError("本轮已使用一次重新发送，验证码仍未被接受；停止重复发码")
    _click_resend_email_otp_stable(driver, timeout=20)
    resent_after = time.time()
    fresh_code = _otp(callback_url, nonce, resent_after, timeout)
    _submit_otp_with_validated_legacy(
        driver,
        fresh_code,
        timeout=timeout,
        legacy_module=legacy_module,
    )


def _is_chatgpt_url(value: object) -> bool:
    try:
        hostname = urllib.parse.urlsplit(str(value or "")).hostname or ""
    except Exception:
        return False
    return hostname.lower() in {"chatgpt.com", "www.chatgpt.com"}


def _open_auth_login_page(driver, *, timeout: int = 45) -> None:
    """Open the login shell once and recover an already-usable timed-out DOM."""
    from selenium.common.exceptions import TimeoutException

    budget = max(10, min(45, int(timeout or 45)))
    try:
        timeouts = getattr(driver, "timeouts", None)
        previous_page_load = getattr(timeouts, "page_load", None)
        previous_script = getattr(timeouts, "script", None)
    except Exception:
        previous_page_load = None
        previous_script = None
    timed_out = False
    driver._repo0810_auth_load_stopped = False
    try:
        driver.set_page_load_timeout(budget)
        driver.get("https://chatgpt.com/auth/login")
    except TimeoutException:
        timed_out = True
        try:
            driver.execute_cdp_cmd("Page.stopLoading", {})
        except Exception as exc:
            raise AuthEntryPreflightError("timeout") from exc
        driver._repo0810_auth_load_stopped = True

        driver.set_script_timeout(2)
        recovery_deadline = time.monotonic() + 10.0
        while True:
            try:
                state = driver.execute_script(r"""
                    const host = String(location.hostname || '').toLowerCase();
                    return {
                        host,
                        has_body: !!document.body,
                        has_interactive: !!document.querySelector(
                            'input,button,a,[role=button],[role=link]'
                        ),
                    };
                """) or {}
            except Exception as exc:
                if time.monotonic() >= recovery_deadline:
                    raise AuthEntryPreflightError("timeout") from exc
                time.sleep(0.5)
                continue
            if isinstance(state, dict) and (
                str(state.get("host") or "").strip().lower()
                in {"chatgpt.com", "www.chatgpt.com", "auth.openai.com"}
                and state.get("has_body") is True
                and state.get("has_interactive") is True
            ):
                break
            if time.monotonic() >= recovery_deadline:
                raise AuthEntryPreflightError("timeout")
            time.sleep(0.5)
    finally:
        try:
            restore_page_load = (
                float(previous_page_load)
                if isinstance(previous_page_load, (int, float))
                else ROXY_TIMEOUT
            )
            driver.set_page_load_timeout(restore_page_load)
        except Exception:
            pass
        if timed_out:
            try:
                restore_script = (
                    float(previous_script)
                    if isinstance(previous_script, (int, float))
                    else ROXY_TIMEOUT
                )
                driver.set_script_timeout(restore_script)
            except Exception:
                pass


def _assert_auth_entry_ready(driver, email: str = "", *, timeout: int = 6) -> None:
    """Open the anonymous NextAuth entry before any target email is touched."""
    try:
        visible_email_form = driver.execute_script(r"""
            const host = String(location.hostname || '').toLowerCase();
            if (!['chatgpt.com', 'www.chatgpt.com', 'auth.openai.com'].includes(host)) {
                return false;
            }
            const visible = element => {
                if (!element || element.disabled) return false;
                const style = getComputedStyle(element);
                if (style.display === 'none' || style.visibility === 'hidden') return false;
                const rect = element.getBoundingClientRect();
                return rect.width > 0 && rect.height > 0;
            };
            return [...document.querySelectorAll(
                String(arguments[0] || '')
            )].some(visible);
        """, _EMAIL_INPUT_SELECTOR_QUERY)
    except Exception:
        visible_email_form = False
    if visible_email_form is True:
        return

    budget = max(2, min(10, int(timeout)))
    previous_timeout = None
    try:
        previous_timeout = getattr(getattr(driver, "timeouts", None), "script", None)
    except Exception:
        previous_timeout = None
    try:
        driver.set_script_timeout(budget + 1)
        result = driver.execute_async_script(r"""
            const timeoutMs = Number(arguments[0]) || 5000;
            const did = String(arguments[1] || '');
            const authLogId = String(arguments[2] || '');
            const done = arguments[arguments.length - 1];
            const controller = new AbortController();
            let settled = false;
            const finish = value => {
                if (settled) return;
                settled = true;
                clearTimeout(timer);
                done(value);
            };
            const timer = setTimeout(() => {
                controller.abort();
                finish({ok: false, stage: 'timeout'});
            }, timeoutMs);
            (async () => {
                try {
                    const csrfResponse = await fetch('/api/auth/csrf', {
                        credentials: 'include',
                        cache: 'no-store',
                        signal: controller.signal,
                    });
                    const csrfData = await csrfResponse.json().catch(() => ({}));
                    const csrfToken = String(csrfData.csrfToken || '');
                    if (!csrfResponse.ok || !csrfToken) {
                        finish({
                            ok: false,
                            stage: 'http_error',
                            status: Number(csrfResponse.status) || 0,
                        });
                        return;
                    }
                    const query = new URLSearchParams({
                        prompt: 'login',
                        'ext-oai-did': did,
                        auth_session_logging_id: authLogId,
                        'ext-passkey-client-capabilities': '11111',
                        screen_hint: 'login_or_signup',
                    });
                    const body = new URLSearchParams({
                        callbackUrl: 'https://chatgpt.com/',
                        csrfToken,
                        json: 'true',
                    });
                    const response = await fetch(
                        '/api/auth/signin/openai?' + query.toString(),
                        {
                            method: 'POST',
                            credentials: 'include',
                            cache: 'no-store',
                            signal: controller.signal,
                            headers: {
                                accept: 'application/json',
                                'content-type': 'application/x-www-form-urlencoded',
                            },
                            body: body.toString(),
                        },
                    );
                    const data = await response.json().catch(() => ({}));
                    const url = String(data.url || '');
                    if (!response.ok || !url) {
                        finish({
                            ok: false,
                            stage: 'http_error',
                            status: Number(response.status) || 0,
                        });
                        return;
                    }
                    finish({ok: true, stage: 'redirect', url});
                } catch (error) {
                    finish({
                        ok: false,
                        stage: error && error.name === 'AbortError'
                            ? 'timeout'
                            : 'network',
                    });
                }
            })();
        """, budget * 1000, str(uuid.uuid4()), str(uuid.uuid4())) or {}
    except Exception as exc:
        raise AuthEntryPreflightError(
            "timeout" if type(exc).__name__ == "TimeoutException" else "network"
        ) from exc
    finally:
        try:
            restore = (
                float(previous_timeout)
                if isinstance(previous_timeout, (int, float))
                else ROXY_TIMEOUT
            )
            driver.set_script_timeout(restore)
        except Exception:
            pass

    if not isinstance(result, dict):
        raise AuthEntryPreflightError("invalid_result")
    if result.get("ok") is not True:
        raise AuthEntryPreflightError(str(result.get("stage") or "invalid_result"))
    redirect_url = str(result.get("url") or "")
    try:
        parsed = urllib.parse.urlsplit(redirect_url)
    except Exception as exc:
        raise AuthEntryPreflightError("invalid_result") from exc
    if parsed.scheme.lower() != "https" or (parsed.hostname or "").lower() != "auth.openai.com":
        raise AuthEntryPreflightError("invalid_result")
    try:
        driver.execute_script(r"""
            const url = String(arguments[0] || '');
            const email = String(arguments[1] || '').trim();
            const target = new URL(url);
            if (email) target.searchParams.set('login_hint', email);
            if (!target.searchParams.get('screen_hint')) {
                target.searchParams.set('screen_hint', 'login_or_signup');
            }
            setTimeout(() => window.location.assign(target.toString()), 0);
            return true;
        """, redirect_url, email)
    except Exception:
        # The command can be interrupted by the navigation it just scheduled.
        pass
    _, email_input = _wait_any(
        driver,
        _EMAIL_INPUT_SELECTORS,
        timeout=max(6, budget + 4),
    )
    if email_input is None:
        raise AuthEntryPreflightError("timeout")


_AUTH_CALLBACK_ERROR_CODES = frozenset({
    "Callback", "OAuthCallback", "OAuthSignin", "OAuthCreateAccount",
    "AccessDenied", "Configuration", "Verification", "CredentialsSignin",
    "SessionRequired", "Default",
})


class RoxySessionError(RuntimeError):
    """A fixed session failure reason without upstream text or credentials."""

    def __init__(self, cause: str, diagnostics: dict | None = None):
        self.failure_phase = "session"
        self.failure_cause = cause
        self.session_diagnostics = dict(diagnostics or {})
        self.safe_message = {
            "auth_callback_error": "ChatGPT auth callback ended on /auth/error",
            "roxy_session_timeout": "等待 /api/auth/session Access/Session 超时",
        }[cause]
        super().__init__(self.safe_message)


def _auth_callback_error_state(url: str) -> dict:
    try:
        parsed = urllib.parse.urlsplit(url)
        if (
            parsed.scheme.lower() != "https"
            or (parsed.hostname or "").lower() not in {"chatgpt.com", "www.chatgpt.com"}
            or parsed.path.rstrip("/").lower() != "/auth/error"
        ):
            return {}
        state = {"session_reason": "auth_callback_error"}
        codes = urllib.parse.parse_qs(parsed.query).get("error", [])
        if len(codes) == 1 and codes[0] in _AUTH_CALLBACK_ERROR_CODES:
            state["auth_error_code"] = codes[0]
        return state
    except ValueError:
        return {}


def _read_chatgpt_session_cdp_once(driver) -> dict | None:
    """Start/poll a bounded in-page session fetch without blocking WebDriver."""
    driver._repo0810_session_probe_diagnostics = {"session_probe": "unavailable"}
    dispatch = getattr(driver, "execute_cdp_cmd", None)
    if not callable(dispatch):
        return None
    script = r"""
        (() => {
          const key = '__repo0810_session_probe_v1';
          const now = Date.now();
          let probe = window[key];
          if (!probe || now >= Number(probe.expiresAt || 0)) {
            probe = {status: 'pending', data: {}, httpStatus: 0, expiresAt: now + 6000};
            window[key] = probe;
            const controller = new AbortController();
            const timer = setTimeout(() => controller.abort(), 4000);
            fetch('/api/auth/session', {
              credentials: 'include',
              cache: 'no-store',
              signal: controller.signal,
            })
              .then(response => {
                probe.httpStatus = response.status;
                if (!response.ok) {
                  probe.status = 'http_error';
                  return;
                }
                return response.json().then(data => {
                  const valid = data && typeof data === 'object' && !Array.isArray(data);
                  probe.status = valid ? 'ready' : 'invalid_payload';
                  probe.data = valid ? data : {};
                }, () => {
                  probe.status = controller.signal.aborted ? 'timeout' : 'invalid_json';
                });
              })
              .catch(() => {
                probe.status = controller.signal.aborted ? 'timeout' : 'network_error';
                probe.data = {};
              })
              .finally(() => clearTimeout(timer));
          }
          return {
            status: String(probe.status || 'pending'),
            http_status: Number(probe.httpStatus || 0),
            data: probe.status === 'ready' ? (probe.data || {}) : {},
          };
        })()
    """
    try:
        payload = dispatch(
            "Runtime.evaluate",
            {
                "expression": script,
                "returnByValue": True,
            },
        )
    except Exception as exc:
        driver._repo0810_session_probe_diagnostics = {
            "session_probe": "cdp_error", "session_exception": type(exc).__name__,
        }
        return None
    driver._repo0810_session_probe_diagnostics = {"session_probe": "invalid_result"}
    if not isinstance(payload, dict):
        return None
    remote = payload.get("result")
    if not isinstance(remote, dict):
        return None
    value = remote.get("value")
    if not isinstance(value, dict):
        return None
    status = str(value.get("status") or "").strip().lower()
    if status not in {
        "pending", "ready", "error", "http_error", "invalid_json",
        "invalid_payload", "network_error", "timeout",
    }:
        return None
    diagnostics = {"session_probe": status}
    http_status = value.get("http_status")
    if isinstance(http_status, int) and not isinstance(http_status, bool) and 100 <= http_status <= 599:
        diagnostics["session_http"] = http_status
    driver._repo0810_session_probe_diagnostics = diagnostics
    data = value.get("data")
    return data if status == "ready" and isinstance(data, dict) else {}


def _fetch_session_state_driven(
    driver,
    *,
    legacy_module=None,
    timeout: int = 90,
    auto_jump_wait: int = 15,
) -> dict:
    legacy = _legacy_module(legacy_module)
    deadline = time.monotonic() + max(1, int(timeout))
    jump_deadline = time.monotonic() + max(3, int(auto_jump_wait))
    forced_open = False
    diagnostics = {}
    last_exception = None
    while True:
        current = str(getattr(driver, "current_url", "") or "")
        if not _is_chatgpt_url(current):
            switched = bool(legacy._switch_to_chatgpt_window_if_any(driver))
            current = str(getattr(driver, "current_url", "") or "") if switched else current
            if not switched and time.monotonic() >= jump_deadline and not forced_open:
                legacy._safe_get(
                    driver,
                    "https://chatgpt.com/",
                    timeout=35,
                    attempts=2,
                    accept_hosts=("chatgpt.com",),
                )
                forced_open = True
                current = str(getattr(driver, "current_url", "") or "")
        callback_error = _auth_callback_error_state(current)
        if callback_error:
            raise RoxySessionError("auth_callback_error", callback_error)
        if _is_chatgpt_url(current):
            try:
                data = _read_chatgpt_session_cdp_once(driver)
                probe = getattr(driver, "_repo0810_session_probe_diagnostics", None)
                diagnostics = dict(probe) if isinstance(probe, dict) else {}
                if data is None:
                    data = legacy._read_chatgpt_session_once(driver) or {}
                    diagnostics = {"session_probe": "legacy"}
                access_token = str(data.get("accessToken") or "")
                session_token = next((
                    str(cookie.get("value") or "")
                    for cookie in driver.get_cookies()
                    if cookie.get("name") == "__Secure-next-auth.session-token"
                ), "") or str(data.get("sessionToken") or data.get("session_token") or "")
                if access_token and session_token:
                    return {
                        "access_token": access_token,
                        "session_token": session_token,
                    }
                diagnostics.update({
                    "access_present": bool(access_token),
                    "session_present": bool(session_token),
                })
            except Exception as exc:
                last_exception = exc
                diagnostics = {
                    "session_probe": "webdriver_error",
                    "session_exception": type(exc).__name__,
                }
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(1.0, remaining))
    diagnostics["session_reason"] = "roxy_session_timeout"
    raise RoxySessionError("roxy_session_timeout", diagnostics) from last_exception


def _fetch_session_with_validated_legacy(driver, *, legacy_module=None) -> dict:
    return _fetch_session_state_driven(
        driver,
        legacy_module=legacy_module,
        timeout=90,
        auto_jump_wait=15,
    )


class _OtpCode(str):
    def __new__(cls, value: str, *, resend_used: bool = False):
        instance = super().__new__(cls, value)
        instance.resend_used = bool(resend_used)
        return instance


class RoxyOtpCallbackError(RuntimeError):
    """Fixed-message OTP boundary error with allowlisted provider metadata."""

    failure_phase = "otp_wait"

    def __init__(self, metadata: object):
        cleaned = safe_otp_failure_metadata(metadata)
        cleaned.setdefault("exception_type", "RuntimeError")
        for key, value in cleaned.items():
            setattr(self, key, value)
        super().__init__("OTP callback failed")


def _otp(
    callback_url: str,
    nonce: str,
    issued_after: float,
    timeout: int,
) -> str:
    data = json.dumps({"nonce": nonce, "issued_after": issued_after}).encode("utf-8")
    request = urllib.request.Request(
        callback_url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        try:
            with urllib.request.urlopen(request, timeout=max(10, int(timeout) + 5)) as response:
                payload = json.loads(response.read())
        except urllib.error.HTTPError as exc:
            payload = json.loads(exc.read() or b"{}")
    except Exception as exc:
        metadata = safe_otp_failure_metadata(exc)
        metadata["failure_cause"] = (
            "otp_callback_transport_timeout" if isinstance(exc, TimeoutError)
            or isinstance(getattr(exc, "reason", None), TimeoutError)
            else "otp_callback_invalid_response" if isinstance(exc, (ValueError, TypeError))
            else "otp_callback_transport_failed"
        )
        raise RoxyOtpCallbackError(metadata) from exc
    if not isinstance(payload, dict) or not payload.get("ok"):
        metadata = safe_otp_failure_metadata(payload.get("otp_failure") if isinstance(payload, dict) else None)
        metadata.setdefault("failure_cause", "otp_callback_failed")
        raise RoxyOtpCallbackError(metadata)
    return str(payload["otp"])


def _is_auth_profile_route(driver) -> bool:
    try:
        parsed = urllib.parse.urlsplit(
            str(getattr(driver, "current_url", "") or "")
        )
    except Exception:
        return False
    if (parsed.hostname or "").lower() != "auth.openai.com":
        return False
    path = (parsed.path or "").lower()
    return any(route in path for route in (
        "/about-you", "/profile", "/signup/profile", "/create-account/profile",
    ))


def _wait_for_auth_profile_route(driver, timeout: float) -> bool:
    return bool(_poll_until(
        lambda: _is_auth_profile_route(driver),
        bool,
        timeout=timeout,
        interval=0.25,
    ))


def _otp_with_one_resend(
    driver,
    callback_url: str,
    nonce: str,
    issued_after: float,
    timeout: int = 60,
    *,
    resend_after: float = 20,
) -> str | None:
    """Wait for OTP and issue at most one resend inside the same total budget."""
    otp_page_recovery_attempts = 0
    wait_started_at = time.monotonic()
    resend_used = False
    resend_attempted = False
    resend_result = "not_attempted"

    def failure(error, *, cause=""):
        metadata = safe_otp_failure_metadata(error)
        if cause:
            metadata["failure_cause"] = cause
        diagnostics = dict(metadata.get("otp_wait_diagnostics", {}))
        diagnostics.update({
            "worker_budget_seconds": timeout,
            "worker_elapsed_seconds": max(0.0, time.monotonic() - wait_started_at),
            "resend_attempted": resend_attempted,
            "resend_result": resend_result,
        })
        metadata["otp_wait_diagnostics"] = diagnostics
        return RoxyOtpCallbackError(metadata)

    def start_waiter(wait_issued_after: float, wait_timeout: float):
        outcome: dict[str, object] = {}

        def wait_for_otp() -> None:
            try:
                outcome["code"] = _otp(
                    callback_url, nonce, wait_issued_after, wait_timeout
                )
            except BaseException as exc:  # re-raised unchanged in the owner thread
                outcome["error"] = exc

        waiter = threading.Thread(
            target=wait_for_otp,
            daemon=True,
            name="otp-callback-wait",
        )
        waiter.start()
        return waiter, outcome

    waiter, outcome = start_waiter(issued_after, timeout)
    delay = max(0.01, min(float(resend_after), max(0.01, float(timeout) - 1)))

    def otp_page_state() -> str:
        if _is_auth_profile_route(driver):
            return "profile"
        return _classify_post_email_state(driver)

    def recover_otp_page(failed_state: str) -> str:
        nonlocal otp_page_recovery_attempts
        last_state = failed_state
        while otp_page_recovery_attempts < 2:
            otp_page_recovery_attempts += 1

            # A chrome-error page is often a failed navigation that still has
            # the authentication page in this window's history.  Going back
            # first restores that page without replaying the email/OTP submit
            # path.  Refresh is only a bounded fallback when history recovery
            # does not produce a usable auth state.
            try:
                driver.back()
            except Exception as exc:
                last_state = f"back_error:{type(exc).__name__}"
                recovered = ""
            else:
                recovered = _poll_until(
                    otp_page_state,
                    lambda state: state in {"otp", "profile", "logged_in"},
                    timeout=10,
                    interval=0.25,
                )
            if recovered in {"profile", "logged_in"}:
                return "profile"
            if recovered == "otp":
                return "otp_recovered"

            if recovered:
                last_state = recovered

            # History can be empty or can land on a still-loading page.  Use
            # refresh only after the back attempt has had a chance to settle.
            try:
                driver.refresh()
            except Exception as exc:
                last_state = f"refresh_error:{type(exc).__name__}"
                continue
            recovered = _poll_until(
                otp_page_state,
                lambda state: state in {"otp", "profile", "logged_in"},
                timeout=10,
                interval=0.25,
            )
            if recovered in {"profile", "logged_in"}:
                return "profile"
            if recovered == "otp":
                return "otp_recovered"
            last_state = recovered or last_state
        raise RuntimeError(
            f"邮箱 OTP 页面同窗连续两次返回/刷新后仍不可用：{last_state}"
        )

    def wait_or_profile(current_waiter, wait_seconds: float) -> str:
        end = time.monotonic() + max(0.0, float(wait_seconds))
        while current_waiter.is_alive():
            remaining = end - time.monotonic()
            if remaining <= 0:
                break
            current_waiter.join(min(0.25, remaining))
            if not current_waiter.is_alive():
                break
            state = otp_page_state()
            if state == "profile":
                return "profile"
            if state in {"browser_error", "route_error_500"}:
                recovered = recover_otp_page(state)
                if recovered == "profile":
                    return "profile"
                # A restored OTP page still owns the same pending callback and deadline.
        return "profile" if _is_auth_profile_route(driver) else ""

    wait_state = wait_or_profile(waiter, delay)
    if wait_state == "profile":
        return None
    if waiter.is_alive():
        resend_attempted = True
        try:
            _click_resend_email_otp_stable(driver, timeout=20)
        except Exception:
            # The initial send may still arrive; keep waiting within the original budget.
            resend_result = "failed"
        else:
            resend_used = True
            resend_result = "sent"
            # A resend gets a new issued_after boundary.  Start that callback
            # immediately so the bridge can cancel the old mailbox waiter;
            # otherwise the old request may consume the resent code first.
            resent_after = time.time()
            remaining_budget = max(
                1.0,
                float(timeout) - (time.monotonic() - wait_started_at),
            )
            waiter, outcome = start_waiter(resent_after, remaining_budget)
        remaining_budget = max(
            1.0,
            float(timeout) - (time.monotonic() - wait_started_at),
        )
        wait_state = wait_or_profile(waiter, remaining_budget)
        if wait_state == "profile":
            return None
    if _is_auth_profile_route(driver):
        return None
    if waiter.is_alive():
        error = TimeoutError("OTP callback transport timeout")
        raise failure(error, cause="otp_callback_transport_timeout") from error
    if "error" in outcome:
        error = outcome["error"]
        raise failure(error) from error
    return _OtpCode(str(outcome.get("code") or ""), resend_used=resend_used)


def _cookie_header(driver) -> str:
    pairs = []
    for cookie in driver.get_cookies():
        domain = str(cookie.get("domain") or "").lower()
        if "chatgpt.com" in domain and cookie.get("name") and cookie.get("value"):
            pairs.append(f"{cookie['name']}={cookie['value']}")
    return "; ".join(pairs)


def _safe_page_state(driver) -> dict:
    """Return bounded secret-free browser state for failure diagnostics."""
    try:
        state = driver.execute_script(r"""
            const visible = x => !!(x && (x.offsetWidth || x.offsetHeight || x.getClientRects().length));
            const disabled = x => !!x.disabled || String(x.getAttribute('aria-disabled') || '').toLowerCase() === 'true';
            const scrub = value => String(value || '')
              .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, '[EMAIL]')
              .replace(/https?:\/\/[^\s"<>]+/gi, '[URL]')
              .replace(/\b\d{5,}\b/g, '[NUMBER]')
              .replace(/\s+/g, ' ').trim().slice(0, 120);
            const title = scrub(document.title);
            const statusText = scrub(document.body?.innerText || '');
            const buttons = [...document.querySelectorAll('button,a,[role=button],[role=link]')]
              .filter(visible);
            const submitButtons = [...document.querySelectorAll('button[type=submit],input[type=submit]')]
              .filter(visible);
            const bodyText = String(document.body?.innerText || '').replace(/\s+/g, ' ').toLowerCase();
            const chromeErrorCode = scrub(document.querySelector('.error-code')?.innerText || document.querySelector('.error-code')?.textContent);
            const chromeErrorText = scrub(document.querySelector('#main-frame-error, #main-message, .interstitial-wrapper')?.innerText || document.querySelector('#main-frame-error, #main-message, .interstitial-wrapper')?.textContent);
            const alertText = scrub([...document.querySelectorAll(
              '[role="alert"], [aria-live="assertive"], [data-testid*="error"]'
            )].filter(visible).map(x => x.innerText || x.textContent || '').join(' '));
            const statusEvidence = (title + ' ' + statusText).toLowerCase();
            const httpStatus500 = /\b500\b/.test(statusEvidence)
              && (/internal\s+server\s+error|route\s+error|http\s+error|server\s+error/.test(statusEvidence)
                || /^\s*500\s*$/.test(statusEvidence));
            const routeError500 = httpStatus500
              || /route error\s*\(\s*500(?:\s+internal server error)?\s*\)/.test(bodyText)
              || (/500\s+internal server error/.test(bodyText) && /istrusted/.test(bodyText));
            const recovery = window.__repo0810EmailRecoveryState;
            const recoveryState = typeof recovery === 'string' && [
              'queued', 'click_dispatched', 'submit_observed', 'missing_email_input',
              'missing_form', 'missing_submit', 'page_busy', 'input_changed',
              'form_invalid', 'dispatch_exception',
            ].includes(recovery) ? recovery : '';
            return {
              email_recovery_state: recoveryState,
              url: location.href,
              title: title,
              status_text: statusText,
              http_status_500: httpStatus500,
              inputs: [...document.querySelectorAll('input')]
                .filter(visible)
                .map(x => ({
                  type: x.type || '',
                  name: x.name || '',
                  autocomplete: x.autocomplete || '',
                  has_value: !!x.value,
                })),
              buttons: buttons.slice(0, 8).map(x => ({
                  tag: (x.tagName || '').toLowerCase(),
                  type: String(x.getAttribute('type') || '').toLowerCase(),
                  disabled: disabled(x),
                  href_path: (() => { try { return new URL(x.href || '', location.href).pathname; } catch (_) { return ''; } })(),
                  name: String(x.getAttribute('name') || '').slice(0, 60),
                  value: String(x.getAttribute('value') || '').slice(0, 72),
                  testid: String(x.getAttribute('data-testid') || '').slice(0, 80),
                })),
              visible_button_count: buttons.filter(x => !disabled(x)).length,
              visible_submit_count: submitButtons.length,
              submit_disabled: submitButtons.some(disabled),
              page_busy: [...document.querySelectorAll('[aria-busy="true"], [data-loading="true"]')]
                .some(visible),
              password_error: /incorrect password|invalid password|wrong password|password is incorrect|密码错误|密码不正确|パスワードが違います/.test(bodyText),
              chrome_error_code: chromeErrorCode,
              chrome_error_text: chromeErrorText,
              alert_text: alertText,
              route_error_500: routeError500,
            };
        """) or {}
        if isinstance(state, dict) and "url" in state:
            state["url"] = safe_url(state.get("url"))
        target = getattr(driver, "_repo0810_last_submit_target", None)
        if isinstance(state, dict) and isinstance(target, dict):
            state["submit_target"] = target
        input_diagnostics = getattr(
            driver, "_repo0810_password_input_diagnostics", None
        )
        if isinstance(state, dict) and isinstance(input_diagnostics, list):
            state["password_input_diagnostics"] = input_diagnostics
        return state if isinstance(state, dict) else {}
    except Exception as exc:
        return {"snapshot_error": type(exc).__name__}


def _session(driver) -> dict:
    driver.get("https://chatgpt.com/")
    end = time.time() + 90
    while time.time() < end:
        try:
            data = driver.execute_async_script("""
                const done = arguments[0];
                fetch('/api/auth/session', {credentials:'include'})
                  .then(r => r.json()).then(x => done(x)).catch(e => done({error:String(e)}));
            """) or {}
            if data.get("accessToken"):
                return data
        except Exception:
            pass
        time.sleep(2)
    raise RuntimeError("Roxy 浏览器登录后未取得 ChatGPT session/accessToken")


def run(req: dict) -> dict:
    email = str(req.get("email") or "").strip().lower()
    if not email or "@" not in email:
        raise ValueError("invalid email")
    callback = str(req.get("otp_callback") or "")
    nonce = str(req.get("otp_nonce") or "")
    if not callback.startswith("http://127.0.0.1:") or not nonce:
        raise ValueError("invalid OTP callback")
    try:
        otp_timeout = max(10, min(600, int(req.get("otp_timeout") or 180)))
    except (TypeError, ValueError):
        otp_timeout = 180

    opened = None
    driver = None
    password = ""
    password_set = False
    password_verified = False
    password_acceptance_evidence = ""
    email_otp_verified = False
    profile_submit_dispatched = False
    password_submit_state = ""
    password_submit_trace: list[dict] = []
    password_route_state = ""
    email_submit_stage = ""
    email_submit_trace: list[dict] = []
    candidate_password_verified = bool(req.get("candidate_password_verified"))
    account_route = "new_registration"
    keep_profile_open = bool(req.get("keep_browser_open", read_settings().keep_browser_open))
    failure_phase = "open_profile"
    try:
        _report_progress(req, failure_phase)
        opened = _create_open_profile(
            str(req.get("proxy") or ""),
            profile_id=str(req.get("profile_id") or ""),
        )
        driver = _driver(opened)
        driver._repo0810_profile_id = str(opened.profile_id or "")
        operation = str(req.get("operation") or "registration").strip().lower()
        if operation == "password_reset":
            failure_phase = "password_reset_prepare"
            password = _password_for_request(req)
            return _run_password_reset_flow(driver, req, password)
        if operation != "registration":
            raise ValueError("unsupported Roxy operation")
        # Request-scoped A/B flag: no future Roxy task changes behavior unless
        # its own bridge request explicitly opts in.
        driver._repo0810_native_pointer_enabled = bool(req.get("native_pointer_submit"))
        driver._repo0810_trusted_keyboard_submit_enabled = bool(
            req.get("trusted_keyboard_submit")
        )
        driver._repo0810_async_email_submit_enabled = bool(
            req.get("async_email_submit")
        )
        failure_phase = "browser_prepare"
        _report_progress(req, failure_phase)
        auth_entry_preflight = bool(req.get("auth_entry_preflight"))
        prepare_deadline = None
        if auth_entry_preflight:
            try:
                hard_timeout = max(
                    10,
                    min(65, int(req.get("browser_prepare_hard_timeout") or 35)),
                )
            except (TypeError, ValueError):
                hard_timeout = 35
            prepare_deadline = _arm_process_deadline(
                hard_timeout,
                {
                    "success": False,
                    "profile_id": str(opened.profile_id or ""),
                    "failure_phase": "browser_prepare",
                    "exception_type": "AuthEntryPreflightHardTimeout",
                    "error": "Roxy anonymous auth preflight exceeded hard deadline",
                    "page_state": {"auth_preflight_stage": "timeout"},
                },
            )
        try:
            if str(req.get("profile_id") or "").strip():
                _reset_profile_auth_state(driver)
            _open_auth_login_page(driver, timeout=45)
            if auth_entry_preflight:
                # Keep the health gate fully anonymous. Supplying login_hint
                # here can skip the email form and jump an existing identity
                # straight to email-verification, which both touches the
                # mailbox too early and makes the preflight wait for the wrong
                # element. The next phase owns the one target-email submit.
                _assert_auth_entry_ready(driver, "", timeout=10)
        finally:
            if prepare_deadline is not None:
                prepare_deadline.set()

        failure_phase = "email_submit"
        _report_progress(req, failure_phase)
        try:
            email_submit_hard_timeout = max(
                30,
                min(180, int(req.get("email_submit_hard_timeout") or 120)),
            )
        except (TypeError, ValueError):
            email_submit_hard_timeout = 120
        email_submit_stage = "input_wait"
        email_submit_page_state = {
            "email_submit_stage": email_submit_stage,
            "email_submit_trace": email_submit_trace,
        }

        def record_email_submit_stage(stage: str) -> None:
            nonlocal email_submit_stage
            normalized = str(stage or "").strip().lower()
            if normalized in _EMAIL_SUBMIT_STAGES:
                email_submit_stage = normalized
                email_submit_page_state["email_submit_stage"] = normalized

        email_submit_deadline = _arm_process_deadline(
            email_submit_hard_timeout,
            {
                "success": False,
                "profile_id": str(opened.profile_id or ""),
                "failure_phase": "email_submit",
                "exception_type": "EmailSubmitHardTimeout",
                "error": "Roxy email submission exceeded hard deadline",
                "page_state": email_submit_page_state,
            },
        )
        try:
            with _webdriver_command_timeout(
                driver,
                12,
                keep_on_error=True,
            ):
                # OTP can arrive while the email-submit transition is loading.
                issued_after = time.time()
                state = _submit_email_with_validated_legacy(
                    driver,
                    email,
                    stage_callback=record_email_submit_stage,
                    transition_trace=email_submit_trace,
                    email_form_timeout=email_submit_hard_timeout,
                )
        finally:
            email_submit_deadline.set()
        password = _password_for_request(req)
        if state == "otp":
            failure_phase = "password_route"
            _report_progress(req, failure_phase)
            password_route_state = "switching"
            routed_state = _switch_otp_to_password(
                driver,
                timeout=20,
                email=email,
                allow_login_fallback=candidate_password_verified,
            )
            password_route_state = routed_state
            if routed_state in {"otp", "email_page", "loading", "unknown"}:
                state = "otp"
            elif candidate_password_verified:
                account_route = "existing_account"
                state = routed_state
            elif routed_state == "password":
                # The OTP-first screen belonged to a new password-capable
                # signup. Submit the exact durable candidate before accepting
                # any email code so local and server password evidence match.
                account_route = "new_registration"
                state = "password"
            elif routed_state == "login_password":
                # A pending local candidate is not password evidence. Reuse
                # the existing-account resolver, which returns to the same
                # email OTP challenge without submitting that candidate.
                account_route = "existing_account"
                state, password_verified = _resolve_existing_login_password(
                    driver,
                    password,
                    candidate_password_verified=False,
                    timeout=90,
                )
                if password_verified:
                    password_acceptance_evidence = "existing_password_accepted"
            elif routed_state == "otp":
                # Some environments render only an email-verification page
                # without a dedicated password continuation control. In that
                # case, continue directly with the OTP flow.
                state = "otp"
            else:
                raise RuntimeError(
                    "邮箱 OTP 页没有可用的“使用密码”入口；"
                    "未验证候选密码不能继续创建 passwordless 账号"
                )
        if state == "login_password":
            account_route = "existing_account"
            if not candidate_password_verified:
                failure_phase = "password_route"
                _report_progress(req, failure_phase)
                password_route_state = "login_password"
                state, password_verified = _resolve_existing_login_password(
                    driver,
                    password,
                    candidate_password_verified=False,
                    timeout=90,
                )
                if password_verified:
                    password_acceptance_evidence = "existing_password_accepted"
            else:
                failure_phase = "password_submit"
                _report_progress(req, failure_phase)
                state = _continue_existing_password_login(
                    driver,
                    password,
                    timeout=90,
                    transition_trace=password_submit_trace,
                )
                password_submit_state = state
                password_verified = state in {"otp", "logged_in"}
                if password_verified:
                    password_acceptance_evidence = "existing_password_accepted"
        if state == "logged_in":
            element = None
        if state == "password":
            failure_phase = "password_submit"
            _report_progress(req, failure_phase)
            _, element = _wait_any(driver, [
                "input[autocomplete=new-password]",
                "input[type=password]",
            ], timeout=10)
            if element is None:
                raise RuntimeError("已识别创建密码页，但没有可用密码输入框")
            state, issued_after = _submit_signup_password(
                driver,
                element,
                password,
                timeout=90,
                transition_trace=password_submit_trace,
            )
            password_submit_state = state
            password_directly_accepted = state in {"otp", "logged_in"}
            if state == "password":
                # Some legacy/open states expose create-account/password but still
                # expect an email-code continuation instead of in-flow password
                # evidence. For unverified candidates, avoid hard failing and
                # try the OTP continuation path.
                if not candidate_password_verified:
                    state = _switch_login_password_to_otp(driver, timeout=10)
                    if state == "otp":
                        pass
                    else:
                        raise RuntimeError("Roxy 提交密码后未进入邮箱验证码页")
                else:
                    raise RuntimeError("Roxy 提交密码后未进入邮箱验证码页")
            if state not in {"otp", "logged_in"}:
                raise RuntimeError("Roxy 提交密码后未进入邮箱验证码页")
            password_set = password_directly_accepted
            if password_set:
                password_acceptance_evidence = "signup_password_accepted"
        elif state not in {"otp", "logged_in"}:
            raise RuntimeError(f"邮箱提交后页面状态不明确，已停止：{state}")

        if state == "otp":
            failure_phase = "otp_wait"
            _report_progress(req, failure_phase)
            element = _wait_for_otp_input_with_recovery(driver, timeout=20)
            code = _otp_with_one_resend(
                driver, callback, nonce, issued_after, otp_timeout
            )
            if code is not None:
                failure_phase = "otp_submit"
                _report_progress(req, failure_phase)
                _submit_otp_with_one_invalid_retry(
                    driver,
                    code,
                    callback,
                    nonce,
                    timeout=otp_timeout,
                )
                _report_progress(req, "otp_submitted")
            email_otp_verified = True

        # The route shown before OTP is not authoritative: OpenAI can send a
        # brand-new account through the same email-code screen as an existing
        # account, then reveal about-you only after OTP acceptance. Reuse the
        # validated helper for every route; it is idempotent and returns without
        # editing when a real ChatGPT session already exists.
        failure_phase = "profile"
        _report_progress(req, failure_phase)
        legacy = _legacy_module()
        profile_submit_dispatched = bool(legacy._complete_profile_page(
            driver,
            str(req.get("name") or "Alex Morgan"),
            str(req.get("birthday") or "1996-05-15"),
            timeout=60,
        ))

        failure_phase = "session"
        _report_progress(req, failure_phase)
        auth_session = _fetch_session_state_driven(driver)
        access_token = str(
            auth_session.get("accessToken")
            or auth_session.get("access_token")
            or ""
        )
        session_token = str(
            auth_session.get("sessionToken")
            or auth_session.get("session_token")
            or ""
        )
        cookies = driver.get_cookies()
        if not session_token:
            session_token = next(
                (
                    str(cookie.get("value") or "")
                    for cookie in cookies
                    if cookie.get("name") == "__Secure-next-auth.session-token"
                ),
                "",
            )
        if not access_token or not session_token:
            raise RuntimeError("Roxy 浏览器登录后未取得完整 Access/Session")
        user_agent = str(driver.execute_script("return navigator.userAgent || ''") or "")
        _report_progress(req, "browser_complete")
        return {
            "success": True,
            "profile_id": opened.profile_id if opened is not None else "",
            "email": email,
            "password": password,
            "password_set": password_set,
            "password_verified": password_verified or password_set,
            "password_acceptance_evidence": password_acceptance_evidence,
            "email_otp_verified": email_otp_verified,
            "account_route": account_route,
            "access_token": access_token,
            "session_token": session_token,
            "cookie_header": _cookie_header(driver),
            "browser_cookies": cookies,
            "user_agent": user_agent,
            "refresh_token": "",
        }
    except Exception as exc:
        failure_phase = str(getattr(exc, "failure_phase", "") or failure_phase)
        if opened is None:
            failed_profile_id = str(getattr(exc, "roxy_profile_id", "") or "")
            if failed_profile_id:
                opened = OpenedProfile(failed_profile_id, "", "")
        page_state = _safe_page_state(driver) if driver is not None else {}
        if failure_phase == "session":
            page_state = dict(page_state)
            session_diagnostics = getattr(exc, "session_diagnostics", None)
            if isinstance(session_diagnostics, dict):
                page_state.update(session_diagnostics)
            page_state["profile_submit_dispatched"] = profile_submit_dispatched
        if password_submit_state in {
            "otp", "logged_in", "password_error", "password", "password_shell",
            "login_password", "login_password_shell", "loading", "email_page", "unknown",
        }:
            page_state = dict(page_state)
            page_state["password_submit_state"] = password_submit_state
        if password_submit_trace:
            page_state = dict(page_state)
            page_state["password_submit_trace"] = password_submit_trace[:4]
        if failure_phase == "password_route" and password_route_state:
            page_state = dict(page_state)
            page_state["password_route_state"] = password_route_state
        if failure_phase == "email_submit" and email_submit_stage in _EMAIL_SUBMIT_STAGES:
            page_state = dict(page_state)
            page_state["email_submit_stage"] = email_submit_stage
        if failure_phase == "email_submit" and email_submit_trace:
            page_state = dict(page_state)
            page_state["email_submit_trace"] = email_submit_trace[:6]
        if failure_phase == "email_submit" and isinstance(exc, RoxyEmailSubmitError):
            page_state = dict(page_state)
            page_state.update(exc.email_submit_diagnostics)
        email_form_diagnostics = getattr(exc, "email_form_diagnostics", None)
        if failure_phase == "email_submit" and isinstance(email_form_diagnostics, dict):
            page_state = dict(page_state)
            page_state["email_form_readiness"] = dict(email_form_diagnostics)
        auth_preflight_stage = str(
            getattr(exc, "auth_preflight_stage", "") or ""
        ).strip().lower()
        if failure_phase == "browser_prepare" and auth_preflight_stage:
            page_state = dict(page_state)
            page_state["auth_preflight_stage"] = auth_preflight_stage
        password_input_stage = str(
            getattr(exc, "password_input_stage", "") or ""
        ).strip().lower()
        if (
            failure_phase == "password_submit"
            and password_input_stage in _TRUSTED_KEYBOARD_INPUT_STAGES
        ):
            page_state = dict(page_state)
            page_state["password_input_stage"] = password_input_stage
            input_diagnostics = getattr(exc, "input_diagnostics", None)
            if isinstance(input_diagnostics, list):
                page_state["password_input_diagnostics"] = [
                    dict(item) for item in input_diagnostics[:2]
                    if isinstance(item, dict)
                ]
        otp_failure = safe_otp_failure_metadata(exc) if failure_phase == "otp_wait" else {}
        local_locations = safe_traceback_summary(exc, {str(Path(__file__).resolve())})
        provider_locations = otp_failure.pop("failure_locations", "")
        failure_locations = " > ".join(
            frame for frame in (local_locations + " > " + provider_locations).split(" > ")
            if frame and frame != "unavailable"
        )
        return {
            "success": False,
            "email": email,
            "password": password,
            "password_set": password_set,
            "password_verified": password_verified or password_set,
            "password_acceptance_evidence": password_acceptance_evidence,
            "email_otp_verified": email_otp_verified,
            "account_route": account_route,
            "keep_profile_open": keep_profile_open,
            "profile_id": opened.profile_id if opened is not None else "",
            "error": safe_public_error(exc, "Roxy browser registration"),
            "failure_phase": failure_phase,
            "failure_cause": getattr(exc, "failure_cause", "") if isinstance(exc, (RoxySessionError, RoxyEmailSubmitError, RoxyPasswordResetError)) else "",
            "failure_locations": " > ".join(failure_locations.split(" > ")[-8:]) or "unavailable",
            "exception_type": type(exc).__name__,
            "page_state": page_state,
            **otp_failure,
        }
    finally:
        if driver is not None and not keep_profile_open:
            try:
                _clear_profile_auth_state(driver)
            except Exception:
                pass
            try:
                driver.quit()
            except Exception:
                pass
        if not keep_profile_open:
            _cleanup(opened)


def main() -> int:
    try:
        req = json.loads(sys.stdin.read() or "{}")
        # Keep malformed requests distinguishable, then validate optional local
        # Roxy resources before opening a Profile or touching an account.
        email = str(req.get("email") or "").strip().lower()
        callback = str(req.get("otp_callback") or "")
        nonce = str(req.get("otp_nonce") or "")
        if not email or "@" not in email:
            raise ValueError("invalid email")
        if not callback.startswith("http://127.0.0.1:") or not nonce:
            raise ValueError("invalid OTP callback")
        require_roxy_configuration()
        result = run(req)
    except Exception as exc:
        # Validation/import-adjacent failures happen before run() establishes a
        # browser phase. Preserve a structured, secret-free provenance record so
        # the bridge never collapses them into a generic registration failure.
        result = {
            "success": False,
            "error": safe_public_error(exc, "Roxy worker"),
            "failure_phase": "worker_preflight",
            "exception_type": type(exc).__name__,
        }
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result.get("success") else 1


if __name__ == "__main__":
    raise SystemExit(main())
