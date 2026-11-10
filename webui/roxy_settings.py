"""Non-secret Roxy preferences and shared native profile payloads."""
from __future__ import annotations

import json
import inspect
import os
from pathlib import Path
import re
import secrets
import tempfile
import threading
import time
from functools import wraps
from urllib.parse import unquote, urlsplit

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, field_validator, model_validator

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_CONFIG_LOCK = threading.RLock()


def runtime_config_admission(operation):
    @wraps(operation)
    def admitted(*args, **kwargs):
        with RUNTIME_CONFIG_LOCK:
            return operation(*args, **kwargs)
    admitted.__signature__ = inspect.signature(operation, eval_str=True)
    return admitted


class RoxySettings(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    api_base: str = "http://127.0.0.1:50000"
    workspace_id: str = "1"
    project_id: str = "2"
    profile_id: str = ""
    workspace_path: str = "/browser/workspace"
    open_path: str = "/browser/open"
    close_path: str = "/browser/close"
    delete_path: str = "/browser/delete"
    max_windows: StrictInt = Field(default=2, ge=1, le=5)
    headless: StrictBool = False
    keep_browser_open: StrictBool = False
    one_profile_per_account: StrictBool = True
    delete_after_run: StrictBool = True
    random_os: StrictBool = True
    os_choices: str = "Windows,macOS"
    random_fingerprint: StrictBool = True
    native_fingerprint_only: StrictBool = True
    follow_proxy_ip: StrictBool = True
    random_name: StrictBool = True
    name_prefix: str = "rb"
    use_proxy_pool: StrictBool = True
    proxy_check_channel: str = "IPRust.io"
    codex_callback_timeout: StrictInt = Field(default=180, ge=10, le=600)
    otp_timeout: StrictInt = 180
    require_2fa: StrictBool = True

    @field_validator("api_base")
    @classmethod
    def local_api(cls, value: str) -> str:
        try:
            url = urlsplit(value.strip())
            valid = (url.scheme == "http" and url.hostname in {"127.0.0.1", "localhost", "::1"}
                     and url.username is None and url.password is None and url.path in {"", "/"}
                     and not url.query and not url.fragment and url.port and 1 <= url.port <= 65535)
        except ValueError:
            valid = False
        if not valid:
            raise ValueError("Roxy API must be a credential-free loopback HTTP address")
        return value.strip().rstrip("/")

    @field_validator("workspace_id", "project_id")
    @classmethod
    def identifier(cls, value: str) -> str:
        value = value.strip()
        if not re.fullmatch(r"[1-9][0-9]{0,19}", value):
            raise ValueError("Roxy workspace/project ID must be a positive integer string")
        return value

    @field_validator("profile_id")
    @classmethod
    def profile(cls, value: str) -> str:
        value = value.strip()
        if value and not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", value):
            raise ValueError("Invalid Roxy profile ID")
        return value

    @field_validator("workspace_path", "open_path", "close_path", "delete_path")
    @classmethod
    def local_path(cls, value: str) -> str:
        if not re.fullmatch(r"/[A-Za-z0-9_/-]+", value) or "//" in value:
            raise ValueError("Roxy endpoint must be a local absolute path")
        return value

    @field_validator("os_choices")
    @classmethod
    def systems(cls, value: str) -> str:
        choices = list(dict.fromkeys(part.strip() for part in value.split(",") if part.strip()))
        if not choices or any(item not in {"Windows", "macOS", "Linux", "IOS", "Android"} for item in choices):
            raise ValueError("Invalid Roxy OS choices")
        return ",".join(choices)

    @field_validator("name_prefix")
    @classmethod
    def metadata(cls, value: str) -> str:
        value = value.strip()
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,48}", value):
            raise ValueError("Invalid Roxy metadata")
        return value

    @field_validator("proxy_check_channel")
    @classmethod
    def channel(cls, value: str) -> str:
        value = value.strip()
        if value and not re.fullmatch(r"[A-Za-z0-9_.-]{1,48}", value):
            raise ValueError("Invalid Roxy proxy check channel")
        return value

    @model_validator(mode="after")
    def supported_contract(self):
        if self.one_profile_per_account and self.profile_id:
            raise ValueError("One profile per account requires an empty fixed profile ID")
        if not self.native_fingerprint_only:
            raise ValueError("This worker supports native Roxy fingerprints only")
        if self.otp_timeout != 180 or not self.require_2fa:
            raise ValueError("Default OTP timeout 180 and required 2FA are fixed registration contracts")
        return self


def settings_path() -> Path:
    return Path(os.environ.get("REPO0810_ROXY_SETTINGS_PATH") or ROOT / "roxy.settings.json")


def read_settings() -> RoxySettings:
    path = settings_path()
    if not path.is_file():
        return RoxySettings()
    if path.stat().st_size > 16 * 1024:
        raise ValueError("Roxy settings file exceeds the allowed size")
    return RoxySettings.model_validate_json(path.read_text(encoding="utf-8"))


def save_settings(settings: RoxySettings) -> RoxySettings:
    settings = RoxySettings.model_validate(settings.model_dump())
    path = settings_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=path.name + ".", suffix=".tmp", delete=False) as output:
            temporary = Path(output.name)
            output.write(json.dumps(settings.model_dump(), ensure_ascii=True, indent=2) + "\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()
    return settings


def proxy_info_from_url(value: str) -> dict:
    """Translate a run-owned proxy without persisting or logging its credentials."""
    try:
        parsed = urlsplit(value if "://" in value else "http://" + value)
        protocol = {"http": "HTTP", "https": "HTTPS", "socks5": "SOCKS5", "socks5h": "SOCKS5"}[parsed.scheme]
        if not parsed.hostname or not parsed.port or not 1 <= parsed.port <= 65535:
            raise ValueError()
        if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            raise ValueError()
        result = {"moduleId": 0, "proxyMethod": "custom", "proxyCategory": protocol,
                  "ipType": "IPV6" if ":" in parsed.hostname else "IPV4", "protocol": protocol,
                  "host": parsed.hostname, "port": str(parsed.port)}
        if parsed.username:
            result["proxyUserName"] = unquote(parsed.username)
        if parsed.password:
            result["proxyPassword"] = unquote(parsed.password)
        return result
    except (ValueError, KeyError, TypeError):
        raise ValueError("Roxy run proxy has an unsupported format") from None


def create_profile_payload(workspace_id, project_id, proxy_info=None, *, settings=None) -> dict:
    settings = settings or read_settings()
    name = (f"{settings.name_prefix}-{int(time.time() * 1000)}-{secrets.token_hex(2)}"
            if settings.random_name else settings.name_prefix)
    choices = settings.os_choices.split(",")
    body = {"workspaceId": workspace_id, "projectId": project_id,
            "name": name, "windowName": name,
            "os": secrets.choice(choices) if settings.random_os else choices[0]}
    fingerprint = {}
    if settings.random_fingerprint:
        fingerprint["randomFingerprint"] = True
    if settings.follow_proxy_ip:
        fingerprint.update({"isLanguageBaseIp": True, "isDisplayLanguageBaseIp": True,
                            "isTimeZone": True, "isPositionBaseIp": True})
    if fingerprint:
        body["fingerInfo"] = fingerprint
    if proxy_info:
        body["proxyInfo"] = dict(proxy_info)
        if settings.proxy_check_channel:
            body["proxyInfo"]["checkChannel"] = settings.proxy_check_channel
        else:
            body["proxyInfo"].pop("checkChannel", None)
    elif settings.use_proxy_pool:
        raise ValueError("Roxy internal proxy is enabled but this run has no proxy resource")
    return body
