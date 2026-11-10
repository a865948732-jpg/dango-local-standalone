"""Explicit optional configuration for the locally installed Roxy workflow."""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, MutableMapping
from urllib.parse import urlsplit
from .roxy_settings import read_settings, settings_path


_WINDOWS_USER_ROXY_ENVIRONMENT = (
    "ROXY_API_BASE",
    "ROXY_WORKSPACE_ID",
    "ROXY_PROJECT_ID",
    "REPO0810_ROXY_LEGACY_ROOT",
    "REPO0810_ROXY_PYTHON",
    "REPO0810_ROXY_MAX_WINDOWS",
)


class RoxyConfigurationError(RuntimeError):
    """Raised before any browser/account side effect when Roxy is not configured."""


@dataclass(frozen=True)
class RoxyConfig:
    api_base: str
    workspace_id: int
    project_id: int
    legacy_root: Path
    python: Path


def bootstrap_windows_user_roxy_environment(
    environ: MutableMapping[str, str] | None = None,
) -> None:
    """Copy saved HKCU Roxy settings into a stale launcher's environment."""
    if not sys.platform.startswith("win"):
        return
    try:
        import winreg

        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Environment",
            0,
            winreg.KEY_READ,
        )
    except (ImportError, OSError):
        return

    target = os.environ if environ is None else environ
    with key:
        for name in _WINDOWS_USER_ROXY_ENVIRONMENT:
            if str(target.get(name) or "").strip():
                continue
            try:
                value = str(winreg.QueryValueEx(key, name)[0] or "").strip()
            except OSError:
                continue
            if value:
                target[name] = value


def _positive_identifier(name: str, value: str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise RoxyConfigurationError(f"{name} 必须是正整数") from exc
    if parsed <= 0:
        raise RoxyConfigurationError(f"{name} 必须是正整数")
    return parsed


def load_roxy_config(environ: Mapping[str, str] | None = None) -> RoxyConfig:
    """Load Roxy only when its machine-owned resources are explicitly named."""
    values = os.environ if environ is None else environ
    if environ is None and settings_path().is_file():
        preferences = read_settings()
        values = {**values, "ROXY_API_BASE": preferences.api_base,
                  "ROXY_WORKSPACE_ID": preferences.workspace_id,
                  "ROXY_PROJECT_ID": preferences.project_id}
    required = (
        "ROXY_WORKSPACE_ID",
        "ROXY_PROJECT_ID",
        "REPO0810_ROXY_LEGACY_ROOT",
    )
    missing = [name for name in required if not str(values.get(name) or "").strip()]
    if missing:
        raise RoxyConfigurationError(
            "Roxy 未配置；请设置 " + ", ".join(missing)
        )

    api_base = str(
        values.get("ROXY_API_BASE") or "http://127.0.0.1:50000"
    ).strip().rstrip("/")
    try:
        url = urlsplit(api_base)
        valid_api = (url.scheme == "http" and url.hostname in {"127.0.0.1", "localhost", "::1"}
                     and url.username is None and url.password is None and not url.query
                     and not url.fragment and url.path in {"", "/"} and url.port
                     and 1 <= url.port <= 65535)
    except ValueError:
        valid_api = False
    if not valid_api:
        raise RoxyConfigurationError("ROXY_API_BASE 必须是本机 loopback HTTP 地址")

    legacy_root = Path(
        str(values["REPO0810_ROXY_LEGACY_ROOT"]).strip()
    ).expanduser().resolve()
    helper = legacy_root / "core" / "roxy_registration.py"
    if not helper.is_file():
        raise RoxyConfigurationError(
            "REPO0810_ROXY_LEGACY_ROOT 缺少 core/roxy_registration.py"
        )

    configured_python = str(values.get("REPO0810_ROXY_PYTHON") or "").strip()
    python = Path(configured_python or sys.executable).expanduser().resolve()
    if not python.is_file():
        raise RoxyConfigurationError("REPO0810_ROXY_PYTHON 不存在或不是文件")

    return RoxyConfig(
        api_base=api_base,
        workspace_id=_positive_identifier(
            "ROXY_WORKSPACE_ID", str(values["ROXY_WORKSPACE_ID"]).strip()
        ),
        project_id=_positive_identifier(
            "ROXY_PROJECT_ID", str(values["ROXY_PROJECT_ID"]).strip()
        ),
        legacy_root=legacy_root,
        python=python,
    )


def require_roxy_configuration() -> RoxyConfig:
    return load_roxy_config()
