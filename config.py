"""最小化 Config（仅 browser_register.py 用到的字段）。

剥离自原 CTF-reg/config.py，去掉 card / billing / stripe / captcha 等支付相关字段，
仅保留注册阶段必需的 proxy 字段。
"""
from __future__ import annotations

from dataclasses import dataclass
import os
import sys
from typing import Optional


def _normalize_proxy_url(value: str, scheme: str = "http") -> Optional[str]:
    value = (value or "").strip()
    if not value:
        return None
    if "://" not in value:
        value = f"{scheme}://{value}"
    return value


def _get_windows_system_proxy() -> Optional[str]:
    """Read the current per-user proxy used by Windows browsers."""
    if not sys.platform.startswith("win"):
        return None

    try:
        import winreg

        path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_READ) as key:
            enabled = int(winreg.QueryValueEx(key, "ProxyEnable")[0] or 0)
            if not enabled:
                return None
            raw = str(winreg.QueryValueEx(key, "ProxyServer")[0] or "").strip()
    except (OSError, TypeError, ValueError):
        return None

    if "=" not in raw:
        return _normalize_proxy_url(raw)

    entries = {}
    for part in raw.split(";"):
        if "=" not in part:
            continue
        name, value = part.split("=", 1)
        entries[name.strip().lower()] = value.strip()

    for name in ("https", "http"):
        if entries.get(name):
            return _normalize_proxy_url(entries[name], "http")
    for name in ("socks5", "socks"):
        if entries.get(name):
            return _normalize_proxy_url(entries[name], "socks5")
    return None


def resolve_proxy(explicit: Optional[str] = None) -> Optional[str]:
    """Resolve the proxy used by registration and reauthorization tasks.

    An explicitly entered proxy wins. On Windows, an empty field follows the
    current per-user browser proxy so the background service and manual browser
    login use the same route. Environment variables remain the fallback.
    """
    value = (explicit or "").strip()
    if value:
        return value

    value = _get_windows_system_proxy()
    if value:
        return value

    for name in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy", "http_proxy", "all_proxy"):
        value = (os.environ.get(name) or "").strip()
        if value:
            return value
    return None


@dataclass
class Config:
    """ChatGPT 注册最小配置。"""
    # 出口代理 URL，例：socks5://user:pass@host:port  或  socks5://127.0.0.1:18899
    # 留 None 走系统直连
    proxy: Optional[str] = None
