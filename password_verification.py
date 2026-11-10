"""Credential-free diagnostics for an explicitly requested password check."""
from __future__ import annotations

import json
import re
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

_PHASES = {
    'verification_setup': '准备验证',
    'network_precheck': '检查网络',
    'warmup': '连接登录页面',
    'csrf': '建立登录会话',
    'auth_url': '获取登录入口',
    'oauth_init': '初始化登录',
    'security_check': '登录安全检查',
    'identify_account': '确认登录方式',
    'password_entry': '打开密码登录入口',
    'password_check': '核对新密码',
}
_LOG_LOCK = threading.Lock()


class PasswordVerificationError(RuntimeError):
    """Expose only a fixed phase, category, exception type and HTTP status."""

    def __init__(self, phase, original=None, *, http_status=None, reason=''):
        self.failure_phase = phase if phase in _PHASES else 'verification_setup'
        self.exception_type = type(original).__name__ if isinstance(original, BaseException) else 'RuntimeError'
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,79}', self.exception_type):
            self.exception_type = 'RuntimeError'
        self.http_status = http_status if isinstance(http_status, int) and 400 <= http_status <= 599 else None
        self.failure_cause = reason if reason in {'unconfirmed', 'invalid_response', 'entry_unavailable'} else 'unknown'
        current = original
        seen = set()
        for _ in range(5):
            if not isinstance(current, BaseException) or id(current) in seen:
                break
            seen.add(id(current))
            # Inspect for classification only. Never return/log arbitrary text.
            text = str(current).lower()
            name = type(current).__name__.lower()
            if self.http_status is None:
                match = re.search(r'\bhttp\s+([45]\d{2})\b', text)
                response = getattr(current, 'response', None)
                status = getattr(response, 'status_code', None)
                if isinstance(status, int) and 400 <= status <= 599:
                    self.http_status = status
                elif match:
                    self.http_status = int(match.group(1))
            if 'timeout' in name or 'timeout' in text or 'timed out' in text:
                self.failure_cause = 'timeout'
            elif self.failure_cause == 'unknown' and (
                any(word in name for word in ('proxy', 'connection', 'ssl'))
                or any(word in text for word in ('tls', 'connection', 'proxyerror'))
            ):
                self.failure_cause = 'network'
            current = current.__cause__ or current.__context__
        if self.http_status == 429:
            self.failure_cause = 'rate_limited'
        self.public_message = self._message()
        super().__init__(self.public_message)

    def _message(self):
        prefix = f'验证尚未完成（{_PHASES[self.failure_phase]}）：'
        if self.http_status == 401 and self.failure_phase == 'password_check':
            detail = '服务端未接受此密码，请核对是否为同一邮箱刚设置的新密码。'
        elif self.http_status == 429:
            detail = '服务端要求稍后再试，请勿连续提交；这不代表密码错误。'
        elif self.failure_cause == 'timeout':
            detail = '网络请求超时，不能据此判断密码错误。'
        elif self.failure_cause == 'network':
            detail = '网络连接失败，不能据此判断密码错误。'
        elif self.failure_phase == 'password_entry' and self.failure_cause == 'entry_unavailable':
            detail = '服务端未提供密码验证入口，尚未核对密码。'
        elif self.http_status is not None:
            detail = f'登录服务返回 HTTP {self.http_status}，不能据此确认新密码。'
        elif self.failure_cause in {'invalid_response', 'unconfirmed'}:
            detail = '未收到明确的验证成功结果，不能保存为已验证密码。'
        elif self.failure_phase == 'password_check':
            detail = '本次请求未能确认新密码。'
        else:
            detail = '此步骤未能完成，尚未进行密码核对。'
        return prefix + detail + ' 本地密码未改动。'

    @property
    def api_status(self):
        if self.http_status in (401, 429):
            return self.http_status
        return 504 if self.failure_cause == 'timeout' else 502


def run_verification_step(phase, operation, *args, **kwargs):
    try:
        return operation(*args, **kwargs)
    except PasswordVerificationError:
        raise
    except Exception as exc:
        raise PasswordVerificationError(phase, exc) from exc


def record_verification_failure(error, directory):
    """Append only allowlisted metadata, never account data or exception text."""
    diagnostic_id = uuid.uuid4().hex[:12]
    record = {
        'diagnostic_id': diagnostic_id,
        'time': datetime.now(timezone.utc).isoformat(),
        'phase': error.failure_phase,
        'cause': error.failure_cause,
        'exception_type': error.exception_type,
        'http_status': error.http_status,
    }
    directory = Path(directory)
    with _LOG_LOCK:
        directory.mkdir(parents=True, exist_ok=True)
        with (directory / 'password-verification.log').open('a', encoding='utf-8') as stream:
            stream.write(json.dumps(record, ensure_ascii=True) + '\n')
    return diagnostic_id
