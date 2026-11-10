"""Fail-closed helpers for logs, SSE messages, and persisted errors.

These helpers intentionally keep only bounded transport metadata.  Upstream
response bodies and arbitrary exception text are never considered safe output.
"""
from __future__ import annotations

import json
import errno
import http.client
import math
import os
import re
import socket
import ssl
import urllib.error
from enum import IntEnum
from urllib.parse import urlsplit, urlunsplit

_HTTP_STATUS_RE = re.compile(
    r"\b(?:HTTP\s*)?([1-5]\d{2})(?!\.\d)\b",
    re.IGNORECASE,
)
_REQUEST_ID_RE = re.compile(
    r"\b(?:request[_ -]?id|req[_ -]?id)\s*[=:]\s*([A-Za-z0-9._:-]{1,120})",
    re.IGNORECASE,
)
_URL_RE = re.compile(r"https?://[^\s|,'\"<>]+", re.IGNORECASE)
_FAILURE_PHASE_VALUE_RE = re.compile(r"[a-z][a-z0-9_]{0,79}", re.IGNORECASE)
_FAILURE_CAUSE_VALUE_RE = re.compile(r"[a-z][a-z0-9_]{0,79}", re.IGNORECASE)
_EXCEPTION_TYPE_VALUE_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,79}")
_SAFE_FAILURE_CAUSE_MESSAGES = {
    "relay_mailbox_missing": "接码地址对应邮箱不存在或已失效",
    "relay_link_unauthorized": "接码地址访问凭证无效或已过期",
    "auth_session_missing": "账号资料已创建，但认证 Session 未建立",
    "relay_layout_unsupported": "接码页版式不受支持，已停止整页扫描以避免读取旧码",
    "relay_sync_degraded": "接码中转轮询期间出现间歇性网络故障，尚未取得验证码",
}
_SAFE_NETWORK_ERROR_KINDS = frozenset({'dns', 'tls', 'timeout', 'connection', 'http', 'unknown'})
_CURL_TRANSPORT_ERRORS = {
    5: ('dns', 'proxy_dns_failed'), 6: ('dns', 'dns_failed'),
    7: ('connection', 'connection_failed'), 16: ('connection', 'http2_failed'),
    18: ('connection', 'partial_response'), 28: ('timeout', 'timeout'),
    35: ('tls', 'tls_handshake_failed'), 52: ('connection', 'empty_response'),
    55: ('connection', 'send_failed'), 56: ('connection', 'receive_failed'),
    60: ('tls', 'tls_verification_failed'), 92: ('connection', 'http2_failed'),
}
_TRANSPORT_REASON_KINDS = dict((reason, kind) for kind, reason in _CURL_TRANSPORT_ERRORS.values())
_TRANSPORT_REASON_KINDS.update(connection_error='connection', proxy_error='connection',
                               ssl_error='tls')


def safe_http_transport_metadata(exc: BaseException) -> dict:
    """Extract fixed transport facts; never return exception prose or URLs."""
    current, fallback, coded, visited = exc, {}, {}, set()
    for _ in range(8):
        if not isinstance(current, BaseException) or id(current) in visited:
            break
        visited.add(id(current))
        code = getattr(current, 'code', None)
        if type(code) is int or isinstance(code, IntEnum):
            code = int(code)
        else:
            code = None
        if code not in _CURL_TRANSPORT_ERRORS:
            # Legacy local errors may wrap libcurl's message instead of its enum.
            match = re.search(r'\bcurl:\s*\(([0-9]{1,2})\)', str(current)[:4096], re.IGNORECASE)
            code = int(match[1]) if match else None
        if code in _CURL_TRANSPORT_ERRORS:
            kind, reason = _CURL_TRANSPORT_ERRORS[code]
            facts = {'transport_kind': kind, 'transport_reason': reason, 'transport_code': code}
            if code == 60:
                return facts
            coded = coded or facts
        kind = type(current).__name__
        if isinstance(current, ssl.SSLError) or kind == 'SSLError':
            fallback = {'transport_kind': 'tls', 'transport_reason': 'ssl_error'}
        elif isinstance(current, socket.gaierror):
            fallback = {'transport_kind': 'dns', 'transport_reason': 'dns_failed'}
        elif isinstance(current, TimeoutError) or kind in {'Timeout', 'ConnectTimeout', 'ReadTimeout'}:
            fallback = {'transport_kind': 'timeout', 'transport_reason': 'timeout'}
        elif isinstance(current, ConnectionError) or kind in {'ConnectionError', 'ProxyError'}:
            fallback = {'transport_kind': 'connection',
                        'transport_reason': 'proxy_error' if kind == 'ProxyError' else 'connection_error'}
        reason = getattr(current, 'reason', None)
        nested = reason if isinstance(reason, BaseException) else current.__cause__
        if not isinstance(nested, BaseException) and current.args and isinstance(current.args[0], BaseException):
            nested = current.args[0]
        if not isinstance(nested, BaseException) and not current.__suppress_context__:
            nested = current.__context__
        if not isinstance(nested, BaseException):
            break
        current = nested
    return coded or fallback
_OTP_WAIT_COUNT_KEYS = (
    'polls_ok', 'polls_failed', 'empty_polls', 'messages', 'skipped_seen',
    'rejected_missing_time', 'rejected_old', 'rejected_sender', 'rejected_no_otp',
)
_OTP_WAIT_MESSAGES = {
    'empty': '中转页面可访问，但本轮验证码轮询未返回邮件',
    'rejected': '中转返回了邮件，但未取得符合本次时间与来源要求的验证码',
    'unavailable': '中转同步不可用，尚未取得验证码',
    'degraded': '中转轮询期间出现间歇性网络故障，仍未取得验证码',
}
_OTP_WAIT_TIME_KEYS = {
    'callback_budget_seconds': 600, 'callback_elapsed_seconds': 3600,
    'worker_budget_seconds': 600, 'worker_elapsed_seconds': 3600,
}
_OTP_FAILURE_CAUSES = frozenset({
    'relay_mailbox_missing', 'relay_link_unauthorized', 'relay_layout_unsupported',
    'relay_sync_unavailable', 'otp_wait_timeout', 'otp_callback_transport_timeout',
    'otp_callback_transport_failed', 'otp_callback_invalid_response', 'otp_callback_failed',
    'relay_sync_degraded',
})
_OTP_EXCEPTION_TYPES = frozenset({
    'TimeoutError', 'OtpWaitTimeoutError', 'RuntimeError', 'PermissionError',
    'ValueError', 'TypeError', 'ConnectionError', 'ConnectionRefusedError',
    'ConnectionResetError', 'ConnectionAbortedError', 'BrokenPipeError',
    'OSError', 'HTTPError', 'URLError', 'SSLError', 'gaierror', 'JSONDecodeError',
    'RoxyOtpCallbackError',
})
_OTP_FAILURE_SOURCE_FUNCTIONS = {
    'roxy_bridge.py': {'_wait_for_otp_with_budget', 'do_POST'},
    'icloud_relay.py': {'wait_for_otp', '_poll_messages'},
}

_ROXY_CREATE_REASONS = frozenset({
    'unknown', 'daily_quota', 'workspace_required', 'core_type_unsupported',
    'core_unavailable', 'core_version_unsupported', 'core_os_unsupported',
})
_ROXY_VERSION = r'[0-9]{1,4}(?:\.[0-9]{1,8}){0,3}'
_ROXY_VERSIONS = _ROXY_VERSION + r'(?:、' + _ROXY_VERSION + r'){0,31}'
_ROXY_CORE = r'(?:Chrome|Firefox)'
# Templates verified in Roxy's packaged create handler and locale files.
_ROXY_CREATE_MESSAGE_PATTERNS = (
    ('workspace_required', r'workspaceId is required'),
    ('core_type_unsupported', r'coreType 仅支持 Chrome 或 Firefox'),
    ('core_type_unsupported', r'coreType only supports Chrome or Firefox'),
    ('core_unavailable', rf'当前系统暂无可用的 {_ROXY_CORE} 内核'),
    ('core_unavailable', rf'No available {_ROXY_CORE} kernel on the current system'),
    ('core_version_unsupported', rf'当前系统不支持 {_ROXY_CORE} {_ROXY_VERSION} 内核，可用版本：{_ROXY_VERSIONS}'),
    ('core_version_unsupported', rf'Current system does not support {_ROXY_CORE} {_ROXY_VERSION} kernel\. Available versions: {_ROXY_VERSIONS}'),
    ('core_os_unsupported', rf'当前系统不支持使用{_ROXY_VERSION}内核'),
    ('core_os_unsupported', rf'Current system does not support using {_ROXY_VERSION} kernel'),
)
_ROXY_MESSAGE_STATES = frozenset({
    'recognized', 'unrecognized', 'missing', 'invalid_type', 'too_long',
})
_PROXY_PROBE_ENUMS = {
    'service': frozenset({'ipinfo'}),
    'stage': frozenset({'request', 'http_status', 'json_decode', 'validate_response', 'intel'}),
    'reason': frozenset({
        'http_error', 'tls_error', 'connection_error', 'proxy_error', 'timeout',
        'invalid_json', 'invalid_shape', 'missing_ip', 'invalid_ip', 'unknown',
    }),
    'exception_type': frozenset({
        'HTTPError', 'SSLError', 'ConnectionError', 'ProxyError', 'Timeout',
        'ConnectTimeout', 'ReadTimeout', 'JSONDecodeError', 'ValueError', 'TypeError',
        'AttributeError', 'RuntimeError', 'RequestException', 'InvalidURL',
        'InvalidSchema', 'MissingSchema', 'InvalidProxyURL', 'URLRequired',
        'TooManyRedirects', 'ChunkedEncodingError', 'ContentDecodingError',
    }),
    'transport_reason': frozenset({
        'peer_disconnected', 'connection_reset', 'connection_aborted',
        'connection_refused', 'dns_error', 'tls_error', 'connect_timeout',
        'read_timeout', 'tunnel_rejected', 'unknown',
    }),
}
_PROXY_TRANSPORT_TYPES = frozenset({
    'ConnectionError', 'ProxyError', 'SSLError', 'ConnectTimeout', 'ReadTimeout',
    'Timeout', 'HTTPError', 'MaxRetryError', 'NewConnectionError',
    'NameResolutionError', 'ConnectTimeoutError', 'ReadTimeoutError',
    'ProtocolError', 'RemoteDisconnected', 'ConnectionResetError',
    'ConnectionRefusedError', 'ConnectionAbortedError', 'BrokenPipeError',
    'gaierror', 'TimeoutError', 'OSError', 'ClosedPoolError', 'EmptyPoolError',
})
_PROXY_NETWORK_ERRNOS = frozenset({
    errno.ETIMEDOUT, errno.ECONNRESET, errno.ECONNREFUSED, errno.ECONNABORTED,
    errno.ENETUNREACH, errno.EHOSTUNREACH, errno.EPIPE,
    socket.EAI_AGAIN, socket.EAI_NONAME, 10051, 10053, 10054, 10060, 10061, 10065,
})


def safe_proxy_probe_metadata(value: object) -> dict:
    """Retain fixed probe provenance; never accept exception/response text."""
    if not isinstance(value, dict):
        return {}
    result = {}
    for key, allowed in _PROXY_PROBE_ENUMS.items():
        item = value.get(key)
        if type(item) is str and item in allowed:
            result[key] = item
    status = value.get('http_status')
    if type(status) is int and 100 <= status <= 599:
        result['http_status'] = status
    elapsed = value.get('elapsed_ms')
    if type(elapsed) is int and elapsed >= 0:
        result['elapsed_ms'] = min(elapsed, 120000)
    index = value.get('pass_index')
    if type(index) is int and index in {1, 2}:
        result['pass_index'] = index
    attempts = value.get('attempt_count')
    if type(attempts) is int and 1 <= attempts <= 3:
        result['attempt_count'] = attempts
    root = value.get('root_exception_type')
    if type(root) is str and root in _PROXY_TRANSPORT_TYPES:
        result['root_exception_type'] = root
    chain = value.get('exception_chain')
    if type(chain) is list:
        safe_chain = [item for item in chain[:8] if type(item) is str and item in _PROXY_TRANSPORT_TYPES]
        if safe_chain:
            result['exception_chain'] = safe_chain
    for key in ('errno', 'winerror'):
        number = value.get(key)
        if type(number) is int and number in _PROXY_NETWORK_ERRNOS:
            result[key] = number
    tunnel_status = value.get('tunnel_http_status')
    if type(tunnel_status) is int and 100 <= tunnel_status <= 599:
        result['tunnel_http_status'] = tunnel_status
    locations = value.get('failure_locations')
    frame = r'proxy_screening\.py:[1-9][0-9]{0,6}:_probe'
    if type(locations) is str and re.fullmatch(frame + r'(?: > ' + frame + r'){0,7}', locations):
        result['failure_locations'] = locations
    return result


def safe_proxy_transport_metadata(exc: BaseException) -> dict:
    """Inspect bounded exception links/args in memory; return no free text."""
    from requests import exceptions as request_errors
    pending, seen, errors = [exc], set(), []
    while pending and len(errors) < 16:
        error = pending.pop(0)
        if not isinstance(error, BaseException) or id(error) in seen:
            continue
        seen.add(id(error))
        errors.append(error)
        pending.extend(getattr(error, field, None) for field in
                       ('reason', '__cause__', '__context__', 'original_error'))
        pending.extend(item for item in error.args[:16] if isinstance(item, BaseException))
    result = {'transport_reason': 'unknown'}
    chain = [type(error).__name__ for error in errors]
    result['exception_chain'] = chain
    # Prefer specific terminal conditions over their generic connection wrapper.
    classifications = (
        ('dns_error', socket.gaierror),
        ('tls_error', (ssl.SSLError, request_errors.SSLError)),
        ('connect_timeout', request_errors.ConnectTimeout),
        ('read_timeout', request_errors.ReadTimeout),
        ('peer_disconnected', http.client.RemoteDisconnected),
        ('connection_reset', ConnectionResetError),
        ('connection_aborted', (ConnectionAbortedError, BrokenPipeError)),
        ('connection_refused', ConnectionRefusedError),
    )
    for reason, types in classifications:
        root = next((error for error in errors if isinstance(error, types)), None)
        if root is not None:
            result['transport_reason'] = reason
            result['root_exception_type'] = type(root).__name__
            break
    for error in errors:
        for field in ('errno', 'winerror'):
            number = getattr(error, field, None)
            if type(number) is int and number in _PROXY_NETWORK_ERRNOS:
                result.setdefault(field, number)
                if result['transport_reason'] == 'unknown' and isinstance(error, OSError):
                    numeric_causes = {
                        errno.ECONNRESET: 'connection_reset', 10054: 'connection_reset',
                        errno.ECONNABORTED: 'connection_aborted', 10053: 'connection_aborted',
                        errno.EPIPE: 'connection_aborted',
                        errno.ECONNREFUSED: 'connection_refused', 10061: 'connection_refused',
                    }
                    if number in numeric_causes:
                        result['transport_reason'] = numeric_causes[number]
                        result['root_exception_type'] = type(error).__name__
        if isinstance(error, OSError):
            for argument in error.args[:16]:
                if type(argument) is str and len(argument) <= 128:
                    matched = re.fullmatch(r'Tunnel connection failed: ([1-5][0-9]{2}) [A-Za-z ]{1,48}', argument)
                    if matched:
                        result.update(transport_reason='tunnel_rejected',
                                      root_exception_type=type(error).__name__,
                                      tunnel_http_status=int(matched[1]))
    return safe_proxy_probe_metadata(result)


def _safe_roxy_code(value: object) -> str:
    if type(value) is int:
        return str(value) if 1 <= value <= 9999999999 else ''
    if type(value) is str and re.fullmatch(r'[1-9][0-9]{0,9}', value.strip()):
        return value.strip()
    return ''


def safe_roxy_rejection_metadata(value: object) -> dict:
    """Revalidate create-rejection fields without accepting upstream text."""
    if not isinstance(value, dict):
        return {}
    reason = value.get('reason')
    source = value.get('reason_source')
    state = value.get('message_state')
    result = {
        'reason': reason if type(reason) is str and reason in _ROXY_CREATE_REASONS else 'unknown',
        'reason_source': source if type(source) is str and source in {'code', 'msg', 'message', 'none'} else 'none',
        'message_state': state if type(state) is str and state in _ROXY_MESSAGE_STATES else 'unrecognized',
        'upstream_text_stored': False,
    }
    code = _safe_roxy_code(value.get('roxy_code'))
    if code:
        result['roxy_code'] = code
    status = value.get('http_status')
    if type(status) is int and 100 <= status <= 599:
        result['http_status'] = status
    return result


def safe_roxy_create_rejection(payload: object, http_status: object = None) -> dict:
    """Classify bounded messages in memory; return only fixed safe metadata."""
    payload = payload if isinstance(payload, dict) else {}
    code = _safe_roxy_code(payload.get('code'))
    field = 'msg'
    message = payload.get(field)
    if message is None or message == '':
        field = 'message'
        message = payload.get(field)
    reason, source = 'unknown', 'none'
    if message is None or message == '':
        state = 'missing'
    elif type(message) is not str:
        state = 'invalid_type'
    elif len(message) > 2048:
        state = 'too_long'
    elif not message.strip():
        state = 'missing'
    else:
        state = 'unrecognized'
        # Keep the established hard quota stop, without exposing any appendix.
        if '窗口单日创建次数已经超出' in message:
            reason, source, state = 'daily_quota', field, 'recognized'
        else:
            for candidate, pattern in _ROXY_CREATE_MESSAGE_PATTERNS:
                if re.fullmatch(pattern, message.strip(' \t\r\n')):
                    reason, source, state = candidate, field, 'recognized'
                    break
    if code == '416':
        reason, source = 'daily_quota', 'code'
    return safe_roxy_rejection_metadata({
        'reason': reason, 'reason_source': source, 'message_state': state,
        'roxy_code': code, 'http_status': http_status,
    })


def safe_otp_wait_diagnostics(value: object) -> dict:
    """Retain fixed states and bounded numbers, never arbitrary mail metadata."""
    if not isinstance(value, dict):
        return {}
    result = {}
    state = value.get('state')
    if isinstance(state, str) and state in _OTP_WAIT_MESSAGES:
        result['state'] = state
    kinds = value.get('network_error_kinds')
    if isinstance(kinds, (list, tuple)):
        safe_kinds = [
            item for item in kinds
            if isinstance(item, str) and item in _SAFE_NETWORK_ERROR_KINDS
        ]
        if safe_kinds:
            result['network_error_kinds'] = list(dict.fromkeys(safe_kinds))[:8]
    for key in _OTP_WAIT_COUNT_KEYS:
        count = value.get(key)
        if type(count) is int and count >= 0:
            result[key] = min(count, 99999)
    for key, upper in _OTP_WAIT_TIME_KEYS.items():
        seconds = value.get(key)
        if (type(seconds) in {int, float} and seconds >= 0
                and (type(seconds) is int or math.isfinite(seconds))):
            bounded = min(seconds, upper)
            result[key] = round(bounded, 3) if type(bounded) is float else bounded
    resend_attempted = value.get('resend_attempted')
    if type(resend_attempted) is bool:
        result['resend_attempted'] = resend_attempted
    resend_result = value.get('resend_result')
    if isinstance(resend_result, str) and resend_result in {'not_attempted', 'sent', 'failed'}:
        result['resend_result'] = resend_result
    return result


def safe_otp_failure_metadata(value: object) -> dict:
    """Keep only fixed OTP provenance across the loopback/process boundaries."""
    if isinstance(value, BaseException):
        chain = []
        seen = set()
        current = value
        for _ in range(8):
            if id(current) in seen:
                break
            seen.add(id(current))
            chain.append(current)
            nested = getattr(current, 'reason', None)
            if not isinstance(nested, BaseException):
                nested = current.__cause__
            if not isinstance(nested, BaseException):
                break
            current = nested
        merged = {}
        for error in reversed(chain):
            fields = {key: getattr(error, key, None) for key in (
                'exception_type', 'failure_cause', 'relay_network_error_kind',
                'otp_wait_diagnostics', 'failure_locations',
            )}
            if not fields['exception_type']:
                fields['exception_type'] = type(error).__name__
            if not fields['failure_cause'] and isinstance(error, TimeoutError):
                fields['failure_cause'] = 'otp_wait_timeout'
            cleaned = safe_otp_failure_metadata(fields)
            if 'otp_wait_diagnostics' in cleaned:
                diagnostics = dict(merged.get('otp_wait_diagnostics', {}))
                diagnostics.update(cleaned['otp_wait_diagnostics'])
                cleaned['otp_wait_diagnostics'] = diagnostics
            # An unannotated wrapper must not replace the deepest exception type.
            if merged.get('exception_type') and not getattr(error, 'exception_type', None):
                cleaned.pop('exception_type', None)
            merged.update(cleaned)
        return merged
    if not isinstance(value, dict):
        return {}
    result = {}
    exception_type = value.get('exception_type')
    if isinstance(exception_type, str) and exception_type in _OTP_EXCEPTION_TYPES:
        result['exception_type'] = exception_type
    failure_cause = value.get('failure_cause')
    if isinstance(failure_cause, str) and failure_cause in _OTP_FAILURE_CAUSES:
        result['failure_cause'] = failure_cause
    network_kind = value.get('relay_network_error_kind')
    if isinstance(network_kind, str) and network_kind in _SAFE_NETWORK_ERROR_KINDS:
        result['relay_network_error_kind'] = network_kind
    diagnostics = safe_otp_wait_diagnostics(value.get('otp_wait_diagnostics'))
    if diagnostics:
        result['otp_wait_diagnostics'] = diagnostics
    locations = value.get('failure_locations')
    if isinstance(locations, str):
        frames = []
        for frame in locations[:2048].split(' > '):
            match = re.fullmatch(r'([a-z_]+\.py):([1-9][0-9]{0,6}):([A-Za-z_][A-Za-z0-9_]{0,79})', frame)
            if match and match[3] in _OTP_FAILURE_SOURCE_FUNCTIONS.get(match[1], set()):
                frames.append(frame)
        if frames:
            result['failure_locations'] = ' > '.join(frames[-8:])
    return result


def safe_network_error_kind(value: object) -> str:
    kind = str(value or '').strip().lower()
    return kind if kind in _SAFE_NETWORK_ERROR_KINDS else ''


def network_error_kind(exc: BaseException) -> str:
    """Classify transport types without copying arbitrary exception text."""
    transport = safe_http_transport_metadata(exc)
    if 'transport_code' in transport and not isinstance(exc, urllib.error.HTTPError):
        return transport['transport_kind']
    current = exc
    visited: set[int] = set()
    for _ in range(8):
        if id(current) in visited:
            break
        visited.add(id(current))
        if isinstance(current, urllib.error.HTTPError):
            return 'http'
        if isinstance(current, socket.gaierror):
            return 'dns'
        if isinstance(current, ssl.SSLError):
            return 'tls'
        if isinstance(current, TimeoutError):
            return 'timeout'
        if isinstance(current, ConnectionError):
            return 'connection'
        if isinstance(current, OSError):
            if current.errno in {errno.ETIMEDOUT, 10060}:
                return 'timeout'
            if current.errno in {errno.ECONNRESET, errno.ECONNREFUSED, errno.ECONNABORTED,
                                 errno.ENETUNREACH, errno.EHOSTUNREACH, 10051, 10054, 10061, 10065}:
                return 'connection'
        reason = getattr(current, 'reason', None)
        nested = reason if isinstance(reason, BaseException) else current.__cause__
        if not isinstance(nested, BaseException):
            break
        current = nested
    return transport.get('transport_kind', 'unknown')


def safe_transport_error(exc: BaseException, operation: str) -> str:
    """Transport summary with no URL, response, or exception-message content."""
    kind = type(exc).__name__
    if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,79}', kind):
        kind = 'Error'
    status = f'; HTTP {exc.code}' if isinstance(exc, urllib.error.HTTPError) and 100 <= exc.code <= 599 else ''
    return f'{kind}: {operation} failed (relay_network_error_kind={network_error_kind(exc)}{status})'


def safe_traceback_summary(exc: BaseException, allowed_files: set[str]) -> str:
    """Keep source locations only; never format messages, source, or locals."""
    allowed = {os.path.normcase(os.path.abspath(path)) for path in allowed_files}
    frames = []
    current = exc
    visited: set[int] = set()
    for _ in range(8):
        if id(current) in visited:
            break
        visited.add(id(current))
        tb = current.__traceback__
        while tb:
            filename = tb.tb_frame.f_code.co_filename
            name = tb.tb_frame.f_code.co_name
            if (os.path.normcase(os.path.abspath(filename)) in allowed
                    and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,79}', name)):
                frames.append(f'{os.path.basename(filename)}:{tb.tb_lineno}:{name}')
            tb = tb.tb_next
        nested = current.__cause__
        if not isinstance(nested, BaseException):
            break
        current = nested
    return ' > '.join(frames[-8:]) or 'unavailable'
_SAFE_ERROR_CATEGORIES = (
    ("otp timeout", "OTP timeout"),
    ("otp_pending_keep_profile", "OTP pending; keep profile"),
    ("stopped", "stopped"),
    ("stop", "stopped"),
    ("cancelled", "cancelled"),
    ("canceled", "cancelled"),
    ("rate_limit", "rate limited"),
    ("timed out", "timeout"),
    ("timeout", "timeout"),
    ("connection", "network error"),
)
_SENSITIVE_KEY_RE = re.compile(
    r"(?:password|passcode|otp|secret|token|cookie|authorization|verifier|session_id|factor_id)",
    re.IGNORECASE,
)
_KEY_VALUE_RE = re.compile(
    r"\b(password|passcode|otp|secret|access_token|refresh_token|id_token|session_token|"
    r"cookie|authorization|verifier|body|factor_id|session_id)\s*[=:]\s*([^\s,;|]+)",
    re.IGNORECASE,
)
# Only expose upstream error identifiers that are useful for routing and
# classification.  Never copy arbitrary response fields into logs.
_SAFE_ERROR_CODES = frozenset({
    "account_deactivated",
    "registration_disallowed",
    "wrong_email_otp_code",
    "invalid_grant",
    "invalid_state",
    "rate_limit_exceeded",
    "insufficient_balance",
    "invalid_request_error",
    "invalid_request",
    "invalid_input",
    "fraud_guard",
    "verify_geo_block",
    "max_verify_attempts",
    "username_already_exists",
    "email_address_changed",
    "password_too_weak",
    "password_contains_user_info",
    "password_already_used",
    "password_reset_required",
    "invalid_username",
    "incorrect_code",
    "unhandled_provider_error",
    "unauthorized",
    "forbidden",
})


def safe_error_code(value: object) -> str:
    """Return an upstream error code only when it is explicitly allowlisted."""
    code = str(value or "").strip().lower()
    return code if code in _SAFE_ERROR_CODES else ""


def _response_error_fields(response: object) -> tuple[list, list, bool, bool]:
    """Read bounded code/type fields separately; never return prose or bodies."""
    raw_text = getattr(response, "text", "") or ""
    if not isinstance(raw_text, str) or not raw_text:
        return [], [], False, False
    try:
        payload = json.loads(raw_text[:16_384])
    except (TypeError, ValueError, json.JSONDecodeError):
        return [], [], False, False
    if not isinstance(payload, dict):
        return [], [], False, False
    error = payload.get("error")
    codes, types = [], []
    if isinstance(error, dict):
        codes.append(error.get("code"))
        types.append(error.get("type"))
    codes.append(payload.get("code"))
    if isinstance(error, str):
        codes.append(error)
    types.append(payload.get("type"))
    return codes, types, 'error' in payload, True


def _response_error_identifiers(response: object) -> tuple[list, bool, bool]:
    """Compatibility view of bounded upstream identifiers."""
    codes, types, present, parsed = _response_error_fields(response)
    return codes + types, present, parsed


def safe_response_error_code(response: object) -> str:
    """Extract a safe code, falling back to type only when code is absent."""
    codes, types, _present, _parsed = _response_error_fields(response)
    has_code_value = any(item is not None and item != "" for item in codes)
    candidates = codes if has_code_value else types
    for candidate in candidates:
        code = safe_error_code(candidate)
        if code:
            return code
    return ""


_PASSWORD_RESET_PHASES = frozenset({
    'unknown', 'starting', 'protocol_start', 'proxy_acquire', 'proxy_check', 'warmup', 'csrf',
    'auth_url', 'oauth_init', 'sentinel', 'authorize_continue', 'identify_account',
    'reset_page', 'mailbox_lookup', 'mailbox_prepare', 'otp_send', 'otp_wait',
    'otp_validate', 'password_submit', 'success', 'cancelled',
})
_PASSWORD_RESET_CAUSES = _OTP_FAILURE_CAUSES | frozenset({
    'unknown', 'mailbox_missing', 'missing_email', 'cancelled', 'transport_failed',
    'proxy_warmup_failed', 'oauth_init_http_error', 'oauth_init_redirect_invalid',
    'oauth_init_cookie_missing', 'upstream_http_error', 'invalid_json',
    'invalid_response', 'otp_delivery_rejected', 'invalid_otp_format',
    'missing_new_password_state', 'password_too_short', 'missing_reset_success',
    'invalid_login_state', 'invalid_reset_state', 'proxy_unavailable',
})
_PASSWORD_RESET_EXCEPTION_TYPES = _OTP_EXCEPTION_TYPES | frozenset({
    'PasswordResetProtocolError', 'AuthorizeRateLimitError', 'RequestsError',
    'RequestException', 'ProxyError', 'Timeout', 'ConnectTimeout', 'ReadTimeout',
    'MailProviderError', 'RoxyRegistrationError',
})
_PASSWORD_RESET_MESSAGES = {
    'success': '密码已自动重置并保存',
    'skipped': '账号当前不是待自动重置状态',
    'not_found': '找不到注册结果',
    'mailbox_missing': '邮箱池中找不到对应接码记录，请先补齐接码来源',
    'cancelled': '任务已取消',
    'persist_failed': '官网已返回成功，但本地密码未能安全保存',
    'deferred_rate_limited': '检测到授权限流，已停止剩余账号',
    'reset_failed': '密码重置失败，本地未保存新密码',
}
_PASSWORD_RESET_EVENTS = frozenset({
    'proxy_check', 'warmup_after', 'oauth_init_after', 'password_reset_page',
    'password_reset_otp_send', 'password_reset_otp_validate', 'password_reset_submit',
    'password_reset_http',
    'password_reset_transport',
})
_PASSWORD_RESET_SOURCE_FUNCTIONS = {
    'auth_flow.py': {'run_protocol_password_reset', 'auth_oauth_init', 'warmup',
        'get_csrf_token', 'get_auth_url', 'get_sentinel_token', 'authorize_continue',
        'send_password_reset_otp', 'validate_password_reset_otp', 'submit_password_reset',
        '_password_reset_response_json', '_password_reset_auth_url', '_password_reset_cancelled'},
    'registrar.py': {'run_protocol_password_reset', 'reset_registered_password_account',
        'process_account', '_do_registered_password_reset_batch'},
    'icloud_relay.py': {'wait_for_otp', '_poll_messages'},
}


def safe_auth_response_metadata(response: object) -> dict:
    """Keep response shape and challenge presence, never header/body values."""
    headers = getattr(response, 'headers', {}) or {}
    content_type = str(headers.get('Content-Type') or '').split(';', 1)[0].strip().lower()
    kind = {'application/json': 'json', 'text/html': 'html'}.get(content_type, 'other')
    result = {
        'response_kind': kind,
        'challenge_header_present': headers.get('cf-mitigated') == 'challenge',
        'request_id_present': bool(headers.get('x-request-id') or headers.get('request-id')),
    }
    status = getattr(response, 'status_code', None)
    if type(status) is int and 100 <= status <= 599:
        result['http_status'] = status
    if type(status) is int and status >= 400:
        codes, types, present, parsed = _response_error_fields(response)
        has_code_value = any(item is not None and item != "" for item in codes)
        has_type_value = any(item is not None and item != "" for item in types)
        code = next((safe_error_code(item) for item in codes if safe_error_code(item)), '')
        error_type = next((safe_error_code(item) for item in types if safe_error_code(item)), '')
        # Never label a generic `type` as the specific `code` when an unknown
        # code was actually supplied.  If code is absent, keep the historical
        # allowlisted-type fallback for compatibility, with its source explicit.
        if code or not has_code_value and error_type:
            result['error_code'] = code or error_type
        if parsed:
            result['upstream_error_present'] = present
        result['error_code_state'] = (
            'recognized' if code else 'unrecognized' if has_code_value else
            'recognized' if error_type else 'unrecognized' if has_type_value else
            'unparseable' if not parsed else 'missing'
        )
        result['error_code_source'] = (
            'code' if has_code_value else 'type' if has_type_value else
            'missing' if parsed else 'unparseable'
        )
        if error_type:
            result['error_type'] = error_type
    else:
        code = safe_response_error_code(response)
        if code:
            result['error_code'] = code
    return result


def safe_password_reset_diagnostics(value: object) -> list[dict]:
    """Second whitelist at the persistence boundary; no arbitrary strings."""
    if isinstance(value, dict):
        value = value.get('events')
    if not isinstance(value, list):
        return []
    result = []
    for item in value[-200:]:
        if not isinstance(item, dict) or type(item.get('event')) is not str or item['event'] not in _PASSWORD_RESET_EVENTS:
            continue
        event = {'event': item['event']}
        for key in ('success', 'final_https', 'final_host_matches', 'final_error',
                    'auth_oai_did_present', 'location_present', 'challenge_header_present',
                    'request_id_present', 'retry_scheduled', 'upstream_error_present'):
            if type(item.get(key)) is bool:
                event[key] = item[key]
        status = item.get('http_status')
        if type(status) is int and 100 <= status <= 599:
            event['http_status'] = status
        attempt = item.get('attempt')
        if type(attempt) is int and 1 <= attempt <= 4:
            event['attempt'] = attempt
        phase = item.get('phase')
        if type(phase) is str and phase in _PASSWORD_RESET_PHASES:
            event['phase'] = phase
        kind = item.get('response_kind')
        if type(kind) is str and kind in {'html', 'json', 'other'}:
            event['response_kind'] = kind
        code = safe_error_code(item.get('error_code'))
        if code:
            event['error_code'] = code
        error_type = safe_error_code(item.get('error_type'))
        if error_type:
            event['error_type'] = error_type
        if type(item.get('error_code_source')) is str and item['error_code_source'] in {
            'code', 'type', 'missing', 'unparseable'
        }:
            event['error_code_source'] = item['error_code_source']
        if type(item.get('error_code_state')) is str and item['error_code_state'] in {'recognized', 'unrecognized', 'missing', 'unparseable'}:
            event['error_code_state'] = item['error_code_state']
        event.update(safe_password_reset_failure_metadata({
            key: item.get(key) for key in ('transport_kind', 'transport_code', 'transport_reason',
                                         'transport_attempts', 'transport_elapsed_ms')
        }))
        result.append(event)
    return result[-16:]


def safe_password_reset_failure_metadata(value: object) -> dict:
    """Retain only fixed provenance from local exception attributes or receipts."""
    if isinstance(value, BaseException):
        fields = {key: getattr(value, key, None) for key in (
            'failure_phase', 'failure_cause', 'http_status', 'error_code',
            'exception_type', 'failure_locations', 'diagnostics', 'transport_kind',
            'transport_code', 'transport_reason', 'transport_attempts', 'transport_elapsed_ms',
            'proxy_attempts', 'proxy_switches', 'proxy_max_attempts', 'proxy_retry_stop',
            'proxy_attempt_history',
            'upstream_error_present', 'error_code_state', 'error_type', 'error_code_source',
            'proxy_release_failed',
        )}
        fields['exception_type'] = fields['exception_type'] or type(value).__name__
        if fields['failure_phase'] == 'otp_wait':
            fields.update(safe_otp_failure_metadata(value))
        kind = network_error_kind(value)
        transport = safe_http_transport_metadata(value)
        if not (fields['failure_phase'] == 'otp_wait' and kind == 'timeout' and 'transport_code' not in transport):
            fields.update(transport)
        if kind != 'unknown' and not (fields['failure_phase'] == 'otp_wait' and kind == 'timeout'):
            fields['transport_kind'] = kind
        if (fields['failure_phase'] != 'otp_wait' and kind in {'dns', 'tls', 'timeout', 'connection'}
                and not fields['failure_cause']):
            fields['failure_cause'] = 'transport_failed'
        return safe_password_reset_failure_metadata(fields)
    if not isinstance(value, dict):
        return {}
    result = {}
    for key, allowed in (
        ('failure_phase', _PASSWORD_RESET_PHASES),
        ('failure_cause', _PASSWORD_RESET_CAUSES),
        ('exception_type', _PASSWORD_RESET_EXCEPTION_TYPES),
        ('relay_network_error_kind', _SAFE_NETWORK_ERROR_KINDS),
        ('transport_kind', _SAFE_NETWORK_ERROR_KINDS),
    ):
        item = value.get(key)
        if type(item) is str and item in allowed:
            result[key] = item
    status = value.get('http_status')
    if type(status) is int and 100 <= status <= 599:
        result['http_status'] = status
    code = safe_error_code(value.get('error_code'))
    if code:
        result['error_code'] = code
    error_type = safe_error_code(value.get('error_type'))
    if error_type:
        result['error_type'] = error_type
    if type(value.get('error_code_source')) is str and value['error_code_source'] in {
        'code', 'type', 'missing', 'unparseable'
    }:
        result['error_code_source'] = value['error_code_source']
    if type(value.get('upstream_error_present')) is bool:
        result['upstream_error_present'] = value['upstream_error_present']
    if type(value.get('error_code_state')) is str and value['error_code_state'] in {'recognized', 'unrecognized', 'missing', 'unparseable'}:
        result['error_code_state'] = value['error_code_state']
    transport_code = value.get('transport_code')
    if type(transport_code) is int and transport_code in _CURL_TRANSPORT_ERRORS:
        result['transport_code'] = transport_code
    reason = value.get('transport_reason')
    if type(reason) is str and reason in _TRANSPORT_REASON_KINDS:
        result['transport_reason'] = reason
    for key, maximum in (('transport_attempts', 4), ('transport_elapsed_ms', 180000)):
        number = value.get(key)
        if type(number) is int and (1 if key == 'transport_attempts' else 0) <= number <= maximum:
            result[key] = number
    otp = safe_otp_wait_diagnostics(value.get('otp_wait_diagnostics'))
    if otp and result.get('failure_phase') == 'otp_wait':
        result['otp_wait_diagnostics'] = otp
    events = safe_password_reset_diagnostics(value.get('diagnostics'))
    if events:
        result['diagnostics'] = events
    locations = value.get('failure_locations')
    if type(locations) is str:
        frames = []
        for frame in locations[:2048].split(' > '):
            match = re.fullmatch(r'([a-z_]+\.py):([1-9][0-9]{0,6}):([A-Za-z_][A-Za-z0-9_]{0,79})', frame)
            if match and match[3] in _PASSWORD_RESET_SOURCE_FUNCTIONS.get(match[1], set()):
                frames.append(frame)
        if frames:
            result['failure_locations'] = ' > '.join(frames[-8:])
    for key, minimum, maximum in (('proxy_attempts', 0, 3), ('proxy_switches', 0, 2),
                                  ('proxy_max_attempts', 1, 3)):
        if type(value.get(key)) is int and minimum <= value[key] <= maximum:
            result[key] = value[key]
    if type(value.get('proxy_retry_stop')) is str and value['proxy_retry_stop'] in {
        'completed', 'cancelled', 'not_retryable', 'no_next_proxy', 'max_attempts', 'lease_release_failed'
    }:
        result['proxy_retry_stop'] = value['proxy_retry_stop']
    if type(value.get('proxy_release_failed')) is bool:
        result['proxy_release_failed'] = value['proxy_release_failed']
    history = value.get('proxy_attempt_history')
    if isinstance(history, list):
        safe_history = []
        for item in history[:3]:
            if not isinstance(item, dict):
                continue
            clean = safe_password_reset_failure_metadata({key: item.get(key) for key in (
                'failure_phase', 'failure_cause', 'http_status', 'error_code', 'error_type',
                'error_code_source', 'error_code_state', 'upstream_error_present', 'exception_type',
                'transport_code', 'transport_kind', 'transport_reason', 'transport_attempts',
            )})
            if type(item.get('status')) is str and item['status'] in {'success', 'reset_failed', 'cancelled', 'persist_failed'}:
                clean['status'] = item['status']
            safe_history.append(clean)
        result['proxy_attempt_history'] = safe_history
    return result


def password_reset_failure_category(value: dict) -> str:
    """Classify structured evidence; never guess from upstream prose."""
    status, cause = value.get('status'), value.get('failure_cause')
    if status in {'success', 'skipped', 'cancelled'}:
        return ''
    if status in {'not_found', 'mailbox_missing'} or cause in {
        'relay_mailbox_missing', 'relay_link_unauthorized', 'relay_layout_unsupported',
    }:
        return 'configuration'
    if value.get('error_code') in {
        'account_deactivated', 'invalid_grant', 'invalid_username', 'wrong_email_otp_code',
        'incorrect_code', 'password_too_weak', 'password_contains_user_info', 'password_already_used',
    }:
        return 'account'
    if status == 'deferred_rate_limited' or value.get('http_status') in {403, 429} or (
        type(value.get('http_status')) is int and value['http_status'] >= 500
    ) or cause in {
        'proxy_unavailable', 'proxy_warmup_failed', 'relay_sync_unavailable', 'relay_sync_degraded', 'transport_failed',
        'otp_callback_transport_timeout', 'otp_callback_transport_failed',
    } or value.get('transport_kind') in {'dns', 'tls', 'timeout', 'connection'} or (
        value.get('exception_type') in {'RequestsError', 'RequestException', 'ProxyError',
            'Timeout', 'ConnectTimeout', 'ReadTimeout', 'ConnectionError', 'SSLError', 'URLError'}
    ) or value.get('error_code') in {'rate_limit_exceeded', 'invalid_state'}:
        return 'network'
    if cause in {'otp_delivery_rejected', 'upstream_http_error', 'invalid_json',
                 'invalid_response', 'invalid_reset_state', 'invalid_login_state',
                 'oauth_init_cookie_missing', 'oauth_init_redirect_invalid',
                 'missing_new_password_state', 'missing_reset_success'}:
        return 'protocol'
    return 'unknown'


def safe_password_reset_result(value: dict) -> dict:
    """Credential-free result for SSE, log and DB, with fixed UI guidance."""
    email = str(value.get('email') or '').strip().lower()[:254]
    if not re.fullmatch(r"[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9.-]+", email):
        email = ''
    status = value.get('status')
    if type(status) is not str or status not in _PASSWORD_RESET_MESSAGES:
        status = 'reset_failed'
    result = {'email': email, 'status': status, 'message': _PASSWORD_RESET_MESSAGES[status]}
    result.update(safe_password_reset_failure_metadata(value))
    result['category'] = password_reset_failure_category(result)
    if status == 'reset_failed':
        if result.get('failure_cause') == 'transport_failed':
            descriptions = {'connection': '授权服务连接异常', 'tls': '授权服务 TLS 连接失败',
                            'dns': '授权服务 DNS 解析失败', 'timeout': '授权服务连接超时'}
            result['message'] = descriptions.get(result.get('transport_kind'), '授权服务网络请求失败')
            if result.get('transport_attempts', 0) > 1:
                result['message'] += f"，已尝试 {result['transport_attempts']} 次"
            result['message'] += '，本地未保存新密码'
        details = [f'{key}={result[key]}' for key in (
            'failure_phase', 'failure_cause', 'http_status', 'error_code', 'error_type',
            'error_code_source', 'error_code_state', 'transport_code'
        ) if key in result]
        if details:
            result['message'] += ' (' + '; '.join(details) + ')'
        if result.get('proxy_retry_stop') == 'max_attempts':
            result['message'] += '；已达到代理尝试上限（3次）'
        elif result.get('proxy_retry_stop') == 'no_next_proxy':
            result['message'] += '；没有下一条可用代理'
    index = value.get('index')
    if type(index) is int and 1 <= index <= 100:
        result['index'] = index
    return result


_JSON_KEY_VALUE_RE = re.compile(
    r'("(?:password|passcode|otp|secret|totp_secret|access_token|refresh_token|'
    r'id_token|session_token|cookie|authorization|verifier|body|factor_id|session_id)"'
    r'\s*:\s*)("(?:\\.|[^"\\])*"|[^,}\s]+)',
    re.IGNORECASE,
)


def safe_url(value: object) -> str:
    """Return only scheme/host/path; query and fragment are always discarded."""
    try:
        parsed = urlsplit(str(value or ""))
        if parsed.scheme or parsed.netloc:
            host = parsed.hostname or ""
            if ":" in host and not host.startswith("["):
                host = f"[{host}]"
            try:
                port = parsed.port
            except ValueError:
                port = None
            authority = f"{host}:{port}" if host and port is not None else host
            return urlunsplit((parsed.scheme, authority, parsed.path, "", ""))
        return parsed.path
    except Exception:
        return ""


def safe_response_summary(response: object, operation: str = "upstream request") -> str:
    """Describe a response using an allowlist of transport metadata only."""
    status = getattr(response, "status_code", "unknown")
    headers = getattr(response, "headers", {}) or {}
    request_id = str(
        headers.get("x-request-id")
        or headers.get("request-id")
        or headers.get("x-amzn-requestid")
        or ""
    )[:120]
    location = safe_url(headers.get("Location") or headers.get("location") or "")
    parts = [f"{operation}: HTTP {status}"]
    if request_id:
        parts.append(f"request_id={request_id}")
    error_code = safe_response_error_code(response)
    if error_code:
        parts.append(f"error_code={error_code}")
    if location:
        parts.append(f"location={location}")
    return " ".join(parts)


def sanitize_text(value: object) -> str:
    """Redact credentials and strip sensitive URL components in observable text."""
    text = str(value or "")
    text = _JSON_KEY_VALUE_RE.sub(
        lambda match: f'{match.group(1)}"[REDACTED]"',
        text,
    )
    text = _KEY_VALUE_RE.sub(lambda match: f"{match.group(1)}=[REDACTED]", text)
    return _URL_RE.sub(lambda match: safe_url(match.group(0)), text)


def sanitize_observable(value: object, *, allow_secret_keys: set[str] | None = None):
    """Recursively sanitize a value before logs, SSE, or database persistence."""
    allowed = {str(key).lower() for key in (allow_secret_keys or set())}
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            normalized = str(key).lower()
            if _SENSITIVE_KEY_RE.search(normalized) and normalized not in allowed:
                result[key] = "[REDACTED]"
            else:
                result[key] = sanitize_observable(item, allow_secret_keys=allowed)
        return result
    if isinstance(value, list):
        return [sanitize_observable(item, allow_secret_keys=allowed) for item in value]
    if isinstance(value, tuple):
        return tuple(sanitize_observable(item, allow_secret_keys=allowed) for item in value)
    if isinstance(value, str):
        return sanitize_text(value)
    return value


def safe_public_error(exc: BaseException | str, operation: str = "operation") -> str:
    """Convert an arbitrary exception into fail-closed, user-safe metadata."""
    raw = str(exc or "")
    kind = type(exc).__name__ if isinstance(exc, BaseException) else "Error"
    metadata: list[str] = []

    # ``safe_message`` follows the same trust model as failure_phase/cause below:
    # it is accepted only from a structured attribute on the exception object,
    # which only this codebase sets (fixed, secret-free guidance text).  It lets
    # deliberate diagnostics (e.g. the warmup guidance) survive fail-closed
    # compaction instead of collapsing into ``registration failed (HTTP 409)``
    # — where that 409 was merely a status-shaped number extracted from the
    # guidance text, not a real HTTP status.
    safe_message = (
        str(getattr(exc, "safe_message", "") or "").strip()
        if isinstance(exc, BaseException)
        else ""
    )

    rejection = safe_roxy_rejection_metadata(getattr(exc, 'roxy_rejection', None))
    transport_status = getattr(exc, 'http_status', None)
    if type(transport_status) is not int or not 100 <= transport_status <= 599:
        transport_status = rejection.get('http_status')
    status = _HTTP_STATUS_RE.search(raw) if not rejection and not transport_status else None
    if transport_status:
        metadata.append(f"HTTP {transport_status}")
    elif status:
        metadata.append(f"HTTP {status.group(1)}")
    request_id = _REQUEST_ID_RE.search(raw)
    if request_id:
        metadata.append(f"request_id={request_id.group(1)}")
    # Failure provenance is accepted only from structured exception attributes.
    # Parsing arbitrary error text would let nested/upstream messages inject an
    # earlier marker and override the worker's authoritative phase/type.
    failure_phase = (
        str(getattr(exc, "failure_phase", "") or "").strip()
        if isinstance(exc, BaseException)
        else ""
    )
    exception_type = (
        str(getattr(exc, "exception_type", "") or "").strip()
        if isinstance(exc, BaseException)
        else ""
    )
    failure_cause = (
        str(getattr(exc, "failure_cause", "") or "").strip()
        if isinstance(exc, BaseException)
        else ""
    )
    error_code = (
        safe_error_code(getattr(exc, "error_code", ""))
        if isinstance(exc, BaseException)
        else ""
    )
    if _FAILURE_PHASE_VALUE_RE.fullmatch(failure_phase):
        metadata.append(f"failure_phase={failure_phase.lower()}")
    if _EXCEPTION_TYPE_VALUE_RE.fullmatch(exception_type):
        metadata.append(f"exception_type={exception_type}")
    if _FAILURE_CAUSE_VALUE_RE.fullmatch(failure_cause):
        metadata.append(f"failure_cause={failure_cause.lower()}")
    if error_code:
        metadata.append(f"error_code={error_code}")
    network_kind = safe_network_error_kind(getattr(exc, 'relay_network_error_kind', ''))
    if network_kind:
        metadata.append(f'relay_network_error_kind={network_kind}')
    otp_diagnostics = safe_otp_wait_diagnostics(getattr(exc, 'otp_wait_diagnostics', None))
    if failure_phase.lower() == 'otp_wait':
        priority = ('worker_budget_seconds', 'worker_elapsed_seconds',
                    'callback_budget_seconds', 'callback_elapsed_seconds',
                    'resend_attempted', 'resend_result')
        ordered_keys = [key for key in priority if key in otp_diagnostics]
        ordered_keys.extend(key for key in otp_diagnostics if key not in priority)
        for key in ordered_keys:
            value = otp_diagnostics[key]
            field = 'poll_state' if key == 'state' else key
            prefix = 'otp' if key in _OTP_WAIT_TIME_KEYS or key.startswith('resend_') else 'relay'
            metadata.append(f'{prefix}_{field}={value}')

    seen_urls: set[str] = set()
    for match in _URL_RE.finditer(raw):
        cleaned = safe_url(match.group(0))
        if not cleaned or cleaned in seen_urls:
            continue
        # curl 系异常自带文档链接（curl.se/libcurl/c/libcurl-errors.html），
        # 对诊断零信息量，别让它占掉仅有的 url 名额。
        if "curl.se/libcurl" in cleaned.lower():
            continue
        seen_urls.add(cleaned)
        metadata.append(f"url={cleaned}")
        if len(seen_urls) >= 2:
            break

    lowered = raw.lower()
    category = _SAFE_FAILURE_CAUSE_MESSAGES.get(failure_cause.lower()) or (
        _OTP_WAIT_MESSAGES.get(otp_diagnostics.get('state'))
        if failure_phase.lower() == 'otp_wait' else None
    ) or next(
        (safe for marker, safe in _SAFE_ERROR_CATEGORIES if marker in lowered),
        "failed",
    )

    suffix = f" ({'; '.join(metadata)})" if metadata else ""
    if safe_message:
        return f"{kind}: {safe_message}{suffix}"
    return f"{kind}: {operation} {category}{suffix}"
