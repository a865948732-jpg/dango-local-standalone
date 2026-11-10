"""Strict local input normalization; never inspect arbitrary strings for credentials."""
from __future__ import annotations

import json
import re
from urllib.parse import urlsplit
import uuid

MAX_BODY_BYTES = 65536
MAX_BATCH_ITEMS = 10
MAX_TOKEN_LENGTH = 32768
_TOKEN = re.compile(r'[A-Za-z0-9._~+/-]+=*\Z', re.ASCII)


class InputError(Exception):
    def __init__(self, code: str, message: str, status: int = 400):
        super().__init__(message)
        self.code, self.message, self.status = code, message, status


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate JSON field')
        value[key] = item
    return value


def parse_access_token(value: object) -> str:
    if isinstance(value, str):
        if len(value) > MAX_TOKEN_LENGTH:
            raise InputError('invalid_token', 'Access Token 内容过长。')
        value = value.strip(' \t\r\n')
        if value.startswith(('{', '[')):
            try:
                value = json.loads(value, object_pairs_hook=unique_object)
            except (ValueError, UnicodeError, RecursionError):
                raise InputError('invalid_token', 'Token JSON 格式无效。') from None
    if isinstance(value, dict):
        candidates = [value[key] for key in ('access_token', 'accessToken') if key in value]
        if not candidates or any(not isinstance(item, str) for item in candidates):
            raise InputError('invalid_token', 'Token JSON 需要明确的 access_token 或 accessToken 字段。')
        normalized = [_raw_token(item) for item in candidates]
        if len(set(normalized)) != 1:
            raise InputError('invalid_token', 'Token JSON 中的认证字段不一致。')
        return normalized[0]
    return _raw_token(value)


def _raw_token(value):
    if not isinstance(value, str):
        raise InputError('invalid_token', 'Access Token 格式无效。')
    value = value.strip(' \t\r\n')
    if value.lower() == 'bearer':
        raise InputError('invalid_token', '请填写有效的 Access Token。')
    if re.match(r'^Bearer[ \t]+', value, re.IGNORECASE):
        value = re.sub(r'^Bearer[ \t]+', '', value, count=1, flags=re.IGNORECASE)
    if not value or len(value) > MAX_TOKEN_LENGTH or not _TOKEN.fullmatch(value):
        raise InputError('invalid_token', '请填写有效的 Access Token。')
    return value


def validate_uuid(value: object, code='invalid_request_id') -> str:
    try:
        if not isinstance(value, str) or str(uuid.UUID(value)) != value:
            raise ValueError
    except (ValueError, AttributeError):
        raise InputError(code, '请求标识无效。') from None
    return value


def validate_proxy(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise InputError('invalid_proxy', '请填写固定出口代理 URL。')
    try:
        parsed = urlsplit(value)
        if (any(ord(char) <= 32 or ord(char) >= 127 or char == '\\' for char in value)
                or parsed.scheme not in {'http', 'https', 'socks5', 'socks5h'}
                or not parsed.hostname or parsed.port is None or parsed.port == 0
                or parsed.path not in {'', '/'} or parsed.query or parsed.fragment):
            raise ValueError
    except ValueError:
        raise InputError('invalid_proxy', '代理 URL 格式无效。') from None
    return value


def validate_payload(payload: object) -> dict:
    if not isinstance(payload, dict) or payload.get('acknowledged') is not True:
        raise InputError('acknowledgement_required', '请确认结账及 UPI 委托的影响后再提取。')
    if set(payload) - {'request_id', 'source', 'email', 'access_token', 'proxy',
                       'chatgpt_proxy', 'stripe_proxy', 'acknowledged'}:
        raise InputError('invalid_request', '提取请求包含不支持的字段。')
    request_id = validate_uuid(payload.get('request_id'))
    source = payload.get('source')
    if not isinstance(source, str) or source not in {'registered', 'manual'}:
        raise InputError('invalid_source', '请选择账号来源。')
    email = payload.get('email', '')
    if (not isinstance(email, str) or len(email) > 254
            or not re.fullmatch(r'[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+', email)):
        raise InputError('invalid_email', '请填写有效的账号邮箱。')
    legacy = payload.get('proxy')
    chatgpt = payload.get('chatgpt_proxy', legacy)
    if 'proxy' in payload and 'chatgpt_proxy' in payload and legacy != chatgpt:
        raise InputError('invalid_proxy', '旧代理与 ChatGPT 代理配置不一致。')
    proxy = validate_proxy(chatgpt)
    stripe_proxy = validate_proxy(payload.get('stripe_proxy', proxy))
    token = payload.get('access_token', '')
    if source == 'registered':
        if token != '':
            raise InputError('invalid_request', '工作区账号使用已保存的 Access Token。')
    else:
        token = parse_access_token(token)
    return {'request_id': request_id, 'source': source, 'email': email.lower(),
            'access_token': token, 'proxy': proxy, 'stripe_proxy': stripe_proxy}


def validate_batch(payload: object) -> dict:
    if not isinstance(payload, dict) or payload.get('acknowledged') is not True:
        raise InputError('acknowledgement_required', '请确认本批任务的外部影响。')
    if set(payload) - {'batch_id', 'acknowledged', 'items'}:
        raise InputError('invalid_request', '批量请求包含不支持的字段。')
    batch_id = validate_uuid(payload.get('batch_id'), 'invalid_batch_id')
    items = payload.get('items')
    if not isinstance(items, list) or not 1 <= len(items) <= MAX_BATCH_ITEMS:
        raise InputError('batch_limit', '每批必须包含 1 至 10 个任务。')
    normalized = [validate_payload(item) for item in items]
    if len({item['request_id'] for item in normalized}) != len(normalized):
        raise InputError('duplicate_request', '同一批次不能重复提交请求标识。')
    if len({(item['source'], item['email']) for item in normalized}) != len(normalized):
        raise InputError('duplicate_account', '同一批次不能重复提交账号。')
    return {'batch_id': batch_id, 'items': normalized}
