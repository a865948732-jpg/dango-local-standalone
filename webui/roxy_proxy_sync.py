"""Explicit proxy-library import. Does not open profiles or start account flows."""
from __future__ import annotations

import ipaddress
import json
import re
import threading
import time
from urllib.parse import unquote, urlsplit

import requests
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from .roxy_config import RoxyConfigurationError, require_roxy_configuration

router = APIRouter()
_SYNC_LOCK = threading.Lock()
_MAX_BYTES = 512 * 1024
_MAX_PROXIES = 100
_LOOPBACK = {'127.0.0.1', 'localhost', '::1'}


class RoxySyncError(RuntimeError):
    """Only fixed, credential-free messages may cross the API boundary."""


def _host(value: str) -> tuple[str, str]:
    value = value.strip('[]').lower()
    try:
        address = ipaddress.ip_address(value)
        return str(address), 'IPV6' if address.version == 6 else 'IPV4'
    except ValueError:
        value = value.encode('idna').decode('ascii')
        if len(value) > 253 or not all(
            re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
            for label in value.rstrip('.').split('.')
        ):
            raise ValueError('invalid host') from None
        return value.rstrip('.'), 'IPV4'


def _parse_proxy(value: object, line: int) -> dict:
    try:
        if not isinstance(value, str) or not value.strip() or len(value) > 4096:
            raise ValueError()
        value = value.strip()
        if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError()
        parsed = urlsplit(value if '://' in value else 'http://' + value)
        if parsed.scheme not in ('http', 'https', 'socks5'):
            raise ValueError()
        if parsed.path not in ('', '/') or parsed.query or parsed.fragment:
            raise ValueError()
        if not parsed.hostname or not parsed.port or not 1 <= parsed.port <= 65535:
            raise ValueError()
        host, ip_type = _host(parsed.hostname)
        credentials = []
        for raw in (parsed.username or '', parsed.password or ''):
            if re.search(r'%(?![0-9a-fA-F]{2})', raw):
                raise ValueError()
            decoded = unquote(raw, errors='strict')
            if any(ord(c) < 32 or ord(c) == 127 for c in decoded):
                raise ValueError()
            credentials.append(decoded)
        return {
            'ipType': ip_type, 'protocol': parsed.scheme.upper(),
            'host': host, 'port': str(parsed.port),
            'proxyUserName': credentials[0], 'proxyPassword': credentials[1],
            'remark': 'Dango 手动同步',
        }
    except (ValueError, UnicodeError):
        raise HTTPException(400, f'第 {line} 条代理格式不支持；请用 [http/https/socks5://][账号:密码@]主机:端口，特殊字符需 URL 编码') from None


def _key(row: dict) -> tuple:
    try:
        return (str(row['protocol']).upper(), _host(str(row['host']))[0],
                int(row['port']), str(row.get('proxyUserName') or ''),
                str(row.get('proxyPassword') or ''))
    except (KeyError, TypeError, ValueError, UnicodeError):
        raise RoxySyncError('Roxy 代理列表格式不完整，已停止同步以免重复导入') from None


def _api_base(value: str) -> str:
    try:
        url = urlsplit(value)
        if (url.scheme != 'http' or url.hostname not in _LOOPBACK
                or url.username is not None or url.password is not None
                or url.path not in ('', '/') or url.query or url.fragment
                or not url.port or not 1 <= url.port <= 65535):
            raise ValueError()
        host = '[::1]' if url.hostname == '::1' else '127.0.0.1'
        return f'http://{host}:{url.port}'
    except ValueError:
        raise RoxySyncError('Roxy API 必须使用本机 HTTP 地址，不能带账号、路径或跳转参数') from None


def _call(session, base, method, path, **kwargs):
    try:
        response = session.request(method, base + path, timeout=(3, 8), allow_redirects=False, **kwargs)
        if response.status_code != 200:
            raise RoxySyncError('Roxy 接口未成功响应；请检查客户端登录和 API 服务')
        payload = response.json()
        if not isinstance(payload, dict) or payload.get('code') not in (0, '0'):
            raise RoxySyncError('Roxy 拒绝了请求；请检查当前团队和 API 权限')
        return payload.get('data')
    except (requests.RequestException, ValueError):
        raise RoxySyncError('Roxy 接口连接失败或未返回 JSON；请确认客户端已登录且 API 已开启') from None


def _existing(session, base, workspace):
    keys, seen = set(), set()
    deadline = time.monotonic() + 20
    for page in range(1, 21):
        if time.monotonic() > deadline:
            raise RoxySyncError('读取 Roxy 代理列表超时，未能完成核对')
        data = _call(session, base, 'GET', '/proxy/list', params={
            'workspaceId': workspace, 'page_index': page, 'page_size': 100,
        })
        if not isinstance(data, dict) or not isinstance(data.get('rows'), list):
            raise RoxySyncError('Roxy 代理列表格式不正确，未能完成核对')
        rows = data['rows']
        total = data.get('total')
        if not isinstance(total, int) or total < 0:
            raise RoxySyncError('Roxy 代理总数无效，未能完成核对')
        for row in rows:
            if not isinstance(row, dict) or not row.get('id') or str(row['id']) in seen:
                raise RoxySyncError('Roxy 分页返回重复或不完整，已停止同步')
            seen.add(str(row['id']))
            keys.add(_key(row))
        if len(seen) >= total:
            return keys
        if not rows:
            break
    raise RoxySyncError('Roxy 代理列表未能完整读取，已停止同步')


def sync_proxies(proxies: list) -> dict:
    parsed = [_parse_proxy(value, index + 1) for index, value in enumerate(proxies)]
    unique = {_key(row): row for row in parsed}
    try:
        config = require_roxy_configuration()
    except RoxyConfigurationError:
        raise HTTPException(400, '请先完成本机 Roxy 接入配置') from None
    base = _api_base(config.api_base)
    workspace = str(config.workspace_id)
    if not _SYNC_LOCK.acquire(blocking=False):
        raise HTTPException(409, '已有代理同步正在进行，请等待结果')
    try:
        with requests.Session() as session:
            # Proxy credentials must never follow redirects or system proxy settings.
            session.trust_env = False
            session.headers.update({'Accept': 'application/json'})
            before = _existing(session, base, workspace)
            missing = {key: row for key, row in unique.items() if key not in before}
            result = {
                'ok': True, 'confirmed_new': 0, 'pending': 0,
                'skipped_existing': len(unique) - len(missing),
                'duplicate_input': len(parsed) - len(unique),
                'workspace_id': workspace, 'network_tested': False,
            }
            if missing:
                channels = _call(session, base, 'GET', '/proxy/detect_channel', params={'workspaceId': workspace})
                options = [row['value'] for row in channels if isinstance(row, dict)
                           and isinstance(row.get('value'), str) and row['value']] if isinstance(channels, list) else []
                if not options:
                    raise RoxySyncError('Roxy 未提供代理检测渠道，未提交任何新代理')
                try:
                    _call(session, base, 'POST', '/proxy/batch_create', json={
                        'workspaceId': workspace, 'checkChannel': options[0],
                        'proxyList': list(missing.values()),
                    })
                except RoxySyncError:
                    # A lost response does not mean the write failed. Never retry POST.
                    pass
                try:
                    after = _existing(session, base, workspace)
                    result['confirmed_new'] = len(set(missing) & after)
                except RoxySyncError:
                    result['pending'] = len(missing)
                    result['ok'] = False
                    result['message'] = '已提交，但无法回读确认。请先在 Roxy 代理列表核对，不要连续点击重试。'
                    return result
                result['pending'] = len(missing) - result['confirmed_new']
                result['ok'] = result['pending'] == 0
            if result['ok']:
                result['message'] = '已在 Roxy 代理库核对保存；尚未检测网络，也未创建或修改浏览器环境。'
            else:
                result['message'] = '仅部分或尚无新增代理得到回读确认。请先核对 Roxy 代理列表，不要连续点击重试。'
            return result
    finally:
        _SYNC_LOCK.release()


@router.post('/api/roxy/proxies/sync')
async def api_sync_proxies(request: Request):
    origin = request.headers.get('origin')
    if (not request.client or request.client.host not in _LOOPBACK
            or request.url.hostname not in _LOOPBACK
            or request.headers.get('X-Dango-Proxy-Sync') != '1'
            or (origin is not None and origin != str(request.base_url).rstrip('/'))
            or request.headers.get('sec-fetch-site') == 'cross-site'):
        raise HTTPException(403, '请从本机 Dango 代理页面手动同步')
    if request.headers.get('content-type', '').split(';')[0].strip().lower() != 'application/json':
        raise HTTPException(415, '同步请求必须是 JSON')
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > _MAX_BYTES:
            raise HTTPException(413, '代理内容过大，请分批同步，每次最多 100 条')
    try:
        data = json.loads(body)
    except (ValueError, UnicodeError):
        raise HTTPException(400, '代理同步请求格式不正确') from None
    proxies = data.get('proxies') if isinstance(data, dict) else None
    if (not isinstance(data, dict) or set(data) != {'proxies'}
            or not isinstance(proxies, list) or not 1 <= len(proxies) <= _MAX_PROXIES):
        raise HTTPException(400, '请提交 1–100 条已保存代理；不能修改 Roxy 接入地址')
    try:
        result = await run_in_threadpool(sync_proxies, proxies)
    except RoxySyncError as exc:
        raise HTTPException(502, str(exc)) from None
    return JSONResponse(result, headers={'Cache-Control': 'no-store'})
