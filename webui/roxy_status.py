"""Read-only local API connectivity; never probes exits or opens profiles."""
from datetime import datetime, timezone
from urllib.parse import urlsplit

import requests
from fastapi import APIRouter, HTTPException, Request, Response

from .roxy_config import RoxyConfigurationError, require_roxy_configuration

router = APIRouter()
_LOOPBACK = {'127.0.0.1', 'localhost', '::1'}


def read_roxy_connection() -> dict:
    result = {
        'configured': False, 'connected': False, 'status': 'not_configured',
        'api_base': None, 'proxy_total': None,
        'checked_at': datetime.now(timezone.utc).isoformat(),
    }
    try:
        config = require_roxy_configuration()
        url = urlsplit(config.api_base)
        if (url.scheme != 'http' or url.hostname not in _LOOPBACK
                or url.username is not None or url.password is not None
                or url.path not in ('', '/') or url.query or url.fragment
                or not url.port or not 1 <= url.port <= 65535):
            return result
        host = '[::1]' if url.hostname == '::1' else '127.0.0.1'
        base = f'http://{host}:{url.port}'
    except (RoxyConfigurationError, ValueError, OSError):
        return result
    result.update(configured=True, api_base=base, status='offline')
    try:
        with requests.Session() as session:
            session.trust_env = False
            response = session.get(
                base + '/proxy/list',
                params={'workspaceId': str(config.workspace_id), 'page_index': 1, 'page_size': 1},
                headers={'Accept': 'application/json'},
                timeout=(2, 3), allow_redirects=False,
            )
            if response.status_code in (401, 403):
                result['status'] = 'auth_required'
                return result
            if response.status_code == 429:
                result['status'] = 'rate_limited'
                return result
            if response.status_code != 200:
                result['status'] = 'api_error'
                return result
            payload = response.json()
            if not isinstance(payload, dict):
                result['status'] = 'api_error'
                return result
            code = payload.get('code')
            if code in (401, 403, '401', '403'):
                result['status'] = 'auth_required'
                return result
            data = payload.get('data')
            if (type(code) not in (int, str) or code not in (0, '0')
                    or not isinstance(data, dict) or not isinstance(data.get('rows'), list)
                    or type(data.get('total')) is not int or data['total'] < 0):
                result['status'] = 'api_error'
                return result
            result.update(connected=True, status='connected', proxy_total=data['total'])
    except (ValueError, TypeError):
        result['status'] = 'api_error'
    except requests.RequestException:
        result['status'] = 'offline'
    return result


@router.get('/api/roxy/connection')
def roxy_connection(request: Request, response: Response):
    if request.client is None or request.client.host not in _LOOPBACK:
        raise HTTPException(403, '仅允许本机查看 Roxy 接入状态')
    origin = request.headers.get('origin')
    if (request.headers.get('sec-fetch-site') == 'cross-site'
            or (origin and origin.rstrip('/') != str(request.base_url).rstrip('/'))):
        raise HTTPException(403, '仅允许本机同源页面查看 Roxy 接入状态')
    response.headers['Cache-Control'] = 'no-store'
    return read_roxy_connection()
