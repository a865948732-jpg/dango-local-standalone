"""Restricted stdin transport for the isolated upstream Sentinel runtime."""
from __future__ import annotations

import json
import os
import sys
from urllib.parse import urlsplit


def read_broker_response(connection):
    if not connection.poll(30):
        raise TimeoutError('sentinel broker response unavailable')
    raw = connection.recv_bytes(4096)
    result = json.loads(raw.decode('utf-8'))
    if isinstance(result, dict) and result.get('chunked') is True:
        size = result.get('size')
        if type(size) is not int or not 0 < size <= 1048576:
            raise ValueError('sentinel broker response too large')
        body = bytearray()
        while len(body) < size:
            connection.send_bytes(b'next')
            if not connection.poll(30):
                raise TimeoutError('sentinel broker response unavailable')
            part = connection.recv_bytes(min(4096, size-len(body)))
            if not part:
                raise ValueError('sentinel broker response incomplete')
            body.extend(part)
        result = json.loads(body.decode('utf-8'))
    return result


def validate_request(payload):
    url = payload.get('url')
    if not isinstance(url, str) or len(url) > 4096:
        raise ValueError('unsupported sentinel destination')
    parts = urlsplit(url)
    if (parts.scheme != 'https' or parts.port not in (None, 443)
            or parts.username is not None or parts.password is not None
            or parts.fragment or parts.hostname not in {'chatgpt.com', 'sentinel.openai.com'}
            or not parts.path.startswith('/backend-api/sentinel/')
            or any(ord(char) <= 32 or char == '\\' for char in url)):
        raise ValueError('unsupported sentinel destination')
    method = payload.get('method', 'GET')
    if method not in {'GET', 'POST'}:
        raise ValueError('unsupported sentinel method')
    proxy = payload.get('proxy')
    if not isinstance(proxy, str) or not proxy:
        raise ValueError('sentinel proxy required')
    headers = payload.get('headers')
    if not isinstance(headers, dict):
        raise ValueError('invalid sentinel headers')
    safe_headers = {}
    for key, value in headers.items():
        if not isinstance(key, str) or not isinstance(value, str) or '\r' in value or '\n' in value:
            raise ValueError('invalid sentinel headers')
        if key.lower() in {'authorization', 'proxy-authorization', 'host'}:
            continue
        if key.lower() == 'cookie' and parts.hostname != 'chatgpt.com':
            continue
        safe_headers[key] = value
    return url, method, proxy, safe_headers


def main():
    try:
        payload = json.loads(sys.stdin.buffer.read(65537).decode('utf-8'))
        url, method, proxy, headers = validate_request(payload)
        broker = os.environ.get('REFINE_SENTINEL_PIPE')
        if broker:
            from multiprocessing.connection import Client
            key = bytes.fromhex(os.environ.get('REFINE_SENTINEL_PIPE_KEY', ''))
            if len(key) != 32:
                raise ValueError('sentinel broker unavailable')
            with Client(broker, family='AF_PIPE' if os.name == 'nt' else 'AF_UNIX',
                        authkey=key) as connection:
                connection.send_bytes(json.dumps(payload).encode('utf-8'))
                result = read_broker_response(connection)
            if not isinstance(result, dict) or result.get('ok') is not True:
                raise ValueError('sentinel transport failed')
            sys.stdout.write(json.dumps({'status': result['status'], 'body': result['body']}))
            return
        from curl_cffi import requests
        response = requests.request(
            method=method, url=url, headers=headers, data=payload.get('body'),
            proxy=proxy, timeout=25, impersonate='chrome136',
            verify=True, allow_redirects=False,
        )
        if response.status_code < 200 or response.status_code >= 300:
            raise ValueError('sentinel response rejected')
        if len(response.content) > 262144:
            raise ValueError('sentinel response too large')
        sys.stdout.write(json.dumps({'status': response.status_code, 'body': response.text}))
    except Exception:
        sys.stderr.write('sentinel transport failed')
        raise SystemExit(1) from None


if __name__ == '__main__':
    main()
