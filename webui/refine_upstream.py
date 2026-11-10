"""Pinned UPI extraction with application-owned transport and delivery checks."""
from __future__ import annotations

import base64
from contextlib import contextmanager
from contextvars import ContextVar, copy_context
from decimal import Decimal, InvalidOperation
from html.parser import HTMLParser
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import subprocess
import tempfile
import threading
import time
import uuid
from urllib.parse import parse_qs, urlsplit
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
UPSTREAM = ROOT / 'third_party' / 'upi-zero-link'
REVISION = '0768b1cb564e830aad7aa7403acf44010a72345d'
PROJECT = {
    'name': 'upi-zero-link',
    'repo_url': 'https://github.com/wangshen233/upi-zero-link',
    'revision': REVISION,
    'license': 'MIT',
}
STAGES = frozenset({
    'checkout', 'stripe_init', 'tax_update', 'payment_method',
    'stripe_confirm', 'approve', 'instructions', 'reconnect',
})
_SESSIONS = ContextVar('refine_sessions', default=None)
_EVIDENCE = ContextVar('refine_evidence', default=None)
_POSTS = ContextVar('refine_posts', default=None)
_STRIPE_PROXY = ContextVar('refine_stripe_proxy', default=None)
_CHATGPT_PROXY = ContextVar('refine_chatgpt_proxy', default=None)
_REQUEST_GATE = ContextVar('refine_request_gate', default=None)
_ABORT_TRANSPORT = ContextVar('refine_abort_transport', default=False)
_LOAD_LOCK = threading.Lock()
_PROTOCOL = None
_BROKER_READ_TIMEOUT = 5
_BROKER_SHUTDOWN_TIMEOUT = 30


class _TransportAbort(BaseException):
    """Cross upstream catch/retry blocks, then restore the original exception."""
    def __init__(self, error):
        self.error = error


def project_status() -> dict:
    missing = [name for name in ('requests', 'curl_cffi')
               if importlib.util.find_spec(name) is None]
    if not shutil.which('node'):
        missing.append('node')
    if not (UPSTREAM / 'upi_zero_link' / 'protocol.py').is_file():
        missing.append('upi-zero-link')
    return {'project': dict(PROJECT), 'available': not missing,
            'missing_dependencies': missing}


def stripe_url(value: object, *, qr: bool = False) -> bool:
    if not isinstance(value, str) or not value or len(value) > 4096:
        return False
    if any(ord(char) <= 32 or char == '\\' for char in value):
        return False
    try:
        parsed = urlsplit(value)
        host = 'qr.stripe.com' if qr else 'payments.stripe.com'
        return bool(parsed.scheme == 'https' and parsed.hostname == host
                    and parsed.port in (None, 443)
                    and parsed.username is None and parsed.password is None
                    and not parsed.fragment
                    and (parsed.path.startswith('/upi/instructions/')
                         if not qr else parsed.path.startswith('/'))
                    and (len(parsed.path) > len('/upi/instructions/')
                         if not qr else len(parsed.path) > 1))
    except ValueError:
        return False


def verification_evidence(payload: object) -> dict | None:
    if not isinstance(payload, dict):
        return None
    state = payload.get('intent_state')
    if not isinstance(state, str) or state not in {'requires_action', 'processing'}:
        return None
    uri = payload.get('mobile_auth_url') or payload.get('upi_uri')
    if not isinstance(uri, str) or len(uri) > 8192:
        return None
    try:
        parsed = urlsplit(uri)
    except ValueError:
        return None
    if parsed.scheme != 'upi' or parsed.netloc != 'mandate' or parsed.fragment:
        return None
    values = parse_qs(parsed.query, keep_blank_values=True)
    if any(len(values.get(key, [])) != 1 for key in ('fam', 'am', 'cu', 'amrule')):
        return None
    if values['cu'][0] != 'INR' or values['amrule'][0] != 'MAX':
        return None
    try:
        first = Decimal(values['fam'][0])
        ceiling = Decimal(values['am'][0])
        if (not first.is_finite() or not ceiling.is_finite()
                or first not in {Decimal(0), Decimal(1)}
                or not first <= ceiling <= Decimal(1999)):
            return None
    except (InvalidOperation, ValueError):
        return None
    return {'intent_state': state, 'first_amount': format(first, '.2f'),
            'authorization_limit': format(ceiling, '.2f')}


class _PayloadParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.values = []

    def handle_starttag(self, tag, attrs):
        if tag == 'meta':
            names = [name for name, _ in attrs]
            if len(names) != len(set(names)):
                # Duplicate HTML attributes disagree with DOM first-value semantics.
                self.values.extend(['', ''])
                return
            values = dict(attrs)
            if values.get('id') == 'payload':
                self.values.append(values.get('data-message', ''))


def decode_instruction_page(text: str) -> dict | None:
    if not isinstance(text, str) or len(text) > 262144:
        return None
    parser = _PayloadParser()
    parser.feed(text)
    if len(parser.values) != 1:
        return None

    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate payload field')
            result[key] = value
        return result

    try:
        encoded = parser.values[0]
        raw = base64.b64decode(encoded + '=' * (-len(encoded) % 4),
                              altchars=b'-_', validate=True)
        result = json.loads(raw.decode('utf-8'), object_pairs_hook=unique_pairs)
        return result if isinstance(result, dict) else None
    except (ValueError, UnicodeError):
        return None


def normalize_result(result: object, *, now: float | None = None) -> dict | None:
    if not isinstance(result, dict) or result.get('ok') is not True:
        return None
    if type(result.get('due')) is not int or result['due'] != 0:
        return None
    if not stripe_url(result.get('url')):
        return None
    qr = result.get('qr_png') or ''
    if qr and not stripe_url(qr, qr=True):
        return None
    try:
        expiry = int(str(result.get('expires_at') or ''))
    except (ValueError, TypeError):
        return None
    current = time.time() if now is None else now
    if not current < expiry <= current + 86400:
        return None
    proof = result.get('verification')
    if not isinstance(proof, dict):
        return None
    try:
        verified = verification_evidence({
            'intent_state': proof.get('intent_state'),
            'upi_uri': 'upi://mandate?cu=INR&amrule=MAX&fam=' +
                str(proof.get('first_amount', '')) + '&am=' +
                str(proof.get('authorization_limit', '')),
        })
    except (ValueError, InvalidOperation):
        return None
    if not verified:
        return None
    return {'url': result['url'], 'qr_png': qr, 'expires_at': expiry,
            'seconds_left': max(0, int(expiry - current)), 'due': 0,
            'verification': verified}


def _secure_request(session, method, url, **kwargs):
    if (not isinstance(url, str) or len(url) > 8192
            or any(ord(char) <= 32 or ord(char) >= 127 or char == '\\' for char in url)):
        raise ValueError('unsupported upstream destination')
    parsed = urlsplit(url)
    if (parsed.scheme != 'https' or parsed.username is not None
            or parsed.password is not None or parsed.port not in (None, 443)
            or parsed.fragment or parsed.hostname not in {
                'chatgpt.com', 'api.stripe.com', 'payments.stripe.com',
                'sentinel.openai.com', 'auth.openai.com',
            }):
        raise ValueError('unsupported upstream destination')
    if kwargs.get('verify') is False:
        raise ValueError('certificate verification required')
    if parsed.hostname == 'api.stripe.com' and parsed.path.endswith('/confirm'):
        data = kwargs.get('data')
        destination = data.get('return_url', '') if isinstance(data, dict) else ''
        if (not isinstance(destination, str) or len(destination) > 4096
                or any(ord(char) <= 32 or char == '\\' for char in destination)):
            raise ValueError('unsupported checkout return destination')
        target = urlsplit(destination)
        if (target.scheme != 'https' or target.hostname not in {
                'chatgpt.com', 'checkout.stripe.com', 'pay.openai.com',
            } or target.username is not None or target.password is not None
                or target.port not in (None, 443)):
            raise ValueError('unsupported checkout return destination')
    kwargs['verify'] = True
    kwargs['allow_redirects'] = False
    if str(method).upper() == 'POST':
        attempted = _POSTS.get()
        if attempted is not None:
            if url in attempted:
                raise ValueError('upstream POST replay blocked')
            attempted.add(url)
    try:
        gate = _REQUEST_GATE.get()
        if gate is not None:
            gate(str(method).upper(), url)
        return session.request(method, url, **kwargs)
    except Exception as error:
        if _ABORT_TRANSPORT.get():
            raise _TransportAbort(error) from None
        raise


def scan_instruction(payload):
    if not isinstance(payload, dict):
        return {}
    intent = payload.get('setup_intent')
    action = intent.get('next_action') if isinstance(intent, dict) else None
    item = action.get('upi_handle_redirect_or_display_qr_code') if isinstance(action, dict) else None
    if not isinstance(item, dict):
        return {}
    qr = item.get('qr_code')
    if not isinstance(qr, dict) or not stripe_url(item.get('hosted_instructions_url')):
        return {}
    expiry = qr.get('expires_at')
    if isinstance(expiry, bool) or not str(expiry or '').isdigit():
        return {}
    image = qr.get('image_url_png') or ''
    if image and not stripe_url(image, qr=True):
        return {}
    return {'hosted_instructions_url': item['hosted_instructions_url'],
            'image_url_png': image, 'expires_at': expiry}


def _dispatch_request(session, method, url, **kwargs):
    # Session.request owns the transport checks; the facade must not count a POST twice.
    return session.request(method, url, **kwargs)


def _controlled_sentinel_run(command, **kwargs):
    assets = UPSTREAM / 'upi_zero_link' / '_vendor' / 'sentinel_assets'
    if len(command) != 2 or Path(command[1]).resolve() != (assets / 'sentinel_bridge.js').resolve():
        raise ValueError('unsupported sentinel program')
    node = shutil.which('node')
    if not node:
        raise ValueError('sentinel runtime unavailable')
    environment = {key: value for key, value in os.environ.items()
                   if key.upper() in {'PATH', 'SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP'}}
    environment.update(PYTHON_BIN=sys.executable,
                       REFINE_FETCH_HELPER=str(Path(__file__).with_name('refine_sentinel_fetch.py')))
    with _sentinel_broker(environment) as failures:
        try:
            process = subprocess.run(
                [node, str(Path(__file__).with_name('refine_sentinel.cjs')),
                 str(assets / 'sentinel_bridge.js')],
                input=kwargs.get('input'), capture_output=True, timeout=65,
                cwd=str(assets), env=environment, check=False,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
            )
        finally:
            if failures:
                raise _TransportAbort(failures[0]) from None
        return process


def _sentinel_transport(payload):
    from .refine_sentinel_fetch import validate_request
    from curl_cffi import requests
    url, method, proxy, headers = validate_request(payload)
    if proxy != _CHATGPT_PROXY.get():
        raise ValueError('sentinel route mismatch')
    session = requests.Session(impersonate='chrome136')
    try:
        session.proxies = {'http': proxy, 'https': proxy}
        response = _secure_request(session, method, url, headers=headers,
                                   data=payload.get('body'), timeout=25)
        if response.status_code < 200 or response.status_code >= 300:
            raise ValueError('sentinel response rejected')
        if len(response.content) > 262144:
            raise ValueError('sentinel response too large')
        return {'ok': True, 'status': response.status_code, 'body': response.text}
    finally:
        session.close()


@contextmanager
def _sentinel_broker(environment):
    # Keep child fetches inside this task's gate and replay context.
    failures = []
    if not _ABORT_TRANSPORT.get():
        yield failures
        return
    from multiprocessing import AuthenticationError
    from multiprocessing.connection import Client, Listener, answer_challenge, deliver_challenge
    temporary = tempfile.TemporaryDirectory(prefix='refine-sentinel-') if os.name != 'nt' else None
    address = ('\\\\.\\pipe\\refine-sentinel-' + uuid.uuid4().hex if os.name == 'nt'
               else str(Path(temporary.name) / 'transport.sock'))
    family = 'AF_PIPE' if os.name == 'nt' else 'AF_UNIX'
    key = os.urandom(32)
    listener = Listener(address, family=family)
    environment.update(REFINE_SENTINEL_PIPE=address, REFINE_SENTINEL_PIPE_KEY=key.hex())
    stopped = threading.Event()

    class TimedRead:
        def __init__(self, connection):
            self.connection = connection

        def send_bytes(self, value):
            self.connection.send_bytes(value)

        def recv_bytes(self, limit):
            if not self.connection.poll(_BROKER_READ_TIMEOUT):
                raise TimeoutError('sentinel child stalled')
            return self.connection.recv_bytes(limit)

    def send_result(connection, result):
        raw = json.dumps(result).encode('utf-8')
        if len(raw) > 1048576:
            raise ValueError('sentinel broker response too large')
        if len(raw) <= 4096:
            connection.send_bytes(raw)
            return
        # Pull-sized messages avoid blocking a full pipe when a child stops reading.
        connection.send_bytes(json.dumps({'chunked': True, 'size': len(raw)}).encode())
        for offset in range(0, len(raw), 4096):
            if TimedRead(connection).recv_bytes(16) != b'next':
                raise ValueError('sentinel child protocol rejected')
            connection.send_bytes(raw[offset:offset+4096])

    def serve():
        while not stopped.is_set():
            try:
                connection = listener.accept()
            except (OSError, EOFError):
                return
            with connection:
                if stopped.is_set():
                    return
                timed = TimedRead(connection)
                try:
                    deliver_challenge(timed, key)
                    answer_challenge(timed, key)
                except (AuthenticationError, OSError, EOFError, TimeoutError):
                    continue
                try:
                    raw = timed.recv_bytes(65536)
                    payload = json.loads(raw.decode('utf-8'))
                    if failures:
                        result = {'ok': False}
                    else:
                        result = _sentinel_transport(payload)
                except _TransportAbort as aborted:
                    failures.append(aborted.error)
                    result = {'ok': False}
                except Exception as error:
                    failures.append(error)
                    result = {'ok': False}
                try:
                    send_result(connection, result)
                except (OSError, EOFError, TimeoutError, ValueError) as error:
                    failures.append(error)

    context = copy_context()
    worker = threading.Thread(target=context.run, args=(serve,), daemon=True,
                              name='upi-sentinel-transport')
    worker.start()
    try:
        yield failures
    finally:
        stopped.set()

        def wake_listener():
            try:
                with Client(address, family=family):
                    pass
            except (OSError, EOFError):
                pass

        wake = threading.Thread(target=wake_listener, daemon=True, name='upi-sentinel-close')
        wake.start()
        try:
            worker.join(timeout=_BROKER_SHUTDOWN_TIMEOUT)
            if worker.is_alive():
                raise _TransportAbort(TimeoutError('sentinel broker shutdown incomplete'))
        finally:
            listener.close()
            wake.join(timeout=1)
            if temporary is not None:
                temporary.cleanup()
            environment.pop('REFINE_SENTINEL_PIPE', None)
            environment.pop('REFINE_SENTINEL_PIPE_KEY', None)


def _load_protocol():
    global _PROTOCOL
    with _LOAD_LOCK:
        if _PROTOCOL is not None:
            return _PROTOCOL
        name = '_dango_refine_upi'
        spec = importlib.util.spec_from_file_location(
            name, UPSTREAM / 'upi_zero_link' / '__init__.py',
            submodule_search_locations=[str(UPSTREAM / 'upi_zero_link')],
        )
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        try:
            spec.loader.exec_module(module)
        except Exception:
            for key in list(sys.modules):
                if key == name or key.startswith(name + '.'):
                    sys.modules.pop(key, None)
            raise
        protocol = sys.modules[name + '.protocol']
        http = sys.modules[name + '._vendor.http']
        original_factory = http.make_session

        def secure_factory(*args, **kwargs):
            session = original_factory(*args, **kwargs)
            original_request = session.request

            class Transport:
                request = staticmethod(original_request)

            session.request = lambda method, url, **options: _secure_request(
                Transport, method, url, **options,
            )
            handles = _SESSIONS.get()
            if handles is not None:
                handles.append(session)
            return session

        def stripe_factory(proxy, **kwargs):
            route = _STRIPE_PROXY.get()
            return secure_factory(proxy if route is None else route, **kwargs)

        def verify_url(url, request_get=None, *, proxy='', **kwargs):
            if not stripe_url(url):
                return False, 'link_unverified'
            # The instruction request has its own session without account headers.
            session = stripe_factory(proxy)
            response = session.get(url, timeout=25)
            if response.status_code != 200:
                return False, 'link_unverified'
            evidence = verification_evidence(decode_instruction_page(response.text))
            if evidence is None:
                return False, 'link_unverified'
            target = _EVIDENCE.get()
            if target is not None:
                target.clear()
                target.update(evidence)
            return True, 'verified'

        http.make_session = secure_factory
        http.request = _dispatch_request
        protocol.make_session = stripe_factory
        protocol.request_http = _dispatch_request
        protocol.verify.verify_url = verify_url
        protocol._scan = scan_instruction
        protocol.APPROVE_ATTEMPTS = 1
        sentinel = sys.modules[name + '._vendor.sentinel_token']
        sentinel.os = SimpleNamespace(environ={})
        attestation = sys.modules[name + '._vendor.attestation']
        attestation.os = SimpleNamespace(environ={})
        sentinel.subprocess = SimpleNamespace(
            run=_controlled_sentinel_run, TimeoutExpired=subprocess.TimeoutExpired,
        )
        # A failed proof does not authorize another proxy scheme or a proof-free checkout.
        risk = sys.modules[name + '._vendor.risk']
        risk._alternate_proxy_scheme = lambda proxy: ''
        original_risk_headers = protocol.checkout_risk_headers

        def checked_risk_headers(*args, **kwargs):
            headers = original_risk_headers(*args, **kwargs)
            if not headers.get('openai-sentinel-token'):
                raise ValueError('sentinel proof unavailable')
            return headers

        protocol.checkout_risk_headers = checked_risk_headers
        _PROTOCOL = protocol
        return protocol


def extract_one(account: dict, proxy: str, emit, *, stripe_proxy=None, request_gate=None) -> dict:
    from .refine_input import validate_proxy
    proxy = validate_proxy(proxy)
    stripe_proxy = proxy if stripe_proxy is None else validate_proxy(stripe_proxy)
    protocol = _load_protocol()
    handles = []
    proof = {}
    handles_token = _SESSIONS.set(handles)
    proof_token = _EVIDENCE.set(proof)
    posts_token = _POSTS.set(set())
    stripe_token = _STRIPE_PROXY.set(stripe_proxy)
    chatgpt_token = _CHATGPT_PROXY.set(proxy)
    gate_token = _REQUEST_GATE.set(request_gate)
    abort_token = _ABORT_TRANSPORT.set(True)
    try:
        try:
            result = protocol.extract(account, proxy, tries=1, emit=emit)
        except _TransportAbort as stopped:
            raise stopped.error from None
        if isinstance(result, dict) and result.get('ok') is True:
            return {**result, 'verification': dict(proof)}
        return result
    finally:
        _SESSIONS.reset(handles_token)
        _EVIDENCE.reset(proof_token)
        _POSTS.reset(posts_token)
        _STRIPE_PROXY.reset(stripe_token)
        _CHATGPT_PROXY.reset(chatgpt_token)
        _REQUEST_GATE.reset(gate_token)
        _ABORT_TRANSPORT.reset(abort_token)
        for session in handles:
            try:
                session.close()
            except Exception:
                pass
