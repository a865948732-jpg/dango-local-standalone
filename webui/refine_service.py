"""Workspace-owned jobs with durable, credential-free request reservations."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from copy import deepcopy
import json
import inspect
import os
from pathlib import Path
import re
import sqlite3
import threading
import time
from urllib.parse import urlsplit
import uuid

from . import db, qualification_store
from .refine_input import InputError, parse_access_token, validate_payload as _validate_payload, validate_batch
from .refine_ledger import Ledger, LedgerError, STATUSES
from .refine_upstream import STAGES, extract_one, normalize_result, project_status
from .qualification_status import qualification_category

ERROR_MESSAGES = {
    'no_access_token': '账号没有可用的 Access Token。',
    'qualification_required': '账号没有最新的 UPI 支付资格合格结果，请先完成检测并确认金额为 0 元。',
    'nonzero_due': '结账金额不是零，已停止提取。',
    'upi_unavailable': '本次结账不支持 UPI。',
    'tax_unverified': '无法确认税区与应付金额，已停止提取。',
    'declined': 'Stripe 拒绝建立委托；请确认账号的外部状态。',
    'link_unverified': '链接核验未通过，未交付支付链接。',
    'no_link': '上游没有返回可核验的 UPI 链接。',
    'network_error': '上游通信失败；没有自动重新执行提取。',
    'upstream_error': '提取未完成；没有自动重新执行提取。',
    'unknown': '发生未分类异常；没有自动重新执行提取。',
    'parse_error': '上游数据解析失败；没有自动重新执行提取。',
    'result_unverified': '金额、链接、有效期或委托证据不完整，未交付结果。',
    'service_interrupted': '服务中断，外部状态待核对；没有自动重新执行。',
    'cancelled': '已停止后续请求；已发出的外部请求不会被撤销。',
}


class RefineError(Exception):
    def __init__(self, code: str, message: str, status: int = 400):
        super().__init__(message)
        self.code, self.message, self.status = code, message, status


class RefineCancelled(Exception):
    pass


def _workspace(value: object) -> str:
    if value not in {'1', '2'}:
        raise RefineError('invalid_workspace', '工作区无效。')
    return str(value)


def validate_payload(payload):
    try:
        return _validate_payload(payload)
    except InputError as error:
        raise RefineError(error.code, error.message, error.status) from None


def _is_upi_qualified(row):
    """Require the eligible evidence to come from a UPI region specifically."""
    if qualification_category(row) != 'eligible':
        return False
    regions = row.get('regions') if isinstance(row, dict) else None
    return any(
        str(region.get('channel') or '').lower() == 'upi'
        and qualification_category({**row, 'regions': [region]}) == 'eligible'
        for region in regions if isinstance(region, dict)
    ) if isinstance(regions, list) else False


def _diagnostics(error=None, code=None):
    category, exception_type, location, http_status = 'unknown', None, None, None
    match = re.fullmatch(r'[a-z_]+_http_([45][0-9]{2})', code or '')
    if match:
        category, http_status = 'http', int(match.group(1))
    elif code in {'nonzero_due', 'upi_unavailable', 'tax_unverified', 'declined',
                  'link_unverified', 'no_link', 'result_unverified'}:
        category = 'verification'
    elif code == 'cancelled':
        category = 'cancelled'
    elif error is not None:
        name = type(error).__name__
        allowed = {'TimeoutError', 'ConnectionError', 'OSError', 'ValueError', 'TypeError',
                   'KeyError', 'IndexError', 'JSONDecodeError', 'RuntimeError', 'Exception',
                   'ReadTimeout', 'ConnectTimeout', 'Timeout', 'ProxyError', 'SSLError',
                   'RequestsError', 'RequestException', 'CurlError', 'RefineCancelled', 'LedgerError'}
        exception_type = name if name in allowed else 'Exception'
        if isinstance(error, (TimeoutError, ConnectionError, OSError)) or name in {
                'ReadTimeout', 'ConnectTimeout', 'Timeout', 'ProxyError', 'SSLError',
                'RequestsError', 'RequestException', 'CurlError'}:
            category = 'network'
        elif isinstance(error, (ValueError, TypeError, KeyError, IndexError)):
            category = 'parse'
        trace = error.__traceback__
        while trace:
            file = Path(trace.tb_frame.f_code.co_filename).name
            function = trace.tb_frame.f_code.co_name
            if file in {'refine_service.py', 'refine_upstream.py', 'refine_sentinel_fetch.py',
                        'protocol.py'} and re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*', function):
                location = {'file': file, 'function': function, 'line': trace.tb_lineno}
            trace = trace.tb_next
    return {'category': category, 'exception_type': exception_type,
            'http_status': http_status, 'location': location}


class JobService:
    def __init__(self, *, extractor=extract_one, database_path=db.database_path_for,
                 executor=None, availability=project_status, state_dir=None, key=None):
        self.extractor = extractor
        self.database_path = database_path
        self.availability = availability
        self.executor = executor or ThreadPoolExecutor(max_workers=2, thread_name_prefix='upi-refine')
        self.lock = threading.RLock()
        self.jobs, self.requests = {}, {}
        self._pending, self._draining = {}, set()
        self._state_dir = Path(state_dir or os.environ.get('DANGO_REFINE_STATE_DIR')
                               or Path(__file__).resolve().parent / 'refine-state')
        self._key, self._ledger, self._fault = key, None, False

    def close(self, *, wait=True):
        with self.lock:
            self._fault = True
            for pending in self._pending.values():
                pending[0].clear()
            self._pending.clear()
        shutdown = getattr(self.executor, 'shutdown', None)
        if shutdown is not None:
            shutdown(wait=wait, cancel_futures=True)
        with self.lock:
            if self._ledger is not None:
                self._ledger.close()

    def _unavailable(self):
        self._fault = True
        return RefineError('ledger_unavailable', '任务账本或保护密钥不可用，提交已停用。', 503)

    def _ensure(self):
        if self._fault:
            raise self._unavailable()
        try:
            if self._ledger is None:
                ledger = Ledger(self._state_dir, key=self._key)
                self._ledger = ledger
                for job in ledger.load():
                    job.update(result=None, result_available=False, recovered=True)
                    if job['error'] is not None:
                        job['error']['message'] = ERROR_MESSAGES.get(
                            job['error']['code'], '上游接口拒绝请求；没有自动重新执行。')
                    if job['status'] in {'queued', 'running'}:
                        job.update(status='needs_review', finished_at=time.time(),
                                   error={'code': 'service_interrupted',
                                          'message': ERROR_MESSAGES['service_interrupted'],
                                          'confirm_attempted': job.get('confirm_attempted', False)})
                        ledger.save(job)
                    self.jobs[(job['_workspace'], job['job_id'])] = job
                    self.requests[(job['_workspace'], job['request_id'])] = (
                        job['job_id'], job['_digest'])
            self._ledger.check()
        except LedgerError:
            raise self._unavailable() from None

    def _save(self, job):
        try:
            self._ledger.save(job)
        except LedgerError:
            raise self._unavailable() from None

    def _connection(self, workspace):
        path = Path(self.database_path(_workspace(workspace))).resolve()
        connection = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True)
        connection.execute('PRAGMA query_only=ON')
        return connection

    def _qualified_upi_emails(self, workspace):
        """Return emails with the latest complete UPI/zero-amount evidence."""
        path = Path(self.database_path(_workspace(workspace))).resolve()
        results = qualification_store.latest_results(path)
        return {email for email, row in results.items()
                if isinstance(email, str) and _is_upi_qualified(row)}

    def accounts(self, workspace, *, query='', limit=50, offset=0):
        query = str(query or '')[:254]
        limit, offset = max(1, min(int(limit), 100)), max(0, int(offset))
        qualified = self._qualified_upi_emails(workspace)
        where = ("COALESCE(TRIM(access_token), '')<>'' "
                 "AND LOWER(email) IN (SELECT value FROM json_each(?)) AND email LIKE ?")
        params = (json.dumps(sorted(qualified), ensure_ascii=False), '%' + query + '%')
        with closing(self._connection(workspace)) as connection:
            total = connection.execute('SELECT count(*) FROM registered WHERE ' + where,
                                       params).fetchone()[0]
            rows = connection.execute('SELECT email FROM registered WHERE ' + where +
                ' ORDER BY created_at DESC LIMIT ? OFFSET ?', params + (limit, offset)).fetchall()
        return {'accounts': [{'email': row[0], 'has_access_token': True, 'upi_qualified': True}
                             for row in rows], 'total': total}

    def _account(self, workspace, payload):
        if payload['source'] == 'manual':
            return {'email': payload['email'], 'access_token': payload['access_token']}
        with closing(self._connection(workspace)) as connection:
            row = connection.execute('SELECT email, access_token FROM registered WHERE lower(email)=?',
                                     (payload['email'],)).fetchone()
        if not row or not str(row[1] or '').strip():
            raise RefineError('account_unavailable', '当前工作区账号没有可用的 Access Token。')
        if row[0].strip().lower() not in self._qualified_upi_emails(workspace):
            raise RefineError('qualification_required', ERROR_MESSAGES['qualification_required'])
        try:
            token = parse_access_token(str(row[1]))
        except InputError:
            raise RefineError('invalid_token', '账号的 Access Token 格式无效。') from None
        return {'email': row[0], 'access_token': token}

    def _new_job(self, workspace, payload, account, batch_id):
        return {'job_id': uuid.uuid4().hex, 'request_id': payload['request_id'],
                'batch_id': batch_id, 'email': payload['email'], 'status': 'queued',
                'stage': 'queued', 'last_stage': 'queued', 'stage_durations': {},
                'created_at': time.time(), 'finished_at': None, 'result': None, 'error': None,
                'diagnostics': None, 'confirm_attempted': False, 'external_attempted': False,
                'cancel_requested': False, 'result_available': False, 'recovered': False,
                'hidden': False, 'request_attempts': [], '_workspace': workspace,
                '_digest': self._ledger.fingerprint(payload),
                '_identity': self._ledger.fingerprint(['account', workspace, account['email'].lower()]),
                '_token_digest': self._ledger.fingerprint(['token', account['access_token']]),
                '_manual': payload['source'] == 'manual', '_revision': 0}

    def start(self, workspace, payload):
        workspace, payload = _workspace(workspace), validate_payload(payload)
        with self.lock:
            self._ensure()
            previous = self.requests.get((workspace, payload['request_id']))
            if previous:
                if previous[1] != self._ledger.fingerprint(payload):
                    raise RefineError('request_conflict', '同一请求标识不能用于不同输入。', 409)
                return self.get(workspace, previous[0])
            if any(owner == workspace and job['status'] in {'queued', 'running'}
                   for (owner, _), job in self.jobs.items()):
                raise RefineError('job_active', '当前工作区已有提取任务，请等待结果。', 409)
            return self._admit(workspace, [payload], None)[0]

    def start_batch(self, workspace, payload):
        workspace = _workspace(workspace)
        try:
            batch = validate_batch(payload)
        except InputError as error:
            raise RefineError(error.code, error.message, error.status) from None
        with self.lock:
            self._ensure()
            jobs = self._admit(workspace, batch['items'], batch['batch_id'])
            return {'batch_id': batch['batch_id'], 'jobs': jobs}

    def _admit(self, workspace, payloads, batch_id):
        new, returned, secrets = [], [], []
        try:
            for payload in payloads:
                previous = self.requests.get((workspace, payload['request_id']))
                if previous:
                    job = self.jobs[(workspace, previous[0])]
                    if previous[1] != self._ledger.fingerprint(payload) or job['batch_id'] != batch_id:
                        raise RefineError('request_conflict', '同一请求标识不能用于不同输入或批次。', 409)
                    returned.append(job)
                    continue
                account = self._account(workspace, payload)
                secrets.append(account)
                job = self._new_job(workspace, payload, account, batch_id)
                if any(other['request_id'] == job['request_id'] for other in new):
                    raise RefineError('invalid_batch', '批次包含重复请求标识。')
                if any(other['_token_digest'] == job['_token_digest']
                       or other['_identity'] == job['_identity'] for other in new):
                    raise RefineError('duplicate_account', '批次包含重复账号。')
                if any(owner == workspace and old['status'] in {'queued', 'running'} and
                       (old['_token_digest'] == job['_token_digest'] or old['_identity'] == job['_identity'])
                       for (owner, _), old in self.jobs.items()):
                    raise RefineError('duplicate_account', '该账号已有未完成任务。', 409)
                new.append(job)
                returned.append(job)
            if not new:
                return [self.get(workspace, job['job_id']) for job in returned]
            workspace_jobs = [job for (owner, _), job in self.jobs.items() if owner == workspace]
            if any(job['status'] == 'needs_review' for job in workspace_jobs):
                raise RefineError('needs_review', '当前工作区存在待核对任务，提交已停用。', 409)
            if workspace not in self._draining and any(job['status'] == 'running' for job in workspace_jobs):
                raise RefineError('needs_review', '任务执行中断，当前工作区需要核对。', 409)
            if len(workspace_jobs) + len(new) > 100:
                raise RefineError('job_limit', '本地任务保护记录达到上限，提交已停用。', 409)
            if sum(job['status'] in {'queued', 'running'} for job in workspace_jobs) + len(new) > 10:
                raise RefineError('queue_full', '当前工作区待处理任务不能超过 10 项。', 409)
            if batch_id and sum(job['batch_id'] == batch_id for job in workspace_jobs) + len(new) > 10:
                raise RefineError('batch_limit', '每批最多 10 个唯一任务。')
            if not self.availability()['available']:
                raise RefineError('dependencies_missing', '提炼依赖尚未就绪。', 503)
            try:
                self._ledger.reserve(new)
            except LedgerError as error:
                if str(error) == 'workspace_needs_review':
                    raise RefineError('needs_review', '当前工作区存在待核对任务。', 409) from None
                if str(error) == 'queue_full':
                    raise RefineError('queue_full', '当前工作区待处理任务不能超过 10 项。', 409) from None
                raise self._unavailable() from None
            for job, account in zip(new, secrets):
                job_key = (workspace, job['job_id'])
                self.jobs[job_key] = job
                self.requests[(workspace, job['request_id'])] = (job['job_id'], job['_digest'])
                payload = next(item for item in payloads if item['request_id'] == job['request_id'])
                self._pending[job_key] = (account, payload['proxy'], payload['stripe_proxy'])
            secrets = []
            if workspace not in self._draining:
                self._draining.add(workspace)
                try:
                    self.executor.submit(self._drain, workspace)
                except Exception:
                    self._draining.discard(workspace)
                    for job in new:
                        pending = self._pending.pop((workspace, job['job_id']), None)
                        if pending:
                            pending[0].clear()
                        job.update(status='failed', finished_at=time.time(),
                            error={'code': 'job_start_failed', 'message': '无法启动本地任务。',
                                   'confirm_attempted': False})
                        self._save(job)
                    raise RefineError('job_start_failed', '无法启动提取任务。', 503) from None
            return [self.get(workspace, job['job_id']) for job in returned]
        finally:
            for account in secrets:
                account.clear()

    def _drain(self, workspace):
        try:
            while True:
                with self.lock:
                    self._ensure()
                    if any(owner == workspace and job['status'] == 'needs_review'
                           for (owner, _), job in self.jobs.items()):
                        for (owner, job_id), job in self.jobs.items():
                            if owner == workspace and job['status'] == 'queued':
                                job.update(status='cancelled', finished_at=time.time(),
                                    error={'code': 'cancelled', 'message': '同批存在待核对任务，后续任务已停止。',
                                           'confirm_attempted': False})
                                self._save(job)
                                pending = self._pending.pop((owner, job_id), None)
                                if pending:
                                    pending[0].clear()
                        return
                    selected = next((job_id for (owner, job_id), job in self.jobs.items()
                                     if owner == workspace and job['status'] == 'queued'), None)
                    if selected is None:
                        return
                    pending = self._pending.pop((workspace, selected))
                self._run(workspace, selected, *pending)
        except RefineError:
            with self.lock:
                for job_key in list(self._pending):
                    if job_key[0] == workspace:
                        self._pending.pop(job_key)[0].clear()
        finally:
            with self.lock:
                self._draining.discard(workspace)
                records = [job for (owner, _), job in self.jobs.items() if owner == workspace]
                if (not self._fault and any(job['status'] == 'queued' for job in records)
                        and not any(job['status'] in {'running', 'needs_review'} for job in records)):
                    self._draining.add(workspace)
                    try:
                        self.executor.submit(self._drain, workspace)
                    except Exception:
                        self._draining.discard(workspace)
                        for job in records:
                            if job['status'] == 'queued':
                                pending = self._pending.pop((workspace, job['job_id']), None)
                                if pending:
                                    pending[0].clear()
                                job.update(status='failed', finished_at=time.time(),
                                    error={'code': 'job_start_failed', 'message': '无法启动本地任务。',
                                           'confirm_attempted': False})
                                self._save(job)

    def _run(self, workspace, job_id, account, proxy, stripe_proxy):
        stage_started = time.monotonic()
        try:
            with self.lock:
                job = self.jobs[(workspace, job_id)]
                if job['status'] != 'queued' or job['cancel_requested']:
                    account.clear()
                    return
                job['status'] = 'running'
                self._save(job)
        except Exception:
            account.clear()
            raise

        def emit(message):
            nonlocal stage_started
            if not isinstance(message, str) or not message.startswith('stage '):
                return
            stage = message[6:]
            if stage not in STAGES or stage == 'reconnect':
                return
            with self.lock:
                self._ensure()
                if job['cancel_requested']:
                    raise RefineCancelled()
                now = time.monotonic()
                previous = job['last_stage']
                job['stage_durations'][previous] = job['stage_durations'].get(previous, 0) + max(0, now-stage_started)
                job.update(stage=stage, last_stage=stage)
                stage_started = now
                self._save(job)

        def gate(method, url):
            with self.lock:
                self._ensure()
                if job['cancel_requested']:
                    raise RefineCancelled()
                if str(method).upper() == 'POST':
                    stage = job['last_stage']
                    target = urlsplit(url)
                    confirm = target.hostname == 'api.stripe.com' and target.path.endswith('/confirm')
                    if confirm and job['confirm_attempted']:
                        raise RefineError('duplicate_confirm', '确认尝试已登记，禁止重复执行。', 409)
                    if len(job['request_attempts']) >= 32:
                        raise RefineError('request_limit', '请求次数超过保护上限。', 409)
                    job['request_attempts'].append({'stage': stage, 'method': 'POST'})
                    job['external_attempted'] = True
                    if confirm:
                        job['confirm_attempted'] = True
                    self._save(job)

        normalized, code, diagnostic = None, 'upstream_error', None
        try:
            parameters = inspect.signature(self.extractor).parameters
            supports_kwargs = any(item.kind == inspect.Parameter.VAR_KEYWORD for item in parameters.values())
            kwargs = {name: value for name, value in {'stripe_proxy': stripe_proxy, 'request_gate': gate}.items()
                      if name in parameters or supports_kwargs}
            result = self.extractor(account, proxy, emit, **kwargs)
            normalized = normalize_result(result)
            if normalized is None:
                raw_code = result.get('error') if isinstance(result, dict) else None
                if isinstance(raw_code, str) and (raw_code in ERROR_MESSAGES or re.fullmatch(
                        r'(checkout|stripe_init|tax_update|payment_method|stripe_confirm|approve|instructions)_http_[45][0-9]{2}', raw_code)):
                    code = raw_code
                elif isinstance(result, dict) and result.get('ok') is True:
                    code = 'result_unverified'
            diagnostic = _diagnostics(code=code)
        except RefineCancelled as error:
            code, diagnostic = 'cancelled', _diagnostics(error, 'cancelled')
        except Exception as error:
            diagnostic = _diagnostics(error)
            code = {'network': 'network_error', 'parse': 'parse_error'}.get(diagnostic['category'], 'unknown')
            if isinstance(error, RefineError) and error.code == 'ledger_unavailable':
                return
        finally:
            account.clear()
            proxy = stripe_proxy = ''
        with self.lock:
            job['stage_durations'][job['last_stage']] = job['stage_durations'].get(job['last_stage'], 0) + max(0, time.monotonic()-stage_started)
            job['finished_at'], job['diagnostics'] = time.time(), diagnostic
            if normalized is not None:
                job.update(status='completed', stage='completed', result=normalized, result_available=True)
            else:
                uncertain = (job['confirm_attempted'] and code != 'cancelled') or (
                    job['external_attempted'] and diagnostic['category'] in {'network', 'unknown', 'parse'})
                status = 'needs_review' if uncertain else 'cancelled' if code == 'cancelled' else 'failed'
                job.update(status=status, error={'code': code,
                    'message': ERROR_MESSAGES.get(code, '上游接口拒绝请求；没有自动重新执行。'),
                    'confirm_attempted': job['confirm_attempted']})
            self._save(job)

    def _public(self, job):
        result = deepcopy({field: value for field, value in job.items() if not field.startswith('_')})
        if result.get('result'):
            result['result']['seconds_left'] = max(0, int(result['result']['expires_at'] - time.time()))
        return result

    def get(self, workspace, job_id):
        with self.lock:
            self._ensure()
            job = self.jobs.get((_workspace(workspace), job_id))
            if job is None:
                raise RefineError('job_not_found', '任务不存在或不属于当前工作区。', 404)
            return self._public(job)

    def get_request(self, workspace, request_id):
        with self.lock:
            self._ensure()
            previous = self.requests.get((_workspace(workspace), request_id))
            if previous is None:
                raise RefineError('job_not_found', '任务不存在或不属于当前工作区。', 404)
            return self.get(workspace, previous[0])

    def list(self, workspace):
        with self.lock:
            self._ensure()
            return [self._public(job) for (owner, _), job in reversed(list(self.jobs.items()))
                    if owner == _workspace(workspace) and not job['hidden']]

    def overview(self, workspace):
        workspace = _workspace(workspace)
        with self.lock:
            reason = None
            try:
                self._ensure()
            except RefineError:
                reason = 'ledger_unavailable'
            records = [job for (owner, _), job in self.jobs.items() if owner == workspace]
            stats = {status: sum(job['status'] == status for job in records) for status in sorted(STATUSES)}
            stats.update(accepted_unique=len(records), hidden=sum(bool(job['hidden']) for job in records),
                         valid_results=sum(job['status'] == 'completed' and bool(job.get('result'))
                                           and normalize_result({'ok': True, **job['result']}) is not None
                                           for job in records))
            if not reason and stats['needs_review']:
                reason = 'needs_review'
            if not reason and workspace not in self._draining and stats['running']:
                reason = 'needs_review'
            return {'jobs': [self._public(job) for job in reversed(records) if not job['hidden']],
                    'stats': stats, 'submission_available': reason is None, 'blocked_reason': reason}

    def cancel(self, workspace, job_id):
        with self.lock:
            self._ensure()
            self.get(workspace, job_id)
            job = self.jobs[(_workspace(workspace), job_id)]
            if job['confirm_attempted']:
                return {'accepted': False, 'reason': 'external_operation_possible', 'job': self._public(job)}
            if job['status'] not in {'queued', 'running'}:
                return {'accepted': False, 'reason': 'not_active', 'job': self._public(job)}
            job['cancel_requested'] = True
            if job['status'] == 'queued':
                job.update(status='cancelled', finished_at=time.time(),
                    error={'code': 'cancelled', 'message': ERROR_MESSAGES['cancelled'], 'confirm_attempted': False})
                pending = self._pending.pop((_workspace(workspace), job_id), None)
                if pending:
                    pending[0].clear()
            self._save(job)
            return {'accepted': True, 'job': self._public(job)}

    def clear(self, workspace, job_id):
        with self.lock:
            self._ensure()
            self.get(workspace, job_id)
            job = self.jobs[(_workspace(workspace), job_id)]
            if job['status'] in {'queued', 'running'}:
                raise RefineError('job_active', '活动任务不能清理。', 409)
            job.update(hidden=True, result=None, result_available=False)
            self._save(job)
            return {'cleared': True, 'job_id': job_id}


SERVICE = JobService()
