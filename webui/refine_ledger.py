"""Durable metadata only; credentials and payment results never enter this ledger."""
from __future__ import annotations

from contextlib import closing
import ctypes
from ctypes import wintypes
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import uuid

from .refine_input import unique_object


class LedgerError(Exception):
    pass


class _Blob(ctypes.Structure):
    _fields_ = [('size', wintypes.DWORD), ('data', ctypes.POINTER(ctypes.c_ubyte))]


def _dpapi(value, *, decrypt=False):
    if os.name != 'nt':
        raise LedgerError('protected_key_unavailable')
    buffer = (ctypes.c_ubyte * len(value)).from_buffer_copy(value)
    source, target = _Blob(len(value), buffer), _Blob()
    crypt = ctypes.WinDLL('crypt32', use_last_error=True)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    function = crypt.CryptUnprotectData if decrypt else crypt.CryptProtectData
    function.argtypes = [ctypes.POINTER(_Blob), ctypes.c_void_p,
                         ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                         wintypes.DWORD, ctypes.POINTER(_Blob)]
    function.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    if not function(ctypes.byref(source), None, None, None, None, 1, ctypes.byref(target)):
        raise LedgerError('protected_key_unavailable')
    try:
        return ctypes.string_at(target.data, target.size)
    finally:
        kernel.LocalFree(target.data)


FIELDS = ('job_id', 'request_id', 'batch_id', 'email', 'status', 'stage', 'last_stage',
          'stage_durations', 'created_at', 'finished_at', 'error', 'diagnostics',
          'confirm_attempted', 'external_attempted', 'cancel_requested', 'hidden',
          'request_attempts')
STATUSES = {'queued', 'running', 'completed', 'failed', 'cancelled', 'needs_review'}
PHASES = {'queued', 'checkout', 'stripe_init', 'tax_update', 'payment_method',
          'stripe_confirm', 'approve', 'instructions'}
EXCEPTIONS = {'TimeoutError', 'ConnectionError', 'OSError', 'ValueError', 'TypeError',
              'KeyError', 'IndexError', 'JSONDecodeError', 'RuntimeError', 'Exception',
              'ReadTimeout', 'ConnectTimeout', 'Timeout', 'ProxyError', 'SSLError',
              'RequestsError', 'RequestException', 'CurlError', 'RefineCancelled', 'LedgerError'}
ERROR_CODES = {'no_access_token', 'nonzero_due', 'upi_unavailable', 'tax_unverified',
               'declined', 'link_unverified', 'no_link', 'network_error', 'upstream_error',
               'unknown', 'parse_error', 'result_unverified', 'service_interrupted',
               'cancelled', 'job_start_failed'}
COLUMNS = ('workspace', 'job_id', 'request_id', 'digest', 'identity', 'token_digest',
           'manual', 'revision', 'metadata')
MARKER = b'DANGO_REFINE_LEDGER_V2'
CREATE_META = 'CREATE TABLE meta (version INTEGER, key_check TEXT, records_mac TEXT)'
CREATE_JOBS = '''CREATE TABLE jobs (
    workspace TEXT NOT NULL, job_id TEXT NOT NULL,
    request_id TEXT NOT NULL, digest TEXT NOT NULL,
    identity TEXT NOT NULL, token_digest TEXT NOT NULL,
    manual INTEGER NOT NULL, revision INTEGER NOT NULL,
    metadata TEXT NOT NULL, PRIMARY KEY(workspace,job_id),
    UNIQUE(workspace,request_id))'''
SCHEMA = {('table', 'meta', 'meta', CREATE_META), ('table', 'jobs', 'jobs', CREATE_JOBS),
          ('index', 'sqlite_autoindex_jobs_1', 'jobs', None),
          ('index', 'sqlite_autoindex_jobs_2', 'jobs', None)}


def _number(value, minimum=0):
    return type(value) in (int, float) and math.isfinite(value) and value >= minimum


def _uuid(value):
    try:
        return isinstance(value, str) and str(uuid.UUID(value)) == value
    except (ValueError, AttributeError):
        return False


def _valid_metadata(job):
    if (not isinstance(job, dict) or set(job) != set(FIELDS)
            or not isinstance(job['job_id'], str) or not re.fullmatch('[0-9a-f]{32}', job['job_id'])
            or not _uuid(job['request_id'])
            or (job['batch_id'] is not None and not _uuid(job['batch_id']))
            or not isinstance(job['email'], str) or len(job['email']) > 254
            or not re.fullmatch(r'[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+', job['email'])
            or job['status'] not in STATUSES or job['stage'] not in PHASES | {'completed'}
            or job['last_stage'] not in PHASES
            or not _number(job['created_at'], 1)
            or any(type(job[field]) is not bool for field in (
                'confirm_attempted', 'external_attempted', 'cancel_requested', 'hidden'))):
        return False
    terminal = job['status'] not in {'queued', 'running'}
    if (terminal and not _number(job['finished_at'], job['created_at'])
            or not terminal and job['finished_at'] is not None
            or job['hidden'] and not terminal
            or (job['stage'] == 'completed') != (job['status'] == 'completed')
            or job['confirm_attempted'] and not job['external_attempted']):
        return False
    durations = job['stage_durations']
    attempts = job['request_attempts']
    if (not isinstance(durations, dict) or set(durations) - PHASES
            or any(not _number(value) for value in durations.values())
            or not isinstance(attempts, list) or len(attempts) > 32
            or bool(attempts) != job['external_attempted']
            or any(not isinstance(item, dict) or set(item) != {'stage', 'method'}
                   or item['stage'] not in PHASES or item['method'] != 'POST' for item in attempts)):
        return False
    error = job['error']
    if error is not None:
        if (not isinstance(error, dict) or set(error) != {'code', 'confirm_attempted'}
                or not isinstance(error['code'], str)
                or not (error['code'] in ERROR_CODES or re.fullmatch(
                    r'(checkout|stripe_init|tax_update|payment_method|stripe_confirm|approve|instructions)_http_[45][0-9]{2}', error['code']))
                or type(error['confirm_attempted']) is not bool
                or error['confirm_attempted'] != job['confirm_attempted']):
            return False
    if (error is not None) != (job['status'] in {'failed', 'cancelled', 'needs_review'}):
        return False
    diagnostic = job['diagnostics']
    if diagnostic is not None:
        if (not isinstance(diagnostic, dict)
                or set(diagnostic) != {'category', 'exception_type', 'http_status', 'location'}
                or diagnostic['category'] not in {'unknown', 'http', 'verification', 'cancelled', 'network', 'parse'}
                or diagnostic['exception_type'] not in EXCEPTIONS | {None}
                or diagnostic['http_status'] is not None and (
                    type(diagnostic['http_status']) is not int or not 400 <= diagnostic['http_status'] <= 599)):
            return False
        location = diagnostic['location']
        if location is not None and (not isinstance(location, dict)
                or set(location) != {'file', 'function', 'line'}
                or location['file'] not in {'refine_service.py', 'refine_upstream.py', 'refine_sentinel_fetch.py', 'protocol.py'}
                or not isinstance(location['function'], str)
                or not re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]{0,127}', location['function'])
                or type(location['line']) is not int or not 1 <= location['line'] <= 1000000):
            return False
    return True


class Ledger:
    VERSION = 2

    def __init__(self, directory, *, key=None):
        self.directory = Path(directory).resolve()
        self.path = self.directory / 'jobs.sqlite3'
        self.key_path = self.directory / 'key.dpapi'
        self.marker_path = self.directory.with_name(self.directory.name + '.initialized')
        self.owner_path = self.directory.with_name(self.directory.name + '.owner')
        self._owner = None
        try:
            self.directory.parent.mkdir(parents=True, exist_ok=True)
            try:
                self._owner = self.owner_path.open('x+b')
                self._owner.write(b'1')
                self._owner.flush()
                os.fsync(self._owner.fileno())
                first_owner = True
            except FileExistsError:
                self._owner = self.owner_path.open('r+b')
                first_owner = False
            self._owner.seek(0)
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(self._owner.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self._owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
            new = not self.directory.exists()
            if new:
                if self.marker_path.exists() or not first_owner:
                    raise LedgerError('state_files_missing')
                with self.marker_path.open('xb') as stream:
                    stream.write(MARKER)
                    stream.flush()
                    os.fsync(stream.fileno())
                self.directory.mkdir(parents=True, exist_ok=False)
                value = key if key is not None else os.urandom(32)
                if not isinstance(value, bytes) or len(value) < 32:
                    raise LedgerError('invalid_key')
                with self.key_path.open('xb') as stream:
                    stream.write(_dpapi(value))
                    stream.flush()
                    os.fsync(stream.fileno())
                self.key = value
                self.key_hash = hashlib.sha256(self.key_path.read_bytes()).digest()
                with closing(sqlite3.connect(self.path)) as connection:
                    connection.execute('PRAGMA journal_mode=WAL')
                    connection.execute('PRAGMA synchronous=FULL')
                    connection.execute(CREATE_META)
                    connection.execute('INSERT INTO meta VALUES (?,?,?)',
                                       (self.VERSION, self.fingerprint('key-check'), self.fingerprint(['records-v2', []])))
                    connection.execute(CREATE_JOBS)
                    connection.execute('PRAGMA user_version=2')
                    connection.commit()
            else:
                if not self.path.is_file() or not self.key_path.is_file():
                    raise LedgerError('state_files_missing')
                encrypted = self.key_path.read_bytes()
                self.key = _dpapi(encrypted, decrypt=True)
                if len(self.key) < 32 or (key is not None and not hmac.compare_digest(key, self.key)):
                    raise LedgerError('key_mismatch')
                self.key_hash = hashlib.sha256(encrypted).digest()
            self.check()
        except LedgerError:
            self.close()
            raise
        except Exception:
            self.close()
            raise LedgerError('ledger_unavailable') from None

    def close(self):
        if self._owner is not None:
            self._owner.close()
            self._owner = None

    def fingerprint(self, value):
        encoded = json.dumps(value, sort_keys=True, ensure_ascii=True,
                             separators=(',', ':'), allow_nan=False).encode('utf-8')
        return hmac.new(self.key, encoded, hashlib.sha256).hexdigest()

    def _connect(self):
        connection = sqlite3.connect(self.path.as_uri() + '?mode=rw', uri=True, timeout=5)
        try:
            connection.execute('PRAGMA synchronous=FULL')
        except Exception:
            connection.close()
            raise
        return connection

    def _check_files(self):
        if (self._owner is None or self._owner.closed
                or not self.path.is_file() or not self.key_path.is_file()
                or not self.marker_path.is_file()
                or self.marker_path.stat().st_size != len(MARKER)
                or self.marker_path.read_bytes() != MARKER
                or not hmac.compare_digest(hashlib.sha256(self.key_path.read_bytes()).digest(), self.key_hash)):
            raise LedgerError('state_files_changed')

    def _checked_rows(self, connection):
        if set(connection.execute('SELECT type,name,tbl_name,sql FROM sqlite_master')) != SCHEMA:
            raise LedgerError('ledger_incompatible')
        meta = connection.execute('SELECT version,key_check,records_mac FROM meta').fetchall()
        if (connection.execute('PRAGMA user_version').fetchone()[0] != self.VERSION
                or len(meta) != 1 or meta[0][0] != self.VERSION
                or not isinstance(meta[0][1], str)
                or not hmac.compare_digest(meta[0][1], self.fingerprint('key-check'))
                or connection.execute('PRAGMA quick_check').fetchone()[0] != 'ok'
                or tuple(row[1] for row in connection.execute('PRAGMA table_info(jobs)')) != COLUMNS):
            raise LedgerError('ledger_incompatible')
        rows = connection.execute('SELECT ' + ','.join(COLUMNS) + ' FROM jobs ORDER BY workspace,job_id').fetchall()
        if (not isinstance(meta[0][2], str)
                or not hmac.compare_digest(meta[0][2], self.fingerprint(['records-v2', rows]))):
            raise LedgerError('records_changed')
        result = []
        for workspace, job_id, request_id, digest, identity, token_digest, manual, revision, metadata in rows:
            job = json.loads(metadata, object_pairs_hook=unique_object,
                             parse_constant=lambda value: (_ for _ in ()).throw(ValueError('invalid number')))
            if (not _valid_metadata(job) or workspace not in {'1', '2'}
                    or job['job_id'] != job_id or job['request_id'] != request_id
                    or type(revision) is not int or revision < 0 or type(manual) is not int or manual not in (0, 1)
                    or any(not isinstance(value, str) or not re.fullmatch('[0-9a-f]{64}', value)
                           for value in (digest, identity, token_digest))):
                raise LedgerError('invalid_metadata')
            job.update(_workspace=workspace, _digest=digest, _identity=identity,
                       _token_digest=token_digest, _manual=bool(manual), _revision=revision)
            result.append(job)
        if any(sum(job['_workspace'] == workspace for job in result) > 100 for workspace in ('1', '2')):
            raise LedgerError('invalid_metadata')
        return sorted(result, key=lambda job: (job['created_at'], job['job_id']))

    def _seal(self, connection):
        rows = connection.execute('SELECT ' + ','.join(COLUMNS) + ' FROM jobs ORDER BY workspace,job_id').fetchall()
        connection.execute('UPDATE meta SET records_mac=?', (self.fingerprint(['records-v2', rows]),))

    def check(self):
        try:
            self._check_files()
            with closing(self._connect()) as connection:
                connection.execute('BEGIN')
                self._checked_rows(connection)
        except LedgerError:
            raise
        except Exception:
            raise LedgerError('ledger_unavailable') from None

    @staticmethod
    def _metadata(job):
        metadata = {field: job.get(field) for field in FIELDS}
        if metadata['error'] is not None:
            metadata['error'] = {field: metadata['error'].get(field) for field in ('code', 'confirm_attempted')}
        if not _valid_metadata(metadata):
            raise LedgerError('invalid_metadata')
        return json.dumps(metadata,
                          ensure_ascii=True, separators=(',', ':'), allow_nan=False)

    def load(self):
        try:
            self._check_files()
            with closing(self._connect()) as connection:
                connection.execute('BEGIN')
                return self._checked_rows(connection)
        except LedgerError:
            raise
        except Exception:
            raise LedgerError('ledger_unavailable') from None

    def reserve(self, jobs):
        try:
            self._check_files()
            with closing(self._connect()) as connection:
                connection.execute('BEGIN IMMEDIATE')
                records = self._checked_rows(connection)
                workspace = jobs[0]['_workspace']
                existing = [job for job in records if job['_workspace'] == workspace]
                if any(job['status'] == 'needs_review' for job in existing):
                    raise LedgerError('workspace_needs_review')
                if sum(job['status'] in {'queued', 'running'} for job in existing) + len(jobs) > 10:
                    raise LedgerError('queue_full')
                for job in jobs:
                    connection.execute('INSERT INTO jobs VALUES (?,?,?,?,?,?,?,?,?)',
                        (workspace, job['job_id'], job['request_id'], job['_digest'],
                         job['_identity'], job['_token_digest'], int(job['_manual']), 0,
                         self._metadata(job)))
                self._seal(connection)
                connection.commit()
        except LedgerError:
            raise
        except Exception:
            raise LedgerError('ledger_unavailable') from None

    def save(self, job):
        try:
            self._check_files()
            with closing(self._connect()) as connection:
                connection.execute('BEGIN IMMEDIATE')
                self._checked_rows(connection)
                changed = connection.execute('''UPDATE jobs SET metadata=?,revision=revision+1
                    WHERE workspace=? AND job_id=? AND revision=?''',
                    (self._metadata(job), job['_workspace'], job['job_id'], job['_revision']))
                if changed.rowcount != 1:
                    raise LedgerError('stale_state')
                self._seal(connection)
                connection.commit()
                job['_revision'] += 1
        except LedgerError:
            raise
        except Exception:
            raise LedgerError('ledger_unavailable') from None
