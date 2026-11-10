"""Durable storage for payment qualification jobs."""
from __future__ import annotations

import json
import sqlite3
import time
from typing import Any
from safe_diagnostics import sanitize_text

from . import db


def _connect(database_path=None) -> sqlite3.Connection:
    path = database_path if database_path is not None else db.active_database_path()
    con = sqlite3.connect(str(path), timeout=30)
    con.row_factory = sqlite3.Row
    return con


def init() -> None:
    with _connect() as con:
        con.executescript(
            """
            CREATE TABLE IF NOT EXISTS qualification_tasks (
                job_id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                total INTEGER NOT NULL,
                completed INTEGER NOT NULL DEFAULT 0,
                created_at REAL NOT NULL,
                finished_at REAL,
                payload_json TEXT NOT NULL DEFAULT '{}',
                results_json TEXT NOT NULL DEFAULT '[]'
            );
            CREATE INDEX IF NOT EXISTS idx_qualification_tasks_created
                ON qualification_tasks(created_at DESC);
            """
        )


def save(job: dict[str, Any]) -> None:
    # The public API redacts the template; retaining it here lets a 711 task
    # resume or retry after a WebUI restart without exposing credentials.
    payload = {key: value for key, value in job.items() if key == "items" or key in {"regions", "retries", "workers", "proxy_mode", "proxy_template", "session_minutes", "max_attempts", "retry_counts"}}
    with _connect() as con:
        con.execute(
            """INSERT INTO qualification_tasks
               (job_id,status,total,completed,created_at,finished_at,payload_json,results_json)
               VALUES (?,?,?,?,?,?,?,?)
               ON CONFLICT(job_id) DO UPDATE SET
                 status=excluded.status, completed=excluded.completed,
                 finished_at=excluded.finished_at, payload_json=excluded.payload_json,
                 results_json=excluded.results_json""",
            (
                job["job_id"], job.get("status", "running"), int(job.get("total", 0)),
                int(job.get("completed", 0)), float(job.get("created_at", time.time())),
                job.get("finished_at"), json.dumps(payload, ensure_ascii=False),
                json.dumps(job.get("results") or [], ensure_ascii=False),
            ),
        )


def get(job_id: str) -> dict[str, Any] | None:
    with _connect() as con:
        row = con.execute("SELECT * FROM qualification_tasks WHERE job_id=?", (job_id,)).fetchone()
    if not row:
        return None
    payload = json.loads(row["payload_json"] or "{}")
    return {
        "job_id": row["job_id"], "status": row["status"], "total": row["total"],
        "completed": row["completed"], "created_at": row["created_at"],
        "finished_at": row["finished_at"], "results": json.loads(row["results_json"] or "[]"),
        **payload,
    }


def list_tasks(limit: int = 20, offset: int = 0) -> tuple[list[dict[str, Any]], int]:
    with _connect() as con:
        total = int(con.execute("SELECT COUNT(*) FROM qualification_tasks").fetchone()[0])
        rows = con.execute(
            "SELECT job_id,status,total,completed,created_at,finished_at FROM qualification_tasks "
            "ORDER BY created_at DESC LIMIT ? OFFSET ?", (limit, offset)
        ).fetchall()
    return [dict(row) for row in rows], total


def latest_results(database_path=None) -> dict[str, dict[str, Any]]:
    """Read latest per-email evidence only, never the credential-bearing payload."""
    connection = _connect() if database_path is None else _connect(database_path)
    with connection as con:
        if not con.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='qualification_tasks'").fetchone():
            return {}
        rows = con.execute(
            "SELECT results_json FROM qualification_tasks ORDER BY created_at DESC, rowid DESC"
        ).fetchall()
    latest = {}
    for task in rows:
        try:
            results = json.loads(task['results_json'] or '[]')
        except (TypeError, ValueError):
            continue
        if not isinstance(results, list):
            continue
        for result in results:
            if not isinstance(result, dict) or not isinstance(result.get('email'), str):
                continue
            email = result['email'].strip().lower()
            if email and email not in latest:
                latest[email] = _public_result(result)
    return latest


def _public_result(row: dict[str, Any]) -> dict[str, Any]:
    # Only these fields contribute to category and explanation. No submitted
    # tokens, proxy metadata or task payload may enter the registered list.
    fields = {'email', 'status', 'routing_version', 'qualified', 'partial', 'interrupted',
              'amount_minor', 'payment_method_types', 'available_channels', 'reason_codes', 'error'}
    region_fields = {'qualified', 'channel', 'amount_minor', 'payment_method_types', 'reason_codes',
                     'country', 'currency', 'requested_country', 'requested_currency', 'error'}
    def safe(value):
        if isinstance(value, str):
            return sanitize_text(value)
        if isinstance(value, list):
            return [safe(item) for item in value if isinstance(item, (str, int, float, bool)) or item is None]
        return value if isinstance(value, (int, float, bool)) or value is None else None
    public = {key: safe(value) for key, value in row.items() if key in fields}
    regions = row.get('regions')
    if isinstance(regions, list):
        public['regions'] = [{key: safe(value) for key, value in region.items() if key in region_fields}
                             for region in regions if isinstance(region, dict)]
    return public


def delete(job_id: str) -> bool:
    with _connect() as con:
        cur = con.execute("DELETE FROM qualification_tasks WHERE job_id=?", (job_id,))
        return cur.rowcount > 0


init()
