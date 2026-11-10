"""SQLite 号池 + 注册结果存储。

表结构：
  outlook_accounts: 接码号池（多种邮箱混放，kind 列区分 + 状态机）
  registered:       注册成功结果（凭证 JSON）

关于 outlook_accounts 这个表名：
    它现在装的不止 outlook（还有 gmail / icloud / qq ...），名字已经不准，
    但改表名要动迁移和一堆 SQL，收益只是好看一点，风险不值。
    真正区分类型的是 kind 列。

凭证字段用「并集列」而不是 extra_json：
    outlook/gmail 用 password+client_id+refresh_token，
    icloud 这类中转只用 relay_url，各自把不用的列留空。
    几种邮箱的规模下，并集列比 JSON 好 —— 能建索引、能加约束、
    SQL 里直接看得见。加新邮箱时如果要新字段，就再 ALTER 加一列。
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import re
import sqlite3
import sys
import threading
import time
from contextvars import ContextVar
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path
from typing import Optional

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
from safe_diagnostics import sanitize_text, safe_password_reset_result

_DB_PATH_OVERRIDE = os.environ.get("GPT_OUTLOOK_WEBUI_DB_PATH", "").strip()
_BASE_DB_PATH = (
    Path(_DB_PATH_OVERRIDE).expanduser().resolve()
    if _DB_PATH_OVERRIDE
    else Path(__file__).resolve().parent / "webui.db"
)
DB_PATH = _BASE_DB_PATH
_DB_SWITCH_LOCK = threading.Lock()
_ACTIVE_DB_PATH: ContextVar[Path | None] = ContextVar("webui_active_db_path", default=None)
_INITIALIZED_DB_PATHS: set[Path] = set()


def normalize_account(value: object) -> str:
    """Return the only supported workspace identifiers."""
    return str(value or "1").strip() if str(value or "1").strip() in {"1", "2"} else "1"


def database_path_for(account: object) -> Path:
    account = normalize_account(account)
    if account == "1":
        return _BASE_DB_PATH
    return _BASE_DB_PATH.with_name(f"{_BASE_DB_PATH.stem}-account-{account}{_BASE_DB_PATH.suffix}")


def active_database_path() -> Path:
    return _ACTIVE_DB_PATH.get() or DB_PATH


def activate_database(account: object):
    """Bind a request/task-local database path without changing other requests."""
    normalized = normalize_account(account)
    target = database_path_for(normalized)
    token = _ACTIVE_DB_PATH.set(target)
    if target not in _INITIALIZED_DB_PATHS:
        with _DB_SWITCH_LOCK:
            if target not in _INITIALIZED_DB_PATHS:
                init_db()
                _INITIALIZED_DB_PATHS.add(target)
    return normalized, token


def reset_database(token) -> None:
    _ACTIVE_DB_PATH.reset(token)


def switch_database(account: object) -> str:
    """Select an isolated database and initialize it before the next query."""
    global DB_PATH
    normalized = normalize_account(account)
    target = database_path_for(normalized)
    with _DB_SWITCH_LOCK:
        changed = DB_PATH != target
        DB_PATH = target
        if changed:
            init_db()
    return normalized

_lock = threading.Lock()  # SQLite 写入串行化

PASSWORD_PENDING_REGISTERED = "password_registered_unverified"
ACCOUNT_POOL_VALUES = ("momo", "upi", "pending")
DEFAULT_ACCOUNT_POOL = "pending"
PASSWORD_PENDING_CANDIDATE = "candidate_not_accepted"
PASSWORD_RECOVERY_REQUIRED = "password_recovery_required"
_LEGACY_PASSWORD_RECOVERY_REASONS = {"existing_account_password_unknown"}
PASSWORD_RECOVERY_PENDING_REASONS = {
    PASSWORD_RECOVERY_REQUIRED,
    *_LEGACY_PASSWORD_RECOVERY_REASONS,
}

_REBIND_MAILBOX_STATUSES = (
    "available",
    "claimed",
    "used",
    "failed",
    "retry_pending",
)



def _conn() -> sqlite3.Connection:
    con = sqlite3.connect(str(active_database_path()), check_same_thread=False, timeout=30)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    return con


def _reconcile_completed_mailbox_status(
    con: sqlite3.Connection,
    email: str = "",
) -> int:
    """Promote failed/in-use mailboxes with all mandatory credentials.

    ``available`` may be an intentional manual reset, so it is not touched.
    Refresh token is optional; password, access/session and both TOTP fields
    are required before a mailbox can be reconciled to ``done``.
    """
    where = [
        "outlook_accounts.status IN ('failed', 'in_use')",
        "EXISTS ("
        "SELECT 1 FROM registered r "
        "WHERE lower(r.email)=lower(outlook_accounts.email) "
        "AND COALESCE(TRIM(r.password), '')<>'' "
        "AND COALESCE(TRIM(r.access_token), '')<>'' "
        "AND COALESCE(TRIM(r.session_token), '')<>'' "
        "AND COALESCE(TRIM(r.totp_secret), '')<>'' "
        "AND COALESCE(TRIM(r.totp_factor_id), '')<>'' "
        "AND (r.extra_json IS NULL OR (json_valid(r.extra_json) "
        "AND COALESCE(json_extract(r.extra_json, '$.pending'), 0)=0))"
        ")",
    ]
    params: list[object] = [time.time()]
    normalized = (email or "").strip().lower()
    if normalized:
        where.append("lower(outlook_accounts.email)=lower(?)")
        params.append(normalized)
    rc = con.execute(
        "UPDATE outlook_accounts SET status='done', finished_at=?, fail_reason=NULL "
        f"WHERE {' AND '.join(where)}",
        params,
    )
    return rc.rowcount


def _migrate_unverified_passwords(con: sqlite3.Connection) -> int:
    """Discard only passwords that lack evidence of server acceptance.

    ``password_registered_unverified`` is written only after the registration
    endpoint returns success.  It must survive restarts as an escrowed password,
    while remaining hidden from ordinary credential reads until a later login
    verifies it.  Browser-only candidates and ambiguous legacy pending rows are
    still converted to the explicit password-recovery state.  The migration is
    intentionally idempotent.
    """
    rows = con.execute(
        "SELECT registered.email, registered.password, registered.extra_json "
        "FROM registered "
        "WHERE COALESCE(TRIM(registered.password), '') <> '' "
        "AND NOT EXISTS ("
        "SELECT 1 FROM runs "
        "WHERE lower(runs.email)=lower(registered.email) "
        "AND COALESCE(runs.run_kind, 'registration')='registration' "
        "AND lower(COALESCE(runs.status, '')) "
        "IN ('running', 'pending', 'in_progress', 'cancelling')"
        ")"
    ).fetchall()
    migrated = 0
    for row in rows:
        try:
            extra = json.loads(row["extra_json"] or "{}")
        except (TypeError, ValueError, json.JSONDecodeError):
            extra = {}
        if not isinstance(extra, dict) or not bool(extra.get("pending")):
            continue
        if str(extra.get("pending_reason") or "") == PASSWORD_PENDING_REGISTERED:
            # The provider already accepted this exact password. Keep it as an
            # unverified escrow value instead of forcing an unnecessary reset.
            continue
        extra["pending"] = True
        extra["pending_reason"] = PASSWORD_RECOVERY_REQUIRED
        con.execute(
            "UPDATE registered SET password='', extra_json=? WHERE email=?",
            (json.dumps(extra, ensure_ascii=False), row["email"]),
        )
        migrated += 1
    return migrated


def init_db():
    con = _conn()
    con.executescript("""
        CREATE TABLE IF NOT EXISTS outlook_accounts (
            email           TEXT PRIMARY KEY,
            password        TEXT,
            client_id       TEXT,
            refresh_token   TEXT,
            relay_url       TEXT,       -- 中转取码 URL（icloud 类用，其余留空）
            kind            TEXT NOT NULL DEFAULT 'outlook',
                            -- 邮箱类型，对应 mail_providers 注册表的 kind
            status          TEXT NOT NULL DEFAULT 'available',
                            -- available / in_use / done / failed
            imported_at     REAL,
            claimed_at      REAL,
            finished_at     REAL,
            fail_reason     TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_outlook_status ON outlook_accounts(status);
        -- idx_outlook_kind 不在这里建：老库此刻还没有 kind 列，
        -- 建索引会当场报错。放到下面补完列之后再建。

        CREATE TABLE IF NOT EXISTS settings (
            key     TEXT PRIMARY KEY,
            value   TEXT
        );

        CREATE TABLE IF NOT EXISTS registered (
            email           TEXT PRIMARY KEY,
            password        TEXT,
            access_token    TEXT,
            session_token   TEXT,
            refresh_token   TEXT,
            id_token        TEXT,
            device_id       TEXT,
            csrf_token      TEXT,
            cookie_header   TEXT,
            totp_secret     TEXT,
            totp_factor_id  TEXT,
            extra_json      TEXT,
            created_at      REAL
        );

        CREATE TABLE IF NOT EXISTS rebind_mailboxes (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            email           TEXT NOT NULL UNIQUE,
            mail_api        TEXT NOT NULL DEFAULT '',
            status          TEXT NOT NULL DEFAULT 'available',
            claimed_at     REAL,
            cooldown_until REAL,
            used_at        REAL,
            imported_at    REAL NOT NULL,
            fail_reason    TEXT DEFAULT '',
            failure_stage  TEXT NOT NULL DEFAULT '',
            release_safe   INTEGER NOT NULL DEFAULT 0,
            claimed_by     TEXT DEFAULT '',
            assigned_old_email TEXT DEFAULT ''
        );

        CREATE INDEX IF NOT EXISTS idx_rebind_mailbox_status
        ON rebind_mailboxes(status, imported_at);

        CREATE TABLE IF NOT EXISTS rebind_runs (
            run_id          TEXT PRIMARY KEY,
            status          TEXT NOT NULL DEFAULT 'finished',
            created_at      REAL NOT NULL,
            updated_at      REAL NOT NULL,
            payload_json    TEXT NOT NULL DEFAULT '{}',
            source          TEXT NOT NULL DEFAULT 'webui'
        );

        CREATE INDEX IF NOT EXISTS idx_rebind_runs_created_at
        ON rebind_runs(created_at DESC);

        CREATE TABLE IF NOT EXISTS pending_totp_enrollments (
            email           TEXT PRIMARY KEY,
            secret          TEXT NOT NULL,
            factor_id       TEXT NOT NULL,
            session_id      TEXT NOT NULL,
            created_at      REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS runs (
            run_id          TEXT PRIMARY KEY,
            email           TEXT,
            status          TEXT,        -- running / done / failed
            started_at      REAL,
            finished_at     REAL,
            log_path        TEXT,
            error           TEXT,
            error_category  TEXT,        -- network / account / unknown
            run_kind        TEXT NOT NULL DEFAULT 'registration',
                            -- registration / reauthorization
            timing_json     TEXT,
            result_json     TEXT
        );

        -- The run_kind column was added after the original runs table.  Keep
        -- these indexes out of the initial script so legacy databases can be
        -- migrated before SQLite resolves the indexed column names.

        CREATE TABLE IF NOT EXISTS active_identity_leases (
            email           TEXT PRIMARY KEY,
            run_id          TEXT NOT NULL,
            created_at      REAL NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_active_identity_leases_run
        ON active_identity_leases(run_id);

        CREATE TABLE IF NOT EXISTS roxy_profile_usage (
            profile_id       TEXT PRIMARY KEY,
            ip_tag           TEXT NOT NULL,
            use_count        INTEGER NOT NULL DEFAULT 0,
            last_reserved_at REAL NOT NULL,
            retired_at       REAL
        );

        CREATE INDEX IF NOT EXISTS idx_roxy_profile_usage_ip
        ON roxy_profile_usage(ip_tag);

        CREATE TABLE IF NOT EXISTS roxy_ip_usage (
            ip_tag           TEXT PRIMARY KEY,
            use_count        INTEGER NOT NULL DEFAULT 0,
            last_reserved_at REAL NOT NULL,
            retired_at       REAL
        );

        CREATE TABLE IF NOT EXISTS roxy_ip_quarantine (
            ip_tag           TEXT PRIMARY KEY,
            quarantined_at   REAL NOT NULL
        );
    """)
    con.commit()
    # 老 DB migrate：error_category 在后期才加，对已建表补列
    cur = con.execute("PRAGMA table_info(runs)")
    cols = {r[1] for r in cur.fetchall()}
    if "error_category" not in cols:
        con.execute("ALTER TABLE runs ADD COLUMN error_category TEXT")
        con.commit()
    if "run_kind" not in cols:
        con.execute(
            "ALTER TABLE runs ADD COLUMN run_kind TEXT NOT NULL DEFAULT 'registration'"
        )
        con.commit()
    if "timing_json" not in cols:
        con.execute("ALTER TABLE runs ADD COLUMN timing_json TEXT")
        con.commit()
    if "result_json" not in cols:
        con.execute("ALTER TABLE runs ADD COLUMN result_json TEXT")
        con.commit()

    # Build run indexes only after all legacy columns have been migrated.
    con.execute(
        "CREATE INDEX IF NOT EXISTS idx_runs_email_kind_started "
        "ON runs(email, run_kind, started_at DESC)"
    )
    con.execute(
        "CREATE INDEX IF NOT EXISTS idx_runs_status_kind_email "
        "ON runs(status, run_kind, email)"
    )
    con.commit()

    # 老 DB migrate：换绑邮箱失败阶段与安全释放标记后期加入。
    cur = con.execute("PRAGMA table_info(rebind_mailboxes)")
    rebind_mailbox_cols = {r[1] for r in cur.fetchall()}
    if "failure_stage" not in rebind_mailbox_cols:
        con.execute(
            "ALTER TABLE rebind_mailboxes ADD COLUMN failure_stage TEXT NOT NULL DEFAULT ''"
        )
        con.commit()
    if "release_safe" not in rebind_mailbox_cols:
        con.execute(
            "ALTER TABLE rebind_mailboxes ADD COLUMN release_safe INTEGER NOT NULL DEFAULT 0"
        )
        con.commit()
    if "cooldown_until" not in rebind_mailbox_cols:
        con.execute("ALTER TABLE rebind_mailboxes ADD COLUMN cooldown_until REAL")
        con.commit()

    # 老 DB migrate：号池多邮箱混放（kind / relay_url 在后期才加）
    # 存量行全部是 outlook 时代导进去的，DEFAULT 'outlook' 正好把它们
    # 归位，不需要额外 UPDATE。重复执行无副作用。
    cur = con.execute("PRAGMA table_info(outlook_accounts)")
    acc_cols = {r[1] for r in cur.fetchall()}
    if "kind" not in acc_cols:
        con.execute(
            "ALTER TABLE outlook_accounts ADD COLUMN kind TEXT NOT NULL DEFAULT 'outlook'"
        )
        con.commit()
    if "relay_url" not in acc_cols:
        con.execute("ALTER TABLE outlook_accounts ADD COLUMN relay_url TEXT")
        con.commit()
    # 索引建在补列之后，否则老库上 CREATE INDEX 会因为没有 kind 列而失败
    con.execute(
        "CREATE INDEX IF NOT EXISTS idx_outlook_kind ON outlook_accounts(kind, status)"
    )
    con.commit()

    # 老 DB migrate：registered 的 2FA 两列（totp_secret / totp_factor_id）后期才加。
    # secret 一次性下发、服务端取不回，务必单独补列持久化。重复执行无副作用。
    cur = con.execute("PRAGMA table_info(registered)")
    reg_cols = {r[1] for r in cur.fetchall()}
    if "totp_secret" not in reg_cols:
        con.execute("ALTER TABLE registered ADD COLUMN totp_secret TEXT")
        con.commit()
    if "totp_factor_id" not in reg_cols:
        con.execute("ALTER TABLE registered ADD COLUMN totp_factor_id TEXT")
        con.commit()

    # Remove legacy pending passwords before any status reconciliation.
    # They are candidates only; authorization and 2FA do not make them trusted.
    _migrate_unverified_passwords(con)
    con.commit()

    # A completed credential row is stronger evidence than a stale mailbox    # failure/in-use marker.  This also repairs historical status drift at
    # startup without touching intentionally reset ``available`` rows.
    _reconcile_completed_mailbox_status(con)
    con.commit()


# ──────────────────────── Roxy Profile/IP 生命周期 ────────────────────────


ROXY_IP_RETIRE_COOLDOWN_SECONDS = 900.0


def _normalized_roxy_lifecycle_key(value: str, field: str) -> str:
    normalized = str(value or "").strip()
    if not normalized:
        raise ValueError(f"Roxy {field} 不能为空")
    return normalized


def list_retired_roxy_profile_ids() -> list[str]:
    con = _conn()
    try:
        return [
            str(row["profile_id"])
            for row in con.execute(
                "SELECT profile_id FROM roxy_profile_usage "
                "WHERE retired_at IS NOT NULL ORDER BY profile_id"
            )
        ]
    finally:
        con.close()


def list_retired_roxy_ip_tags() -> list[str]:
    cutoff = time.time() - ROXY_IP_RETIRE_COOLDOWN_SECONDS
    with _conn() as con:
        rows = con.execute(
            "SELECT ip_tag FROM roxy_ip_usage "
            "WHERE retired_at IS NOT NULL AND retired_at>? "
            "UNION SELECT ip_tag FROM roxy_ip_quarantine "
            "WHERE quarantined_at>? "
            "ORDER BY ip_tag",
            (cutoff, cutoff),
        ).fetchall()
    return [str(row["ip_tag"]) for row in rows if row["ip_tag"]]


def retire_roxy_profile_egress(profile_id: str, ip_tag: str) -> None:
    """Retire a browser Profile and temporarily quarantine its failing egress."""
    profile_id = _normalized_roxy_lifecycle_key(profile_id, "Profile ID")
    ip_tag = _normalized_roxy_lifecycle_key(ip_tag, "IP 指纹")
    now = time.time()

    with _lock:
        con = _conn()
        try:
            con.execute("BEGIN IMMEDIATE")
            con.execute(
                "INSERT INTO roxy_profile_usage("
                "profile_id, ip_tag, use_count, last_reserved_at, retired_at"
                ") VALUES (?, ?, 0, ?, ?) "
                "ON CONFLICT(profile_id) DO UPDATE SET "
                "ip_tag=excluded.ip_tag, retired_at=excluded.retired_at",
                (profile_id, ip_tag, now, now),
            )
            con.execute(
                "INSERT INTO roxy_ip_usage("
                "ip_tag, use_count, last_reserved_at, retired_at"
                ") VALUES (?, 0, ?, ?) "
                "ON CONFLICT(ip_tag) DO UPDATE SET retired_at=excluded.retired_at",
                (ip_tag, now, now),
            )
            con.execute(
                "INSERT INTO roxy_ip_quarantine(ip_tag, quarantined_at) "
                "VALUES (?, ?) ON CONFLICT(ip_tag) DO UPDATE SET "
                "quarantined_at=excluded.quarantined_at",
                (ip_tag, now),
            )
            con.commit()
        except Exception:
            con.rollback()
            raise
        finally:
            con.close()


def reserve_roxy_profile_use(
    profile_id: str,
    ip_tag: str,
    *,
    limit: int = 3,
) -> dict:
    """Atomically reserve one registration assignment for a Roxy Profile/IP.

    The reservation occurs before the browser worker starts. Therefore parallel
    tasks cannot sneak a fourth use through either the Profile or its shared
    egress IP. The third reservation is allowed but marks the Profile/IP as
    retired so no later task can acquire it.
    """
    profile_id = _normalized_roxy_lifecycle_key(profile_id, "Profile ID")
    ip_tag = _normalized_roxy_lifecycle_key(ip_tag, "IP 指纹")
    limit = max(1, int(limit))
    now = time.time()

    with _lock:
        con = _conn()
        try:
            con.execute("BEGIN IMMEDIATE")
            profile = con.execute(
                "SELECT use_count, retired_at FROM roxy_profile_usage "
                "WHERE profile_id=?",
                (profile_id,),
            ).fetchone()
            if profile is not None and profile["retired_at"] is not None:
                con.commit()
                return {
                    "allowed": False,
                    "reason": "profile_retired",
                    "profile_uses": int(profile["use_count"] or 0),
                    "ip_uses": 0,
                    "retire_profile": True,
                    "retire_ip": False,
                }

            ip = con.execute(
                "SELECT use_count, retired_at FROM roxy_ip_usage WHERE ip_tag=?",
                (ip_tag,),
            ).fetchone()
            quarantined = con.execute(
                "SELECT 1 FROM roxy_ip_quarantine "
                "WHERE ip_tag=? AND quarantined_at>?",
                (ip_tag, now - ROXY_IP_RETIRE_COOLDOWN_SECONDS),
            ).fetchone()
            ip_retirement_active = bool(
                quarantined is not None
                or (
                    ip is not None
                    and ip["retired_at"] is not None
                    and now - float(ip["retired_at"])
                    < ROXY_IP_RETIRE_COOLDOWN_SECONDS
                )
            )
            if ip_retirement_active:
                con.execute(
                    "INSERT INTO roxy_profile_usage("
                    "profile_id, ip_tag, use_count, last_reserved_at, retired_at"
                    ") VALUES (?, ?, 0, ?, ?) "
                    "ON CONFLICT(profile_id) DO UPDATE SET "
                    "ip_tag=excluded.ip_tag, retired_at=excluded.retired_at, "
                    "last_reserved_at=excluded.last_reserved_at",
                    (profile_id, ip_tag, now, now),
                )
                con.commit()
                return {
                    "allowed": False,
                    "reason": "ip_retired",
                    "profile_uses": 0,
                    "ip_uses": int(ip["use_count"] or 0),
                    "retire_profile": True,
                    "retire_ip": True,
                }

            # A healthy Roxy module becomes eligible again after the bounded
            # cooldown.  Start a fresh per-window usage budget instead of
            # permanently exhausting a fixed local proxy inventory.
            if ip is not None and ip["retired_at"] is not None:
                ip = None

            profile_uses = int(profile["use_count"] or 0) + 1 if profile else 1
            ip_uses = int(ip["use_count"] or 0) + 1 if ip else 1
            retire_profile = profile_uses >= limit
            retire_ip = ip_uses >= limit
            profile_retired_at = now if retire_profile or retire_ip else None
            ip_retired_at = now if retire_ip else None

            con.execute(
                "INSERT INTO roxy_profile_usage("
                "profile_id, ip_tag, use_count, last_reserved_at, retired_at"
                ") VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(profile_id) DO UPDATE SET "
                "ip_tag=excluded.ip_tag, use_count=excluded.use_count, "
                "last_reserved_at=excluded.last_reserved_at, "
                "retired_at=excluded.retired_at",
                (profile_id, ip_tag, profile_uses, now, profile_retired_at),
            )
            con.execute(
                "INSERT INTO roxy_ip_usage("
                "ip_tag, use_count, last_reserved_at, retired_at"
                ") VALUES (?, ?, ?, ?) "
                "ON CONFLICT(ip_tag) DO UPDATE SET "
                "use_count=excluded.use_count, last_reserved_at=excluded.last_reserved_at, "
                "retired_at=excluded.retired_at",
                (ip_tag, ip_uses, now, ip_retired_at),
            )
            con.commit()
            return {
                "allowed": True,
                "reason": "",
                "profile_uses": profile_uses,
                "ip_uses": ip_uses,
                "retire_profile": retire_profile or retire_ip,
                "retire_ip": retire_ip,
            }
        except Exception:
            con.rollback()
            raise
        finally:
            con.close()


# ──────────────────────── outlook 号池 ────────────────────────


def parse_lines(text: str, kind: str = "") -> list[dict]:
    """解析导入文本，委托给 mail_providers 注册表。

    kind 指定 → 用该 provider 的格式解析（推荐）
    kind 为空 → 按段数猜（段数唯一时才行，Outlook/Gmail 都是 4 段会猜不出）

    非法行抛 ImportValidationError（带行号和原因），**不再静默跳过**。
    以前这里是 `if len(parts) != 4: continue`，用户看到"导入成功"
    但号少了几个，完全没法排查。
    """
    from mail_providers import parse_import_text

    return parse_import_text(text or "", kind)


def import_accounts(text: str, kind: str = "") -> dict:
    """批量入库。已存在的 email 仅在凭证变化时更新。

    解析阶段全对才写：有一行非法就整批拒绝（抛 ImportValidationError），
    不会出现"写进去一半"对不上账的情况。
    """
    rows = parse_lines(text, kind)
    now = time.time()
    inserted = updated = skipped = 0
    with _lock:
        con = _conn()
        for r in rows:
            row_kind = r.get("kind") or kind or "outlook"
            # 凭证并集：不同 provider 用不同子集，没有的留空字符串
            password = r.get("password", "") or ""
            client_id = r.get("client_id", "") or ""
            refresh = r.get("refresh_token", "") or ""
            relay = r.get("relay_url", "") or ""

            cur = con.execute(
                "SELECT refresh_token, relay_url, kind FROM outlook_accounts WHERE email=?",
                (r["email"],),
            )
            existing = cur.fetchone()
            if existing is None:
                con.execute(
                    "INSERT INTO outlook_accounts(email, password, client_id, refresh_token, "
                    "relay_url, kind, status, imported_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, 'available', ?)",
                    (r["email"], password, client_id, refresh, relay, row_kind, now),
                )
                inserted += 1
            elif (
                (existing["refresh_token"] or "") != refresh
                or (existing["relay_url"] or "") != relay
                or (existing["kind"] or "") != row_kind
            ):
                # 凭证或类型变了 → 覆盖并重置为可用
                con.execute(
                    "UPDATE outlook_accounts SET refresh_token=?, password=?, client_id=?, "
                    "relay_url=?, kind=?, status='available', imported_at=?, fail_reason=NULL "
                    "WHERE email=?",
                    (refresh, password, client_id, relay, row_kind, now, r["email"]),
                )
                updated += 1
            else:
                skipped += 1
        con.commit()
    return {"parsed": len(rows), "inserted": inserted, "updated": updated, "skipped": skipped}


def count_accounts(status: str = "", kind: str = "") -> int:
    con = _conn()
    sql = "SELECT COUNT(*) FROM outlook_accounts"
    where, args = [], []
    if status:
        where.append("status=?")
        args.append(status)
    if kind:
        where.append("kind=?")
        args.append(kind.strip().lower())
    if where:
        sql += " WHERE " + " AND ".join(where)
    return con.execute(sql, args).fetchone()[0]


def list_accounts(
    status: str = "", limit: int = 50, offset: int = 0, kind: str = ""
) -> list[dict]:
    con = _conn()
    sql = "SELECT * FROM outlook_accounts"
    where, args = [], []
    if status:
        where.append("status=?")
        args.append(status)
    if kind:
        where.append("kind=?")
        args.append(kind.strip().lower())
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY imported_at DESC LIMIT ? OFFSET ?"
    args += [limit, offset]
    return [dict(r) for r in con.execute(sql, args).fetchall()]


def stats_by_kind() -> dict:
    """按邮箱类型分组统计，给 WebUI 顶部展示"每种邮箱各有多少号"。"""
    con = _conn()
    cur = con.execute(
        "SELECT kind, status, COUNT(*) AS n FROM outlook_accounts GROUP BY kind, status"
    )
    out: dict[str, dict] = {}
    for r in cur.fetchall():
        k = r["kind"] or "outlook"
        slot = out.setdefault(
            k, {"available": 0, "in_use": 0, "done": 0, "failed": 0, "total": 0}
        )
        slot[r["status"]] = r["n"]
        slot["total"] += r["n"]
    return out


def get_account(email: str) -> Optional[dict]:
    con = _conn()
    cur = con.execute("SELECT * FROM outlook_accounts WHERE email=?", (email.lower(),))
    row = cur.fetchone()
    return dict(row) if row else None


def claim_account(email: str) -> Optional[dict]:
    """原子 claim 指定邮箱（available / failed -> in_use）。

    failed 也允许重试 claim：之前 OpenAI 风控误判 / 网络抖动等导致 fail 的号
    应允许用户手动重试，已 done 的号才禁止重 claim（防误覆盖凭证）。

    按 email 指定时不过滤 kind —— 用户点名要这个号，它是什么类型
    由记录自己的 kind 列说了算，调用方读 account["kind"] 即可。
    """
    email = (email or "").strip().lower()
    if not email:
        return None
    with _lock:
        con = _conn()
        cur = con.execute(
            "SELECT * FROM outlook_accounts WHERE email=? AND status IN ('available', 'failed')",
            (email,),
        )
        row = cur.fetchone()
        if not row:
            return None
        rc = con.execute(
            "UPDATE outlook_accounts SET status='in_use', claimed_at=?, fail_reason=NULL "
            "WHERE email=? AND status IN ('available', 'failed')",
            (time.time(), email),
        )
        con.commit()
        if rc.rowcount != 1:
            return None
        return dict(row)


def claim_next(kind: str = "") -> Optional[dict]:
    """原子 claim 任一 available 号。

    kind 指定 → 只从该类型里挑（"选了 gmail 就只跑 gmail 号"）
    kind 为空 → 全池子里挑最早导入的

    多类型混放的关键就在这里：号池里 outlook 和 gmail 并存，
    但当前配置选了哪种，就只 claim 哪种，不会串。
    """
    k = (kind or "").strip().lower()
    with _lock:
        con = _conn()
        for _ in range(50):  # 有限重试，避免并发抢号时无限递归爆栈
            if k:
                cur = con.execute(
                    "SELECT * FROM outlook_accounts WHERE status='available' AND kind=? "
                    "ORDER BY imported_at ASC LIMIT 1",
                    (k,),
                )
            else:
                cur = con.execute(
                    "SELECT * FROM outlook_accounts WHERE status='available' "
                    "ORDER BY imported_at ASC LIMIT 1"
                )
            row = cur.fetchone()
            if not row:
                return None
            rc = con.execute(
                "UPDATE outlook_accounts SET status='in_use', claimed_at=? "
                "WHERE email=? AND status='available'",
                (time.time(), row["email"]),
            )
            con.commit()
            if rc.rowcount == 1:
                return dict(row)
            # 被别的线程抢走了，换下一个再试
        return None


def mark_done(email: str) -> None:
    with _lock:
        con = _conn()
        con.execute(
            "UPDATE outlook_accounts SET status='done', finished_at=?, fail_reason=NULL WHERE email=?",
            (time.time(), email.lower()),
        )
        con.commit()


def mark_failed(email: str, reason: str = "") -> None:
    safe_reason = sanitize_text(reason)[:500]
    with _lock:
        con = _conn()
        con.execute(
            "UPDATE outlook_accounts SET status='failed', finished_at=?, fail_reason=? WHERE email=?",
            (time.time(), safe_reason, email.lower()),
        )
        # A later retry may fail after this identity was already completed by
        # registration/recovery.  Never let the weaker retry outcome demote the
        # durable five-field completion evidence.
        _reconcile_completed_mailbox_status(con, email)
        con.commit()


def release_unused(email: str) -> str:
    """Release a truly fresh claim, but quarantine resumable registration history.

    A server-accepted password or any persisted authorization/MFA field means the
    remote identity may already exist.  Returning that mailbox to ``available``
    would let the auto loop treat it as a brand-new signup and repeat account
    creation.  Candidate-only passwords remain retryable because they were never
    accepted by the server.
    """
    normalized = (email or "").strip().lower()
    with _lock:
        con = _conn()
        # Reconcile first while the row is still ``in_use``.  Completed
        # identities become ``done``; the UPDATE below then handles only truly
        # incomplete rows.  Explicit reset_to_available remains unaffected.
        _reconcile_completed_mailbox_status(con, normalized)
        row = con.execute(
            "SELECT password, access_token, session_token, refresh_token, "
            "id_token, device_id, csrf_token, cookie_header, totp_secret, "
            "totp_factor_id, extra_json FROM registered WHERE email=?",
            (normalized,),
        ).fetchone()
        history_state = registration_history_state(dict(row) if row else {})
        if history_state in ("password_registered", "authorized_pending"):
            reason = (
                "检测到历史注册进度，需续接处理；已禁止自动按全新账号重试"
            )
            con.execute(
                "UPDATE outlook_accounts SET status='failed', finished_at=?, "
                "fail_reason=? WHERE email=? AND status='in_use'",
                (time.time(), reason, normalized),
            )
            released_status = "failed"
        else:
            con.execute(
                "UPDATE outlook_accounts SET status='available', claimed_at=NULL, "
                "finished_at=NULL, fail_reason=NULL "
                "WHERE email=? AND status='in_use'",
                (normalized,),
            )
            released_status = "available"
        con.commit()
        return released_status


def reset_to_available(email: str) -> bool:
    """手动重置单个号：done / failed → available，清空时间戳和失败原因。

    场景：注册成功但 refresh_token 没拿到，主人想重新跑一遍这个号。
    """
    with _lock:
        con = _conn()
        rc = con.execute(
            "UPDATE outlook_accounts SET status='available', claimed_at=NULL, "
            "finished_at=NULL, fail_reason=NULL "
            "WHERE lower(email)=lower(?)",
            (email,),
        )
        con.commit()
        return rc.rowcount > 0


def bulk_reset_to_available(emails: list[str]) -> int:
    """批量重置多个号。返回实际被改的行数。"""
    if not emails:
        return 0
    with _lock:
        con = _conn()
        rc = con.execute(
            f"UPDATE outlook_accounts SET status='available', claimed_at=NULL, "
            f"finished_at=NULL, fail_reason=NULL "
            f"WHERE lower(email) IN ({','.join(['lower(?)'] * len(emails))})",
            emails,
        )
        con.commit()
        return rc.rowcount


def reset_failed_to_available() -> int:
    """把所有 failed 号一次性重置为 available（清掉 fail_reason）。返回受影响行数。

    场景：代理短暂抽风导致一波号被冤枉标 failed，主人想给它们一次机会。
    """
    with _lock:
        con = _conn()
        rc = con.execute(
            "UPDATE outlook_accounts SET status='available', fail_reason=NULL, "
            "finished_at=NULL WHERE status='failed'"
        )
        con.commit()
        return rc.rowcount


def release_stale_in_use(stale_seconds: float = 1800) -> int:
    """把 claimed_at 超过 N 秒还在 in_use 的号释放回 available。

    场景：上次 webui 强退/进程崩溃，号卡在 in_use 永远不释放。默认 30 分钟。
    """
    with _lock:
        con = _conn()
        cutoff = time.time() - stale_seconds
        rc = con.execute(
            "UPDATE outlook_accounts SET status='available', claimed_at=NULL "
            "WHERE status='in_use' AND (claimed_at IS NULL OR claimed_at < ?)",
            (cutoff,),
        )
        con.commit()
        return rc.rowcount


def delete_account(email: str) -> bool:
    with _lock:
        con = _conn()
        rc = con.execute("DELETE FROM outlook_accounts WHERE email=?", (email.lower(),))
        con.commit()
        return rc.rowcount > 0


def delete_accounts_by_status(status: str) -> int:
    """按状态批量删除。status 必须是 available/in_use/done/failed 之一；
    传 'all' 删全部。返回受影响行数。"""
    valid = {"available", "in_use", "done", "failed", "all"}
    s = (status or "").strip().lower()
    if s not in valid:
        return 0
    with _lock:
        con = _conn()
        if s == "all":
            rc = con.execute("DELETE FROM outlook_accounts")
        else:
            rc = con.execute("DELETE FROM outlook_accounts WHERE status=?", (s,))
        con.commit()
        return rc.rowcount


def delete_accounts_by_emails(emails: list[str]) -> int:
    """按 email 列表批量删除。返回受影响行数。"""
    cleaned = [e.strip().lower() for e in (emails or []) if e and e.strip()]
    if not cleaned:
        return 0
    with _lock:
        con = _conn()
        placeholders = ",".join("?" * len(cleaned))
        rc = con.execute(
            f"DELETE FROM outlook_accounts WHERE email IN ({placeholders})",
            cleaned,
        )
        con.commit()
        return rc.rowcount


def stats() -> dict:
    con = _conn()
    cur = con.execute(
        "SELECT status, COUNT(*) AS n FROM outlook_accounts GROUP BY status"
    )
    out = {"available": 0, "in_use": 0, "done": 0, "failed": 0, "total": 0}
    for r in cur.fetchall():
        out[r["status"]] = r["n"]
        out["total"] += r["n"]
    return out


# ──────────────────────── 注册结果存储 ────────────────────────


def save_registered(d: dict) -> None:
    """保存注册成功（或部分成功）的凭证。覆盖同邮箱旧记录。

    凭证三件套（access_token / session_token / refresh_token）单独存列；
    其余字段（如 device_id / cookie_header / id_token / 自定义元数据）打包进 extra_json。
    """
    email = (d.get("email") or "").lower()
    if not email:
        return
    password = d.get("password", "") or ""
    extra = {k: v for k, v in d.items() if k not in {
        "email", "password", "access_token", "session_token", "refresh_token",
        "id_token", "device_id", "csrf_token", "cookie_header",
        "totp_secret", "totp_factor_id",
    }}
    with _lock:
        con = _conn()
        # ⚠️ INSERT OR REPLACE 是**整行替换**，不是按字段合并 —— 没写的列会被清空。
        #    重跑同一个邮箱时这会咬人：第一轮 register_password 设了密码但 OTP 超时，
        #    save_password_early 把密码存下了；第二轮 OpenAI 已经认识这个邮箱了，
        #    走 passwordless_login 分支根本不调 register_password，
        #    这一轮的 d["password"] 是空的 —— 直接 REPLACE 就把上一轮的密码冲没了。
        #    密码是 OpenAI 侧的**持久状态**，"这一轮没设" ≠ "这个号没有密码"，
        #    所以空值不覆盖非空旧值。
        #    token 三件套正相反：每轮跑都是全新的，旧的可能已失效，照常整列覆盖。
        # totp_secret 和密码同理，甚至更严：secret【一次性下发、服务端取不回】，
        #    丢了 = 该号 2FA 永久锁死。重跑同邮箱（已绑过 2FA）时这一轮不会再绑，
        #    d 里没有 secret —— 绝不能拿空值把库里已存的 secret 冲没。
        #    与密码合成一次 SELECT，顺带把两列旧值一起兜住。
        totp_secret = (d.get("totp_secret") or "").strip()
        totp_factor_id = (d.get("totp_factor_id") or "").strip()
        if not password or not totp_secret:
            row = con.execute(
                "SELECT password, totp_secret, totp_factor_id, extra_json, "
                "access_token, session_token, refresh_token "
                "FROM registered WHERE email=?",
                (email,),
            ).fetchone()
            if row:
                old_record = dict(row)
                old_extra = {}
                if old_record.get("extra_json"):
                    try:
                        old_extra = json.loads(old_record["extra_json"])
                    except Exception:
                        old_extra = {}
                old_pending_reason = str(old_extra.get("pending_reason") or "")
                # Any pending marker means the stored password is not yet a
                # trusted server-confirmed credential.  In particular,
                # password_registered_unverified is an early escrow value, not
                # evidence that the account can log in with that password.
                old_password_is_unverified = bool(old_extra.get("pending"))
                old_password = (row["password"] or "").strip()
                if (
                    not password
                    and old_password
                    and old_pending_reason == PASSWORD_PENDING_REGISTERED
                ):
                    # The registration endpoint accepted this exact value in an
                    # earlier step. Preserve the escrowed password and its
                    # unverified marker when a later partial save has no password.
                    password = row["password"]
                    extra["pending"] = True
                    extra["pending_reason"] = PASSWORD_PENDING_REGISTERED
                elif not password and not old_password_is_unverified and old_password:
                    password = row["password"]
                if not totp_secret and (row["totp_secret"] or "").strip():
                    totp_secret = row["totp_secret"]
                    # factor_id 跟着 secret 走：本轮没绑就沿用旧的
                    totp_factor_id = totp_factor_id or (row["totp_factor_id"] or "")
        con.execute(
            "INSERT OR REPLACE INTO registered "
            "(email, password, access_token, session_token, refresh_token, "
            "id_token, device_id, csrf_token, cookie_header, "
            "totp_secret, totp_factor_id, extra_json, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                email,
                password,
                d.get("access_token", ""),
                d.get("session_token", ""),
                d.get("refresh_token", ""),
                d.get("id_token", ""),
                d.get("device_id", ""),
                d.get("csrf_token", ""),
                d.get("cookie_header", ""),
                totp_secret,
                totp_factor_id,
                json.dumps(extra, ensure_ascii=False) if extra else None,
                time.time(),
            ),
        )
        _reconcile_completed_mailbox_status(con, email)
        con.commit()


def update_registered_diagnostics(email: str, diagnostics: dict) -> bool:
    """Merge secret-free registration provenance into an existing credential row."""
    normalized = _normalize_email(email)
    if not normalized or not isinstance(diagnostics, dict):
        return False
    with _lock:
        con = _conn()
        try:
            row = con.execute(
                "SELECT extra_json FROM registered WHERE email=?", (normalized,)
            ).fetchone()
            if not row:
                return False
            try:
                extra = json.loads(row["extra_json"] or "{}")
            except (TypeError, ValueError, json.JSONDecodeError):
                extra = {}
            if not isinstance(extra, dict):
                extra = {}
            extra["registration_diagnostics"] = diagnostics
            con.execute(
                "UPDATE registered SET extra_json=? WHERE email=?",
                (json.dumps(extra, ensure_ascii=False), normalized),
            )
            con.commit()
            return True
        finally:
            con.close()


def _account_pool_metadata(extra: object) -> dict[str, object]:
    """Return the public, non-sensitive account-pool projection."""
    if not isinstance(extra, dict):
        return {
            "account_pool": DEFAULT_ACCOUNT_POOL,
            "pool_source": "",
            "pool_updated_at": None,
            "pool_error_code": "",
        }
    pool = str(extra.get("account_pool") or "").strip().lower()
    if pool not in ACCOUNT_POOL_VALUES:
        pool = DEFAULT_ACCOUNT_POOL
    return {
        "account_pool": pool,
        "pool_source": str(extra.get("pool_source") or "")[:80],
        "pool_updated_at": extra.get("pool_updated_at"),
        "pool_error_code": str(extra.get("pool_error_code") or "")[:120],
    }


def get_registered_pool(email: str) -> str:
    row = get_registered(email, include_pending_password=True)
    return str((_account_pool_metadata((row or {}).get("extra"))).get("account_pool"))


def update_registered_pool(
    email: str,
    pool: str,
    *,
    source: str = "momo_check",
    error_code: str = "",
) -> bool:
    normalized = _normalize_email(email)
    normalized_pool = str(pool or "").strip().lower()
    if not normalized or normalized_pool not in ACCOUNT_POOL_VALUES:
        return False
    with _lock:
        con = _conn()
        try:
            row = con.execute(
                "SELECT extra_json FROM registered WHERE email=?", (normalized,)
            ).fetchone()
            if not row:
                return False
            extra: dict[str, object] = {}
            if row["extra_json"]:
                try:
                    parsed = json.loads(row["extra_json"])
                    if isinstance(parsed, dict):
                        extra = parsed
                except Exception:
                    extra = {}
            extra.update({
                "account_pool": normalized_pool,
                "pool_source": str(source or "momo_check")[:80],
                "pool_updated_at": time.time(),
                "pool_error_code": str(error_code or "")[:120],
            })
            con.execute(
                "UPDATE registered SET extra_json=? WHERE email=?",
                (json.dumps(extra, ensure_ascii=False), normalized),
            )
            con.commit()
            return True
        finally:
            con.close()


_REGISTERED_AUTH_FIELDS = (
    "access_token",
    "session_token",
    "refresh_token",
    "id_token",
    "device_id",
    "csrf_token",
    "cookie_header",
)


def registration_history_state(record: dict) -> str:
    """Classify local evidence before deciding whether a mailbox is fresh.

    The state deliberately does not expose credential values.  Only
    ``candidate_not_accepted`` is considered safe to retry as a fresh signup.
    """
    if not isinstance(record, dict) or not record:
        return "fresh"
    if has_completed_registration_evidence(record):
        return "completed"

    extra = record.get("extra")
    if not isinstance(extra, dict):
        extra = {}
        raw_extra = record.get("extra_json")
        if raw_extra:
            try:
                parsed = json.loads(raw_extra)
                if isinstance(parsed, dict):
                    extra = parsed
            except Exception:
                extra = {}

    def present(key: str) -> bool:
        value = record.get(key)
        return bool(value.strip()) if isinstance(value, str) else bool(value)

    if any(present(key) for key in (
        "access_token", "session_token", "refresh_token", "id_token",
        "device_id", "csrf_token", "cookie_header", "totp_secret",
        "totp_factor_id",
    )):
        return "authorized_pending"

    if present("password"):
        if str(extra.get("pending_reason") or "") == PASSWORD_PENDING_CANDIDATE:
            return "candidate_only"
        return "password_registered"
    return "fresh"


def has_completed_registration_evidence(record: dict) -> bool:
    """Return whether saved credentials prove authorization plus local 2FA completion.

    ``list_registered`` exposes token/factor lengths instead of full values, while
    recovery code works with complete rows.  Accept both shapes so the status rule
    stays identical at the API and worker boundaries.
    """
    if not isinstance(record, dict):
        return False

    extra = record.get("extra")
    if not isinstance(extra, dict):
        extra = {}
        raw_extra = record.get("extra_json")
        if raw_extra:
            try:
                extra = json.loads(raw_extra)
            except Exception:
                extra = {}
    if bool(extra.get("pending")):
        return False

    def present(value_key: str, length_key: str) -> bool:
        value = record.get(value_key)
        if isinstance(value, str):
            if value.strip():
                return True
        elif value:
            return True
        try:
            return int(record.get(length_key) or 0) > 0
        except (TypeError, ValueError):
            return False

    return all((
        present("password", "password_len"),
        present("access_token", "at_len"),
        present("session_token", "st_len"),
        present("totp_secret", "totp_len"),
        present("totp_factor_id", "totp_factor_len"),
    ))


def _hide_unverified_pending_password(record: dict) -> dict:
    """Hide passwords that have no evidence of server-side acceptance."""
    extra = record.get("extra")
    if not isinstance(extra, dict):
        extra = {}
        raw_extra = record.get("extra_json")
        if raw_extra:
            try:
                extra = json.loads(raw_extra)
            except Exception:
                extra = {}
    pending_reason = str(extra.get("pending_reason") or "")
    # ``password_registered_unverified`` is deliberately included here.  The
    # value is captured before a later password-login boundary proves it, so it
    # must never leak through normal list/detail/export responses or be treated
    # as a usable primary password.  ``include_pending_password=True`` remains
    # the explicit escrow/recovery view.
    if bool(extra.get("pending")):
        record["password"] = ""
    return record


def merge_registered_credentials(
    email: str,
    updates: dict,
    *,
    create_if_missing: bool = False,
) -> Optional[dict]:
    """Merge non-empty authorization fields without touching password or TOTP.

    Existing-account OTP continuation can produce a valid Session/Access pair
    before this installation has any ``registered`` row for the mailbox.  The
    explicit ``create_if_missing`` mode preserves that durable authorization as
    a password-recovery-pending record instead of discarding it.
    """
    normalized = (email or "").strip().lower()
    if not normalized:
        return None

    values = {
        key: value.strip() if isinstance(value, str) else value
        for key in _REGISTERED_AUTH_FIELDS
        if (value := (updates or {}).get(key)) is not None
        and (not isinstance(value, str) or value.strip())
    }

    with _lock:
        con = _conn()
        try:
            row = con.execute(
                "SELECT extra_json FROM registered WHERE email=?",
                (normalized,),
            ).fetchone()
            if not row:
                if not create_if_missing or not values:
                    return None
                auth_values = {key: "" for key in _REGISTERED_AUTH_FIELDS}
                auth_values.update(values)
                extra_json = json.dumps({
                    "pending": True,
                    "pending_reason": PASSWORD_RECOVERY_REQUIRED,
                }, ensure_ascii=False)
                con.execute(
                    "INSERT INTO registered "
                    "(email, password, access_token, session_token, refresh_token, "
                    "id_token, device_id, csrf_token, cookie_header, extra_json, created_at) "
                    "VALUES (?, '', ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        normalized,
                        auth_values["access_token"],
                        auth_values["session_token"],
                        auth_values["refresh_token"],
                        auth_values["id_token"],
                        auth_values["device_id"],
                        auth_values["csrf_token"],
                        auth_values["cookie_header"],
                        extra_json,
                        time.time(),
                    ),
                )
                con.commit()
            elif values:
                assignments = [f"{key}=?" for key in values]
                parameters = list(values.values())
                con.execute(
                    f"UPDATE registered SET {', '.join(assignments)} WHERE email=?",
                    (*parameters, normalized),
                )
                _reconcile_completed_mailbox_status(con, normalized)
                con.commit()
        finally:
            con.close()

    return get_registered(normalized)


def merge_registered_oauth_tokens(
    email: str,
    *,
    refresh_token: str,
    access_token: str = "",
    id_token: str = "",
) -> Optional[dict]:
    """Store a newly issued OAuth token set without touching account secrets.

    A refresh token is the durable success boundary for the dedicated RT task,
    so callers may not perform a partial write without one. Blank access/ID
    tokens deliberately preserve their existing values.
    """
    normalized_refresh_token = (refresh_token or "").strip()
    if not normalized_refresh_token:
        raise ValueError("refresh_token 不能为空")
    return merge_registered_credentials(
        email,
        {
            "refresh_token": normalized_refresh_token,
            "access_token": (access_token or "").strip(),
            "id_token": (id_token or "").strip(),
        },
    )


def touch_registered_completion(email: str) -> bool:
    """Move a durably completed account to the top of registration results."""
    normalized = (email or "").strip().lower()
    if not normalized:
        return False
    with _lock:
        con = _conn()
        try:
            row = con.execute(
                "SELECT password, access_token, session_token, totp_secret, "
                "totp_factor_id, extra_json FROM registered WHERE email=?",
                (normalized,),
            ).fetchone()
            if not row or not has_completed_registration_evidence(dict(row)):
                return False
            con.execute(
                "UPDATE registered SET created_at=? WHERE email=?",
                (time.time(), normalized),
            )
            con.commit()
            return True
        finally:
            con.close()


def touch_registered_authorized_pending(email: str) -> bool:
    """Move a durable existing-account continuation to the result-list top.

    This deliberately remains separate from ``touch_registered_completion``:
    the candidate password is still pending server-side verification, so the
    row may be surfaced as recent but must not be promoted to completed.
    """
    normalized = (email or "").strip().lower()
    if not normalized:
        return False
    with _lock:
        con = _conn()
        try:
            row = con.execute(
                "SELECT password, access_token, session_token, totp_secret, "
                "totp_factor_id, extra_json FROM registered WHERE email=?",
                (normalized,),
            ).fetchone()
            if not row:
                return False
            record = dict(row)
            extra = {}
            if record.get("extra_json"):
                try:
                    parsed = json.loads(record["extra_json"])
                    if isinstance(parsed, dict):
                        extra = parsed
                except Exception:
                    extra = {}
            required = (
                "access_token",
                "session_token",
                "totp_secret",
                "totp_factor_id",
            )
            if extra.get("pending") is not True:
                return False
            if any(not str(record.get(field) or "").strip() for field in required):
                return False
            con.execute(
                "UPDATE registered SET created_at=? WHERE email=?",
                (time.time(), normalized),
            )
            con.commit()
            return True
        finally:
            con.close()


def save_missing_totp_secret(email: str, secret: str, factor_id: str = "") -> bool:
    """Save a newly activated TOTP secret only while the local value is empty."""
    normalized = (email or "").strip().lower()
    normalized_secret = (secret or "").strip()
    if not normalized or not normalized_secret:
        return False

    with _lock:
        con = _conn()
        try:
            rc = con.execute(
                "UPDATE registered "
                "SET totp_secret=?, totp_factor_id=? "
                "WHERE email=? AND COALESCE(TRIM(totp_secret), '')=''",
                (normalized_secret, (factor_id or "").strip(), normalized),
            )
            if rc.rowcount == 1:
                _reconcile_completed_mailbox_status(con, normalized)
            con.commit()
            return rc.rowcount == 1
        finally:
            con.close()


def save_pending_totp_enrollment(email: str, enrollment: dict) -> None:
    """Durably retain one-time TOTP material before irreversible activation."""
    normalized = (email or "").strip().lower()
    values = {
        key: str((enrollment or {}).get(key) or "").strip()
        for key in ("secret", "factor_id", "session_id")
    }
    if not normalized or not all(values.values()):
        raise ValueError("待激活 TOTP 凭据不完整")
    with _lock:
        con = _conn()
        try:
            con.execute(
                "INSERT INTO pending_totp_enrollments "
                "(email, secret, factor_id, session_id, created_at) "
                "VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(email) DO UPDATE SET "
                "secret=excluded.secret, factor_id=excluded.factor_id, "
                "session_id=excluded.session_id, created_at=excluded.created_at",
                (
                    normalized,
                    values["secret"],
                    values["factor_id"],
                    values["session_id"],
                    time.time(),
                ),
            )
            con.commit()
        finally:
            con.close()


def get_pending_totp_enrollment(email: str) -> Optional[dict]:
    normalized = (email or "").strip().lower()
    if not normalized:
        return None
    con = _conn()
    try:
        row = con.execute(
            "SELECT secret, factor_id, session_id "
            "FROM pending_totp_enrollments WHERE email=?",
            (normalized,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        con.close()


def activate_pending_totp_enrollment(email: str) -> bool:
    """Atomically promote pending TOTP recovery data after activate HTTP 200."""
    normalized = (email or "").strip().lower()
    if not normalized:
        return False
    with _lock:
        con = _conn()
        try:
            pending = con.execute(
                "SELECT secret, factor_id FROM pending_totp_enrollments WHERE email=?",
                (normalized,),
            ).fetchone()
            if not pending:
                return False
            rc = con.execute(
                "UPDATE registered SET totp_secret=?, totp_factor_id=? "
                "WHERE email=? AND COALESCE(TRIM(totp_secret), '')='' "
                "AND COALESCE(TRIM(totp_factor_id), '')=''",
                (pending["secret"], pending["factor_id"], normalized),
            )
            if rc.rowcount != 1:
                con.rollback()
                return False
            con.execute(
                "DELETE FROM pending_totp_enrollments WHERE email=?",
                (normalized,),
            )
            _reconcile_completed_mailbox_status(con, normalized)
            con.commit()
            return True
        finally:
            con.close()


def save_password_early(email: str, password: str) -> None:
    """Persist a password immediately after the registration endpoint accepts it."""
    normalized = (email or "").strip().lower()
    accepted_password = (password or "").strip()
    if not normalized or not accepted_password:
        return
    with _lock:
        con = _conn()
        try:
            row = con.execute(
                "SELECT password, extra_json, access_token, session_token, "
                "refresh_token, id_token, cookie_header, totp_secret, "
                "totp_factor_id FROM registered WHERE email=?",
                (normalized,),
            ).fetchone()
            extra = {}
            if row and row["extra_json"]:
                try:
                    extra = json.loads(row["extra_json"])
                except Exception:
                    extra = {}
            completed_evidence = bool(
                row
                and any(
                    (row[key] or "").strip()
                    for key in (
                        "access_token", "session_token", "refresh_token",
                        "id_token", "cookie_header", "totp_secret",
                        "totp_factor_id",
                    )
                )
            )
            if (
                row
                and extra.get("pending") is False
                and (row["password"] or "").strip()
                and completed_evidence
            ):
                return
            extra["pending"] = True
            extra["pending_reason"] = PASSWORD_PENDING_REGISTERED
            encoded_extra = json.dumps(extra, ensure_ascii=False)
            if row:
                con.execute(
                    "UPDATE registered SET password=?, extra_json=? WHERE email=?",
                    (accepted_password, encoded_extra, normalized),
                )
            else:
                con.execute(
                    "INSERT INTO registered "
                    "(email, password, access_token, session_token, refresh_token, "
                    "id_token, device_id, csrf_token, cookie_header, extra_json, created_at) "
                    "VALUES (?, ?, '', '', '', '', '', '', '', ?, ?)",
                    (normalized, accepted_password, encoded_extra, time.time()),
                )
            con.commit()
        finally:
            con.close()


def save_password_candidate(email: str, password: str) -> bool:
    """Escrow an unaccepted browser candidate without overwriting trusted passwords."""
    normalized = (email or "").strip().lower()
    candidate = (password or "").strip()
    if not normalized or not candidate:
        return False
    with _lock:
        con = _conn()
        try:
            row = con.execute(
                "SELECT password, extra_json FROM registered WHERE email=?",
                (normalized,),
            ).fetchone()
            extra = {}
            if row and row["extra_json"]:
                try:
                    extra = json.loads(row["extra_json"])
                except Exception:
                    extra = {}
            existing_password = (row["password"] or "").strip() if row else ""
            pending_reason = str(extra.get("pending_reason") or "")
            # An early server-accepted value has higher precedence than a
            # later browser candidate, but it is still hidden until explicitly
            # verified by mark_password_verified().
            trusted_existing = bool(existing_password) and (
                extra.get("pending") is False
                or pending_reason == PASSWORD_PENDING_REGISTERED
            )
            if trusted_existing:
                return False
            extra["pending"] = True
            extra["pending_reason"] = PASSWORD_PENDING_CANDIDATE
            encoded_extra = json.dumps(extra, ensure_ascii=False)
            if row:
                con.execute(
                    "UPDATE registered SET password=?, extra_json=? WHERE email=?",
                    (candidate, encoded_extra, normalized),
                )
            else:
                con.execute(
                    "INSERT INTO registered "
                    "(email, password, access_token, session_token, refresh_token, "
                    "id_token, device_id, csrf_token, cookie_header, extra_json, created_at) "
                    "VALUES (?, ?, '', '', '', '', '', '', '', ?, ?)",
                    (normalized, candidate, encoded_extra, time.time()),
                )
            con.commit()
            return True
        finally:
            con.close()


def mark_password_recovery_required(email: str) -> bool:
    """Clear an untrusted password while preserving authorization and MFA evidence."""
    normalized = (email or "").strip().lower()
    if not normalized:
        return False
    with _lock:
        con = _conn()
        try:
            row = con.execute(
                "SELECT extra_json FROM registered WHERE email=?",
                (normalized,),
            ).fetchone()
            if not row:
                return False
            extra = {}
            if row["extra_json"]:
                try:
                    extra = json.loads(row["extra_json"])
                except Exception:
                    extra = {}
            extra["pending"] = True
            extra["pending_reason"] = PASSWORD_RECOVERY_REQUIRED
            con.execute(
                "UPDATE registered SET password='', extra_json=? WHERE email=?",
                (json.dumps(extra, ensure_ascii=False), normalized),
            )
            con.commit()
            return True
        finally:
            con.close()

def normalize_authorized_passwordless_recovery(email: str) -> bool:
    """Atomically classify an authorized passwordless MFA row for recovery."""
    normalized = (email or "").strip().lower()
    if not normalized:
        return False
    with _lock:
        con = _conn()
        try:
            con.execute("BEGIN IMMEDIATE")
            row = con.execute(
                "SELECT password, access_token, session_token, totp_secret, "
                "totp_factor_id, extra_json FROM registered WHERE email=?",
                (normalized,),
            ).fetchone()
            if not row:
                con.rollback()
                return False
            active = con.execute(
                "SELECT 1 FROM active_identity_leases WHERE email=? LIMIT 1",
                (normalized,),
            ).fetchone()
            record = dict(row)
            if (
                active
                or (record.get("password") or "").strip()
                or not _has_saved_authorization(record)
                or not _has_saved_mfa(record)
            ):
                con.rollback()
                return False

            try:
                extra = json.loads(record.get("extra_json") or "{}")
            except (TypeError, ValueError, json.JSONDecodeError):
                extra = {}
            if not isinstance(extra, dict):
                extra = {}
            extra["pending"] = True
            extra["pending_reason"] = PASSWORD_RECOVERY_REQUIRED
            con.execute(
                "UPDATE registered SET password='', extra_json=? WHERE email=?",
                (json.dumps(extra, ensure_ascii=False), normalized),
            )
            con.commit()
            return True
        finally:
            con.close()


def mark_password_verified(
    email: str,
    password: str,
    *,
    allow_recovery_replace: bool = False,
) -> bool:
    """Promote a server-verified password without weakening candidate checks.

    Normal callers may only promote the exact candidate already escrowed in
    ``registered.password``. The explicit recovery endpoint can replace an
    empty password only while ``password_recovery_required`` is still present.
    """
    normalized = (email or "").strip().lower()
    candidate = password if isinstance(password, str) else ""
    if not normalized or not candidate or not candidate.strip():
        return False
    with _lock:
        con = _conn()
        try:
            row = con.execute(
                "SELECT password, extra_json FROM registered WHERE email=?",
                (normalized,),
            ).fetchone()
            if not row:
                return False
            extra = {}
            if row["extra_json"]:
                try:
                    extra = json.loads(row["extra_json"])
                except Exception:
                    extra = {}
            stored_password = row["password"] or ""
            recovery_replace_allowed = bool(
                allow_recovery_replace
                and not stored_password
                and str(extra.get("pending_reason") or "")
                in PASSWORD_RECOVERY_PENDING_REASONS
            )
            if stored_password != candidate and not recovery_replace_allowed:
                return False
            extra["pending"] = False
            extra.pop("pending_reason", None)
            con.execute(
                "UPDATE registered SET password=?, extra_json=? WHERE email=?",
                (
                    candidate,
                    json.dumps(extra, ensure_ascii=False) if extra else None,
                    normalized,
                ),
            )
            _reconcile_completed_mailbox_status(con, normalized)
            con.commit()
            return True
        finally:
            con.close()


def list_password_recovery_emails(limit: int = 100) -> list[str]:
    """Return registered identities explicitly waiting for password recovery.

    The pending marker lives in ``extra_json`` for backwards compatibility with
    older databases, so the predicate is parsed in Python instead of relying on
    SQLite JSON1 being enabled on every installation.
    """
    try:
        bounded_limit = max(1, min(int(limit), 1000))
    except (TypeError, ValueError):
        bounded_limit = 100
    con = _conn()
    try:
        rows = con.execute(
            "SELECT email, extra_json FROM registered ORDER BY created_at ASC"
        ).fetchall()
    finally:
        con.close()
    result: list[str] = []
    for row in rows:
        try:
            extra = json.loads(row["extra_json"] or "{}")
        except (TypeError, ValueError, json.JSONDecodeError):
            extra = {}
        if not isinstance(extra, dict):
            continue
        if str(extra.get("pending_reason") or "").strip() not in PASSWORD_RECOVERY_PENDING_REASONS:
            continue
        email = str(row["email"] or "").strip().lower()
        if email:
            result.append(email)
        if len(result) >= bounded_limit:
            break
    return result


def page_password_reset_candidates(limit: int = 100, offset: int = 0, query: str = "", selected: list[str] | None = None) -> dict:
    """List recovery candidates without selecting credentials or mailbox URLs."""
    limit, offset = max(1, min(int(limit), 100)), max(0, int(offset))
    query = str(query or "").strip().lower()
    con = _conn()
    try:
        records = con.execute("""
            SELECT email, extra_json,
                EXISTS(SELECT 1 FROM outlook_accounts AS box WHERE lower(box.email)=lower(registered.email))
                OR EXISTS(SELECT 1 FROM rebind_mailboxes AS box WHERE lower(box.email)=lower(registered.email)) AS mailbox_ready,
                EXISTS(SELECT 1 FROM active_identity_leases AS lease WHERE lower(lease.email)=lower(registered.email))
                OR EXISTS(SELECT 1 FROM runs AS run WHERE lower(run.email)=lower(registered.email)
                    AND run.status IN ('running','pending','in_progress','cancelling')) AS active
            FROM registered ORDER BY created_at DESC, email ASC
        """).fetchall()
    finally:
        con.close()
    rows = []
    for record in records:
        try:
            extra = json.loads(record['extra_json'] or '{}')
        except (TypeError, ValueError):
            continue
        if not isinstance(extra, dict):
            continue
        reason = str(extra.get('pending_reason') or '').strip()
        email = str(record['email'] or '').strip().lower()
        if reason not in PASSWORD_RECOVERY_PENDING_REASONS:
            continue
        blocked = ('账号已冻结' if extra.get('frozen') else
                   '账号正在其他任务中' if record['active'] else
                   '缺少接码来源' if not record['mailbox_ready'] else '')
        rows.append({'email':email, 'registration_status':'password_recovery_required',
                     'pending_reason':reason, 'mailbox_ready':bool(record['mailbox_ready']),
                     'selectable':not blocked, 'blocked_reason':blocked})
    selected_set = set(selected or [])
    matching = [row for row in rows if query in row['email']]
    return {'total':len(matching), 'items':matching[offset:offset + limit],
            'selection_items':[row for row in rows if row['email'] in selected_set]}


def password_reset_task_metadata(run_id: str) -> dict | None:
    """Return only the selected workspace's reset-task metadata and receipt."""
    con = _conn()
    try:
        con.execute('BEGIN')
        row = con.execute("SELECT run_id,status,result_json FROM runs WHERE run_id=? AND run_kind='password_reset'", (run_id,)).fetchone()
        if not row:
            return None
        emails = [item[0] for item in con.execute(
            'SELECT email FROM active_identity_leases WHERE run_id=? ORDER BY email', (run_id,))]
        return {**dict(row), 'emails':emails}
    finally:
        con.close()


def normalize_totp_secret(raw: str) -> str:
    """把用户手填的 TOTP secret 规范化成可用的 base32，非法值抛 ValueError。

    登录侧（auth_flow._totp_now）拿到 secret 直接 b32decode，**不做任何校验** ——
    脏值存进去要等到真登录时才炸，那时只看到一句 base32 解码异常，
    根本看不出是手填填错了。所以校验必须挡在写库这一关。

    接受的输入：
      - 裸 base32:  JBSWY3DPEHPK3PXP / jbswy3dp ehpk 3pxp / JBSW-Y3DP-EHPK
      - otpauth URI: otpauth://totp/ChatGPT:a@b.com?secret=JBSWY3DP&issuer=...
        （从手机 App 导出/二维码解码出来的就是这个格式，直接粘进来很常见）
    """
    s = (raw or "").strip()
    if not s:
        return ""
    # otpauth:// URI 抽 secret 参数
    if s.lower().startswith("otpauth://"):
        try:
            from urllib.parse import urlparse, parse_qs
            qs = parse_qs(urlparse(s).query)
            s = (qs.get("secret") or [""])[0]
        except Exception:
            raise ValueError("otpauth 链接解析失败，请直接填 secret")
        if not s:
            raise ValueError("otpauth 链接里没有 secret 参数")
    # 去掉分隔符（手机 App 展示时常带空格/连字符）并统一大写
    s = s.replace(" ", "").replace("-", "").replace("_", "").upper()
    # base32 只有 A-Z 和 2-7，先挡掉明显非法字符再解码，报错更好懂
    if not s or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=" for c in s):
        raise ValueError("TOTP secret 含非法字符（base32 只允许 A-Z 和 2-7）")
    try:
        # 补 padding 后试解，解得开才算合法。auth_flow 那边也是这么补的。
        decoded = base64.b32decode(s + "=" * (-len(s) % 8))
    except Exception:
        raise ValueError("TOTP secret 不是合法的 base32")
    if len(decoded) < 10:
        raise ValueError(f"TOTP secret 太短（解出 {len(decoded)} 字节，通常应为 20 字节）")
    return s


def update_registered_manual(email: str, password: Optional[str] = None,
                             totp_secret: Optional[str] = None) -> bool:
    """手动修正某个已注册账号的密码 / TOTP secret。

    ⚠️ 只改**本地库**，不会同步到 OpenAI —— 这里改密码不等于改了账号密码。
       用途是把外部已知的凭证补进来，或修正记录错误。

    传 None = 该字段不动（不是清空）。用 None 而不是空串做"不修改"的标记，
    是为了留出"主人真想清空某字段"的余地（传空串即清空）。

    totp_secret 会先过 normalize_totp_secret 校验，非法直接抛 ValueError；
    宁可这里报错，也不能让脏值躺进库里等登录时才炸。

    返回 False 表示该邮箱不存在（不会凭空插入新行 —— 手填是"修正已有记录"，
    真要新增外部账号是另一件事，走单独的导入功能）。
    """
    email = (email or "").strip().lower()
    if not email:
        return False
    sets, vals = [], []
    if password is not None:
        sets.append("password=?")
        vals.append(password)
    if totp_secret is not None:
        # 空串 = 主人主动清空；非空则必须过校验
        sets.append("totp_secret=?")
        vals.append(normalize_totp_secret(totp_secret) if totp_secret.strip() else "")
    if not sets:
        return False
    with _lock:
        con = _conn()
        row = con.execute("SELECT email FROM registered WHERE email=?", (email,)).fetchone()
        if not row:
            return False
        vals.append(email)
        con.execute(f"UPDATE registered SET {', '.join(sets)} WHERE email=?", vals)
        con.commit()
        return True


def get_registered_operation_state(email: str) -> dict:
    """Return a secret-free authorization decision for credential operations."""
    normalized = (email or "").strip().lower()
    if not normalized:
        return {
            "exists": False,
            "complete": False,
            "unresolved_failed": False,
            "active": False,
            "pool_status": "",
        }
    con = _conn()
    try:
        row = con.execute(
            "SELECT password, access_token, session_token, totp_secret, "
            "totp_factor_id, extra_json FROM registered WHERE lower(email)=lower(?)",
            (normalized,),
        ).fetchone()
        pool = con.execute(
            "SELECT status FROM outlook_accounts WHERE lower(email)=lower(?)",
            (normalized,),
        ).fetchone()
        latest_registration = con.execute(
            "SELECT status FROM runs "
            "WHERE lower(email)=lower(?) "
            "AND COALESCE(run_kind, 'registration')='registration' "
            "ORDER BY started_at DESC LIMIT 1",
            (normalized,),
        ).fetchone()
        active_run = con.execute(
            "SELECT 1 FROM runs AS run "
            "WHERE run.status IN ('running', 'pending', 'in_progress', 'cancelling') "
            "AND (lower(run.email)=lower(?) OR EXISTS ("
            "SELECT 1 FROM active_identity_leases AS lease "
            "WHERE lease.run_id=run.run_id AND lower(lease.email)=lower(?)"
            ")) LIMIT 1",
            (normalized, normalized),
        ).fetchone()
    finally:
        con.close()
    complete = bool(row and has_completed_registration_evidence(dict(row)))
    extra: dict = {}
    if row and row["extra_json"]:
        try:
            parsed_extra = json.loads(row["extra_json"])
            if isinstance(parsed_extra, dict):
                extra = parsed_extra
        except (TypeError, ValueError, json.JSONDecodeError):
            extra = {}
    authorized_pending = bool(
        row
        and not complete
        and _has_saved_authorization(dict(row))
        and bool(extra.get("pending"))
    )
    pool_status = (pool["status"] or "") if pool else ""
    latest_registration_status = (
        (latest_registration["status"] or "") if latest_registration else ""
    )
    unresolved_failed = bool(
        row
        and not complete
        and (
            pool_status == "failed"
            or latest_registration_status in ("failed", "cancelled")
        )
    )
    return {
        "exists": row is not None,
        "complete": complete,
        "authorized_pending": authorized_pending,
        "unresolved_failed": unresolved_failed,
        "active": active_run is not None,
        "pool_status": pool_status,
        "latest_registration_status": latest_registration_status,
    }


def has_active_registered_run() -> bool:
    """Return whether any saved credential identity still owns an active run."""
    con = _conn()
    try:
        return con.execute(
            "SELECT 1 FROM runs AS run "
            "WHERE run.status IN "
            "('running', 'pending', 'in_progress', 'cancelling') "
            "AND (EXISTS (SELECT 1 FROM registered AS credential "
            "WHERE lower(credential.email)=lower(run.email)) "
            "OR EXISTS (SELECT 1 FROM active_identity_leases AS lease "
            "INNER JOIN registered AS credential "
            "ON lower(credential.email)=lower(lease.email) "
            "WHERE lease.run_id=run.run_id)) "
            "LIMIT 1"
        ).fetchone() is not None
    finally:
        con.close()


def set_registered_frozen(email: str, frozen: bool) -> bool:
    """Set an operator-only freeze marker without changing credentials."""
    normalized = (email or "").strip().lower()
    if not normalized:
        return False
    with _lock:
        con = _conn()
        try:
            row = con.execute(
                "SELECT extra_json FROM registered WHERE email=?",
                (normalized,),
            ).fetchone()
            if not row:
                return False
            try:
                extra = json.loads(row["extra_json"] or "{}")
            except Exception:
                extra = {}
            if frozen:
                extra["frozen"] = True
            else:
                extra.pop("frozen", None)
            con.execute(
                "UPDATE registered SET extra_json=? WHERE email=?",
                (json.dumps(extra, ensure_ascii=False), normalized),
            )
            con.commit()
            return True
        finally:
            con.close()


def update_plus_check(email: str, plus_info: dict) -> None:
    """把 Plus 检查结果写入 extra_json.plus_check。"""
    email = email.lower()
    con = _conn()
    cur = con.execute("SELECT extra_json FROM registered WHERE email=?", (email,))
    row = cur.fetchone()
    if not row:
        return
    extra = {}
    if row["extra_json"]:
        try:
            extra = json.loads(row["extra_json"])
        except Exception:
            extra = {}
    extra["plus_check"] = plus_info
    with _lock:
        con.execute(
            "UPDATE registered SET extra_json=? WHERE email=?",
            (json.dumps(extra, ensure_ascii=False), email),
        )
        con.commit()


def _has_saved_authorization(record: dict) -> bool:
    if any(
        (record.get(field) or "").strip()
        for field in ("access_token", "session_token")
    ):
        return True
    try:
        return int(record.get("at_len") or 0) > 0 or int(record.get("st_len") or 0) > 0
    except (TypeError, ValueError):
        return False


def _has_saved_mfa(record: dict) -> bool:
    return any(
        (record.get(field) or "").strip()
        for field in ("totp_secret", "totp_factor_id")
    )


def _registered_where(
    filt: str,
    query: str = "",
    plus_filter: str = "all",
    pool_filter: str = "all",
) -> tuple[str, list[object]]:
    conditions = []
    params: list[object] = []
    plus_status = (
        "CASE WHEN json_valid(COALESCE(extra_json, '')) "
        "THEN json_extract(extra_json, '$.plus_check.status') END"
    )
    frozen_marker = (
        "CASE WHEN json_valid(COALESCE(extra_json, '')) "
        "THEN json_extract(extra_json, '$.frozen') END"
    )
    result_group = (
        "CASE WHEN json_valid(COALESCE(extra_json, '')) "
        "THEN json_extract(extra_json, '$.result_group') END"
    )
    account_pool = (
        "CASE WHEN json_valid(COALESCE(extra_json, '')) "
        "AND json_extract(extra_json, '$.account_pool') IN ('momo', 'upi') "
        "THEN json_extract(extra_json, '$.account_pool') ELSE 'pending' END"
    )
    # 已成功换绑的账号仍保存在 registered 表中供详情、导出和后续认证读取，
    # 但不再属于普通“注册结果”列表。注册执行流程不受这个展示分组影响。
    conditions.append(f"COALESCE({result_group}, '') != 'rebind'")
    if filt == "has_rt":
        conditions.append("length(refresh_token) > 0")
    elif filt == "no_rt":
        conditions.append("coalesce(length(refresh_token),0) = 0")
    elif filt == "unchecked":
        conditions.append(f"{plus_status} IS NULL")
    elif filt == "free":
        conditions.append(f"{plus_status} = 'free'")
    elif filt == "plus":
        conditions.append(f"{plus_status} IN ('plus_eligible', 'plus_active')")
    elif filt == "banned":
        conditions.append(f"{plus_status} = 'banned'")
    elif filt == "token_invalid":
        # Legacy combined filter compatibility. New callers should use
        # plus_filter so RT and Plus conditions can be combined.
        conditions.append(f"{plus_status} = 'token_invalid'")

    normalized_plus_filter = (plus_filter or "all").strip().lower()
    if normalized_plus_filter == "frozen":
        conditions.append(f"{frozen_marker} = 1")
    elif normalized_plus_filter == "unchecked":
        conditions.append(f"{plus_status} IS NULL")
    elif normalized_plus_filter == "plus":
        conditions.append(f"{plus_status} IN ('plus_eligible', 'plus_active')")
    elif normalized_plus_filter == "abnormal":
        conditions.append(f"{plus_status} IN ('token_invalid', 'banned', 'error')")
    elif normalized_plus_filter == "qualification_eligible":
        from .qualification_store import latest_results
        from .qualification_status import qualification_category
        eligible = [email for email, row in latest_results().items()
                    if qualification_category(row) == 'eligible']
        # One JSON parameter avoids SQLite's variable limit for a full pool.
        # Apply this condition before COUNT and LIMIT/OFFSET in all callers.
        conditions.append("LOWER(email) IN (SELECT value FROM json_each(?))")
        params.append(json.dumps(eligible))
    elif normalized_plus_filter in {
        "free", "plus_eligible", "plus_active", "token_invalid", "banned", "error",
    }:
        conditions.append(f"{plus_status} = ?")
        params.append(normalized_plus_filter)

    normalized_pool_filter = (pool_filter or "all").strip().lower()
    if normalized_pool_filter in ACCOUNT_POOL_VALUES:
        conditions.append(f"{account_pool} = ?")
        params.append(normalized_pool_filter)

    normalized_query = (query or "").strip().lower()
    if normalized_query:
        escaped_query = (
            normalized_query
            .replace("\\", "\\\\")
            .replace("%", "\\%")
            .replace("_", "\\_")
        )
        conditions.append("LOWER(email) LIKE ? ESCAPE '\\'")
        params.append(f"%{escaped_query}%")

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    return where, params


def count_registered(
    filter_rt: str = "all",
    query: str = "",
    plus_filter: str = "all",
    pool_filter: str = "all",
) -> int:
    con = _conn()
    where, params = _registered_where(filter_rt, query, plus_filter, pool_filter)
    cur = con.execute(f"SELECT COUNT(*) FROM registered {where}", params)
    count = cur.fetchone()[0]
    con.close()
    return count


def list_registered_selection(
    filter_rt: str = "all", query: str = "", plus_filter: str = "all",
    pool_filter: str = "all", limit: int = 2001,
) -> list[str]:
    """Snapshot the filtered account identities without reading credentials."""
    con = _conn()
    try:
        where, params = _registered_where(filter_rt, query, plus_filter, pool_filter)
        rows = con.execute(
            f"SELECT email FROM registered {where} ORDER BY created_at DESC, email LIMIT ?",
            (*params, limit),
        ).fetchall()
        return [row["email"] for row in rows]
    finally:
        con.close()


def list_registered(
    limit: int = 20,
    offset: int = 0,
    filter_rt: str = "all",
    query: str = "",
    plus_filter: str = "all",
    pool_filter: str = "all",
) -> list[dict]:
    con = _conn()
    where, params = _registered_where(filter_rt, query, plus_filter, pool_filter)
    cur = con.execute(
        f"SELECT email, password, totp_secret, length(totp_factor_id) AS totp_factor_len, "
        f"length(access_token) AS at_len, length(session_token) AS st_len, "
        f"length(refresh_token) AS rt_len, extra_json, created_at FROM registered "
        f"{where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
        (*params, limit, offset),
    )
    result_rows = cur.fetchall()
    force_delete_flags = _force_delete_eligibility_flags(
        con,
        {
            (row["email"] or "").strip().lower()
            for row in result_rows
            if row["email"]
        },
    )
    con.close()
    rows = []
    for r in result_rows:
        d = dict(r)
        extra = {}
        plus = None
        if d.get("extra_json"):
            try:
                extra = json.loads(d["extra_json"])
                plus = extra.get("plus_check")
            except Exception:
                extra = {}
        d.update(_account_pool_metadata(extra))
        if isinstance(extra.get("registration_diagnostics"), dict):
            d["registration_diagnostics"] = extra["registration_diagnostics"]
        d["plus_check"] = plus
        d["pending_reason"] = str(extra.get("pending_reason") or "")
        d["frozen"] = bool(extra.get("frozen"))
        d["authorization_present"] = _has_saved_authorization(d)
        d["mfa_present"] = _has_saved_mfa(d)
        d["registration_pending"] = not has_completed_registration_evidence(d)
        d["force_deletable"] = bool(
            force_delete_flags.get((d.get("email") or "").strip().lower())
        )
        d["extra"] = extra
        _hide_unverified_pending_password(d)
        d.pop("extra", None)
        d.pop("extra_json", None)
        rows.append(d)
    return rows


_FAILED_ATTEMPT_PHASE_LABELS = {
    "network": ("网络阶段", "网络或代理异常"),
    "browser": ("浏览器注册阶段", "浏览器流程失败（旧记录无阶段信息）"),
    "warmup": ("初始化阶段", "初始化失败"),
    "sentinel": ("安全校验阶段", "安全校验失败"),
    "signup": ("提交邮箱阶段", "提交邮箱失败"),
    "password": ("密码阶段", "密码注册失败"),
    "email_otp": ("邮箱验证阶段", "邮箱验证码失败"),
    "account": ("创建账号阶段", "创建账号失败"),
    "authorization": ("授权阶段", "获取授权失败"),
    "two_factor": ("2FA 阶段", "2FA 绑定失败"),
    "cancelled": ("任务阶段", "任务已取消"),
    "unknown": ("未知阶段", "注册流程失败"),
}


def _classify_failed_attempt(
    error: str,
    pool_reason: str,
    category: str,
    diagnostic: str = "",
) -> tuple[str, str]:
    """Reduce internal errors to an allowlisted, credential-free UI reason."""
    text = f"{error or ''}\n{pool_reason or ''}\n{diagnostic or ''}".lower()

    structured_phase = re.search(
        r"\bfailure_phase=([a-z][a-z0-9_]{0,79})\b",
        text,
    )
    if structured_phase:
        phase = {
            "worker_preflight": "warmup",
            "open_profile": "warmup",
            "browser_prepare": "warmup",
            "email_submit": "signup",
            "password_route": "password",
            "password_submit": "password",
            "otp": "email_otp",
            "otp_wait": "email_otp",
            "otp_submit": "email_otp",
            "otp_submitted": "email_otp",
            "profile": "account",
            "browser_complete": "authorization",
        }.get(structured_phase.group(1), "unknown")
        reason = _FAILED_ATTEMPT_PHASE_LABELS[phase][1]
        if phase == "email_otp" and any(
            marker in text for marker in ("timeout", "timed out", "超时")
        ):
            reason = "邮箱验证码超时"
        return phase, reason

    def has(*markers: str) -> bool:
        return any(marker.lower() in text for marker in markers)

    if has("用户取消", "cancelled", "canceled"):
        phase = "cancelled"
    elif has("429", "rate_limit", "too many requests"):
        phase = "network"
    elif has("cloudflare", "forbidden", "unsupported_country", "403"):
        phase = "network"
    elif has("warmup", "oai-did", "invalid_state"):
        phase = "warmup"
    elif has("2fa", "totp", "mfa") and not has("otp secret"):
        phase = "two_factor"
    elif has(
        "callback", "回调", "access_token", "session token", "session_token",
        "refresh_token", "获取认证", "认证 session", "st=无 at=无",
    ):
        phase = "authorization"
    elif has("create_account", "创建账户", "创建账号", "上游建号"):
        phase = "account"
    elif has("otp 超时", "验证码超时", "等待 otp", "email otp timeout"):
        phase = "email_otp"
    elif has(
        "密码注册", "设置密码", "register_password", "密码失败",
        "log-in/password",
    ):
        phase = "password"
    elif has("email-otp", "email_otp", "验证码", " otp"):
        phase = "email_otp"
    elif has("sentinel", "proof of work", "pow"):
        phase = "sentinel"
    elif has("signup", "authorize/continue", "提交邮箱"):
        phase = "signup"
    elif has("driver=roxy"):
        phase = "browser"
    elif category == "network" or has("proxy", "代理", "network", "connect", "timeout"):
        phase = "network"
    elif category == "account":
        phase = "account"
    else:
        phase = "unknown"

    reason = _FAILED_ATTEMPT_PHASE_LABELS[phase][1]
    if phase == "email_otp" and has("超时", "timeout", "timed out"):
        reason = "邮箱验证码超时"
    return phase, reason


def _mask_failed_identity(email: str) -> str:
    normalized = (email or "").strip().lower()
    if "@" not in normalized:
        return "[已脱敏]"
    local, domain = normalized.rsplit("@", 1)
    if len(local) <= 2:
        masked_local = (local[:1] or "*") + "***"
    elif len(local) <= 4:
        masked_local = local[:1] + "***" + local[-1:]
    else:
        masked_local = local[:2] + "***" + local[-2:]
    return f"{masked_local}@{domain}"


def _read_failed_attempt_diagnostic(log_path: str) -> str:
    """Read a bounded local log tail for phase inference; never return it to UI."""
    value = (log_path or "").strip()
    if not value:
        return ""
    path = Path(value)
    if not path.is_absolute():
        path = active_database_path().parent / path
    try:
        if path.suffix.lower() != ".log" or not path.is_file():
            return ""
        with path.open("rb") as handle:
            size = handle.seek(0, 2)
            handle.seek(max(0, size - 65536))
            return handle.read().decode("utf-8", errors="replace")
    except Exception:
        return ""


def _force_delete_eligibility_flags(
    con: sqlite3.Connection,
    keys: set[str],
) -> dict[str, bool]:
    """Return UI-safe force-delete eligibility from authoritative live state.

    Credential fields are read only to apply the same predicate as the
    deletion transaction; this projection exposes only one boolean per email.
    Email identities are normalized on write, so exact comparisons keep the
    registered/runs indexes usable and restrict active-run checks to this page.
    """
    if not keys:
        return {}
    sorted_keys = sorted(keys)
    placeholders = ",".join("?" * len(sorted_keys))
    rows = con.execute(
        "SELECT credential.email, credential.password, "
        "credential.access_token, credential.session_token, "
        "credential.totp_secret, credential.totp_factor_id, "
        "credential.extra_json, account.status AS pool_status, "
        "(SELECT run.status FROM runs AS run "
        " WHERE run.email=credential.email "
        " AND COALESCE(run.run_kind, 'registration')='registration' "
        " ORDER BY run.started_at DESC LIMIT 1) AS latest_registration_status "
        "FROM registered AS credential "
        "LEFT JOIN outlook_accounts AS account ON account.email=credential.email "
        f"WHERE credential.email IN ({placeholders})",
        sorted_keys,
    ).fetchall()
    active_keys = {
        (row[0] or "").strip().lower()
        for row in con.execute(
            "SELECT email FROM runs "
            f"WHERE email IN ({placeholders}) "
            "AND status IN ('running', 'pending', 'in_progress', 'cancelling') "
            "UNION SELECT lease.email FROM active_identity_leases AS lease "
            "INNER JOIN runs AS run ON run.run_id=lease.run_id "
            f"WHERE lease.email IN ({placeholders}) "
            "AND run.status IN ('running', 'pending', 'in_progress', 'cancelling')",
            (*sorted_keys, *sorted_keys),
        )
    }
    flags: dict[str, bool] = {}
    for row in rows:
        record = dict(row)
        key = (record.get("email") or "").strip().lower()
        flags[key] = key not in active_keys and _is_force_delete_eligible(record)
    return flags


def _failed_attempt_candidates_sql() -> str:
    """Build the shared lightweight unresolved-registration query."""
    return """
        WITH registration_ranked AS (
            SELECT LOWER(TRIM(email)) AS identity_key,
                   status, error, error_category, log_path, started_at, finished_at,
                   ROW_NUMBER() OVER (
                       PARTITION BY LOWER(TRIM(email))
                       ORDER BY COALESCE(finished_at, started_at) DESC, started_at DESC
                   ) AS row_number
            FROM runs
            WHERE COALESCE(run_kind, 'registration')='registration'
              AND COALESCE(TRIM(email), '')<>''
        ),
        latest_registration AS (
            SELECT * FROM registration_ranked WHERE row_number=1
        ),
        failed_ranked AS (
            SELECT LOWER(TRIM(email)) AS identity_key,
                   status, error, error_category, log_path, started_at, finished_at,
                   ROW_NUMBER() OVER (
                       PARTITION BY LOWER(TRIM(email))
                       ORDER BY COALESCE(finished_at, started_at) DESC, started_at DESC
                   ) AS row_number
            FROM runs
            WHERE status='failed'
              AND COALESCE(run_kind, 'registration') IN ('registration', 'reauthorization')
              AND COALESCE(TRIM(email), '')<>''
        ),
        latest_failed AS (
            SELECT * FROM failed_ranked WHERE row_number=1
        ),
        failed_pool AS (
            SELECT LOWER(TRIM(email)) AS identity_key,
                   fail_reason, finished_at
            FROM outlook_accounts
            WHERE status='failed' AND COALESCE(TRIM(email), '')<>''
        ),
        candidate_keys AS (
            SELECT identity_key FROM latest_registration WHERE status='failed'
            UNION
            SELECT identity_key FROM failed_pool
        ),
        candidate_rows AS (
            SELECT candidate.identity_key,
                   COALESCE(failed.error, registration.error, '') AS error,
                   COALESCE(failed.error_category, registration.error_category, '')
                       AS error_category,
                   COALESCE(failed.log_path, registration.log_path, '') AS log_path,
                   COALESCE(pool.fail_reason, '') AS fail_reason,
                   COALESCE(
                       failed.finished_at, registration.finished_at, pool.finished_at,
                       failed.started_at, registration.started_at, 0
                   ) AS created_at
            FROM candidate_keys AS candidate
            LEFT JOIN latest_registration AS registration
              ON registration.identity_key=candidate.identity_key
            LEFT JOIN latest_failed AS failed
              ON failed.identity_key=candidate.identity_key
            LEFT JOIN failed_pool AS pool
              ON pool.identity_key=candidate.identity_key
            WHERE (?='' OR INSTR(candidate.identity_key, ?) > 0)
              AND NOT EXISTS (
                  SELECT 1 FROM registered AS credential
                  WHERE credential.email=candidate.identity_key
                    AND COALESCE(TRIM(credential.password), '')<>''
                    AND COALESCE(TRIM(credential.access_token), '')<>''
                    AND COALESCE(TRIM(credential.session_token), '')<>''
                    AND COALESCE(TRIM(credential.totp_secret), '')<>''
                    AND COALESCE(TRIM(credential.totp_factor_id), '')<>''
                    AND CASE
                        WHEN credential.extra_json IS NULL THEN 1
                        WHEN json_valid(credential.extra_json)=0 THEN 1
                        ELSE COALESCE(
                            json_extract(credential.extra_json, '$.pending'), 0
                        )=0
                    END
              )
              AND NOT EXISTS (
                  SELECT 1 FROM registered AS credential
                  WHERE credential.email=candidate.identity_key
                    AND (
                        COALESCE(TRIM(credential.access_token), '')<>''
                        OR COALESCE(TRIM(credential.session_token), '')<>''
                    )
                    AND credential.extra_json IS NOT NULL
                    AND json_valid(credential.extra_json)
                    AND COALESCE(
                        json_extract(credential.extra_json, '$.pending'), 0
                    )=1
              )
              AND NOT EXISTS (
                  SELECT 1 FROM runs AS active
                  WHERE active.email=candidate.identity_key
                    AND active.status IN ('running', 'cancelling')
                    AND COALESCE(active.run_kind, 'registration')='registration'
              )
        )
    """


def _query_failed_attempt_candidates(
    con: sqlite3.Connection,
    query: str = "",
    *,
    limit: Optional[int] = None,
    offset: int = 0,
) -> tuple[list[dict], int]:
    """Return lightweight candidates without touching diagnostic log files."""
    normalized_query = (query or "").strip().lower()
    sql = _failed_attempt_candidates_sql()
    params: list[object] = [normalized_query, normalized_query]
    if limit is None:
        rows = con.execute(
            sql + " SELECT candidate_rows.*, COUNT(*) OVER() AS _total "
            "FROM candidate_rows ORDER BY created_at DESC",
            params,
        ).fetchall()
    else:
        rows = con.execute(
            sql + " SELECT candidate_rows.*, COUNT(*) OVER() AS _total "
            "FROM candidate_rows ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (*params, max(0, int(limit)), max(0, int(offset))),
        ).fetchall()
    total = int(rows[0]["_total"] or 0) if rows else 0
    if not rows and limit is not None and offset:
        total = int(con.execute(
            sql + " SELECT COUNT(*) FROM candidate_rows",
            params,
        ).fetchone()[0])
    return [dict(row) for row in rows], total


def _decorate_failed_attempt_candidates(
    con: sqlite3.Connection,
    candidates: list[dict],
) -> list[dict]:
    keys = {str(row.get("identity_key") or "") for row in candidates}
    force_delete_flags = _force_delete_eligibility_flags(con, keys)
    out = []
    for row in candidates:
        key = str(row.get("identity_key") or "")
        phase, reason = _classify_failed_attempt(
            str(row.get("error") or ""),
            str(row.get("fail_reason") or ""),
            str(row.get("error_category") or ""),
            _read_failed_attempt_diagnostic(str(row.get("log_path") or "")),
        )
        out.append({
            "email": key,
            "identity_hash": hashlib.sha256(key.encode("utf-8")).hexdigest()[:12],
            "_identity_key": key,
            "result_kind": "failed_attempt",
            "registration_status": "failed",
            "failure_phase": phase,
            "failure_reason": reason,
            "failure_phase_label": _FAILED_ATTEMPT_PHASE_LABELS[phase][0],
            "selectable": True,
            "has_credentials": False,
            "force_deletable": bool(force_delete_flags.get(key)),
            "created_at": row.get("created_at") or 0,
        })
    return out


def _list_failed_attempt_results(query: str = "") -> list[dict]:
    """Return all sanitized unresolved attempts for internal compatibility."""
    con = _conn()
    try:
        candidates, _ = _query_failed_attempt_candidates(con, query=query)
        return _decorate_failed_attempt_candidates(con, candidates)
    finally:
        con.close()

def _credential_registration_status(row: dict) -> str:
    pending_reason = str(row.get("pending_reason") or "")
    recovery_required = pending_reason in {
        PASSWORD_PENDING_REGISTERED,
        PASSWORD_RECOVERY_REQUIRED,
        *_LEGACY_PASSWORD_RECOVERY_REASONS,
    } or (
        pending_reason == PASSWORD_PENDING_CANDIDATE
        and row.get("authorization_present")
        and row.get("mfa_present")
    )
    if recovery_required:
        return PASSWORD_RECOVERY_REQUIRED
    if row.get("registration_pending"):
        return (
            "password_pending"
            if row.get("authorization_present") and row.get("password")
            else "pending"
        )
    return "completed"


def _visible_credential_registration_cte(
    filter_rt: str,
    query: str,
    plus_filter: str,
    pool_filter: str = "all",
) -> tuple[str, list[object]]:
    where, params = _registered_where(filter_rt, query, plus_filter, pool_filter)
    return f"""
        WITH filtered_registered AS (
            SELECT email, password, totp_secret,
                   length(totp_factor_id) AS totp_factor_len,
                   length(access_token) AS at_len,
                   length(session_token) AS st_len,
                   length(refresh_token) AS rt_len,
                   extra_json, created_at
            FROM registered
            {where}
        ),
        registration_ranked AS (
            SELECT email, status,
                   ROW_NUMBER() OVER (
                       PARTITION BY email ORDER BY started_at DESC
                   ) AS row_number
            FROM runs
            WHERE COALESCE(run_kind, 'registration')='registration'
              AND COALESCE(email, '')<>''
        ),
        latest_registration AS (
            SELECT email, status FROM registration_ranked WHERE row_number=1
        ),
        visible_credentials AS (
            SELECT credential.*
            FROM filtered_registered AS credential
            LEFT JOIN latest_registration AS latest
              ON latest.email=credential.email
            LEFT JOIN outlook_accounts AS account
              ON account.email=credential.email
            WHERE NOT (
                (COALESCE(latest.status, '')='failed' OR COALESCE(account.status, '')='failed')
                AND NOT (
                    COALESCE(TRIM(credential.password), '')<>''
                    AND COALESCE(credential.at_len, 0)>0
                    AND COALESCE(credential.st_len, 0)>0
                    AND COALESCE(TRIM(credential.totp_secret), '')<>''
                    AND COALESCE(credential.totp_factor_len, 0)>0
                    AND CASE
                        WHEN credential.extra_json IS NULL THEN 1
                        WHEN json_valid(credential.extra_json)=0 THEN 1
                        ELSE COALESCE(
                            json_extract(credential.extra_json, '$.pending'), 0
                        )=0
                    END
                )
                AND NOT (
                    (COALESCE(credential.at_len, 0)>0 OR COALESCE(credential.st_len, 0)>0)
                    AND credential.extra_json IS NOT NULL
                    AND json_valid(credential.extra_json)
                    AND COALESCE(
                        json_extract(credential.extra_json, '$.pending'), 0
                    )=1
                )
                AND NOT EXISTS (
                    SELECT 1 FROM runs AS active
                    WHERE active.email=credential.email
                      AND active.status IN ('running', 'cancelling')
                      AND COALESCE(active.run_kind, 'registration')='registration'
                )
            )
        )
    """, params


def page_credential_registration_results(
    limit: int = 20,
    offset: int = 0,
    filter_rt: str = "all",
    query: str = "",
    plus_filter: str = "all",
    pool_filter: str = "all",
) -> dict:
    """Return one credential page and its total without failure-log I/O."""
    con = _conn()
    try:
        cte, params = _visible_credential_registration_cte(
            filter_rt, query, plus_filter, pool_filter
        )
        result_rows = con.execute(
            cte
            + " SELECT page.*, totals.total_count FROM "
              "(SELECT COUNT(*) AS total_count FROM visible_credentials) AS totals "
              "LEFT JOIN (SELECT * FROM visible_credentials "
              "ORDER BY created_at DESC LIMIT ? OFFSET ?) AS page ON 1=1",
            (*params, max(0, int(limit)), max(0, int(offset))),
        ).fetchall()
        total = int(result_rows[0]["total_count"] or 0) if result_rows else 0
        page_rows = [row for row in result_rows if row["email"] is not None]
        force_delete_flags = _force_delete_eligibility_flags(
            con,
            {
                (row["email"] or "").strip().lower()
                for row in page_rows
                if row["email"]
            },
        )
    finally:
        con.close()

    rows = []
    for result_row in page_rows:
        row = dict(result_row)
        row.pop("total_count", None)
        extra = {}
        plus = None
        if row.get("extra_json"):
            try:
                extra = json.loads(row["extra_json"])
                plus = extra.get("plus_check")
            except Exception:
                extra = {}
        row["plus_check"] = plus
        row["pending_reason"] = str(extra.get("pending_reason") or "")
        row["frozen"] = bool(extra.get("frozen"))
        row["authorization_present"] = _has_saved_authorization(row)
        row["mfa_present"] = _has_saved_mfa(row)
        row["registration_pending"] = not has_completed_registration_evidence(row)
        key = (row.get("email") or "").strip().lower()
        row["force_deletable"] = bool(force_delete_flags.get(key))
        row["extra"] = extra
        _hide_unverified_pending_password(row)
        row.pop("extra", None)
        row.pop("extra_json", None)
        row["result_kind"] = "credential"
        row["registration_status"] = _credential_registration_status(row)
        row["selectable"] = True
        row["has_credentials"] = True
        rows.append(row)
    return {"items": rows, "total": total}


def list_registration_results(
    limit: int = 20,
    offset: int = 0,
    filter_rt: str = "all",
    query: str = "",
) -> list[dict]:
    """Compatibility combined view used by legacy callers."""
    rows: list[dict] = []
    failed_attempts = _list_failed_attempt_results(query=query)
    failed_keys = {row["_identity_key"] for row in failed_attempts}
    if filter_rt != "failed_attempt":
        fetch_limit = max(0, offset) + max(0, limit) + len(failed_attempts)
        credentials = list_registered(
            limit=fetch_limit,
            offset=0,
            filter_rt=filter_rt,
            query=query,
        )
        for row in credentials:
            normalized_email = (row.get("email") or "").strip().lower()
            if normalized_email in failed_keys:
                continue
            row["result_kind"] = "credential"
            row["registration_status"] = _credential_registration_status(row)
            row["selectable"] = True
            row["has_credentials"] = True
            rows.append(row)
    if filter_rt in ("all", "failed_attempt"):
        rows.extend(failed_attempts)
    rows.sort(key=lambda row: row.get("created_at") or 0, reverse=True)
    page = rows[offset:offset + limit]
    for row in page:
        row.pop("_identity_key", None)
    return page


def list_credential_registration_results(
    limit: int = 20,
    offset: int = 0,
    filter_rt: str = "all",
    query: str = "",
    plus_filter: str = "all",
) -> list[dict]:
    return page_credential_registration_results(
        limit=limit,
        offset=offset,
        filter_rt=filter_rt,
        query=query,
        plus_filter=plus_filter,
    )["items"]


def count_credential_registration_results(
    filter_rt: str = "all",
    query: str = "",
    plus_filter: str = "all",
) -> int:
    return int(page_credential_registration_results(
        limit=0,
        offset=0,
        filter_rt=filter_rt,
        query=query,
        plus_filter=plus_filter,
    )["total"])


def page_failed_attempt_results(
    limit: int = 20,
    offset: int = 0,
    query: str = "",
) -> dict:
    """Return one failed-attempt page; only that page reads diagnostics."""
    con = _conn()
    try:
        candidates, total = _query_failed_attempt_candidates(
            con,
            query=query,
            limit=limit,
            offset=offset,
        )
        rows = _decorate_failed_attempt_candidates(con, candidates)
    finally:
        con.close()
    for row in rows:
        row.pop("_identity_key", None)
    return {"items": rows, "total": total}


def list_failed_attempt_results(
    limit: int = 20,
    offset: int = 0,
    query: str = "",
) -> list[dict]:
    return page_failed_attempt_results(limit=limit, offset=offset, query=query)["items"]


def count_failed_attempt_results(query: str = "") -> int:
    con = _conn()
    try:
        sql = _failed_attempt_candidates_sql()
        normalized_query = (query or "").strip().lower()
        return int(con.execute(
            sql + " SELECT COUNT(*) FROM candidate_rows",
            (normalized_query, normalized_query),
        ).fetchone()[0])
    finally:
        con.close()


def count_registration_results(filter_rt: str = "all", query: str = "") -> int:
    failed_attempts = _list_failed_attempt_results(query=query)
    if filter_rt == "failed_attempt":
        return len(failed_attempts)
    credential_count = count_registered(filter_rt=filter_rt, query=query)
    overlap_count = 0
    for failed in failed_attempts:
        key = failed["_identity_key"]
        matching = list_registered(
            limit=1, offset=0, filter_rt=filter_rt, query=key
        )
        if matching and (matching[0].get("email") or "").strip().lower() == key:
            overlap_count += 1
    if filter_rt == "all":
        return credential_count - overlap_count + len(failed_attempts)
    return credential_count - overlap_count


def list_registered_full(limit: int = 5000) -> list[dict]:
    """返回完整凭证（用于批量导出）。每行同 get_registered 的格式。"""
    con = _conn()
    cur = con.execute(
        "SELECT * FROM registered ORDER BY created_at DESC LIMIT ?",
        (limit,),
    )
    out = []
    for row in cur.fetchall():
        d = dict(row)
        if d.get("extra_json"):
            try:
                d["extra"] = json.loads(d["extra_json"])
            except Exception:
                d["extra"] = {}
        _hide_unverified_pending_password(d)
        d.pop("extra_json", None)
        out.append(d)
    return out

def list_registered_by_emails(emails: list[str]) -> list[dict]:
    """按 email 列表返回完整凭证（批量导出勾选的号用）。

    - 行序 = created_at 倒序，和「注册结果」表格里看到的一致，方便核对。
    - 查不到的 email 直接不出现（号已被删掉的情况），不报错。
    - SQLite 单条语句变量数有上限（默认 999），所以分批查。
    """
    cleaned = [e.strip().lower() for e in (emails or []) if e and e.strip()]
    if not cleaned:
        return []

    con = _conn()
    out = []
    CHUNK = 500
    for i in range(0, len(cleaned), CHUNK):
        part = cleaned[i:i + CHUNK]
        placeholders = ",".join("?" * len(part))
        cur = con.execute(
            f"SELECT * FROM registered WHERE email IN ({placeholders})",
            part,
        )
        for row in cur.fetchall():
            d = dict(row)
            if d.get("extra_json"):
                try:
                    d["extra"] = json.loads(d["extra_json"])
                except Exception:
                    d["extra"] = {}
            _hide_unverified_pending_password(d)
            d.pop("extra_json", None)
            out.append(d)

    out.sort(key=lambda d: d.get("created_at") or 0, reverse=True)
    return out

def get_registered(
    email: str,
    *,
    include_pending_password: bool = False,
) -> Optional[dict]:
    con = _conn()
    cur = con.execute("SELECT * FROM registered WHERE email=?", (email.lower(),))
    row = cur.fetchone()
    if not row:
        return None
    out = dict(row)
    if out.get("extra_json"):
        try:
            out["extra"] = json.loads(out["extra_json"])
        except Exception:
            out["extra"] = {}
    out.update(_account_pool_metadata(out.get("extra")))
    if isinstance(out.get("extra", {}).get("registration_diagnostics"), dict):
        out["registration_diagnostics"] = out["extra"]["registration_diagnostics"]
    out.pop("extra_json", None)
    if not include_pending_password:
        _hide_unverified_pending_password(out)
    return out

def update_registered_credentials(email: str, credentials: dict) -> bool:
    """Update saved authorization fields without changing the account identity."""
    normalized = _normalize_email(email)
    if not normalized or not isinstance(credentials, dict):
        return False
    fields = (
        "access_token", "session_token", "refresh_token", "id_token",
        "device_id", "csrf_token", "cookie_header",
    )
    updates = {}
    for field in fields:
        if field in credentials and credentials[field] is not None:
            updates[field] = str(credentials[field]).strip()
    if not updates:
        return False
    with _lock:
        con = _conn()
        try:
            if not con.execute("SELECT 1 FROM registered WHERE email=?", (normalized,)).fetchone():
                return False
            assignments = ", ".join(f"{field}=?" for field in updates)
            con.execute(
                f"UPDATE registered SET {assignments} WHERE email=?",
                (*updates.values(), normalized),
            )
            con.commit()
            return True
        finally:
            con.close()

def _normalize_email(value: str) -> str:
    return (value or "").strip().lower()


def list_rebind_mailboxes() -> list[dict]:
    con = _conn()
    try:
        rows = con.execute(
            "SELECT id, email, status, claimed_at, used_at, "
            "imported_at, fail_reason, failure_stage, release_safe, "
            "CASE WHEN TRIM(mail_api) <> '' THEN 1 ELSE 0 END "
            "AS mail_api_configured FROM rebind_mailboxes "
            "ORDER BY imported_at DESC, id DESC"
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        con.close()


def get_rebind_mailbox(email: str) -> Optional[dict]:
    """Return one mailbox from the dedicated rebind pool for OTP recovery.

    Successful rebinds leave their mailbox in ``used`` state, but reauthorization
    and missing-2FA repair still need the saved receive API.  This lookup is
    intentionally separate from ``get_account`` so registration never consumes
    or mutates the rebind mailbox pool.
    """
    normalized = _normalize_email(email)
    if not normalized:
        return None
    con = _conn()
    try:
        row = con.execute(
            "SELECT * FROM rebind_mailboxes WHERE lower(email)=lower(?)",
            (normalized,),
        ).fetchone()
        if not row:
            return None
        mailbox = dict(row)
        mailbox["kind"] = "rebind_api"
        return mailbox
    finally:
        con.close()


def rebind_mailbox_stats() -> dict:
    con = _conn()
    try:
        rows = con.execute(
            "SELECT status, COUNT(*) AS count FROM rebind_mailboxes GROUP BY status"
        ).fetchall()
        counts = {status: 0 for status in _REBIND_MAILBOX_STATUSES}
        counts.update({str(row[0]): int(row[1]) for row in rows})
        return {"total": sum(counts.values()), **counts}
    finally:
        con.close()


def import_rebind_mailboxes(text: str) -> dict:
    """Import the separate mailbox pool. Format: ``email----mail_api``."""
    errors: list[dict] = []
    parsed: list[tuple[str, str]] = []
    for line_no, raw in enumerate((text or "").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = [part.strip() for part in line.split("----", 1)]
        email = _normalize_email(parts[0])
        mail_api = parts[1] if len(parts) == 2 else ""
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            errors.append({"line": line_no, "error": "邮箱格式不正确"})
            continue
        if not mail_api:
            errors.append({"line": line_no, "error": "缺少收信 API（格式：邮箱----收信API）"})
            continue
        parsed.append((email, mail_api))
    if errors:
        raise ValueError(json.dumps(errors, ensure_ascii=False))
    if not parsed:
        return {"parsed": 0, "inserted": 0, "updated": 0}
    inserted = updated = 0
    now = time.time()
    with _lock:
        con = _conn()
        try:
            con.execute("BEGIN IMMEDIATE")
            for email, mail_api in parsed:
                existing = con.execute(
                    "SELECT status FROM rebind_mailboxes WHERE email=?", (email,)
                ).fetchone()
                if existing:
                    if existing[0] in {"claimed", "used", "retry_pending"}:
                        con.execute(
                            "UPDATE rebind_mailboxes SET mail_api=?, fail_reason='' WHERE email=?",
                            (mail_api, email),
                        )
                    else:
                        con.execute(
                            "UPDATE rebind_mailboxes SET mail_api=?, status='available', "
                            "fail_reason='', claimed_at=NULL, claimed_by='', assigned_old_email='' "
                            "WHERE email=?", (mail_api, email),
                        )
                    updated += 1
                else:
                    con.execute(
                        "INSERT INTO rebind_mailboxes(email, mail_api, status, imported_at) "
                        "VALUES (?, ?, 'available', ?)", (email, mail_api, now),
                    )
                    inserted += 1
            con.commit()
        finally:
            con.close()
    return {"parsed": len(parsed), "inserted": inserted, "updated": updated}


def release_failed_rebind_mailbox(email: str) -> bool:
    """Return only a failure explicitly classified as safe to reuse.

    ``retry_pending`` means the replacement may already own the account and is
    therefore never releasable. This database guard cannot be bypassed by UI.
    """
    normalized = _normalize_email(email)
    if not normalized:
        return False
    with _lock:
        con = _conn()
        try:
            con.execute("BEGIN IMMEDIATE")
            rc = con.execute(
                "UPDATE rebind_mailboxes SET status='available', "
                "claimed_at=NULL, claimed_by='', assigned_old_email='', used_at=NULL, "
                "release_safe=0 WHERE email=? AND status='failed' AND release_safe=1",
                (normalized,),
            )
            con.commit()
            return rc.rowcount > 0
        finally:
            con.close()


def save_rebind_run(run: dict, *, source: str = "webui") -> None:
    """Persist a public rebind run snapshot so results survive process restarts."""
    if not isinstance(run, dict):
        return
    run_id = str(run.get("run_id") or "").strip()
    if not run_id:
        return
    payload = {
        key: value for key, value in run.items()
        if key not in {"options", "cancel_event", "executor"}
    }
    now = time.time()
    created_at = float(run.get("created_at_ts") or now)
    with _lock:
        con = _conn()
        try:
            con.execute(
                "INSERT INTO rebind_runs(run_id, status, created_at, updated_at, payload_json, source) "
                "VALUES (?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(run_id) DO UPDATE SET status=excluded.status, updated_at=excluded.updated_at, "
                "payload_json=excluded.payload_json, source=excluded.source",
                (
                    run_id,
                    str(run.get("status") or "finished"),
                    created_at,
                    now,
                    json.dumps(payload, ensure_ascii=False),
                    str(source or "webui"),
                ),
            )
            con.commit()
        finally:
            con.close()


def _decode_rebind_run(row) -> dict | None:
    if not row:
        return None
    try:
        payload = json.loads(row["payload_json"] or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    payload.setdefault("run_id", row["run_id"])
    payload.setdefault("status", row["status"])
    payload.setdefault("source", row["source"])
    return payload


def get_rebind_run(run_id: str) -> dict | None:
    normalized = str(run_id or "").strip()
    if not normalized:
        return None
    con = _conn()
    try:
        row = con.execute(
            "SELECT run_id, status, payload_json, source FROM rebind_runs WHERE run_id=?",
            (normalized,),
        ).fetchone()
        return _decode_rebind_run(row)
    finally:
        con.close()


def delete_rebind_run(run_id: str) -> bool:
    """Delete one completed rebind run without touching account or mailbox data."""
    normalized = str(run_id or "").strip()
    if not normalized:
        return False
    with _lock:
        con = _conn()
        try:
            rc = con.execute(
                "DELETE FROM rebind_runs "
                "WHERE run_id=? AND status NOT IN ('running', 'cancelling')",
                (normalized,),
            )
            con.commit()
            return rc.rowcount > 0
        finally:
            con.close()


def delete_rebind_run_item(run_id: str, email: str) -> bool:
    """Delete one account snapshot from a completed rebind result only.

    This deliberately changes only the rebind result archive; it never touches
    the registered-account table or the rebind mailbox pool.
    """
    normalized_run_id = str(run_id or "").strip()
    normalized_email = _normalize_email(email)
    if not normalized_run_id or not normalized_email:
        return False
    with _lock:
        con = _conn()
        try:
            con.execute("BEGIN IMMEDIATE")
            row = con.execute(
                "SELECT status, payload_json FROM rebind_runs WHERE run_id=?",
                (normalized_run_id,),
            ).fetchone()
            if not row or row["status"] in {"running", "cancelling"}:
                con.rollback()
                return False
            try:
                payload = json.loads(row["payload_json"] or "{}")
            except (TypeError, ValueError, json.JSONDecodeError):
                payload = {}
            if not isinstance(payload, dict):
                payload = {}
            items = payload.get("items")
            if not isinstance(items, list):
                con.rollback()
                return False

            def item_email(item: dict) -> str:
                account = item.get("account") if isinstance(item.get("account"), dict) else {}
                return _normalize_email(
                    account.get("email") or item.get("new_email") or item.get("email") or ""
                )

            next_items = [
                item for item in items
                if not isinstance(item, dict) or item_email(item) != normalized_email
            ]
            if len(next_items) == len(items):
                con.rollback()
                return False
            payload["items"] = next_items
            payload["summary"] = {
                "total": len(next_items),
                "pending": sum(item.get("status") == "pending" for item in next_items if isinstance(item, dict)),
                "running": sum(item.get("status") == "running" for item in next_items if isinstance(item, dict)),
                "success": sum(item.get("status") == "success" for item in next_items if isinstance(item, dict)),
                "failed": sum(item.get("status") == "failed" for item in next_items if isinstance(item, dict)),
                "cancelled": sum(item.get("status") == "cancelled" for item in next_items if isinstance(item, dict)),
            }
            con.execute(
                "UPDATE rebind_runs SET updated_at=?, payload_json=? WHERE run_id=?",
                (time.time(), json.dumps(payload, ensure_ascii=False), normalized_run_id),
            )
            con.commit()
            return True
        finally:
            con.close()


def _classify_interrupted_rebind_item(item: dict) -> tuple[str, bool]:
    phase = str(item.get("phase") or "").strip()
    logs = item.get("logs") if isinstance(item.get("logs"), list) else []
    markers = {
        str(entry.get("step") or entry.get("phase") or "").strip().lower()
        for entry in logs
        if isinstance(entry, dict)
    }
    phase_text = " ".join(
        [phase, str(item.get("code") or ""), str(item.get("message") or "")]
        + [str(entry.get("phase") or "") for entry in logs if isinstance(entry, dict)]
        + [str(entry.get("code") or "") for entry in logs if isinstance(entry, dict)]
        + [str(entry.get("message") or "") for entry in logs if isinstance(entry, dict)]
    ).lower()
    if (
            "export" in markers
            or "export_failed" in phase_text
            or "重新获取凭证" in phase_text
            or "凭证待刷新" in phase_text
        ):
        return "重新获取凭证", False
    if (
        {"mail_code", "verify"} & markers
        or "验证换绑" in phase_text
        or "提交换绑" in phase_text
    ):
        return "提交换绑", False
    if "begin" in markers or "等待验证码" in phase_text:
        return "等待验证码", True
    if "begin_need_reauth" in markers:
        return "旧邮箱重新授权", True
    if "eligibility" in markers:
        return "换绑资格检查", True
    if "login_old" in markers or "旧邮箱登录" in phase_text:
        return "旧邮箱登录", True
    if "等待中" in phase_text or phase in {"等待中", "等待执行"}:
        return "等待执行", True
    return "未知阶段", False


def cancel_running_rebind_runs(message: str = "服务重启，换绑任务已中断") -> int:
    """Finish orphaned rebind snapshots without reusing a possibly bound email."""
    safe_message = sanitize_text(message)[:500] or "服务重启，换绑任务已中断"
    now = time.time()
    finished_at = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(now))
    unfinished_statuses = {"pending", "running", "cancelling"}
    terminal_statuses = {"success", "failed", "retry_pending", "cancelled"}

    with _lock:
        con = _conn()
        try:
            con.execute("BEGIN IMMEDIATE")
            rows = con.execute(
                "SELECT run_id, payload_json FROM rebind_runs "
                "WHERE status IN ('running', 'cancelling')"
            ).fetchall()
            changed = 0
            for row in rows:
                run_id = str(row["run_id"] or "").strip()
                try:
                    payload = json.loads(row["payload_json"] or "{}")
                except (TypeError, ValueError, json.JSONDecodeError):
                    payload = {}
                if not isinstance(payload, dict):
                    payload = {}

                items = payload.get("items")
                if not isinstance(items, list):
                    items = []
                handled_new_emails: set[str] = set()
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    if str(item.get("status") or "pending") not in unfinished_statuses:
                        continue
                    old_email = _normalize_email(str(item.get("old_email") or ""))
                    new_email = _normalize_email(str(item.get("new_email") or ""))
                    if new_email:
                        handled_new_emails.add(new_email)
                    stage, safe_to_release = _classify_interrupted_rebind_item(item)
                    logs = item.get("logs")
                    if not isinstance(logs, list):
                        logs = []
                        item["logs"] = logs

                    if safe_to_release:
                        public_message = (
                            f"{safe_message}；中断发生在{stage}，换绑尚未提交，"
                            "新邮箱已自动释放。"
                        )
                        item.update(
                            status="failed",
                            phase=f"换绑前中断·{stage}",
                            message=public_message,
                            code="REBIND_INTERRUPTED",
                            failure_stage=stage,
                            release_safe=True,
                            mailbox_disposition="released",
                            finished_at=finished_at,
                        )
                        if new_email:
                            con.execute(
                                "UPDATE rebind_mailboxes SET status='available', fail_reason=?, "
                                "failure_stage=?, release_safe=0, claimed_at=NULL, used_at=NULL, "
                                "assigned_old_email='', claimed_by='' WHERE email=? "
                                "AND status='claimed' AND claimed_by=?",
                                (public_message, stage, new_email, run_id),
                            )
                    else:
                        public_message = (
                            f"{safe_message}；中断发生在{stage}，换绑可能已提交；"
                            "新邮箱已保留并禁止释放，请待补授权/核验。"
                        )
                        item.update(
                            status="retry_pending",
                            phase="换绑状态待核验",
                            message=public_message,
                            code="REBIND_STATE_REVIEW_REQUIRED",
                            failure_stage=stage,
                            release_safe=False,
                            mailbox_disposition="protected",
                            finished_at=finished_at,
                        )
                        if new_email:
                            con.execute(
                                "UPDATE rebind_mailboxes SET status='retry_pending', fail_reason=?, "
                                "failure_stage=?, release_safe=0, assigned_old_email=? "
                                "WHERE email=? AND status='claimed' AND claimed_by=?",
                                (public_message, stage, old_email, new_email, run_id),
                            )

                    entry = {
                        "time": finished_at,
                        "phase": item["phase"],
                        "level": "warning",
                        "message": public_message,
                    }
                    if not logs or logs[-1].get("message") != public_message:
                        logs.append(entry)
                    if len(logs) > 200:
                        del logs[:-200]

                # A claimed row absent from the persisted item list has unknown
                # progress. Protect it rather than risk reusing an already-bound email.
                con.execute(
                    "UPDATE rebind_mailboxes SET status='retry_pending', fail_reason=?, "
                    "failure_stage='未知阶段', release_safe=0 "
                    "WHERE status='claimed' AND claimed_by=? "
                    + (
                        "AND lower(email) NOT IN (" + ",".join("?" * len(handled_new_emails)) + ")"
                        if handled_new_emails else ""
                    ),
                    (f"{safe_message}；阶段未知，邮箱已保留并禁止释放。", run_id, *sorted(handled_new_emails)),
                )

                statuses = {
                    str(item.get("status") or "")
                    for item in items
                    if isinstance(item, dict)
                }
                run_status = "finished" if statuses and statuses <= terminal_statuses else "cancelled"
                payload.update(
                    run_id=run_id,
                    status=run_status,
                    items=items,
                    finished_at=finished_at,
                )
                payload["summary"] = {
                    "total": len(items),
                    "pending": sum(isinstance(item, dict) and item.get("status") == "pending" for item in items),
                    "running": sum(isinstance(item, dict) and item.get("status") == "running" for item in items),
                    "success": sum(isinstance(item, dict) and item.get("status") == "success" for item in items),
                    "failed": sum(isinstance(item, dict) and item.get("status") == "failed" for item in items),
                    "retry_pending": sum(isinstance(item, dict) and item.get("status") == "retry_pending" for item in items),
                    "cancelled": sum(isinstance(item, dict) and item.get("status") == "cancelled" for item in items),
                }
                con.execute(
                    "UPDATE rebind_runs SET status=?, updated_at=?, payload_json=? WHERE run_id=?",
                    (run_status, now, json.dumps(payload, ensure_ascii=False), run_id),
                )
                changed += 1
            con.commit()
            return changed
        finally:
            con.close()

def list_rebind_runs(limit: int = 100) -> list[dict]:
    limit = max(1, min(int(limit), 500))
    con = _conn()
    try:
        rows = con.execute(
            "SELECT run_id, status, payload_json, source FROM rebind_runs "
            "ORDER BY created_at DESC, updated_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [item for row in rows if (item := _decode_rebind_run(row))]
    finally:
        con.close()


def delete_rebind_mailbox(email: str) -> bool:
    normalized = _normalize_email(email)
    if not normalized:
        return False
    with _lock:
        con = _conn()
        try:
            con.execute("BEGIN IMMEDIATE")
            row = con.execute(
                "SELECT status FROM rebind_mailboxes WHERE email=?", (normalized,)
            ).fetchone()
            if not row or row[0] == "claimed":
                con.rollback()
                return False
            rc = con.execute("DELETE FROM rebind_mailboxes WHERE email=?", (normalized,))
            con.commit()
            return rc.rowcount > 0
        finally:
            con.close()


def claim_rebind_mailboxes(count: int, run_id: str) -> list[dict]:
    count = max(0, int(count))
    if not count:
        return []
    with _lock:
        con = _conn()
        try:
            con.execute("BEGIN IMMEDIATE")
            now = time.time()
            rows = con.execute(
                "SELECT * FROM rebind_mailboxes WHERE status='available' "
                "AND (cooldown_until IS NULL OR cooldown_until<=?) "
                "ORDER BY imported_at ASC, id ASC LIMIT ?", (now, count)
            ).fetchall()
            result = []
            for row in rows:
                con.execute(
                    "UPDATE rebind_mailboxes SET status='claimed', claimed_at=?, "
                    "claimed_by=?, fail_reason='', cooldown_until=NULL "
                    "WHERE id=? AND status='available'",
                    (now, run_id, row["id"]),
                )
                item = dict(row)
                item.update(
                    status="claimed", claimed_at=now, claimed_by=run_id,
                    cooldown_until=None,
                )
                result.append(item)
            con.commit()
            return result
        finally:
            con.close()


def set_rebind_mailbox_result(
    email: str,
    *,
    status: str,
    old_email: str = "",
    reason: str = "",
    run_id: str = "",
    failure_stage: str = "",
    release_safe: bool = False,
    cooldown_seconds: float = 0,
) -> bool:
    normalized = _normalize_email(email)
    if status not in _REBIND_MAILBOX_STATUSES:
        raise ValueError(f"invalid rebind mailbox status: {status}")
    with _lock:
        con = _conn()
        try:
            now = time.time()
            stage = sanitize_text(failure_stage)[:200]
            safe_flag = 1 if release_safe and status == "failed" else 0
            cooldown = max(0.0, float(cooldown_seconds or 0))
            cooldown_until = now + cooldown if status == "available" and cooldown else None
            if status == "used":
                rc = con.execute(
                    "UPDATE rebind_mailboxes SET status='used', used_at=?, fail_reason='', "
                    "failure_stage='', release_safe=0, cooldown_until=NULL, "
                    "assigned_old_email=?, claimed_by=? "
                    "WHERE email=?",
                    (now, _normalize_email(old_email), run_id, normalized),
                )
            elif status == "available":
                rc = con.execute(
                    "UPDATE rebind_mailboxes SET status='available', fail_reason=?, "
                    "failure_stage=?, release_safe=0, cooldown_until=?, "
                    "claimed_at=NULL, used_at=NULL, assigned_old_email='', claimed_by='' "
                    "WHERE email=?",
                    (str(reason or "")[:1000], stage, cooldown_until, normalized),
                )
            elif status == "failed":
                rc = con.execute(
                    "UPDATE rebind_mailboxes SET status='failed', fail_reason=?, "
                    "failure_stage=?, release_safe=?, cooldown_until=NULL, "
                    "assigned_old_email=?, claimed_by=? "
                    "WHERE email=?",
                    (
                        str(reason or "换绑失败")[:1000],
                        stage,
                        safe_flag,
                        _normalize_email(old_email),
                        run_id,
                        normalized,
                    ),
                )
            else:
                rc = con.execute(
                    "UPDATE rebind_mailboxes SET status=?, fail_reason=?, failure_stage=?, "
                    "release_safe=0, cooldown_until=NULL, assigned_old_email=?, "
                    "claimed_by=? WHERE email=?",
                    (
                        status,
                        str(reason or "")[:1000],
                        stage,
                        _normalize_email(old_email),
                        run_id,
                        normalized,
                    ),
                )
            con.commit()
            return rc.rowcount > 0
        finally:
            con.close()

def _apply_rebind_result_metadata(
    extra: dict,
    *,
    old_email: str,
    new_email: str,
    run_id: str = "",
    rebound_at: object = None,
) -> dict:
    """Return rebind result metadata without duplicating history on re-import."""
    payload = dict(extra) if isinstance(extra, dict) else {}
    at = rebound_at if rebound_at not in (None, "") else time.time()
    origin = {
        "old_email": _normalize_email(old_email),
        "new_email": _normalize_email(new_email),
        "run_id": str(run_id or ""),
        "at": at,
    }
    payload["result_group"] = "rebind"
    payload["rebind_origin"] = origin
    history = payload.get("rebind_history")
    if not isinstance(history, list):
        history = []
    duplicate = any(
        isinstance(item, dict)
        and _normalize_email(str(item.get("old_email") or "")) == origin["old_email"]
        and _normalize_email(str(item.get("new_email") or "")) == origin["new_email"]
        and str(item.get("run_id") or "") == origin["run_id"]
        for item in history
    )
    if not duplicate:
        history.append(origin.copy())
    payload["rebind_history"] = history
    payload["pending"] = False
    payload.pop("pending_reason", None)
    return payload


def mark_registered_as_rebind_result(
    email: str,
    *,
    old_email: str = "",
    run_id: str = "",
    rebound_at: object = None,
) -> bool:
    """Move an existing credential row into the rebind-results display group."""
    normalized = _normalize_email(email)
    if not normalized:
        return False
    with _lock:
        con = _conn()
        try:
            row = con.execute(
                "SELECT extra_json FROM registered WHERE email=?", (normalized,)
            ).fetchone()
            if not row:
                return False
            try:
                extra = json.loads(row["extra_json"] or "{}")
            except (TypeError, ValueError, json.JSONDecodeError):
                extra = {}
            extra = _apply_rebind_result_metadata(
                extra,
                old_email=old_email,
                new_email=normalized,
                run_id=run_id,
                rebound_at=rebound_at,
            )
            con.execute(
                "UPDATE registered SET extra_json=? WHERE email=?",
                (json.dumps(extra, ensure_ascii=False), normalized),
            )
            con.commit()
            return True
        finally:
            con.close()


def restore_rebind_result_credentials_if_missing(
    account: dict,
    *,
    old_email: str = "",
    run_id: str = "",
    rebound_at: object = None,
) -> bool:
    """Restore a legacy rebind snapshot as the authoritative credential row.

    Legacy 8767 runs persisted result snapshots outside this database.  The
    rebind results page, Plus checks, and reauthorization all read the
    ``registered`` row as their credential authority.  Restore that row only
    when it is absent; if a current row already exists, preserve every current
    credential, fill only locally missing fields, and attach rebind-result metadata.
    """
    source = dict(account or {})
    normalized = _normalize_email(str(source.get("email") or ""))
    if not normalized:
        return False

    snapshot_extra = source.get("extra")
    if not isinstance(snapshot_extra, dict):
        try:
            snapshot_extra = json.loads(source.get("extra_json") or "{}")
        except (TypeError, ValueError, json.JSONDecodeError):
            snapshot_extra = {}
    if not isinstance(snapshot_extra, dict):
        snapshot_extra = {}
    else:
        snapshot_extra = dict(snapshot_extra)
    plus_check = source.get("plus_check")
    if isinstance(plus_check, dict) and plus_check:
        snapshot_extra.setdefault("plus_check", dict(plus_check))

    def text_value(field: str) -> str:
        value = source.get(field)
        return value.strip() if isinstance(value, str) else "" if value is None else str(value)

    created_at = source.get("created_at")
    if not isinstance(created_at, (int, float)):
        try:
            created_at = float(created_at)
        except (TypeError, ValueError):
            created_at = time.time()

    with _lock:
        con = _conn()
        try:
            con.execute("BEGIN IMMEDIATE")
            credential_fields = (
                "password", "access_token", "session_token", "refresh_token",
                "id_token", "device_id", "csrf_token", "cookie_header",
                "totp_secret", "totp_factor_id",
            )
            row = con.execute(
                "SELECT " + ", ".join((*credential_fields, "extra_json"))
                + " FROM registered WHERE email=?",
                (normalized,),
            ).fetchone()
            if row:
                try:
                    existing_extra = json.loads(row["extra_json"] or "{}")
                except (TypeError, ValueError, json.JSONDecodeError):
                    existing_extra = {}
                extra = _apply_rebind_result_metadata(
                    existing_extra,
                    old_email=old_email,
                    new_email=normalized,
                    run_id=run_id,
                    rebound_at=rebound_at,
                )
                updates = {"extra_json": json.dumps(extra, ensure_ascii=False)}
                for field in credential_fields:
                    if (
                        not str(row[field] or "").strip()
                        and text_value(field)
                    ):
                        updates[field] = text_value(field)
                assignments = ", ".join(f"{field}=?" for field in updates)
                con.execute(
                    f"UPDATE registered SET {assignments} WHERE email=?",
                    (*updates.values(), normalized),
                )
                con.commit()
                return False

            extra = _apply_rebind_result_metadata(
                snapshot_extra,
                old_email=old_email,
                new_email=normalized,
                run_id=run_id,
                rebound_at=rebound_at,
            )
            con.execute(
                "INSERT INTO registered("
                "email, password, access_token, session_token, refresh_token, "
                "id_token, device_id, csrf_token, cookie_header, totp_secret, "
                "totp_factor_id, extra_json, created_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    normalized,
                    text_value("password"),
                    text_value("access_token"),
                    text_value("session_token"),
                    text_value("refresh_token"),
                    text_value("id_token"),
                    text_value("device_id"),
                    text_value("csrf_token"),
                    text_value("cookie_header"),
                    text_value("totp_secret"),
                    text_value("totp_factor_id"),
                    json.dumps(extra, ensure_ascii=False),
                    created_at,
                ),
            )
            con.commit()
            return True
        except Exception:
            con.rollback()
            raise
        finally:
            con.close()


def replace_registered_identity(
    old_email: str, new_email: str, credentials: dict, *,
    preserve_password: bool = True, preserve_totp: bool = True,
    password_recovery_required: bool | None = None,
    rebind_run_id: str = "",
) -> dict:
    """Atomically migrate a registered row to a new email and fresh credentials."""
    old = _normalize_email(old_email)
    new = _normalize_email(new_email)
    if not old or not new:
        raise ValueError("旧邮箱和新邮箱不能为空")
    if old == new:
        raise ValueError("新邮箱不能与旧邮箱相同")
    credentials = credentials or {}
    auth_fields = (
        "access_token", "session_token", "refresh_token", "id_token",
        "device_id", "csrf_token", "cookie_header",
    )
    with _lock:
        con = _conn()
        try:
            con.execute("BEGIN IMMEDIATE")
            row = con.execute("SELECT * FROM registered WHERE email=?", (old,)).fetchone()
            if not row:
                raise ValueError("旧邮箱注册结果不存在")
            if con.execute("SELECT 1 FROM registered WHERE email=?", (new,)).fetchone():
                raise ValueError("新邮箱已存在于注册结果中")
            if con.execute(
                "SELECT 1 FROM active_identity_leases WHERE lower(email)=lower(?)", (old,)
            ).fetchone():
                raise ValueError("旧账号当前有其他任务正在运行")
            old_data = dict(row)
            try:
                extra = json.loads(old_data.get("extra_json") or "{}")
            except (TypeError, ValueError, json.JSONDecodeError):
                extra = {}
            if not isinstance(extra, dict):
                extra = {}
            extra = _apply_rebind_result_metadata(
                extra,
                old_email=old,
                new_email=new,
                run_id=rebind_run_id,
            )
            values = {}
            for field in auth_fields:
                value = credentials.get(field)
                if isinstance(value, str):
                    value = value.strip()
                values[field] = value or old_data.get(field) or ""
            password = (
                old_data.get("password") or ""
                if preserve_password
                else credentials.get("password") or ""
            )
            if password_recovery_required is True:
                password = ""
                extra["pending"] = True
                extra["pending_reason"] = PASSWORD_RECOVERY_REQUIRED
            elif password_recovery_required is False:
                extra.pop("pending", None)
                extra.pop("pending_reason", None)
            if preserve_totp:
                totp_secret = old_data.get("totp_secret") or ""
                totp_factor_id = old_data.get("totp_factor_id") or ""
            else:
                totp_secret = credentials.get("totp_secret") or ""
                totp_factor_id = credentials.get("totp_factor_id") or ""
            con.execute(
                "INSERT INTO registered(email, password, access_token, session_token, refresh_token, "
                "id_token, device_id, csrf_token, cookie_header, totp_secret, totp_factor_id, extra_json, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (new, password, values["access_token"], values["session_token"], values["refresh_token"],
                 values["id_token"], values["device_id"], values["csrf_token"], values["cookie_header"],
                 totp_secret, totp_factor_id, json.dumps(extra, ensure_ascii=False),
                 old_data.get("created_at") or time.time()),
            )
            con.execute("DELETE FROM registered WHERE email=?", (old,))
            con.commit()
        except Exception:
            con.rollback()
            raise
        finally:
            con.close()
    return get_registered(new, include_pending_password=True) or {}

_IDENTITY_DEPENDENT_TABLES = (
    "outlook_accounts",
    "active_identity_leases",
    "runs",
    "pending_totp_enrollments",
)


class ActiveIdentityDeleteError(RuntimeError):
    """Raised when deletion races with a newly active identity run."""


class ProtectedIdentityDeleteError(RuntimeError):
    """Raised when an identity becomes failed/incomplete before deletion."""


class ForceDeleteNotEligibleError(RuntimeError):
    """Raised when a force-delete target is missing or no longer protected."""


def _is_force_delete_eligible(record: dict) -> bool:
    """Allow an explicit force deletion only for unresolved identities."""
    extra: dict = {}
    if record.get("extra_json"):
        try:
            parsed_extra = json.loads(record["extra_json"])
            if isinstance(parsed_extra, dict):
                extra = parsed_extra
        except (TypeError, ValueError, json.JSONDecodeError):
            extra = {}
    frozen_marker = extra.get("frozen")
    if "frozen" in extra and frozen_marker is not False:
        return False
    plus_check = extra.get("plus_check")
    plus_status = (
        plus_check.get("status")
        if isinstance(plus_check, dict)
        else ""
    )
    # A persisted invalid-token result is an explicit operator-visible reason
    # to retire credentials, even if their original registration reached done.
    # It remains opt-in behind the dedicated API confirmation and active-run
    # transaction guard.
    if plus_status == "token_invalid":
        return True
    if (record.get("pool_status") or "") == "done":
        return False
    pending_marker = extra.get("pending")
    if "pending" in extra and not isinstance(pending_marker, bool):
        return False
    if pending_marker is True:
        return (
            (record.get("pool_status") or "") == "failed"
            or (record.get("latest_registration_status") or "")
            in ("failed", "cancelled")
        )
    if has_completed_registration_evidence(record):
        return False
    return (
        (record.get("pool_status") or "") == "failed"
        or (record.get("latest_registration_status") or "") in ("failed", "cancelled")
    )


def _raise_if_force_delete_not_eligible(
    con: sqlite3.Connection,
    emails: list[str],
) -> None:
    placeholders = ",".join("?" * len(emails))
    rows = [
        dict(row)
        for row in con.execute(
            "SELECT credential.email, credential.password, "
            "credential.access_token, credential.session_token, "
            "credential.totp_secret, credential.totp_factor_id, "
            "credential.extra_json, account.status AS pool_status, "
            "(SELECT run.status FROM runs AS run "
            " WHERE lower(run.email)=lower(credential.email) "
            " AND COALESCE(run.run_kind, 'registration')='registration' "
            " ORDER BY run.started_at DESC LIMIT 1) AS latest_registration_status "
            "FROM registered AS credential "
            "LEFT JOIN outlook_accounts AS account "
            "ON lower(account.email)=lower(credential.email) "
            f"WHERE credential.email IN ({placeholders})",
            emails,
        )
    ]
    if len(rows) != len(emails) or any(
        not _is_force_delete_eligible(record) for record in rows
    ):
        raise ForceDeleteNotEligibleError()


def _raise_if_protected_identity_delete(
    con: sqlite3.Connection,
    emails: Optional[list[str]] = None,
) -> None:
    params: list[str] = []
    where = ""
    if emails is not None:
        placeholders = ",".join("?" * len(emails))
        where = f"WHERE credential.email IN ({placeholders})"
        params.extend(emails)
    rows = con.execute(
        "SELECT credential.email, credential.password, "
        "credential.access_token, credential.session_token, "
        "credential.totp_secret, credential.totp_factor_id, "
        "credential.extra_json, account.status AS pool_status, "
        "(SELECT run.status FROM runs AS run "
        " WHERE lower(run.email)=lower(credential.email) "
        " AND COALESCE(run.run_kind, 'registration')='registration' "
        " ORDER BY run.started_at DESC LIMIT 1) AS latest_registration_status "
        "FROM registered AS credential "
        "LEFT JOIN outlook_accounts AS account "
        "ON lower(account.email)=lower(credential.email) "
        f"{where}",
        params,
    )
    for row in rows:
        record = dict(row)
        extra: dict = {}
        if record.get("extra_json"):
            try:
                parsed_extra = json.loads(record["extra_json"])
                if isinstance(parsed_extra, dict):
                    extra = parsed_extra
            except (TypeError, ValueError, json.JSONDecodeError):
                extra = {}
        if bool(extra.get("pending")):
            raise ProtectedIdentityDeleteError(record.get("email") or "")
        if has_completed_registration_evidence(record):
            continue
        if (
            (record.get("pool_status") or "") == "failed"
            or (record.get("latest_registration_status") or "")
            in ("failed", "cancelled")
        ):
            raise ProtectedIdentityDeleteError(record.get("email") or "")


def _raise_if_active_identity_run(
    con: sqlite3.Connection,
    emails: Optional[list[str]] = None,
) -> None:
    active_statuses = "('running', 'pending', 'in_progress', 'cancelling')"
    if emails is None:
        row = con.execute(
            "SELECT run.email FROM runs AS run "
            "INNER JOIN registered AS credential "
            "ON lower(credential.email)=lower(run.email) "
            f"WHERE run.status IN {active_statuses} LIMIT 1"
        ).fetchone()
        if not row:
            row = con.execute(
                "SELECT lease.email FROM active_identity_leases AS lease "
                "INNER JOIN runs AS run ON run.run_id=lease.run_id "
                "INNER JOIN registered AS credential "
                "ON lower(credential.email)=lower(lease.email) "
                f"WHERE run.status IN {active_statuses} LIMIT 1"
            ).fetchone()
    else:
        placeholders = ",".join("?" * len(emails))
        row = con.execute(
            f"SELECT email FROM runs WHERE status IN {active_statuses} "
            f"AND email IN ({placeholders}) LIMIT 1",
            emails,
        ).fetchone()
        if not row:
            row = con.execute(
                "SELECT lease.email FROM active_identity_leases AS lease "
                "INNER JOIN runs AS run ON run.run_id=lease.run_id "
                f"WHERE run.status IN {active_statuses} "
                f"AND lease.email IN ({placeholders}) LIMIT 1",
                emails,
            ).fetchone()
    if row:
        raise ActiveIdentityDeleteError(row[0])


def _delete_identity_dependents(con: sqlite3.Connection, emails: list[str]) -> None:
    """Delete non-credential rows that can resurrect a deleted identity."""
    if not emails:
        return
    placeholders = ",".join("?" * len(emails))
    for table in _IDENTITY_DEPENDENT_TABLES:
        con.execute(
            f"DELETE FROM {table} WHERE email IN ({placeholders})",
            emails,
        )


def delete_registered(email: str) -> bool:
    normalized = (email or "").strip().lower()
    if not normalized:
        return False
    with _lock:
        con = _conn()
        try:
            con.execute("BEGIN IMMEDIATE")
            exists = con.execute(
                "SELECT 1 FROM registered WHERE email=?",
                (normalized,),
            ).fetchone()
            if not exists:
                return False
            _raise_if_active_identity_run(con, [normalized])
            _raise_if_protected_identity_delete(con, [normalized])
            rc = con.execute(
                "DELETE FROM registered WHERE email=?",
                (normalized,),
            )
            if rc.rowcount > 0:
                # “删除注册结果”代表删除这一完整身份。只删凭证会让旧失败
                # run 在凭证保护消失后重新进入失败尝试列表；邮箱池、运行记录
                # 和尚未激活的 2FA enrollment 必须在同一事务里一起移除。
                _delete_identity_dependents(con, [normalized])
            con.commit()
            return rc.rowcount > 0
        finally:
            con.close()


def delete_registered_by_emails(emails: list[str]) -> int:
    cleaned = list(dict.fromkeys(
        e.strip().lower() for e in (emails or []) if e and e.strip()
    ))
    if not cleaned:
        return 0
    with _lock:
        con = _conn()
        try:
            con.execute("BEGIN IMMEDIATE")
            placeholders = ",".join("?" * len(cleaned))
            existing = [
                row[0]
                for row in con.execute(
                    f"SELECT email FROM registered WHERE email IN ({placeholders})",
                    cleaned,
                )
            ]
            if not existing:
                return 0
            _raise_if_active_identity_run(con, existing)
            _raise_if_protected_identity_delete(con, existing)
            existing_placeholders = ",".join("?" * len(existing))
            rc = con.execute(
                f"DELETE FROM registered WHERE email IN ({existing_placeholders})",
                existing,
            )
            _delete_identity_dependents(con, existing)
            con.commit()
            return rc.rowcount
        finally:
            con.close()


def force_delete_registered_by_emails(emails: list[str]) -> int:
    """Explicitly delete only unresolved credential identities in one transaction."""
    cleaned = list(dict.fromkeys(
        e.strip().lower() for e in (emails or []) if e and e.strip()
    ))
    if not cleaned:
        return 0
    with _lock:
        con = _conn()
        try:
            con.execute("BEGIN IMMEDIATE")
            _raise_if_active_identity_run(con, cleaned)
            _raise_if_force_delete_not_eligible(con, cleaned)
            placeholders = ",".join("?" * len(cleaned))
            rc = con.execute(
                f"DELETE FROM registered WHERE email IN ({placeholders})",
                cleaned,
            )
            _delete_identity_dependents(con, cleaned)
            con.commit()
            return rc.rowcount
        finally:
            con.close()


def delete_all_registered() -> int:
    with _lock:
        con = _conn()
        try:
            con.execute("BEGIN IMMEDIATE")
            registered_count = con.execute(
                "SELECT COUNT(*) FROM registered"
            ).fetchone()[0]
            if not registered_count:
                return 0
            _raise_if_active_identity_run(con)
            _raise_if_protected_identity_delete(con)
            for table in _IDENTITY_DEPENDENT_TABLES:
                con.execute(
                    f"DELETE FROM {table} "
                    "WHERE email IN (SELECT email FROM registered)"
                )
            rc = con.execute("DELETE FROM registered")
            con.commit()
            return rc.rowcount
        finally:
            con.close()


# ──────────────────────── 运行记录 ────────────────────────


_RUN_PHASE_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_MILLISECOND = Decimal("0.001")


def _valid_run_phase(phase: object) -> bool:
    return (
        isinstance(phase, str)
        and _RUN_PHASE_RE.fullmatch(phase) is not None
        and "token" not in phase
    )


def _round_run_phase_time(value: float) -> float:
    return float(
        Decimal(str(value)).quantize(_MILLISECOND, rounding=ROUND_HALF_UP)
    )


def _decode_run_phase_timing(raw: object) -> dict:
    try:
        payload = json.loads(raw) if isinstance(raw, str) and raw else {}
    except (TypeError, ValueError):
        payload = {}
    raw_events = payload.get("events") if isinstance(payload, dict) else []
    events = []
    if not isinstance(raw_events, list):
        return {"events": events}
    for item in raw_events:
        if not isinstance(item, dict) or not _valid_run_phase(item.get("phase")):
            continue
        try:
            observed_at = float(item.get("at"))
        except (TypeError, ValueError):
            continue
        if not math.isfinite(observed_at):
            continue
        events.append({
            "phase": item["phase"],
            "at": _round_run_phase_time(observed_at),
        })
    return {"events": events}


def record_run_phase(
    run_id: str,
    phase: str,
    observed_at: float | None = None,
) -> bool:
    if not _valid_run_phase(phase):
        return False
    try:
        event_time = float(time.time() if observed_at is None else observed_at)
    except (TypeError, ValueError):
        return False
    if not math.isfinite(event_time):
        return False
    with _lock:
        con = _conn()
        try:
            con.execute("BEGIN IMMEDIATE")
            row = con.execute(
                "SELECT timing_json FROM runs WHERE run_id=?",
                (run_id,),
            ).fetchone()
            if row is None:
                con.rollback()
                return False
            timing = _decode_run_phase_timing(row["timing_json"])
            events = timing["events"]
            if not events or events[-1]["phase"] != phase:
                events.append({
                    "phase": phase,
                    "at": _round_run_phase_time(event_time),
                })
            con.execute(
                "UPDATE runs SET timing_json=? WHERE run_id=?",
                (
                    json.dumps(
                        timing,
                        ensure_ascii=True,
                        separators=(",", ":"),
                    ),
                    run_id,
                ),
            )
            con.commit()
            return True
        finally:
            con.close()


def get_run(run_id: str) -> dict | None:
    con = _conn()
    try:
        row = con.execute(
            "SELECT * FROM runs WHERE run_id=?",
            (run_id,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        con.close()


def get_run_phase_timing(run_id: str) -> dict:
    con = _conn()
    try:
        row = con.execute(
            "SELECT timing_json FROM runs WHERE run_id=?",
            (run_id,),
        ).fetchone()
        return _decode_run_phase_timing(row["timing_json"] if row else None)
    finally:
        con.close()


class RegisteredIdentityUnavailableError(RuntimeError):
    """Raised when a reauthorization identity vanished or is already leased."""


def create_run(
    run_id: str,
    email: str,
    log_path: str,
    *,
    run_kind: str = "registration",
    required_registered_emails: Optional[list[str]] = None,
    claim_account_email: str = "",
) -> Optional[dict]:
    normalized_kind = (run_kind or "registration").strip().lower()
    if normalized_kind not in (
        "registration", "reauthorization", "refresh_token", "password_reset",
    ):
        raise ValueError(f"unsupported run_kind: {normalized_kind}")
    required = list(dict.fromkeys(
        item.strip().lower()
        for item in (required_registered_emails or [])
        if item and item.strip()
    ))
    with _lock:
        con = _conn()
        claimed_account: Optional[dict] = None
        try:
            con.execute("BEGIN IMMEDIATE")
            if required:
                placeholders = ",".join("?" * len(required))
                existing = {
                    row[0]
                    for row in con.execute(
                        f"SELECT email FROM registered WHERE email IN ({placeholders})",
                        required,
                    )
                }
                if len(existing) != len(required):
                    missing = next(
                        item for item in required if item not in existing
                    )
                    raise RegisteredIdentityUnavailableError(missing)
                leased = con.execute(
                    f"SELECT email FROM active_identity_leases "
                    f"WHERE email IN ({placeholders}) LIMIT 1",
                    required,
                ).fetchone()
                if leased:
                    raise RegisteredIdentityUnavailableError(leased[0])
            claim_email = (claim_account_email or "").strip().lower()
            if claim_email:
                if claim_email not in required:
                    raise RegisteredIdentityUnavailableError(claim_email)
                pool_row = con.execute(
                    "SELECT * FROM outlook_accounts "
                    "WHERE lower(email)=lower(?) AND status IN ('available', 'failed')",
                    (claim_email,),
                ).fetchone()
                if not pool_row:
                    raise RegisteredIdentityUnavailableError(claim_email)
                claimed_at = time.time()
                updated = con.execute(
                    "UPDATE outlook_accounts SET status='in_use', claimed_at=?, "
                    "fail_reason=NULL WHERE lower(email)=lower(?) "
                    "AND status IN ('available', 'failed')",
                    (claimed_at, claim_email),
                )
                if updated.rowcount != 1:
                    raise RegisteredIdentityUnavailableError(claim_email)
                claimed_account = dict(pool_row)
                claimed_account["status"] = "in_use"
                claimed_account["claimed_at"] = claimed_at
                claimed_account["fail_reason"] = None
            con.execute(
                "INSERT INTO runs(run_id, email, status, started_at, log_path, run_kind) "
                "VALUES (?, ?, 'running', ?, ?, ?)",
                (run_id, email.lower(), time.time(), log_path, normalized_kind),
            )
            if required:
                created_at = time.time()
                con.executemany(
                    "INSERT INTO active_identity_leases(email, run_id, created_at) "
                    "VALUES (?, ?, ?)",
                    [(item, run_id, created_at) for item in required],
                )
            con.commit()
            return claimed_account
        finally:
            con.close()


def update_run_email(run_id: str, email: str) -> bool:
    normalized = (email or "").strip().lower()
    if not normalized:
        return False
    with _lock:
        con = _conn()
        try:
            rc = con.execute(
                "UPDATE runs SET email=? WHERE run_id=?",
                (normalized, run_id),
            )
            con.commit()
            return rc.rowcount == 1
        finally:
            con.close()


def registration_run_outcome(result: dict) -> dict:
    """Persist only explicit, credential-free completion evidence for this run."""
    complete = (
        result.get("registration_complete") is True
        and result.get("registration_pending") is not True
        and result.get("password_recovery_required") is not True
    )
    return {
        "registration_complete": complete,
        "registration_pending": not complete,
        "password_recovery_required": result.get("password_recovery_required") is True,
    }


def finish_run(
    run_id: str, status: str, error: str = "", category: str = "", *, result: dict | None = None,
) -> None:
    safe_error = sanitize_text(error)[:500]
    outcome_json = (
        json.dumps(registration_run_outcome(result), separators=(",", ":"))
        if status == "done" and isinstance(result, dict) else None
    )
    with _lock:
        con = _conn()
        try:
            if (
                status in {"done", "failed", "cancelled"}
                and isinstance(result, dict) and result.get("type") == "password_reset_batch"
            ):
                run = con.execute("SELECT run_kind FROM runs WHERE run_id=?", (run_id,)).fetchone()
                if not run or run["run_kind"] != "password_reset":
                    raise ValueError("密码重置回执只能保存到密码重置任务")
                accounts = result.get("accounts")
                accounts = accounts if isinstance(accounts, list) else []
                total = result.get("total")
                outcome = {
                    "v": 1, "type": "password_reset_batch",
                    "total": total if type(total) is int and 0 <= total <= 100 else 0,
                    "accounts": [safe_password_reset_result(item) for item in accounts[:100] if isinstance(item, dict)],
                    "upstream_text_stored": False,
                    "truncated": len(accounts) > 100,
                }
                outcome_json = json.dumps(outcome, ensure_ascii=False, separators=(",", ":"))
            con.execute(
                "UPDATE runs SET status=?, finished_at=?, error=?, error_category=?, result_json=? "
                "WHERE run_id=? AND result_json IS NULL",
                (status, time.time(), safe_error, category or None, outcome_json, run_id),
            )
            if status not in ("running", "pending", "in_progress", "cancelling"):
                con.execute(
                    "DELETE FROM active_identity_leases WHERE run_id=?",
                    (run_id,),
                )
            con.commit()
        finally:
            con.close()


def cancel_running_runs(message: str = "服务重启，任务已中断") -> int:
    safe_message = sanitize_text(message)[:500]
    with _lock:
        con = _conn()
        try:
            cur = con.execute(
                "UPDATE runs SET status='cancelled', finished_at=?, error=? "
                "WHERE status='running'",
                (time.time(), safe_message),
            )
            con.execute(
                "DELETE FROM active_identity_leases WHERE run_id NOT IN ("
                "SELECT run_id FROM runs WHERE status IN "
                "('running', 'pending', 'in_progress', 'cancelling')"
                ")"
            )
            con.commit()
            return cur.rowcount
        finally:
            con.close()


def list_runs(limit: int = 50) -> list[dict]:
    con = _conn()
    cur = con.execute(
        "SELECT * FROM runs ORDER BY started_at DESC LIMIT ?", (limit,),
    )
    return [dict(r) for r in cur.fetchall()]


# ──────────────────────── settings (KV) ────────────────────────


def get_setting(key: str, default: str = "") -> str:
    con = _conn()
    cur = con.execute("SELECT value FROM settings WHERE key=?", (key,))
    row = cur.fetchone()
    return row["value"] if row else default


def set_setting(key: str, value) -> None:
    with _lock:
        con = _conn()
        con.execute(
            "INSERT INTO settings(key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, str(value)),
        )
        con.commit()


# ──────────────────────── 邮箱来源配置 ────────────────────────


def get_mail_config() -> dict:
    """返回邮箱来源配置（密码类字段隐藏明文）。

    provider 声明的配置项自动带出来 —— 加新邮箱时这里不用改，
    新 provider 的 config_fields 会自动出现在返回值里。
    """
    from mail_providers import list_providers

    out = {"mail_source": get_setting("mail_source", "outlook")}
    for p in list_providers():
        for f in p["config_fields"]:
            key = f["key"]
            if f.get("type") == "password":
                out[key] = "***" if get_setting(key) else ""
            else:
                out[key] = get_setting(key, "")
    return out


def save_mail_config(data: dict) -> None:
    """保存邮箱配置。password 类字段传 '***' 表示不修改。

    mail_source 校验改成查 mail_providers 注册表：
        以前是写死的白名单 ("outlook", "cf_temp")，选了别的会被
        **静默改回 outlook** —— 用户看到的是"保存成功但选择没生效"。
        现在未知来源直接抛错，问题当场暴露。
    """
    from mail_providers import get_provider_class, list_providers

    if "mail_source" in data:
        src = str(data["mail_source"]).strip().lower()
        get_provider_class(src)  # 未注册的 kind 会抛 MailProviderError
        set_setting("mail_source", src)

    # 按 provider 声明的字段保存，加新邮箱时这里零改动
    for p in list_providers():
        for f in p["config_fields"]:
            key = f["key"]
            if key not in data:
                continue
            val = data[key]
            if f.get("type") == "password":
                if not val or val == "***":
                    continue  # 没填 / 是掩码 → 保持原值
            set_setting(key, str(val).strip())


def get_secret_setting(key: str) -> str:
    """内部用：拿密码类配置的明文。"""
    return get_setting(key, "")


def get_mail_settings() -> dict:
    """内部用：给 create_mail_provider 的 settings（含明文密钥）。

    跟 get_mail_config 的区别：这个不打码，只在服务端构造 provider 时用，
    绝不能直接返回给前端。
    """
    from mail_providers import list_providers

    out = {"mail_source": get_setting("mail_source", "outlook")}
    for p in list_providers():
        for f in p["config_fields"]:
            out[f["key"]] = get_setting(f["key"], "")
    return out


def get_cf_admin_token() -> str:
    """内部用：拿明文 admin_token。"""
    return get_setting("cf_admin_token", "")


# ──────────────────────── SMS 接码配置 ────────────────────────


def get_sms_config() -> dict:
    """返回 SMS 接码配置（api_key 隐藏明文）。

    sms_enabled:        '0'/'1' 是否启用接码（命中 add-phone 时才会用）
    sms_provider:       smsbower
    sms_country:        国家代码或 ID（推荐 '52' = Thailand，OpenAI 走 SMS 的唯一稳定国家）
    sms_service:        服务代码（OpenAI = 'dr'）
    sms_max_price:      号码最高单价（SmsBower / SmsBower 用，单位平台货币；空 / -1 = 不限）
    sms_reuse_phone:    '0'/'1' 同号复用（SmsBower / SmsBower 支持，省钱）
    sms_phone_success_max: 同号最多复用几次（默认 3）
    sms_auto_country:   '0'/'1' 自动选最优国家（按价格 + 库存）
    sms_auto_min_stock: 自动选国家最低库存（默认 20）
    sms_auto_max_price: 自动选国家最高单价（默认 0 = 不限）
    """
    return {
        "sms_enabled":             get_setting("sms_enabled", "0"),
        "sms_provider":            get_setting("sms_provider", "smsbower"),
        "sms_api_key":             "***" if get_setting("sms_api_key") else "",
        "sms_country":             get_setting("sms_country", "52"),
        "sms_service":             get_setting("sms_service", "dr"),
        "sms_max_price":           get_setting("sms_max_price", ""),
        "sms_reuse_phone":         get_setting("sms_reuse_phone", "0"),
        "sms_phone_success_max":   get_setting("sms_phone_success_max", "3"),
        "sms_auto_country":        get_setting("sms_auto_country", "0"),
        "sms_strict_whitelist":    get_setting("sms_strict_whitelist", "0"),
        "sms_allowed_countries":   get_setting("sms_allowed_countries", ""),
        "sms_auto_min_stock":      get_setting("sms_auto_min_stock", "20"),
        "sms_auto_max_price":      get_setting("sms_auto_max_price", ""),
        "sms_max_phone_attempts":  get_setting("sms_max_phone_attempts", ""),
        "sms_per_phone_timeout":   get_setting("sms_per_phone_timeout", "80"),
    }


def save_sms_config(data: dict) -> None:
    """保存 SMS 配置。sms_api_key 传 '***' 表示不修改。"""
    # 校验 provider
    valid_providers = {"smsbower", "herosms"}
    if "sms_provider" in data:
        p = str(data["sms_provider"]).strip().lower()
        if p not in valid_providers:
            p = "smsbower"
        set_setting("sms_provider", p)
    # 字符串字段直接落
    for key in (
        "sms_country", "sms_service", "sms_max_price",
        "sms_phone_success_max", "sms_auto_min_stock", "sms_auto_max_price",
        "sms_max_phone_attempts", "sms_per_phone_timeout",
        "sms_allowed_countries",
    ):
        if key in data:
            set_setting(key, str(data[key]).strip())
    # 布尔字段（前端传 '0'/'1' 或 bool）
    for key in ("sms_enabled", "sms_reuse_phone", "sms_auto_country", "sms_strict_whitelist"):
        if key in data:
            v = data[key]
            if isinstance(v, bool):
                set_setting(key, "1" if v else "0")
            else:
                s = str(v).strip().lower()
                set_setting(key, "1" if s in ("1", "true", "yes", "on") else "0")
    # API key（'***' 不修改）
    if data.get("sms_api_key") and data["sms_api_key"] != "***":
        set_setting("sms_api_key", str(data["sms_api_key"]).strip())


def get_sms_internal_config() -> dict:
    """内部用：拿明文 sms_api_key,供 sms_provider 实例化使用。"""
    return {
        "sms_enabled":             get_setting("sms_enabled", "0") in ("1", "true"),
        "sms_provider":            get_setting("sms_provider", "smsbower"),
        "sms_api_key":             get_setting("sms_api_key", ""),
        "sms_country":             get_setting("sms_country", "52"),
        "sms_service":             get_setting("sms_service", "dr"),
        "sms_max_price":           get_setting("sms_max_price", ""),
        "sms_reuse_phone":         get_setting("sms_reuse_phone", "0") in ("1", "true"),
        "sms_phone_success_max":   get_setting("sms_phone_success_max", "3"),
        "sms_auto_country":        get_setting("sms_auto_country", "0") in ("1", "true"),
        "sms_strict_whitelist":    get_setting("sms_strict_whitelist", "0") in ("1", "true"),
        "sms_allowed_countries":   get_setting("sms_allowed_countries", ""),
        "sms_auto_min_stock":      get_setting("sms_auto_min_stock", "20"),
        "sms_auto_max_price":      get_setting("sms_auto_max_price", ""),
        "sms_max_phone_attempts":  get_setting("sms_max_phone_attempts", ""),
        "sms_per_phone_timeout":   get_setting("sms_per_phone_timeout", "80"),
    }


# ──────────────────────── 自动导出配置 (CPA / SUB2API) ────────────────────────


def get_export_config() -> dict:
    """返回导出配置（敏感字段做明文/'***' 占位）。

    给前端展示用：
      cpa_mgmt_key / sub2api_api_key 已设置时返回 '***'，未设置返回 ''。
      保存时传 '***' 代表不修改。
    """
    return {
        # CPA
        "cpa_enabled":     get_setting("export_cpa_enabled", "0"),
        "cpa_url":         get_setting("export_cpa_url", ""),
        "cpa_mgmt_key":    "***" if get_setting("export_cpa_mgmt_key") else "",
        "cpa_timeout":     get_setting("export_cpa_timeout", "30"),
        # SUB2API
        "sub2api_enabled":    get_setting("export_sub2api_enabled", "0"),
        "sub2api_url":        get_setting("export_sub2api_url", ""),
        "sub2api_api_key":    "***" if get_setting("export_sub2api_api_key") else "",
        "sub2api_group_ids":  get_setting("export_sub2api_group_ids", "2"),
        "sub2api_timeout":    get_setting("export_sub2api_timeout", "30"),
    }


def save_export_config(data: dict) -> None:
    """保存导出配置。密文字段传 '***' 表示不修改。"""
    # 布尔开关
    for key_in, key_out in (
        ("cpa_enabled",     "export_cpa_enabled"),
        ("sub2api_enabled", "export_sub2api_enabled"),
    ):
        if key_in in data:
            v = data[key_in]
            if isinstance(v, bool):
                set_setting(key_out, "1" if v else "0")
            else:
                s = str(v).strip().lower()
                set_setting(key_out, "1" if s in ("1", "true", "yes", "on") else "0")
    # 字符串字段（明文）
    for key_in, key_out in (
        ("cpa_url",            "export_cpa_url"),
        ("cpa_timeout",        "export_cpa_timeout"),
        ("sub2api_url",        "export_sub2api_url"),
        ("sub2api_group_ids",  "export_sub2api_group_ids"),
        ("sub2api_timeout",    "export_sub2api_timeout"),
    ):
        if key_in in data:
            set_setting(key_out, str(data[key_in] or "").strip())
    # 密文字段（'***' 不修改）
    if data.get("cpa_mgmt_key") and data["cpa_mgmt_key"] != "***":
        set_setting("export_cpa_mgmt_key", str(data["cpa_mgmt_key"]).strip())
    if data.get("sub2api_api_key") and data["sub2api_api_key"] != "***":
        set_setting("export_sub2api_api_key", str(data["sub2api_api_key"]).strip())


def get_export_internal_config() -> dict:
    """内部用：拿明文密钥 + 解析后的 enabled 布尔。供 registrar / app.test 调用。

    返回两个子配置 dict，可分别传给 exporter.export_to_cpa / export_to_sub2api。
    """
    cpa = {
        "enabled":      get_setting("export_cpa_enabled", "0") in ("1", "true"),
        "cpa_url":      get_setting("export_cpa_url", ""),
        "cpa_mgmt_key": get_setting("export_cpa_mgmt_key", ""),
        "cpa_timeout":  get_setting("export_cpa_timeout", "30"),
    }
    sub2api = {
        "enabled":            get_setting("export_sub2api_enabled", "0") in ("1", "true"),
        "sub2api_url":        get_setting("export_sub2api_url", ""),
        "sub2api_api_key":    get_setting("export_sub2api_api_key", ""),
        "sub2api_group_ids":  get_setting("export_sub2api_group_ids", "2"),
        "sub2api_timeout":    get_setting("export_sub2api_timeout", "30"),
    }
    return {"cpa": cpa, "sub2api": sub2api}


# 模块加载时自动建表
init_db()
