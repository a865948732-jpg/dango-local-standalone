"""Persistent ASN allocation and MoMo performance policy."""
from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path


class AsnPerformanceStore:
    def __init__(self, path: str | Path):
        self.path = str(path)
        self._lock = threading.RLock()
        with self._connect() as con:
            con.execute("""CREATE TABLE IF NOT EXISTS asn_performance (
                asn TEXT PRIMARY KEY, isp TEXT NOT NULL DEFAULT '', network_type TEXT NOT NULL,
                valid_samples INTEGER NOT NULL DEFAULT 0, hits INTEGER NOT NULL DEFAULT 0,
                enabled INTEGER NOT NULL DEFAULT 1, disabled_reason TEXT NOT NULL DEFAULT '', metadata_json TEXT NOT NULL DEFAULT '{}',
                proxy_failures INTEGER NOT NULL DEFAULT 0, proxy_successes INTEGER NOT NULL DEFAULT 0,
                consecutive_proxy_failures INTEGER NOT NULL DEFAULT 0
            )""")
            cols = {row[1] for row in con.execute("PRAGMA table_info(asn_performance)").fetchall()}
            if "proxy_failures" not in cols:
                con.execute("ALTER TABLE asn_performance ADD COLUMN proxy_failures INTEGER NOT NULL DEFAULT 0")
            if "proxy_successes" not in cols:
                con.execute("ALTER TABLE asn_performance ADD COLUMN proxy_successes INTEGER NOT NULL DEFAULT 0")
            if "consecutive_proxy_failures" not in cols:
                con.execute("ALTER TABLE asn_performance ADD COLUMN consecutive_proxy_failures INTEGER NOT NULL DEFAULT 0")
            con.execute("CREATE TABLE IF NOT EXISTS asn_performance_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")

    def _connect(self):
        con = sqlite3.connect(self.path, timeout=30)
        con.row_factory = sqlite3.Row
        return con

    def configure(self, candidates):
        with self._lock, self._connect() as con:
            for candidate in candidates or []:
                asn = str(candidate.get("asn") or "").strip().upper()
                network = str(candidate.get("network_type") or "unknown").strip().lower()
                if not asn or network not in {"residential_candidate", "mobile"}:
                    continue
                existing = con.execute("SELECT metadata_json FROM asn_performance WHERE asn=?", (asn,)).fetchone()
                metadata = json.loads(existing["metadata_json"] or "{}") if existing else {}
                metadata.update({key: value for key, value in candidate.items() if value not in (None, "")})
                con.execute("""INSERT INTO asn_performance(asn,isp,network_type,metadata_json) VALUES(?,?,?,?)
                    ON CONFLICT(asn) DO UPDATE SET isp=excluded.isp,network_type=excluded.network_type,metadata_json=excluded.metadata_json""",
                    (asn, str(candidate.get("isp") or metadata.get("isp") or ""), network, json.dumps(metadata, ensure_ascii=False)))
        return self.list()

    def list(self):
        with self._connect() as con:
            rows = con.execute("SELECT * FROM asn_performance ORDER BY asn").fetchall()
        result = []
        for row in rows:
            item = dict(row)
            metadata = json.loads(item.pop("metadata_json") or "{}")
            for key in ("country_code", "session_minutes", "max_attempts"):
                if key in metadata:
                    item[key] = metadata[key]
            item["enabled"] = bool(item["enabled"])
            item["hit_rate"] = round(item["hits"] / item["valid_samples"] * 100, 1) if item["valid_samples"] else 0.0
            result.append(item)
        return result

    def internal_config(self, asn):
        with self._connect() as con:
            row = con.execute("SELECT metadata_json FROM asn_performance WHERE asn=?", (str(asn).upper(),)).fetchone()
        return json.loads(row["metadata_json"] or "{}") if row else {}

    def allocate(self, count):
        with self._lock, self._connect() as con:
            rows = [dict(row) for row in con.execute("SELECT asn,enabled FROM asn_performance ORDER BY asn").fetchall() if row["enabled"]]
            if not rows:
                return []
            cursor_row = con.execute("SELECT value FROM asn_performance_meta WHERE key='cursor'").fetchone()
            cursor = int(cursor_row["value"]) if cursor_row else 0
            result = [rows[(cursor + index) % len(rows)]["asn"] for index in range(max(0, int(count)))]
            con.execute("INSERT INTO asn_performance_meta(key,value) VALUES('cursor',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (str((cursor + len(result)) % len(rows)),))
            return result

    def record(self, asn, *, hit, valid=True):
        key = str(asn or "").strip().upper()
        with self._lock, self._connect() as con:
            row = con.execute("SELECT valid_samples,hits,enabled FROM asn_performance WHERE asn=?", (key,)).fetchone()
            if not row or not valid:
                return
            samples = int(row["valid_samples"]) + 1
            hits = int(row["hits"]) + (1 if hit else 0)
            con.execute("UPDATE asn_performance SET valid_samples=?,hits=? WHERE asn=?", (samples, hits, key))

    def finalize_round(self, hits_by_asn):
        """Keep all ASNs enabled after a round so hit-rate comparison stays available.

        Zero-hit ASNs are intentionally not auto-disabled; operators decide based on
        observed MoMo rates. Manual toggle remains available.
        """
        # Touch the payload so callers can still pass round stats without side effects.
        _ = {str(asn or "").strip().upper(): int(hits or 0) for asn, hits in (hits_by_asn or {}).items()}
        return ""

    def record_proxy_outcome(self, asn, *, ok: bool, threshold: int = 5) -> str:
        """Track transport/proxy health without auto-disabling ASN suppliers.

        Operators compare MoMo rates across ASNs manually; only manual toggle may
        disable an ASN. `threshold` is retained for API compatibility.
        """
        key = str(asn or "").strip().upper()
        if not key:
            return ""
        _ = max(1, int(threshold or 5))
        with self._lock, self._connect() as con:
            row = con.execute(
                "SELECT proxy_failures, proxy_successes, consecutive_proxy_failures FROM asn_performance WHERE asn=?",
                (key,),
            ).fetchone()
            if not row:
                return ""
            failures = int(row["proxy_failures"] or 0)
            successes = int(row["proxy_successes"] or 0)
            streak = int(row["consecutive_proxy_failures"] or 0)
            if ok:
                successes += 1
                streak = 0
            else:
                failures += 1
                streak += 1
            con.execute(
                "UPDATE asn_performance SET proxy_failures=?, proxy_successes=?, consecutive_proxy_failures=? WHERE asn=?",
                (failures, successes, streak, key),
            )
            return ""

    def set_enabled(self, asn, enabled):
        with self._connect() as con:
            con.execute("UPDATE asn_performance SET enabled=?,disabled_reason=? WHERE asn=?", (int(bool(enabled)), "" if enabled else "手动停用", str(asn).upper()))
