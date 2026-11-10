"""Native FastAPI adapter for int31 checkout-capability qualification."""
from __future__ import annotations

import re
import threading
import time
import uuid
from contextvars import copy_context
from copy import deepcopy
from decimal import Decimal, InvalidOperation
from concurrent.futures import ThreadPoolExecutor, as_completed
from itertools import cycle
from typing import Any

from fastapi import APIRouter, HTTPException, Query

from qualification import checker
from qualification.int31_client import Int31Error, Int31HTTPError, Int31TaskError, Int31TimeoutError, check_checkout_capabilities
from .proxy_screening import DynamicProxyFactory, FixedAsnConfig, generate_session_proxy, parse_711proxy_template

from . import qualification_store
from .qualification_status import qualification_category
from .asn_performance import AsnPerformanceStore
from safe_diagnostics import sanitize_text


MAX_WORKERS = 32
MAX_ITEMS = 2000
MAX_RETRY_ROUNDS = 3


def _lines(value: Any) -> list[str]:
    if isinstance(value, list):
        values = value
    else:
        values = str(value or "").replace("\r", "").split("\n")
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        item = str(value or "").strip()
        if item and item not in seen:
            seen.add(item)
            result.append(item)
    return result


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _redact(item)
            for key, item in value.items()
            if key.lower() not in {"access_token", "accesstoken", "token", "proxy", "proxyurl", "proxies", "proxy_template", "submitted_row", "cookie", "session_token"}
        }
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value


BUILTIN_PRESETS = {
    name: dict(preset)
    for name, preset in checker.BUILTIN_PRESETS.items()
}
REGION_COUNTRY_CODES = {
    name: str(preset.get("country") or "").upper()
    for name, preset in BUILTIN_PRESETS.items()
}
PROXY_RETRY_LIMIT = 6
PROXY_FAIL_BLACKLIST_THRESHOLD = 5


def _is_finished_result(row: Any) -> bool:
    if not isinstance(row, dict):
        return False
    if row.get("interrupted") or row.get("error"):
        return True
    if row.get("status") in {"checking", "queued", "running"}:
        return False
    return row.get("regions") is not None or "payment_method_types" in row or "available_channels" in row or "qualified" in row


def _count_finished(results: list[Any]) -> int:
    return sum(1 for row in results if _is_finished_result(row))


def _job_summary(results: list[Any], total: int) -> dict[str, int]:
    finished = [row for row in results if _is_finished_result(row)]
    failed = sum(bool(row.get("error") or row.get("interrupted")) for row in finished)
    eligible = sum(qualification_category(row) == 'eligible' for row in finished)
    return {"eligible": eligible, "ineligible": len(finished) - failed - eligible,
            "failed": failed, "completed": len(finished), "pending": max(0, total - len(finished)), "total": total}


def _safe_failure(exc: Exception, item: dict[str, Any]) -> str:
    text = str(exc)
    for key in ("token", "proxy"):
        secret = str(item.get(key) or "")
        if secret:
            text = text.replace(secret, "[REDACTED]")
    return str(sanitize_text(f"{type(exc).__name__}: {text}"))[:500]



def proxy_fingerprint(proxy_url: str) -> dict[str, str]:
    """Return non-secret proxy identity for failure attribution."""
    raw = str(proxy_url or "").strip()
    host = ""
    session = ""
    try:
        # Prefer URL parsing when credentials are present.
        from urllib.parse import urlsplit, unquote
        value = raw if "://" in raw else ("http://" + raw)
        parts = urlsplit(value)
        if parts.hostname and parts.port:
            host = f"{parts.hostname}:{parts.port}"
        elif parts.hostname:
            host = parts.hostname
        username = unquote(parts.username or "")
        match = re.search(r"-session-([A-Za-z0-9_-]+?)(?:-sessTime-|-sessAuto-|$)", username, flags=re.I)
        if match:
            session = match.group(1)
    except Exception:
        host = ""
        session = ""
    if not host:
        # Fallback for host:port:user:pass
        fields = raw.split(":")
        if len(fields) >= 2 and "@" not in raw:
            host = f"{fields[0]}:{fields[1]}"
    fingerprint = host if not session else f"{host}#{session}"
    return {
        "proxy_host": host,
        "proxy_session": session,
        "proxy_fingerprint": fingerprint,
    }



def _normalize_targets(regions: list[Any]) -> list[dict[str, str]]:
    targets: list[dict[str, str]] = []
    if len(regions or []) > len(BUILTIN_PRESETS):
        raise ValueError("选择的目标渠道数量超过限制")
    for entry in regions or ["momo_vn"]:
        if isinstance(entry, dict):
            name = str(entry.get("preset") or entry.get("name") or "momo_vn").strip() or "momo_vn"
            if name not in BUILTIN_PRESETS:
                raise ValueError("未知支付渠道预设")
            preset = dict(BUILTIN_PRESETS[name])
            preset.update({k: str(v) for k, v in entry.items() if v is not None and k not in {"preset"}})
        else:
            name = str(entry or "momo_vn").strip() or "momo_vn"
            if name not in BUILTIN_PRESETS:
                raise ValueError("未知支付渠道预设")
            preset = dict(BUILTIN_PRESETS[name])
        targets.append({
            "preset": name,
            "channel": str(preset.get("channel") or name).lower(),
            "country": str(preset.get("country") or REGION_COUNTRY_CODES.get(name) or "").upper(),
            "currency": str(preset.get("currency") or "").upper(),
            "label": str(preset.get("label") or name),
            "plan": str(preset.get("plan") or "plus"),
        })
    return targets


def _primary_country(targets: list[dict[str, str]]) -> str:
    for target in targets:
        country = str(target.get("country") or "").upper()
        if country:
            return country
    return "VN"


def _target_groups(targets: list[dict[str, str]]) -> list[list[dict[str, str]]]:
    """Group targets that can share one checkout exit.

    The int31 response contains one provider country, currency, amount and
    payment-method list for the proxy used by that request.  Comparing that
    single response with targets from different countries makes every later
    target look mismatched.  Keep same-country/currency channels together,
    while creating an independent checkout request for each country/currency
    pair.
    """
    grouped: dict[tuple[str, str], list[dict[str, str]]] = {}
    order: list[tuple[str, str]] = []
    for target in targets:
        key = (
            str(target.get("country") or "").upper(),
            str(target.get("currency") or "").upper(),
        )
        if key not in grouped:
            grouped[key] = []
            order.append(key)
        grouped[key].append(target)
    return [grouped[key] for key in order]


def _merge_group_results(group_results: list[dict[str, Any]]) -> dict[str, Any]:
    """Merge independent country checks without inventing one global result."""
    regions: list[dict[str, Any]] = []
    methods: set[str] = set()
    reason_codes: set[str] = set()
    countries: set[str] = set()
    currencies: set[str] = set()
    amounts: list[Any] = []
    failures: list[dict[str, str]] = []
    evidence: list[str] = []
    for result in group_results:
        for source in result.get("regions") or []:
            region = deepcopy(source)
            region["qualified"] = _region_eligible(region)
            regions.append(region)
            if region.get("error"):
                failures.append({"preset": str(region.get("preset") or ""), "error": str(region["error"])})
        methods.update(str(value).lower() for value in (result.get("payment_method_types") or result.get("available_channels") or []))
        evidence_text = str(result.get("evidence") or "").strip()
        if evidence_text:
            evidence.append(evidence_text)
        # One amount per checkout, even when it covers multiple same-country channels.
        if result.get("amount_minor") not in (None, ""):
            amounts.append(result["amount_minor"])
        for region in result.get("regions") or []:
            if region.get("reason_codes"):
                reason_codes.update(str(code) for code in region["reason_codes"])
            country = str(region.get("country") or "").upper()
            currency = str(region.get("currency") or "").upper()
            if country:
                countries.add(country)
            if currency:
                currencies.add(currency)
    qualified = any(region["qualified"] for region in regions)
    amount = amounts[0] if len(group_results) == 1 and amounts else None
    merged = {
        "qualified": qualified,
        "result": "eligible" if qualified else "ineligible",
        "reason_codes": [] if qualified else sorted(reason_codes),
        "available_channels": sorted(methods),
        "regions": regions,
        "checkout_backend": next((str(result.get("checkout_backend") or "") for result in group_results if result.get("checkout_backend")), ""),
        "processor_entity": next((str(result.get("processor_entity") or "") for result in group_results if result.get("processor_entity")), ""),
        "provider_country": next(iter(countries)) if len(countries) == 1 else "",
        "currency": next(iter(currencies)) if len(currencies) == 1 else "",
        "amount_minor": amount,
        "is_free_trial": bool(amounts) and len(amounts) == len(group_results) and all(_explicit_zero(value) for value in amounts),
        "payment_method_types": sorted(methods),
        "evidence": "；".join(evidence),
        "email": next((str(result.get("email")) for result in group_results if result.get("email")), ""),
        "region_errors": failures,
        "retryable": bool(failures),
        "partial": bool(failures),
    }
    if failures and not qualified:
        merged.update(status="failed", result="failed", error="部分地区检测失败，请重试失败地区")
    return merged


def _explicit_zero(value: Any) -> bool:
    try:
        return not isinstance(value, bool) and Decimal(str(value)).is_finite() and Decimal(str(value)) == 0
    except (InvalidOperation, ValueError, TypeError):
        return False


def _region_eligible(region: dict[str, Any]) -> bool:
    """Require complete evidence from this region, never a cross-region union."""
    methods = region.get("payment_method_types")
    channel = str(region.get("channel") or "").lower()
    country = str(region.get("country") or "").upper()
    currency = str(region.get("currency") or "").upper()
    return bool(region.get("qualified") is True and not region.get("error")
                and not region.get("reason_codes") and channel
                and isinstance(methods, list) and channel in [str(m).lower() for m in methods]
                and _explicit_zero(region.get("amount_minor"))
                and country and currency
                and country == str(region.get("requested_country") or country).upper()
                and currency == str(region.get("requested_currency") or currency).upper())


def recover_interrupted_jobs() -> int:
    """Mark leftover running slots after a process restart as interrupted."""
    tasks, _total = qualification_store.list_tasks(limit=500, offset=0)
    changed = 0
    for summary in tasks:
        status = str(summary.get("status") or "")
        # Also repair terminal jobs that still contain null slots after a crash/restart.
        if status not in {"running", "retrying", "failed", "completed"}:
            continue
        job = qualification_store.get(str(summary.get("job_id") or ""))
        if not job:
            continue
        results = list(job.get("results") or [])
        items = list(job.get("items") or [])
        mutated = False
        for index in range(max(len(results), len(items), int(job.get("total") or 0))):
            row = results[index] if index < len(results) else None
            item = items[index] if index < len(items) else {}
            email = str((row or {}).get("email") if isinstance(row, dict) else "") or str(item.get("email") or "")
            asn = str((row or {}).get("asn") if isinstance(row, dict) else "") or str(item.get("asn") or "")
            in_flight = row is None or (
                isinstance(row, dict)
                and not row.get("error")
                and (
                    row.get("status") in {"checking", "queued", "running"}
                    or (not row.get("regions") and "qualified" not in row)
                )
            )
            if not in_flight:
                continue
            if index >= len(results):
                results.extend([None] * (index + 1 - len(results)))
            results[index] = {
                "index": index,
                "email": email,
                "asn": asn,
                "qualified": False,
                "interrupted": True,
                "status": "interrupted",
                "error": "检测中断，请重试",
            }
            mutated = True
        if not mutated:
            # Still repair inflated completed counters on terminal jobs.
            finished = _count_finished(results)
            if int(job.get("completed") or 0) != finished or int(job.get("completed") or 0) > int(job.get("total") or 0):
                job["completed"] = finished
                if finished < int(job.get("total") or 0) and str(job.get("status") or "") in {"completed", "failed"}:
                    # Keep terminal, but ensure failed when unfinished leftovers existed historically.
                    job["status"] = "failed" if any(isinstance(row, dict) and row.get("error") for row in results) else job.get("status")
                qualification_store.save(job)
                changed += 1
            continue
        job["results"] = results
        job["completed"] = _count_finished(results)
        job["status"] = "failed"
        job["finished_at"] = job.get("finished_at") or time.time()
        qualification_store.save(job)
        changed += 1
    return changed


class QualificationManager:
    def __init__(self, db_module: Any):
        self.db = db_module
        self.jobs: dict[str, dict[str, Any]] = {}
        self.lock = threading.RLock()
        self.asn_policy = AsnPerformanceStore(qualification_store.db.active_database_path())

    def select_accounts(self, *, query: str = "", pool_filter: str = "all", filter_rt: str = "all", plus_filter: str = "all") -> dict[str, Any]:
        if pool_filter not in {"all", "momo", "upi", "pending"}:
            raise ValueError("未知账户池筛选")
        emails = self.db.list_registered_selection(query=query, pool_filter=pool_filter, filter_rt=filter_rt, plus_filter=plus_filter, limit=MAX_ITEMS + 1)
        if len(emails) > MAX_ITEMS:
            raise ValueError(f"一次最多选择 {MAX_ITEMS} 个账号，请缩小筛选范围")
        return {"ok": True, "emails": emails, "total": len(emails), "scope": "filtered_workspace"}

    def list_accounts(self, *, limit: int = 20, offset: int = 0, query: str = "", pool_filter: str = "all") -> dict[str, Any]:
        rows = self.db.list_registered(limit=limit, offset=offset, query=query, pool_filter=pool_filter)
        total = self.db.count_registered(query=query, pool_filter=pool_filter)
        public = []
        for row in rows:
            public.append({
                "email": row.get("email", ""),
                "account_pool": row.get("account_pool", "pending"),
                "plus_check": row.get("plus_check"),
                "created_at": row.get("created_at"),
                "authorization_present": bool(row.get("authorization_present") or row.get("access_token") or row.get("at_len")),
            })
        return {"ok": True, "accounts": public, "total": total, "limit": limit, "offset": offset}

    def _items(self, payload: dict[str, Any]) -> list[dict[str, Any]]:
        raw_items = payload.get("items")
        if isinstance(raw_items, list):
            items = []
            for raw in raw_items:
                if not isinstance(raw, dict):
                    continue
                items.append({"token": str(raw.get("token") or raw.get("access_token") or "").strip(), "email": str(raw.get("email") or "").strip(), "proxy": str(raw.get("proxy") or "").strip()})
        else:
            emails = list(dict.fromkeys(email.lower() for email in _lines(payload.get("emails"))))
            tokens = _lines(payload.get("tokens") or payload.get("access_tokens"))
            items = []
            for email in emails:
                row = self.db.get_registered(email)
                items.append({"token": str((row or {}).get("access_token") or ""), "email": email, "proxy": "",
                              "input_error": "" if row and row.get("access_token") else ("TOKEN_MISSING" if row else "ACCOUNT_NOT_FOUND")})
            items.extend({"token": token, "email": "", "proxy": ""} for token in tokens)
        proxies = _lines(payload.get("proxies") or payload.get("proxy") or payload.get("proxy_pool"))
        if proxies:
            proxy_cycle = cycle(proxies)
            for item in items:
                if not item.get("proxy"):
                    item["proxy"] = next(proxy_cycle)
        items = [item for item in items if item.get("token") or item.get("email")]
        if len(items) > MAX_ITEMS:
            raise ValueError(f"一次最多检测 {MAX_ITEMS} 个账号，不会截断提交内容")
        return items

    @staticmethod
    def _proxy_config(payload: dict[str, Any], regions: list[Any]) -> tuple[str, str, int]:
        mode = str(payload.get("proxy_mode") or "manual").strip().lower()
        if mode not in {"manual", "711"}:
            raise ValueError("proxy_mode 必须是 manual 或 711")
        if mode == "manual":
            if len(_target_groups(_normalize_targets(regions))) > 1:
                raise ValueError("手动代理池不能自动按国家路由；请一次选择一个国家，或使用 711Proxy 动态")
            return mode, "", 60
        template = str(payload.get("proxy_template") or "").strip()
        if not template:
            raise ValueError("711 模式必须提供 proxy_template")
        try:
            parse_711proxy_template(template)
            session_minutes = int(payload.get("session_minutes") or 60)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"711 配置无效: {exc}") from exc
        if session_minutes not in {10, 30, 60, 120, 180}:
            raise ValueError("session_minutes 必须是 10/30/60/120/180")
        for entry in regions:
            name = str(entry.get("preset") or entry.get("name") or "momo_vn") if isinstance(entry, dict) else str(entry or "momo_vn")
            if REGION_COUNTRY_CODES.get(name, "") == "":
                raise ValueError(f"地区预设没有国家代码: {name}")
        return mode, template, session_minutes

    def create_batch(self, payload: dict[str, Any]) -> dict[str, Any]:
        items = self._items(payload)
        if not items:
            raise ValueError("请至少输入一条有效 Token 或注册账号")
        regions = payload.get("regions")
        if not isinstance(regions, list) or not regions:
            regions = [str(payload.get("preset") or "momo_vn")]
        _normalize_targets(regions)
        proxy_mode, proxy_template, session_minutes = self._proxy_config(payload, regions)
        active_asns = self.asn_policy.allocate(len(items)) if proxy_mode == "711" else []
        if active_asns:
            country = _primary_country(_normalize_targets(regions))
            compatible = {row["asn"] for row in self.asn_policy.list()
                          if row.get("enabled") and str(row.get("country_code") or "").upper() == country}
            active_asns = [asn for asn in active_asns if asn in compatible]
        if active_asns:
            for index, item in enumerate(items):
                item["asn"] = active_asns[index]
        try:
            workers = max(1, min(MAX_WORKERS, int(payload.get("workers") or 2)))
            max_attempts = max(1, min(PROXY_RETRY_LIMIT, int(payload.get("max_attempts") or 3)))
        except (TypeError, ValueError) as exc:
            raise ValueError("workers 必须是整数") from exc
        job_id = uuid.uuid4().hex
        job = {
            "job_id": job_id, "status": "running", "total": len(items), "completed": 0,
            "created_at": time.time(), "finished_at": None, "results": [{"index": i, "email": item.get("email", ""), "status": "queued"} for i, item in enumerate(items)],
            "items": items, "regions": regions, "workers": min(workers, len(items)),
            "proxy_mode": proxy_mode, "proxy_template": proxy_template,
            "session_minutes": session_minutes,
            "max_attempts": max_attempts, "retry_counts": {},
        }
        with self.lock:
            self.jobs[job_id] = job
        qualification_store.save(job)
        threading.Thread(target=copy_context().run, args=(self._run_batch, job_id), daemon=True, name=f"qualification-{job_id[:8]}").start()
        return {"ok": True, "job_id": job_id, "total": len(items), "workers": job["workers"]}

    def _run_multi_region_item(self, index: int, item: dict[str, Any], targets: list[dict[str, str]], job: dict[str, Any] | None = None, previous_result: dict[str, Any] | None = None) -> dict[str, Any]:
        """Run one independent checkout per country/currency target group."""
        group_rows: list[dict[str, Any]] = []
        groups = _target_groups(targets)
        enabled_asns = [row for row in self.asn_policy.list() if row.get("enabled")]
        cache = (previous_result or {}).get("region_checks") or []
        for group in groups:
            country = group[0]["country"]
            target_presets = [target["preset"] for target in group]
            cached = next((row for row in cache if row.get("target_presets") == target_presets
                           and not row.get("error") and not row.get("interrupted")), None)
            if cached is not None and (previous_result or {}).get("routing_version") == 2:
                group_rows.append(deepcopy(cached))
                continue
            group_item = dict(item)
            compatible = [row for row in enabled_asns if str(row.get("country_code") or "").upper() == country]
            if enabled_asns and not compatible:
                row = {"qualified": False, "status": "failed", "proxy_attempts": 0,
                       "error_code": "ASN_REGION_UNAVAILABLE", "error": f"没有已启用的 {country} ASN 策略，请补齐该国家策略"}
            else:
                if compatible:
                    preferred = next((row for row in compatible if row["asn"] == item.get("asn")), None)
                    group_item["asn"] = (preferred or compatible[index % len(compatible)])["asn"]
                else:
                    group_item["asn"] = ""
                try:
                    row = self._run_item(index, group_item, group, job)
                except Exception as exc:
                    row = {"qualified": False, "status": "failed", "proxy_attempts": 0,
                           "error": _safe_failure(exc, group_item)}
            if row.get("error") or row.get("interrupted"):
                row["regions"] = [{"preset": target["preset"], "name": target["label"], "channel": target["channel"],
                                   "requested_country": target["country"], "requested_currency": target["currency"],
                                   "country": "", "currency": "", "amount_minor": None, "payment_method_types": [],
                                   "qualified": False, "status": "failed", "error": row.get("error") or "地区检测中断",
                                   "error_code": row.get("error_code", "REGION_CHECK_FAILED"), "reason_codes": [row.get("error_code", "REGION_CHECK_FAILED")]}
                                  for target in group]
            row["target_presets"] = target_presets
            group_rows.append(row)

        merged = _merge_group_results(group_rows)
        merged.update({
            "index": index,
            "email": item.get("email") or merged.get("email") or "",
            "asn": "",
            "proxy_attempts": sum(int(row.get("proxy_attempts") or 0) for row in group_rows),
            "routing_version": 2,
            "region_checks": group_rows,
        })
        hosts = sorted({str(row.get("proxy_host") or "") for row in group_rows if row.get("proxy_host")})
        merged["proxy_host"] = ",".join(hosts)
        merged["proxy_session"] = ""
        merged["proxy_fingerprint"] = ""
        merged["proxy_regions"] = [
            {"country": group[0].get("country", ""), "asn": row.get("asn", ""), "proxy_host": row.get("proxy_host", ""), "proxy_attempts": row.get("proxy_attempts", 0)}
            for group, row in zip(groups, group_rows)
        ]
        return _redact(merged)

    def _run_item(self, index: int, item: dict[str, Any], regions: list[Any], job: dict[str, Any] | None = None, previous_result: dict[str, Any] | None = None) -> dict[str, Any]:
        if item.get("input_error") or not item.get("token"):
            code = item.get("input_error") or "TOKEN_MISSING"
            return {"index": index, "email": item.get("email", ""), "qualified": False, "status": "failed",
                    "error_code": code, "error": "账号不存在" if code == "ACCOUNT_NOT_FOUND" else "缺少 Access Token，请先补齐凭据", "proxy_attempts": 0}
        normalized_targets = _normalize_targets(regions)
        if len(_target_groups(normalized_targets)) > 1:
            if str((job or {}).get("proxy_mode") or "manual") != "711":
                return {"index": index, "email": item.get("email", ""), "qualified": False, "status": "failed",
                        "error_code": "MANUAL_REGION_ROUTING_UNSUPPORTED", "error": "手动代理池不能自动按国家路由，请分国家检测或使用 711Proxy 动态", "proxy_attempts": 0}
            return self._run_multi_region_item(index, item, normalized_targets, job, previous_result)
        proxy_mode = str((job or {}).get("proxy_mode") or "manual")
        proxy_template = str((job or {}).get("proxy_template") or "")
        session_minutes = int((job or {}).get("session_minutes") or 60)
        targets = _normalize_targets(regions)
        country = _primary_country(targets)
        assigned_asn = str(item.get("asn") or "")
        if proxy_mode == "711" and not assigned_asn:
            enabled = [row for row in self.asn_policy.list() if row.get("enabled")]
            compatible = [row for row in enabled if str(row.get("country_code") or "").upper() == country]
            if enabled and not compatible:
                return {"index": index, "email": item.get("email", ""), "qualified": False, "status": "failed",
                        "error_code": "ASN_REGION_UNAVAILABLE", "error": f"没有已启用的 {country} ASN 策略，请补齐该国家策略", "proxy_attempts": 0}
            if compatible:
                assigned_asn = compatible[index % len(compatible)]["asn"]
                item = {**item, "asn": assigned_asn}
        attempts = 0
        last_error = ""
        last_meta = {"proxy_host": "", "proxy_session": "", "proxy_fingerprint": ""}
        blacklisted = ""
        retry_limit = int((job or {}).get("max_attempts") or PROXY_RETRY_LIMIT)
        factory = None
        if proxy_mode == "711" and assigned_asn:
            stored = self.asn_policy.internal_config(assigned_asn)
            if str(stored.get("country_code") or "").upper() != country:
                return {"index": index, "email": item.get("email", ""), "qualified": False, "status": "failed",
                        "error_code": "ASN_REGION_UNAVAILABLE", "error": f"固定 ASN 策略与 {country} 目标地区不一致，请补齐该国家策略", "proxy_attempts": 0}
            stored.update({
                "asns": [assigned_asn],
                "country_code": country or "VN",
                "session_minutes": stored.get("session_minutes") or session_minutes,
                "proxy_template": stored.get("proxy_template") or proxy_template,
                "max_attempts": stored.get("max_attempts") or 30,
            })
            factory = DynamicProxyFactory(FixedAsnConfig.from_mapping(stored))

        while attempts < retry_limit:
            if job:
                wait = max(0, float(job.get("retry_not_before") or 0) - time.monotonic())
                if wait:
                    time.sleep(min(60, wait))
            attempts += 1
            proxy = ""
            try:
                if proxy_mode == "711":
                    if factory is not None:
                        proxy = factory.next_proxy()
                    else:
                        session_id = f"q{uuid.uuid4().hex[:24]}"
                        proxy = generate_session_proxy(proxy_template, country, session_id, session_minutes)
                else:
                    proxy = item.get("proxy") or ""
                last_meta = proxy_fingerprint(proxy)
                result = dict(check_checkout_capabilities(item["token"], proxy, targets=targets))
                result["index"] = index
                result["email"] = item.get("email") or result.get("email") or ""
                result["asn"] = item.get("asn") or ""
                result["proxy_attempts"] = attempts
                result.update(last_meta)
                if item.get("asn"):
                    self.asn_policy.record(item["asn"], hit=bool(result.get("qualified")), valid=True)
                    self.asn_policy.record_proxy_outcome(
                        item["asn"],
                        ok=True,
                        threshold=PROXY_FAIL_BLACKLIST_THRESHOLD,
                    )
                return _redact(result)
            except Exception as exc:
                last_error = _safe_failure(exc, {**item, "proxy": proxy})
                msg = str(exc)
                http_status = getattr(exc, "status_code", 0)
                if not http_status and isinstance(exc, Int31HTTPError):
                    match = re.search(r"HTTP (\d{3})", msg)
                    http_status = int(match.group(1)) if match else 0
                if http_status in {400, 401, 403, 404, 422}:
                    break
                rate_limited = isinstance(exc, Int31HTTPError) and ("HTTP 429" in msg or " 429" in msg)
                remote_timeout = (
                    isinstance(exc, Int31TaskError)
                    and ("TimeoutException" in msg or "TIMEOUT" in msg.upper())
                ) or isinstance(exc, Int31TimeoutError)
                # Rate limits / remote timeouts are int31-side. Back off, rotate session, do not burn ASN.
                if rate_limited or remote_timeout:
                    if attempts >= retry_limit:
                        break
                    delay = max(min(60, 4 * (2 ** max(0, attempts - 1))), getattr(exc, "retry_after", 0))
                    if job:
                        with self.lock:
                            job["retry_not_before"] = max(float(job.get("retry_not_before") or 0), time.monotonic() + delay)
                    else:
                        time.sleep(delay)
                    continue
                if item.get("asn") and proxy_mode == "711":
                    disabled = self.asn_policy.record_proxy_outcome(
                        item["asn"],
                        ok=False,
                        threshold=PROXY_FAIL_BLACKLIST_THRESHOLD,
                    )
                    if disabled:
                        blacklisted = disabled
                if proxy_mode != "711" or attempts >= retry_limit:
                    break
                if not isinstance(exc, (Int31Error, Int31TaskError, RuntimeError, ValueError)):
                    break
                continue

        row = {
            "index": index,
            "email": item.get("email") or "",
            "asn": item.get("asn") or "",
            "qualified": False,
            "status": "failed",
            "proxy_attempts": attempts,
            "error": last_error or "qualification failed",
        }
        row.update(last_meta)
        if blacklisted:
            row["asn_blacklisted"] = blacklisted
        return _redact(row)


    def _run_batch(self, job_id: str, indices: list[int] | None = None) -> None:
        with self.lock:
            job = self.jobs.get(job_id)
        if not job:
            return
        with ThreadPoolExecutor(max_workers=job["workers"]) as executor:
            hits_by_asn = {str(item.get("asn") or "").upper(): 0 for item in job["items"] if item.get("asn")}
            if len(_target_groups(_normalize_targets(job["regions"]))) > 1:
                hits_by_asn.update({row["asn"]: 0 for row in self.asn_policy.list() if row.get("enabled")})
            futures = {}
            def run(index, item):
                with self.lock:
                    previous = deepcopy(job["results"][index])
                    job["results"][index]["status"] = "checking"
                return self._run_item(index, item, job["regions"], job, previous_result=previous)
            for index in (indices if indices is not None else range(len(job["items"]))):
                item = job["items"][index]
                futures[executor.submit(copy_context().run, run, index, item)] = index
            for future in as_completed(futures):
                index = futures[future]
                try:
                    row = future.result()
                except Exception as exc:
                    row = {"index": index, "email": job["items"][index].get("email") or "", "qualified": False, "error": _safe_failure(exc, job["items"][index])}
                with self.lock:
                    job["results"][index] = row
                    job["completed"] = _count_finished(job["results"])
                    for check in row.get("region_checks") or [row]:
                        asn = str(check.get("asn") or "").upper()
                        if asn in hits_by_asn and check.get("qualified") and not check.get("error"):
                            hits_by_asn[asn] += 1
                    qualification_store.save(job)
        with self.lock:
            # Any leftover checking placeholders mean the worker exited uncleanly.
            for index, row in enumerate(list(job.get("results") or [])):
                if isinstance(row, dict) and row.get("status") in {"checking", "queued", "running"} and not row.get("error") and row.get("regions") is None:
                    job["results"][index] = {
                        "index": index,
                        "email": row.get("email") or (job["items"][index].get("email") if index < len(job.get("items") or []) else "") or "",
                        "asn": row.get("asn") or (job["items"][index].get("asn") if index < len(job.get("items") or []) else "") or "",
                        "qualified": False,
                        "interrupted": True,
                        "status": "interrupted",
                        "error": "检测中断，请重试",
                    }
            job["completed"] = _count_finished(job["results"])
            job["status"] = "failed" if any(isinstance(row, dict) and (row.get("error") or row.get("retryable")) for row in job["results"]) else "completed"
            job["finished_at"] = time.time()
            if job["status"] == "completed" and hits_by_asn:
                job["asn_round_hits"] = hits_by_asn
                if indices is None:
                    job["asn_disabled"] = self.asn_policy.finalize_round(hits_by_asn)
            qualification_store.save(job)

    def public_job(self, job_id: str) -> dict[str, Any]:
        with self.lock:
            job = self.jobs.get(job_id)
        if not job:
            job = qualification_store.get(job_id)
            if job:
                with self.lock:
                    self.jobs[job_id] = job
        if not job:
            raise KeyError(job_id)
        with self.lock:
            public = _redact(deepcopy({key: value for key, value in job.items() if key not in {"items", "retry_not_before"}}))
            public["summary"] = _job_summary(job.get("results") or [], int(job.get("total") or 0))
            return public

    def retry_item(self, job_id: str, index: int) -> dict[str, Any]:
        return self.retry_results(job_id, index=index)

    def retry_results(self, job_id: str, *, index: int | None = None) -> dict[str, Any]:
        with self.lock:
            job = self.jobs.get(job_id) or qualification_store.get(job_id)
            if not job:
                raise KeyError(job_id)
            if job.get("status") in {"running", "retrying"}:
                raise RuntimeError("任务仍在运行，请等待结束再重试")
            if index is not None and not 0 <= index < len(job.get("items") or []):
                raise IndexError(index)
            candidates = [index] if index is not None else list(range(len(job.get("items") or [])))
            counts = job.setdefault("retry_counts", {})
            indices = [i for i in candidates if isinstance(job["results"][i], dict)
                       and (job["results"][i].get("error") or job["results"][i].get("interrupted") or job["results"][i].get("retryable"))
                       and int(counts.get(str(i), 0)) < MAX_RETRY_ROUNDS]
            if not indices:
                raise ValueError("没有可重试的失败项，或已达到每项 3 轮重试上限")
            for i in indices:
                item = job["items"][i]
                # Fetch the latest saved credential; do not perpetuate a missing/stale token.
                if item.get("email"):
                    row = self.db.get_registered(item["email"])
                    item["token"] = str((row or {}).get("access_token") or "")
                    item["input_error"] = "" if item["token"] else ("TOKEN_MISSING" if row else "ACCOUNT_NOT_FOUND")
                counts[str(i)] = int(counts.get(str(i), 0)) + 1
                previous = job["results"][i]
                job["results"][i] = {"index": i, "email": item.get("email", ""), "status": "queued",
                                     "routing_version": previous.get("routing_version"), "region_checks": previous.get("region_checks") or []}
            job["completed"] = _count_finished(job["results"])
            job["status"] = "retrying"
            job["finished_at"] = None
            job.pop("retry_not_before", None)
            self.jobs[job_id] = job
            qualification_store.save(job)
        threading.Thread(target=copy_context().run, args=(self._run_batch, job_id, indices), daemon=True).start()
        return {"ok": True, "job_id": job_id, "indices": indices, "index": index, "status": "retrying"}



def create_qualification_router(db_module: Any) -> APIRouter:
    managers: dict[str, QualificationManager] = {}
    managers_lock = threading.RLock()

    def current_manager() -> QualificationManager:
        path = str(qualification_store.db.active_database_path())
        with managers_lock:
            if path not in managers:
                qualification_store.init()
                recover_interrupted_jobs()
                managers[path] = QualificationManager(db_module)
            return managers[path]

    router = APIRouter(prefix="/api/qualification", tags=["qualification"])

    @router.get("/presets")
    def presets() -> dict[str, Any]:
        return {"ok": True, "presets": checker.list_presets()}

    @router.get("/asn-policy")
    def asn_policy() -> dict[str, Any]:
        return {"ok": True, "asns": current_manager().asn_policy.list()}

    @router.post("/asn-policy")
    def configure_asn_policy(payload: dict[str, Any]) -> dict[str, Any]:
        return {"ok": True, "asns": current_manager().asn_policy.configure(payload.get("asns") or payload.get("candidates") or [])}

    @router.patch("/asn-policy/{asn}")
    def toggle_asn_policy(asn: str, payload: dict[str, Any]) -> dict[str, Any]:
        current_manager().asn_policy.set_enabled(asn, bool(payload.get("enabled")))
        return {"ok": True, "asns": current_manager().asn_policy.list()}

    @router.get("/accounts")
    def accounts(limit: int = Query(20, ge=1, le=200), offset: int = Query(0, ge=0), query: str = "", pool_filter: str = "all") -> dict[str, Any]:
        return current_manager().list_accounts(limit=limit, offset=offset, query=query, pool_filter=pool_filter)

    @router.get("/accounts/selection")
    def selection(query: str = "", pool_filter: str = "all", filter: str = "all", plus_filter: str = "all") -> dict[str, Any]:
        try:
            return current_manager().select_accounts(query=query, pool_filter=pool_filter, filter_rt=filter, plus_filter=plus_filter)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc

    @router.get("/proxies")
    def proxies() -> dict[str, Any]:
        return {"ok": True, "proxies": [], "source": "client_proxy_pool"}

    @router.post("/check")
    def check(payload: dict[str, Any]) -> dict[str, Any]:
        items = current_manager()._items(payload)
        if len(items) != 1:
            raise HTTPException(400, "单条检测只能提交一个 Token 或注册账号")
        regions = payload.get("regions") if isinstance(payload.get("regions"), list) else [payload.get("preset") or "momo_vn"]
        try:
            proxy_mode, proxy_template, session_minutes = current_manager()._proxy_config(payload, regions)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        job = {"proxy_mode": proxy_mode, "proxy_template": proxy_template, "session_minutes": session_minutes}
        return current_manager()._run_item(0, items[0], regions, job)

    @router.post("/batch")
    def batch(payload: dict[str, Any]) -> dict[str, Any]:
        try:
            return current_manager().create_batch(payload)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc

    @router.get("/batch")
    def list_batch(limit: int = Query(20, ge=1, le=200), offset: int = Query(0, ge=0)) -> dict[str, Any]:
        current_manager()
        tasks, total = qualification_store.list_tasks(limit, offset)
        return {"ok": True, "tasks": tasks, "total": total, "limit": limit, "offset": offset}

    @router.get("/batch/{job_id}")
    def get_batch(job_id: str) -> dict[str, Any]:
        try:
            return {"ok": True, **current_manager().public_job(job_id)}
        except KeyError as exc:
            raise HTTPException(404, "任务不存在或已过期") from exc

    @router.post("/batch/{job_id}/retry")
    def retry(job_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        try:
            if payload.get("failed_only") is True:
                return current_manager().retry_results(job_id)
            return current_manager().retry_item(job_id, int(payload.get("index")))
        except (TypeError, ValueError) as exc:
            raise HTTPException(400, str(exc)) from exc
        except RuntimeError as exc:
            raise HTTPException(409, str(exc)) from exc
        except KeyError as exc:
            raise HTTPException(404, "任务不存在或已过期") from exc
        except IndexError as exc:
            raise HTTPException(400, f"index 超出范围: {exc.args[0]}") from exc

    @router.delete("/batch/{job_id}")
    def delete_batch(job_id: str) -> dict[str, Any]:
        manager = current_manager()
        with manager.lock:
            job = manager.jobs.get(job_id) or qualification_store.get(job_id)
            if job and job.get("status") in {"running", "retrying"}:
                raise HTTPException(409, "任务运行中，请等待结束再删除")
            manager.jobs.pop(job_id, None)
        if not qualification_store.delete(job_id):
            raise HTTPException(404, "任务不存在或已过期")
        return {"ok": True, "job_id": job_id}

    return router


from . import db as _db

router = create_qualification_router(_db)

