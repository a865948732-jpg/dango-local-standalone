"""711Proxy ASN screening core isolated from registration workers."""
from __future__ import annotations

import concurrent.futures
import ipaddress
import logging
import re
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from statistics import median
from typing import Any
from urllib.parse import quote, unquote, urlsplit, urlunsplit

import requests
from safe_diagnostics import safe_proxy_probe_metadata, safe_proxy_transport_metadata, safe_traceback_summary

LOGGER = logging.getLogger(__name__)
SUPPORTED_HOSTS = {"global.rotgb.711proxy.com", "global.rotgbapi.711proxy.com"}
SUPPORTED_SESSION_MINUTES = (10, 30, 60, 120, 180)
_SUPPORTED_HOST_PATTERN = "|".join(re.escape(host) for host in sorted(SUPPORTED_HOSTS))
_CREDENTIAL_FIELD = r"[^\s:@/\\\[\]()<>\"',;|]+"
_AUTH_PROXY_RE = re.compile(
    rf"(?:(?P<scheme>https?|socks4a?|socks5h?)://)?"
    rf"(?P<username>{_CREDENTIAL_FIELD}):(?P<password>{_CREDENTIAL_FIELD})@"
    rf"(?P<host>{_SUPPORTED_HOST_PATTERN}):(?P<port>\d{{1,5}})",
    re.I,
)
_LEGACY_PROXY_RE = re.compile(
    rf"(?P<username>{_CREDENTIAL_FIELD}):(?P<password>{_CREDENTIAL_FIELD}):"
    rf"(?P<host>{_SUPPORTED_HOST_PATTERN}):(?P<port>\d{{1,5}})",
    re.I,
)
_HOST_FIRST_PROXY_RE = re.compile(
    rf"(?P<host>{_SUPPORTED_HOST_PATTERN}):(?P<port>\d{{1,5}}):"
    rf"(?P<username>{_CREDENTIAL_FIELD}):(?P<password>{_CREDENTIAL_FIELD})",
    re.I,
)
_SECRET_RE = re.compile(r"(https?://)([^/@:\s]+):([^/@\s]+)@", re.I)
@dataclass
class RawPass:
    ok: bool = False
    ip: str = ""
    country: str = ""
    asn: str = ""
    isp: str = ""
    network_type: str = "unknown"
    latency_ms: int | None = None
    reverse_dns: str = ""
    is_proxy: bool = False
    is_vpn: bool = False
    is_hosting: bool = False
    residential_confidence: int = 0
    intel_sources: int = 1
    intel_conflict: bool = False
    error_code: str = ""
    error: str = ""
    diagnostics: dict[str, Any] = field(default_factory=dict)

@dataclass
class SampleResult:
    index: int
    proxy: str
    masked_proxy: str = ""
    first: RawPass = field(default_factory=RawPass)
    second: RawPass = field(default_factory=RawPass)
    eligible: bool = False
    reason_code: str = ""
    reason: str = ""
    network_type: str = "unknown"
    asn: str = ""
    isp: str = ""
    latency_ms: int | None = None
    quality_score: int = 0

@dataclass
class Job:
    job_id: str
    country_code: str
    sample_count: int
    session_minutes: int
    concurrency: int
    created_at: float
    status: str = "queued"
    completed: int = 0
    success: int = 0
    failed: int = 0
    stage: str = "queued"
    samples: list[SampleResult] = field(default_factory=list)
    error: str = ""
    cancel_event: threading.Event = field(default_factory=threading.Event, repr=False)


@dataclass(frozen=True)
class FixedAsnConfig:
    country_code: str
    session_minutes: int
    asns: tuple[str, ...]
    proxy_template: str
    max_attempts: int = 30

    @classmethod
    def from_mapping(cls, value: dict[str, Any] | None):
        data = value or {}
        asns = tuple(dict.fromkeys(str(x).strip().upper() for x in data.get("asns", []) if str(x).strip()))
        if not 1 <= len(asns) <= 10 or not all(re.fullmatch(r"AS[0-9]+", x) for x in asns):
            raise ValueError("fixed ASN list must contain 1..10 valid ASNs")
        attempts = int(data.get("max_attempts", 30))
        if not 1 <= attempts <= 100:
            raise ValueError("max_attempts must be 1..100")
        minutes = int(data.get("session_minutes", 60))
        if minutes not in SUPPORTED_SESSION_MINUTES:
            raise ValueError("session_minutes must be one of: 10, 30, 60, 120, 180")
        country = str(data.get("country_code", "")).strip().upper()
        if not re.fullmatch(r"[A-Z]{2}", country):
            raise ValueError("country_code must be ISO alpha-2")
        template = str(data.get("proxy_template", "")).strip()
        parse_711proxy_template(template)
        return cls(country, minutes, asns, template, attempts)


class ProxyGenerationError(RuntimeError):
    pass


class DynamicProxyFactory:
    def __init__(self, config: FixedAsnConfig, probe=None):
        self.config = config
        self.probe = probe
        self._asn_index = 0
        # 脱敏前的内部摘要只保存在内存中，供注册控制器把“本次新 Session
        # 已复测通过”的证据传给 run 日志/状态。不会把凭证写入摘要。
        self.last_screening: dict[str, Any] = {}

    def next_proxy(self) -> str:
        last_reason = "ASN 未命中"
        for attempt in range(1, self.config.max_attempts + 1):
            asn = self.config.asns[self._asn_index % len(self.config.asns)]
            self._asn_index += 1
            session_id = f"{uuid.uuid4().int % 100000000:08d}"
            proxy = generate_session_proxy(self.config.proxy_template, self.config.country_code, session_id, self.config.session_minutes)
            probe = self.probe or _probe
            first, second = probe(proxy), probe(proxy)
            quality_min = 80 if self.probe is None else 0
            quality_score = score_probe_quality(first, second)
            eligible, code, reason, _ = evaluate_sample(
                first, second, self.config.country_code, quality_min=quality_min
            )
            final_asn = (second.asn or first.asn or "").upper()
            self.last_screening = {
                "accepted": bool(eligible and final_asn in self.config.asns),
                "proxy": proxy,
                "asn": final_asn,
                "ip": second.ip or first.ip,
                "country": (second.country or first.country or "").upper(),
                "network_type": second.network_type or first.network_type,
                "quality_score": quality_score,
                "probe_count": 2,
                "attempt": attempt,
                "reason_code": code or ("" if eligible else "asn_mismatch"),
            }
            if eligible and final_asn in self.config.asns:
                return proxy
            last_reason = code or reason
        raise ProxyGenerationError(f"动态代理生成失败：{last_reason}，固定 ASN 未命中")


def sanitize_proxy_text(text: str) -> str:
    return _SECRET_RE.sub(r"\1***:***@", str(text or ""))


def _extract_711proxy_candidate(text: str) -> str:
    """Extract one exact allowlisted endpoint, even from pasted pool text."""
    value = str(text or "").strip()
    matches = [
        match
        for pattern in (_AUTH_PROXY_RE, _LEGACY_PROXY_RE, _HOST_FIRST_PROXY_RE)
        if (match := pattern.search(value)) is not None
    ]
    if not matches:
        return value
    match = min(matches, key=lambda item: item.start())
    scheme = match.groupdict().get("scheme") or "http"
    return (
        f"{scheme}://{match.group('username')}:{match.group('password')}@"
        f"{match.group('host')}:{match.group('port')}"
    )


def parse_711proxy_template(text: str) -> dict[str, str]:
    value = _extract_711proxy_candidate(text)
    if "://" not in value:
        value = "http://" + value
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError as exc:
        raise ValueError("invalid 711Proxy template") from exc
    host = (parts.hostname or "").lower()
    if host not in SUPPORTED_HOSTS:
        raise ValueError("unsupported 711Proxy host")
    if not port:
        raise ValueError("proxy template port is missing")
    if not parts.username or parts.password is None:
        raise ValueError("proxy template authentication is missing")
    return {"scheme": parts.scheme or "http", "username": unquote(parts.username), "password": unquote(parts.password), "host": host, "port": str(port)}


def generate_session_proxy(template: str, country_code: str, session_id: str, session_minutes: int = 60) -> str:
    parsed = parse_711proxy_template(template)
    cc = str(country_code or "").strip().upper()
    if not re.fullmatch(r"[A-Z]{2}", cc):
        raise ValueError("country_code must be ISO alpha-2")
    if not re.fullmatch(r"[A-Za-z0-9_-]{4,32}", str(session_id)):
        raise ValueError("invalid session id")
    if not 1 <= int(session_minutes) <= 180:
        raise ValueError("session_minutes must be 1..180")
    username = parsed["username"]
    username = re.sub(r"-region-[A-Za-z]{2}(?=-|$)", "", username, flags=re.I)
    username = re.sub(r"-session-[^-:@]+", "", username, flags=re.I)
    username = re.sub(r"-sessTime-\d+", "", username, flags=re.I)
    username = re.sub(r"-sessAuto-[01]", "", username, flags=re.I)
    username = f"{username}-region-{cc}-session-{session_id}-sessTime-{int(session_minutes)}-sessAuto-1"
    return f"{parsed['scheme']}://{quote(username, safe='-_.')}:{quote(parsed['password'], safe='-_.')}@{parsed['host']}:{parsed['port']}"


def classify_network_type(intel: dict[str, Any] | None) -> str:
    data = intel or {}
    text = " ".join(str(data.get(k, "")) for k in ("org", "isp", "as", "asn", "hostname", "type")).lower()
    privacy = data.get("privacy") if isinstance(data.get("privacy"), dict) else {}
    if any(privacy.get(key) is True for key in ("hosting", "proxy", "vpn", "tor", "relay")) or data.get("hosting") is True or data.get("proxy") is True:
        return "datacenter"
    if any(x in text for x in ("hosting", "datacenter", "data center", "cloud", "amazon", "google llc", "microsoft", "digitalocean", "ovh", "vultr", "proxy", "vpn")):
        return "datacenter"
    if any(x in text for x in ("mobile", "cellular", "wireless", "telkomsel", "indosat", "xl axiata", "verizon wireless")):
        return "mobile"
    if data.get("country") and data.get("org"):
        return "residential_candidate"
    return "unknown"


def score_probe_quality(first: RawPass, second: RawPass) -> int:
    """Score the strength of residential evidence without claiming certainty."""
    if not first.ok or not second.ok:
        return 0
    score = 25  # usable probe pair
    if first.ip == second.ip:
        score += 25
    if first.asn and first.asn == second.asn:
        score += 15
    if first.country and first.country == second.country:
        score += 15
    if second.network_type == "residential_candidate":
        score += 15
    elif second.network_type == "mobile":
        score += 10
    if second.reverse_dns:
        score += 5
    if second.residential_confidence:
        score = max(score, min(100, int(second.residential_confidence)))
    if min(first.intel_sources, second.intel_sources) >= 2:
        score += 10
    else:
        score -= 20
    if first.intel_conflict or second.intel_conflict:
        score -= 25
    if any(getattr(item, key, False) for item in (first, second) for key in ("is_proxy", "is_vpn", "is_hosting")):
        score -= 60
    return max(0, min(100, score))


def evaluate_sample(first: RawPass, second: RawPass, target_country: str, *, quality_min: int = 0):
    if not first.ok or not second.ok:
        return False, first.error_code or second.error_code or "proxy_failed", first.error or second.error or "检测失败", "unknown"
    if first.ip != second.ip:
        return False, "unstable_exit", "两次出口 IP 不一致", second.network_type
    if first.country.upper() != target_country.upper() or second.country.upper() != target_country.upper():
        return False, "country_mismatch", "出口国家与目标地区不一致", second.network_type
    if first.asn != second.asn:
        return False, "asn_changed", "两次 ASN 不一致", second.network_type
    if any(getattr(item, key, False) for item in (first, second) for key in ("is_proxy", "is_vpn", "is_hosting")):
        return False, "proxy_detected", "出口被标记为代理、VPN 或托管网络", second.network_type
    if second.network_type == "datacenter":
        return False, "datacenter_detected", "识别为托管/机房网络", second.network_type
    if second.network_type == "unknown":
        return False, "intel_unknown", "网络类型证据不足", second.network_type
    quality = score_probe_quality(first, second)
    if quality_min and quality < int(quality_min):
        return False, "intel_insufficient", f"住宅证据不足（质量分 {quality}，要求 {int(quality_min)}）", second.network_type
    return True, "", "国家匹配、出口稳定、非明确机房网络", second.network_type


def aggregate_by_asn(samples: list[SampleResult]) -> list[dict[str, Any]]:
    groups: dict[str, list[SampleResult]] = {}
    for sample in samples:
        if sample.asn:
            groups.setdefault(sample.asn, []).append(sample)
    rows = []
    for asn, items in groups.items():
        lats = [x.latency_ms for x in items if x.latency_ms is not None]
        scores = [x.quality_score for x in items if x.quality_score]
        rows.append({"asn": asn, "isp": max((x.isp for x in items if x.isp), key=lambda v: sum(y.isp == v for y in items), default=""), "sample_count": len(items), "success_count": sum(x.first.ok and x.second.ok for x in items), "eligible_count": sum(x.eligible for x in items), "country_match_rate": round(sum(x.first.ok and x.second.ok and x.first.country.upper() == x.second.country.upper() for x in items) / len(items) * 100, 1), "stability_rate": round(sum(x.first.ok and x.second.ok and x.first.ip == x.second.ip for x in items) / len(items) * 100, 1), "residential_rate": round(sum(x.network_type in ("residential_candidate", "mobile") for x in items) / len(items) * 100, 1), "median_latency_ms": int(median(lats)) if lats else None, "median_quality_score": int(median(scores)) if scores else 0})
    return sorted(rows, key=lambda x: (-x["eligible_count"], -x["median_quality_score"], -x["stability_rate"], x["median_latency_ms"] if x["median_latency_ms"] is not None else 999999, x["asn"]))


def fetch_secondary_intel(proxy: str, timeout: float = 8.0) -> dict[str, Any] | None:
    """Fetch a second exit view without relying on the rate-limited ipapi.co API."""
    try:
        response = requests.get(
            "https://ipwho.is/",
            proxies={"http": proxy, "https": proxy},
            timeout=timeout,
        )
        response.raise_for_status()
        data = response.json()
        if data.get("success") is False:
            return None
        connection = data.get("connection") if isinstance(data.get("connection"), dict) else {}
        ip = str(data.get("ip") or "").strip()
        if not ip:
            return None
        raw_asn = str(connection.get("asn") or data.get("asn") or "").strip().upper()
        asn = raw_asn if raw_asn.startswith("AS") else (f"AS{raw_asn}" if raw_asn.isdigit() else raw_asn)
        return {
            "ip": ip,
            "country": str(data.get("country_code") or "").strip().upper(),
            "asn": asn,
            "org": str(connection.get("org") or connection.get("isp") or "").strip(),
            "hostname": str(data.get("hostname") or "").strip().lower(),
        }
    except Exception as exc:  # secondary evidence is advisory; primary remains visible
        LOGGER.debug("secondary intel failed: %s", sanitize_proxy_text(str(exc)))
        return None


def _probe(proxy: str, timeout: float = 12.0) -> RawPass:
    started = time.perf_counter()
    stage = "request"
    response = None
    validation_reason = "unknown"
    try:
        proxies = {"http": proxy, "https": proxy}
        response = requests.get("https://ipinfo.io/json", proxies=proxies, timeout=timeout)
        stage = "http_status"
        response.raise_for_status()
        stage = "json_decode"
        data = response.json()
        stage = "validate_response"
        if not isinstance(data, dict):
            validation_reason = "invalid_shape"
            raise TypeError("Exit lookup response must be an object")
        ip = str(data.get("ip") or "")
        validation_reason = "invalid_ip" if ip else "missing_ip"
        ipaddress.ip_address(ip)
        validation_reason = "unknown"
        stage = "intel"
        org = str(data.get("org") or "")
        asn = org.split(" ", 1)[0] if org.upper().startswith("AS") else str(data.get("asn") or "")
        privacy = data.get("privacy") if isinstance(data.get("privacy"), dict) else {}
        secondary_data = fetch_secondary_intel(proxy, timeout=min(timeout, 8.0))
        secondary_ip = str((secondary_data or {}).get("ip") or "").strip()
        secondary_country = str((secondary_data or {}).get("country") or "").upper()
        secondary_asn = str((secondary_data or {}).get("asn") or "").upper()
        secondary_org = str((secondary_data or {}).get("org") or "")
        secondary_hostname = str((secondary_data or {}).get("hostname") or "").strip().lower()
        combined_network_type = classify_network_type({
            **data,
            "org": f"{org} {secondary_org}",
            "hostname": f"{data.get('hostname') or ''} {secondary_hostname}",
        })
        source_conflict = bool(
            (secondary_ip and secondary_ip != ip)
            or (secondary_country and secondary_country != str(data.get("country") or "").upper())
            or (secondary_asn and secondary_asn != asn)
        )
        if secondary_country and secondary_country != str(data.get("country") or "").upper():
            return RawPass(error_code="intel_conflict", error="出口情报源国家不一致")
        return RawPass(
            True,
            ip,
            str(data.get("country") or "").upper(),
            asn,
            org,
            combined_network_type,
            int((time.perf_counter() - started) * 1000),
            str(data.get("hostname") or secondary_hostname).strip().lower(),
            bool(privacy.get("proxy") is True or data.get("proxy") is True or (secondary_data or {}).get("proxy") is True),
            bool(privacy.get("vpn") is True),
            bool(privacy.get("hosting") is True or data.get("hosting") is True or combined_network_type == "datacenter"),
            0,
            2 if secondary_country and secondary_asn and not source_conflict else 1,
            source_conflict,
        )
    except Exception as exc:
        code, message, reason = "exit_lookup_failed", "exit lookup failed", "unknown"
        if isinstance(exc, requests.exceptions.ProxyError):
            code, message, reason = "proxy_auth_failed", "proxy connection/auth failed", "proxy_error"
        elif isinstance(exc, requests.exceptions.Timeout):
            code, message, reason = "proxy_connect_timeout", "proxy request timed out", "timeout"
        elif isinstance(exc, requests.exceptions.SSLError):
            reason = "tls_error"
        elif isinstance(exc, requests.exceptions.HTTPError):
            reason = "http_error"
        elif isinstance(exc, requests.exceptions.ConnectionError):
            reason = "connection_error"
        elif stage == "json_decode" and isinstance(exc, ValueError):
            reason = "invalid_json"
        elif stage == "validate_response":
            reason = validation_reason
        diagnostics = safe_proxy_probe_metadata({
            **safe_proxy_transport_metadata(exc),
            "service": "ipinfo", "stage": stage, "reason": reason,
            "exception_type": type(exc).__name__,
            "http_status": getattr(response, "status_code", None),
            "elapsed_ms": max(0, int((time.perf_counter() - started) * 1000)),
            "failure_locations": safe_traceback_summary(exc, {__file__}),
        })
        LOGGER.debug("screening probe failed: %s", diagnostics)
        return RawPass(error_code=code, error=message, diagnostics=diagnostics)


class ScreeningManager:
    def __init__(self):
        self._jobs: dict[str, Job] = {}
        self._lock = threading.RLock()
        self._executor = concurrent.futures.ThreadPoolExecutor(max_workers=10, thread_name_prefix="proxy-screen")

    def create_job(self, country_code: str, sample_count: int = 30, session_minutes: int = 60, concurrency: int = 5, proxy_template: str = "") -> Job:
        with self._lock:
            active = next((x for x in self._jobs.values() if x.status in ("queued", "running")), None)
            if active:
                raise RuntimeError(f"筛选任务正在运行: {active.job_id}")
        parse_711proxy_template(proxy_template)
        cc = str(country_code or "").strip().upper()
        if not re.fullmatch(r"[A-Z]{2}", cc): raise ValueError("country_code must be ISO alpha-2")
        if not 1 <= sample_count <= 100: raise ValueError("sample_count must be 1..100")
        if not 1 <= concurrency <= 10: raise ValueError("concurrency must be 1..10")
        if session_minutes not in SUPPORTED_SESSION_MINUTES:
            allowed = ", ".join(str(value) for value in SUPPORTED_SESSION_MINUTES)
            raise ValueError(f"session_minutes must be one of: {allowed}")
        job = Job(str(uuid.uuid4()), cc, sample_count, session_minutes, concurrency, time.time())
        session_ids: set[str] = set()
        for i in range(sample_count):
            session_id = f"{uuid.uuid4().int % 100000000:08d}"
            while session_id in session_ids:
                session_id = f"{uuid.uuid4().int % 100000000:08d}"
            session_ids.add(session_id)
            proxy = generate_session_proxy(proxy_template, cc, session_id, session_minutes)
            job.samples.append(SampleResult(i + 1, proxy, sanitize_proxy_text(proxy)))
        with self._lock: self._jobs[job.job_id] = job
        self._executor.submit(self._run, job)
        return job

    def _run(self, job: Job):
        job.status, job.stage = "running", "检测出口 IP"
        with concurrent.futures.ThreadPoolExecutor(max_workers=job.concurrency) as pool:
            futures = {pool.submit(self._screen, sample, job.country_code): sample for sample in job.samples}
            for future in concurrent.futures.as_completed(futures):
                sample = futures[future]
                if job.cancel_event.is_set(): sample.reason_code, sample.reason = "cancelled", "用户取消"
                else:
                    try: future.result()
                    except Exception: sample.reason_code, sample.reason = "probe_failed", "检测异常"
                job.completed += 1; job.success += int(sample.eligible); job.failed += int(not sample.eligible)
        job.status = "cancelled" if job.cancel_event.is_set() else "completed"
        job.stage = "已取消" if job.cancel_event.is_set() else "检测完成"

    def _screen(self, sample: SampleResult, country: str):
        sample.first, sample.second = _probe(sample.proxy), _probe(sample.proxy)
        sample.asn, sample.isp = sample.second.asn or sample.first.asn, sample.second.isp or sample.first.isp
        sample.latency_ms = sample.second.latency_ms or sample.first.latency_ms
        sample.eligible, sample.reason_code, sample.reason, sample.network_type = evaluate_sample(sample.first, sample.second, country, quality_min=80)
        sample.quality_score = score_probe_quality(sample.first, sample.second)

    def get_job(self, job_id: str):
        with self._lock: return self._jobs.get(job_id)

    def cancel_job(self, job_id: str) -> bool:
        job = self.get_job(job_id)
        if not job or job.status in ("completed", "cancelled", "failed"): return False
        job.cancel_event.set(); return True

    def import_preview(self, job_id: str, asn: str, existing: list[str] | None = None):
        job = self.get_job(job_id)
        if not job: raise KeyError("job not found")
        existing_set = {x.strip() for x in (existing or []) if x.strip()}
        candidates = [x.proxy for x in job.samples if x.asn == asn and x.eligible]
        unique = [x for x in candidates if x not in existing_set]
        return {"asn": asn, "proxies": unique, "candidate_count": len(candidates), "new_count": len(unique), "existing_count": len(candidates) - len(unique), "rejected_count": sum(x.asn == asn and not x.eligible for x in job.samples)}

    def public_job(self, job: Job):
        return {"job_id": job.job_id, "country_code": job.country_code, "sample_count": job.sample_count, "session_minutes": job.session_minutes, "concurrency": job.concurrency, "created_at": job.created_at, "status": job.status, "completed": job.completed, "success": job.success, "failed": job.failed, "stage": job.stage, "error": sanitize_proxy_text(job.error), "asn_summaries": aggregate_by_asn(job.samples), "samples": [{"index": x.index, "masked_proxy": x.masked_proxy, "asn": x.asn, "isp": x.isp, "network_type": x.network_type, "latency_ms": x.latency_ms, "quality_score": x.quality_score, "eligible": x.eligible, "reason_code": x.reason_code, "reason": x.reason, "first": asdict(x.first), "second": asdict(x.second)} for x in job.samples if x.reason_code or x.first.ok]}

MANAGER = ScreeningManager()

