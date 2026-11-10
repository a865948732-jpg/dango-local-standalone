"""auto-loop 控制器：多 worker 并发，每个 worker 用独立代理。

设计：
  - 主控线程 manage_loop：监听 stop/pause、根据 concurrency 启停 worker
  - 多个 worker 线程：claim_next() → 注册 → 完成 → 继续
  - 代理池：按规范化出口发放 run 级独占 lease，避免同出口并发复用
  - 状态机：stopped → running → paused → running / stopped
  - 优雅暂停/停止：当前 worker 跑完才退出，不强杀
  - 复用 registrar.start_registration：每个号开一个 run，由 worker 等其结束
"""
from __future__ import annotations

import json
import logging
import queue
import threading
import time
from typing import Optional
from urllib.parse import urlsplit

from . import db, registrar
from .proxy_screening import DynamicProxyFactory, FixedAsnConfig
from .asn_performance import AsnPerformanceStore
from .roxy_bridge import PROFILE_POOL
from .roxy_settings import proxy_info_from_url, runtime_config_admission
from mail_providers import MailProviderError, get_provider_class
from safe_diagnostics import safe_public_error, safe_url, sanitize_observable

logger = logging.getLogger("auto_loop")


DEFAULT_AUTO_CONCURRENCY = 4
MAX_AUTO_CONCURRENCY = 20
WORKER_START_STAGGER_SECONDS = 0.2
RUN_STATUS_POLL_SECONDS = 0.25


def result_cool_down_seconds(
    ok: bool,
    category: str,
    network_streak: int,
    success_seconds: float = 0.5,
) -> float:
    if ok:
        return max(0.0, float(success_seconds))
    if category == "network":
        return min(12.0, 3.0 * (2 ** max(0, int(network_streak) - 1)))
    return 1.0


def normalize_auto_concurrency(value=None) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = DEFAULT_AUTO_CONCURRENCY
    return max(1, min(parsed, MAX_AUTO_CONCURRENCY))


def resolve_auto_concurrency(
    options: dict,
    profile_capacity: int = MAX_AUTO_CONCURRENCY,
) -> tuple[int, int]:
    requested = normalize_auto_concurrency((options or {}).get("concurrency"))
    if str((options or {}).get("driver") or "protocol").lower() == "roxy":
        if (options or {}).get("roxy_use_proxy_pool"):
            proxy_capacity = (requested if (options or {}).get("fixed_asn_config")
                              else len(_unique_proxy_resources(options)))
            return requested, min(requested, max(0, int(profile_capacity)), proxy_capacity)
        try:
            egress_capacity = int(
                (options or {}).get("_roxy_egress_capacity", profile_capacity)
            )
        except (TypeError, ValueError):
            egress_capacity = 0
        return requested, min(
            requested,
            max(0, int(profile_capacity)),
            max(0, egress_capacity),
        )
    if (options or {}).get("fixed_asn_config"):
        return requested, requested
    return requested, min(requested, len(_unique_proxy_resources(options)))


class AutoLoopState:
    STOPPED = "stopped"
    RUNNING = "running"
    PAUSED = "paused"


def _parse_proxy_pool(text: str) -> list[str]:
    """把多行代理字符串拆成列表。空行 / # 开头注释跳过。"""
    out: list[str] = []
    for line in (text or "").splitlines():
        s = line.strip()
        if s and not s.startswith("#"):
            out.append(s)
    return out


def _proxy_resource_key(proxy: str) -> tuple:
    """Return a secret-preserving canonical identity for one proxy endpoint."""
    value = str(proxy or "").strip()
    if not value:
        return ("direct",)
    candidate = value if "://" in value else f"http://{value}"
    try:
        parsed = urlsplit(candidate)
        scheme = (parsed.scheme or "http").lower()
        host = (parsed.hostname or "").lower()
        if not host:
            return ("raw", value)
        port = parsed.port
        if port is None:
            port = {"http": 80, "https": 443}.get(scheme)
        return (
            scheme,
            parsed.username or "",
            parsed.password or "",
            host,
            port,
            (parsed.path or "").rstrip("/"),
            parsed.query or "",
            parsed.fragment or "",
        )
    except (TypeError, ValueError):
        return ("raw", value)


def _unique_proxy_resources(options: dict) -> list[str]:
    """Keep the first spelling of each normalized protocol egress resource."""
    pool = _parse_proxy_pool(str((options or {}).get("proxy_pool") or ""))
    single = str((options or {}).get("proxy") or "").strip()
    candidates = pool if pool else ([single] if single else [])
    resources: list[str] = []
    seen: set[tuple] = set()
    for candidate in candidates:
        key = _proxy_resource_key(candidate)
        if key in seen:
            continue
        seen.add(key)
        resources.append(candidate)
    return resources


def validate_roxy_proxy_source(proxy_pool: str, fixed_asn_config: dict | None = None) -> list[str]:
    """Validate a custom Roxy source without probing or claiming an account."""
    if fixed_asn_config:
        FixedAsnConfig.from_mapping(fixed_asn_config)
        return []
    resources = _unique_proxy_resources({"proxy_pool": proxy_pool})
    if not resources:
        raise ValueError("Roxy 内置代理已开启，请先选择可用代理池或固定 ASN 配置")
    for proxy in resources:
        proxy_info_from_url(proxy)
    return resources


class ProxyResourceLease:
    def __init__(self, pool, proxy: str, screening: dict | None = None):
        self._pool = pool
        self.proxy = proxy
        self.screening = dict(screening or {})
        self._released = False

    def release(self) -> None:
        if self._released:
            return
        self._released = True
        self._pool._release(self.proxy)


class ProxyResourcePool:
    """Controller-local exclusive leases for normalized protocol egresses."""

    def __init__(self, resources: list[str]):
        self._condition = threading.Condition()
        self._resources = list(resources)
        self._available = list(resources)
        self._leased: set[str] = set()

    def configure(self, resources: list[str]) -> None:
        """Configure the pool without invalidating an active lease."""
        next_resources = list(resources)
        with self._condition:
            if self._leased and next_resources != self._resources:
                raise RuntimeError("代理池正在被其他任务占用，不能切换代理资源")
            if next_resources == self._resources:
                return
            self._resources = next_resources
            self._available = list(next_resources)

    @property
    def available_capacity(self) -> int:
        with self._condition:
            return len(self._available)

    def acquire(self, timeout: float | None = None, *, excluded_keys: set[tuple] | None = None,
                cancel_event=None) -> ProxyResourceLease:
        deadline = None if timeout is None else time.monotonic() + max(0.0, timeout)
        with self._condition:
            excluded = excluded_keys or set()
            if not any(_proxy_resource_key(proxy) not in excluded for proxy in self._resources):
                raise ValueError("没有尚未尝试的代理资源")
            while True:
                if cancel_event is not None and cancel_event.is_set():
                    raise InterruptedError("代理资源等待已取消")
                available = next((index for index, proxy in enumerate(self._available)
                                  if _proxy_resource_key(proxy) not in excluded), None)
                if available is not None:
                    proxy = self._available.pop(available)
                    self._leased.add(proxy)
                    return ProxyResourceLease(self, proxy)
                remaining = None if deadline is None else deadline - time.monotonic()
                if remaining is not None and remaining <= 0:
                    raise TimeoutError("等待独占代理资源超时")
                self._condition.wait(min(0.25, remaining) if remaining is not None else 0.25)

    def _release(self, proxy: str) -> None:
        with self._condition:
            if proxy not in self._leased:
                return
            self._leased.remove(proxy)
            self._available.append(proxy)
            self._condition.notify()


class AutoLoopController:
    """多 worker auto-loop 控制器。

    options 关键字段：
      proxy:                单代理（兼容旧版，concurrency=1 时用）
      proxy_pool:           多代理字符串（每行一个；每个 run 独占一个规范化代理）
      concurrency:          并发 worker 数（默认 4，范围 1-5，并按资源容量降速）
      cool_down_seconds:    成功后每个 worker 的冷却时间（默认 0.5）
      其余参数透传给 registrar.start_registration
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._state = AutoLoopState.STOPPED
        self._manage_thread: Optional[threading.Thread] = None
        self._workers: list[threading.Thread] = []
        self._options: dict = {}
        self._stop_event = threading.Event()
        self._pause_event = threading.Event()  # set = 暂停
        # 进度统计
        self._started_at: float = 0.0
        self._registered_ok = 0
        self._registered_pending = 0
        self._registered_fail = 0
        # 当前每个 worker 在跑啥（worker_id → email）
        self._worker_status: dict[int, dict] = {}
        self._last_message = ""
        self._stop_reason = ""
        # 熔断状态
        self._consecutive_network_fails = 0
        self._circuit_break_threshold = 3
        self._last_break_reason = ""
        # SSE 订阅
        self._subscribers: list[queue.Queue] = []
        # 代理池 / 并发数
        self._proxy_pool: list[str] = []
        self._proxy_resources: list[str] = [""]
        self._proxy_leases = ProxyResourcePool(self._proxy_resources)
        self._dynamic_factories: dict[FixedAsnConfig, DynamicProxyFactory] = {}
        self._requested_concurrency: int = DEFAULT_AUTO_CONCURRENCY
        self._concurrency: int = DEFAULT_AUTO_CONCURRENCY
        # 目标成功数：0 = 不限量（保持旧行为）；>0 时累计成功达标即自动停止
        self._target_count: int = 0

    # ──────────────────────── 公共 API ────────────────────────

    def acquire_protocol_proxy(
        self,
        proxy_pool: str,
        fixed_asn_config: dict | None = None,
        timeout: float | None = 0,
        *,
        excluded_keys: set[tuple] | None = None,
        cancel_event=None,
    ) -> ProxyResourceLease:
        """Acquire one exclusive endpoint for a standalone registration run.

        An explicitly supplied pool never falls back to direct connection.
        The same pool object is reused by auto-loop.
        """
        if fixed_asn_config:
            if cancel_event is not None and cancel_event.is_set():
                raise InterruptedError("代理资源等待已取消")
            configured = dict(fixed_asn_config)
            policy_rows = AsnPerformanceStore(db.DB_PATH).list()
            if policy_rows:
                enabled = {row["asn"] for row in policy_rows if row["enabled"]}
                configured["asns"] = [asn for asn in configured.get("asns", []) if str(asn).upper() in enabled]
                if not configured["asns"]:
                    raise ValueError("ASN 策略中没有可用的住宅 ASN")
            config = FixedAsnConfig.from_mapping(configured)
            with self._lock:
                factory = self._dynamic_factories.setdefault(config, DynamicProxyFactory(config))
            # Generating a fixed-ASN proxy performs network probes (twice per
            # candidate and up to max_attempts).  Never hold the controller
            # lock while doing that work: status/stop requests otherwise block
            # behind every concurrent worker and the UI appears frozen.
            proxy = factory.next_proxy()
            lease = ProxyResourcePool([proxy]).acquire(
                timeout=timeout, excluded_keys=excluded_keys, cancel_event=cancel_event)
            lease.screening = dict(factory.last_screening)
            self._set_message(
                "动态代理已生成并复测通过："
                f"ASN={lease.screening.get('asn') or '-'} "
                f"质量分={lease.screening.get('quality_score', 0)} "
                f"探测={lease.screening.get('probe_count', 0)}次"
            )
            return lease
        resources = _parse_proxy_pool(proxy_pool)
        if not resources:
            raise ValueError("代理池为空")
        resources = _unique_proxy_resources({"proxy_pool": "\n".join(resources)})
        with self._lock:
            self._proxy_leases.configure(resources)
            self._proxy_resources = list(resources)
            self._proxy_pool = list(resources)
            # Keep configuration and acquisition atomic with respect to a
            # concurrent request that might otherwise switch the shared pool
            # between these two operations.
            if excluded_keys or cancel_event is not None:
                return self._proxy_leases.acquire(timeout=timeout, excluded_keys=excluded_keys,
                                                  cancel_event=cancel_event)
            # Preserve the original call shape for existing integrations that
            # replace the pool with a narrow test/delivery double.
            return self._proxy_leases.acquire(timeout=timeout)

    @runtime_config_admission
    def start(self, options: dict) -> dict:
        with self._lock:
            if self._state in (AutoLoopState.RUNNING, AutoLoopState.PAUSED):
                return {"ok": False, "error": f"已经在跑了 (state={self._state})"}
            next_options = dict(options or {})
            next_resources = _unique_proxy_resources(next_options)
            is_roxy = str(next_options.get("driver") or "protocol").lower() == "roxy"
            roxy_proxy_pool = is_roxy and bool(next_options.get("roxy_use_proxy_pool"))
            if roxy_proxy_pool:
                try:
                    next_resources = validate_roxy_proxy_source(
                        str(next_options.get("proxy_pool") or ""),
                        next_options.get("fixed_asn_config"),
                    )
                except (TypeError, ValueError) as exc:
                    return {"ok": False, "error": safe_public_error(exc, "Roxy 代理配置")}
            requested, effective = resolve_auto_concurrency(
                next_options,
                profile_capacity=PROFILE_POOL.max_size,
            )
            if effective < 1:
                return {"ok": False, "error": "没有可独占的代理/出口资源"}
            if next_options.get("fixed_asn_config") and (not is_roxy or roxy_proxy_pool):
                next_resources = [""] * effective
            elif is_roxy and not roxy_proxy_pool:
                # Roxy's bridge owns the real hashed-egress leases. Controller
                # placeholders only prevent its workers from contending for the
                # protocol proxy pool before they reach that bridge.
                next_resources = [""] * effective
            # Validate/switch the shared pool before mutating controller state.
            # An active lease can reject a pool change; in that case the
            # controller must remain stopped with its previous configuration.
            try:
                self._proxy_leases.configure(next_resources)
            except RuntimeError as exc:
                return {"ok": False, "error": str(exc)}
            if roxy_proxy_pool and not next_options.get("fixed_asn_config"):
                effective = min(effective, self._proxy_leases.available_capacity)
                if effective < 1:
                    return {"ok": False, "error": "Roxy 代理池暂无可用独占出口"}
            # 重置
            self._stop_event.clear()
            self._stop_reason = ""
            self._pause_event.clear()
            self._options = next_options
            self._state = AutoLoopState.RUNNING
            self._started_at = time.time()
            self._registered_ok = 0
            self._registered_pending = 0
            self._registered_fail = 0
            self._worker_status.clear()
            self._consecutive_network_fails = 0
            self._last_message = "auto-loop 启动"
            # Worker 数不能超过规范化代理/出口或 Roxy Profile 容量。
            self._requested_concurrency, self._concurrency = requested, effective
            self._proxy_pool = [] if is_roxy and not roxy_proxy_pool else [
                resource for resource in next_resources if resource
            ]
            self._proxy_resources = next_resources
            # 目标成功数（0=不限量）
            self._target_count = max(0, int(self._options.get("target_count") or 0))
            # 启 manage 线程
            self._manage_thread = threading.Thread(
                target=self._manage_loop, daemon=True, name="auto-loop-manage"
            )
            self._manage_thread.start()
        self._broadcast("state", self._snapshot())
        return {
            "ok": True,
            "state": self._state,
            "concurrency": self._concurrency,
            "requested_concurrency": self._requested_concurrency,
            "effective_concurrency": self._concurrency,
            "proxy_pool_size": len(self._proxy_pool),
            "proxy_capacity": len(self._proxy_resources),
            "target_count": self._target_count,
        }

    def pause(self) -> dict:
        with self._lock:
            if self._stop_event.is_set():
                return {"ok": False, "error": self._stop_reason or "已请求停止"}
            if self._state != AutoLoopState.RUNNING:
                return {"ok": False, "error": f"当前 state={self._state}，不可暂停"}
            self._pause_event.set()
            self._state = AutoLoopState.PAUSED
            self._last_message = "已请求暂停（当前 worker 跑完才生效）"
        self._broadcast("state", self._snapshot())
        return {"ok": True, "state": self._state}

    def resume(self) -> dict:
        with self._lock:
            if self._stop_event.is_set():
                return {"ok": False, "error": self._stop_reason or "已请求停止"}
            if self._state != AutoLoopState.PAUSED:
                return {"ok": False, "error": f"当前 state={self._state}，不可恢复"}
            self._pause_event.clear()
            self._state = AutoLoopState.RUNNING
            self._last_message = "已恢复"
        self._broadcast("state", self._snapshot())
        return {"ok": True, "state": self._state}

    def stop(self) -> dict:
        with self._lock:
            if self._state == AutoLoopState.STOPPED:
                return {"ok": False, "error": "没在跑"}
            self._stop_event.set()
            self._pause_event.clear()
            self._last_message = self._stop_reason or "已请求停止（当前 worker 跑完才生效）"
        self._broadcast("state", self._snapshot())
        return {"ok": True}

    def status(self) -> dict:
        return self._snapshot()

    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=100)
        with self._lock:
            self._subscribers.append(q)
        try:
            q.put_nowait({"kind": "state", "data": self._snapshot()})
        except queue.Full:
            pass
        return q

    def unsubscribe(self, q: queue.Queue):
        with self._lock:
            try: self._subscribers.remove(q)
            except ValueError: pass

    # ──────────────────────── 内部 ────────────────────────

    def _snapshot(self) -> dict:
        with self._lock:
            stats = db.stats()
            workers_info = [
                {
                    "id": wid,
                    "email": info.get("email", ""),
                    "run_id": info.get("run_id", ""),
                    "proxy": safe_url(info.get("proxy", "")),
                    "proxy_screening": {
                        key: value for key, value in dict(info.get("proxy_screening") or {}).items()
                        if key != "proxy"
                    },
                    "started_at": info.get("started_at", 0),
                }
                for wid, info in sorted(self._worker_status.items())
            ]
            return {
                "state": self._state,
                "started_at": self._started_at,
                "elapsed": (time.time() - self._started_at) if self._started_at else 0,
                "registered_ok": self._registered_ok,
                "registered_pending": self._registered_pending,
                "registered_fail": self._registered_fail,
                "target_count": self._target_count,
                "remaining": (
                    max(0, self._target_count - self._registered_ok)
                    if self._target_count else None
                ),
                "concurrency": self._concurrency,
                "requested_concurrency": self._requested_concurrency,
                "effective_concurrency": self._concurrency,
                "proxy_pool_size": len(self._proxy_pool),
                "proxy_capacity": len(self._proxy_resources),
                "workers": workers_info,
                "last_message": self._last_message,
                "pool_stats": stats,
            }

    def _broadcast(self, kind: str, data):
        data = sanitize_observable(data)
        with self._lock:
            subs = list(self._subscribers)
        for q in subs:
            try:
                q.put_nowait({"kind": kind, "data": data})
            except queue.Full:
                pass

    def _set_message(self, msg: str):
        with self._lock:
            if not self._stop_reason:
                self._last_message = msg
        self._broadcast("state", self._snapshot())

    def _wait_cool_down(self, seconds: float):
        """等待冷却时间，按 100ms 分段以便 stop/pause 及时生效。"""
        remaining = max(0.0, float(seconds))
        while remaining > 0:
            if self._stop_event.is_set() or self._pause_event.is_set():
                break
            chunk = min(0.1, remaining)
            time.sleep(chunk)
            remaining -= chunk

    def _proxy_for_worker(self, worker_id: int) -> str:
        """Return the deterministic non-repeating startup assignment."""
        try:
            return self._proxy_resources[worker_id]
        except IndexError as exc:
            raise RuntimeError("worker 数超过独占代理资源容量") from exc

    def _record_finish(self, ok: bool, category: str) -> int:
        """worker 结束一个 run 后调用，更新计数并返回网络失败连续次数。

        网络错误属于可恢复的环境波动：worker 会按 3/6/12 秒退避后继续
        领取下一个账号，不再因为连续三次错误把整个 auto-loop 切到暂停态。
        """
        with self._lock:
            if ok:
                self._registered_ok += 1
                self._consecutive_network_fails = 0
            elif category in {"registration_pending", "registration_outcome_unknown"}:
                self._registered_pending += 1
                self._consecutive_network_fails = 0
            else:
                self._registered_fail += 1
                if category == "network":
                    self._consecutive_network_fails += 1
                else:
                    self._consecutive_network_fails = 0
            quota_blocked = not ok and category == "roxy_daily_quota"
            if quota_blocked:
                self._stop_reason = "Roxy 每日窗口创建额度已用尽（code=416），停止领取新邮箱"
                self._stop_event.set()
                self._pause_event.clear()
            self._last_message = self._stop_reason or (
                f"累计 ok={self._registered_ok} pending={self._registered_pending} fail={self._registered_fail}"
            )
            # 目标数量：累计成功达标 → 触发停止（stop_event 幂等，多 worker 同时命中也安全）
            target_reached = bool(
                not self._stop_reason
                and self._target_count and self._registered_ok >= self._target_count
            )
            network_streak = self._consecutive_network_fails

        if quota_blocked:
            logger.warning("Roxy 每日创建额度已用尽，停止批量任务；等待已启动任务完成")
            self._broadcast("state", self._snapshot())
        elif target_reached:
            with self._lock:
                self._stop_event.set()
                self._last_message = self._stop_reason or (
                    f"🎯 已达目标 {self._target_count} 个，自动停止"
                    f"（成功 {self._registered_ok} / 待处理 {self._registered_pending} / 失败 {self._registered_fail}）"
                )
            logger.info(f"已达目标 {self._target_count} 个成功，触发自动停止")
            self._broadcast("state", self._snapshot())
            return network_streak

        return network_streak

    def _manage_loop(self):
        """主控线程：启动 worker，等所有 worker 结束，更新最终状态。"""
        try:
            workers = []
            for wid in range(self._concurrency):
                t = threading.Thread(
                    target=self._worker_loop, args=(wid,),
                    daemon=True, name=f"auto-loop-worker-{wid}",
                )
                t.start()
                workers.append(t)
                # 每个 worker 之间短暂错开启动，避免完全同时打 OpenAI
                time.sleep(WORKER_START_STAGGER_SECONDS)
            self._workers = workers
            # 等所有 worker 退出
            for t in workers:
                t.join()
        except Exception as e:
            logger.error(safe_public_error(e, "auto loop manager"))
        finally:
            with self._lock:
                self._state = AutoLoopState.STOPPED
                self._worker_status.clear()
                reason = f"已停止：{self._stop_reason}" if self._stop_reason else "已停止"
                self._last_message = (
                    f"{reason}（成功 {self._registered_ok} / 待处理 {self._registered_pending} / 失败 {self._registered_fail}）"
                )
            self._broadcast("state", self._snapshot())

    def _worker_loop(self, worker_id: int):
        """单 worker 循环：claim → 跑 → 等结束 → 继续。"""
        idle_round = 0
        logger.info("[worker-%s] 启动", worker_id)

        while True:
            # 检查停止
            if self._stop_event.is_set():
                logger.info(f"[worker-{worker_id}] 已停止")
                return

            # 检查暂停
            if self._pause_event.is_set():
                while self._pause_event.is_set() and not self._stop_event.is_set():
                    time.sleep(0.5)
                if self._stop_event.is_set():
                    return

            # 目标数量闸门：已成功 + 在跑的（复用 _worker_status 当在跑数）≥ 目标 → 本 worker 退出
            # 不新增易泄漏的计数器；_worker_status 已在锁内正常维护，最大限度压低超额
            with self._lock:
                if self._target_count and (
                    self._registered_ok + len(self._worker_status) >= self._target_count
                ):
                    logger.info(
                        f"[worker-{worker_id}] 目标 {self._target_count} 已锁定，退出"
                    )
                    return

            fixed_config = self._options.get("fixed_asn_config")
            prebuilt_lease = None
            uses_custom_proxy = (str(self._options.get("driver") or "protocol").lower() == "protocol"
                                 or bool(self._options.get("roxy_use_proxy_pool")))
            try:
                if fixed_config and uses_custom_proxy:
                    prebuilt_lease = self.acquire_protocol_proxy("", fixed_config, timeout=30)
                else:
                    prebuilt_lease = self._proxy_leases.acquire(timeout=30)
                if self._options.get("roxy_use_proxy_pool"):
                    proxy_info_from_url(prebuilt_lease.proxy)
            except Exception as exc:
                if prebuilt_lease is not None:
                    prebuilt_lease.release()
                self._set_message(safe_public_error(exc, "注册代理资源获取"))
                time.sleep(1)
                continue
            if self._stop_event.is_set() or self._pause_event.is_set():
                prebuilt_lease.release()
                continue

            # claim 下一个号。要不要走号池由 provider 的 pooled 决定，
            # 非池化的（CF 这类自己造地址的）用虚拟占位。
            try:
                mail_source = db.get_setting("mail_source", "outlook")
                pooled = get_provider_class(mail_source).pooled
                # Quota stopping and admission share a lock to close check/action races.
                with self._lock:
                    if self._stop_event.is_set() or self._pause_event.is_set():
                        prebuilt_lease.release()
                        continue
                    if pooled:
                        account = db.claim_next(kind=mail_source)
                    else:
                        account = {
                            "email": f"{mail_source}_placeholder_"
                                     f"{int(time.time())}_{worker_id}@placeholder.local",
                            "password": "", "client_id": "", "refresh_token": "",
                            "relay_url": "", "kind": mail_source,
                        }
            except MailProviderError as e:
                prebuilt_lease.release()
                logger.error("[worker-%s] 停止: %s", worker_id, safe_public_error(e, "mail provider setup"))
                self._set_message(safe_public_error(e, "mail provider setup"))
                return
            except Exception:
                prebuilt_lease.release()
                raise
            if not account:
                if prebuilt_lease is not None:
                    prebuilt_lease.release()
                idle_round += 1
                if idle_round == 1:
                    self._set_message(
                        f"worker-{worker_id} 号池空，等待新号..."
                    )
                # 空 10 轮（约 30s）就停掉这个 worker
                if idle_round >= 10:
                    logger.info(f"[worker-{worker_id}] 号池空 30s，停止")
                    return
                # 等 3s 再试
                for _ in range(30):
                    if self._stop_event.is_set() or self._pause_event.is_set():
                        break
                    time.sleep(0.1)
                continue
            idle_round = 0

            proxy_lease = prebuilt_lease
            proxy = proxy_lease.proxy
            try:
                # 给这个 run 注入独占代理；完成/失败后 finally 释放。
                run_options = dict(self._options)
                run_options["mail_source"] = (
                    account.get("kind") or mail_source
                ).strip().lower()
                run_options["proxy"] = proxy
                screening = getattr(proxy_lease, "screening", None)
                screening_dict = dict(screening) if isinstance(screening, dict) else {}
                if screening_dict:
                    run_options["proxy_screening"] = screening_dict
                logger.info(
                    "[worker-%s] 新 Session 代理已筛选通过：proxy=%s ASN=%s 质量分=%s 探测=%s次；交给注册 run",
                    worker_id,
                    safe_url(proxy) or "直连",
                    screening_dict.get("asn", "-"),
                    screening_dict.get("quality_score", 0),
                    screening_dict.get("probe_count", 0),
                )

                # 启一个 run
                try:
                    with self._lock:
                        if self._stop_event.is_set() or self._pause_event.is_set():
                            if pooled:
                                db.release_unused(account["email"])
                            continue
                        run_id = registrar.start_registration(account, run_options)
                except Exception as e:
                    logger.error("[worker-%s] 启动注册失败: %s", worker_id, safe_public_error(e, "registration start"))
                    if pooled:
                        db.release_unused(account["email"])
                    time.sleep(2)
                    continue

                with self._lock:
                    self._worker_status[worker_id] = {
                        "email": account["email"],
                        "run_id": run_id,
                        "proxy": proxy,
                        "proxy_screening": screening_dict,
                        "started_at": time.time(),
                    }
                self._broadcast("state", self._snapshot())
                self._broadcast("run_started", {
                    "worker_id": worker_id,
                    "email": account["email"],
                    "run_id": run_id,
                    "proxy": proxy,
                })

                # 等当前 run 跑完
                ok, category = self._wait_run_finish(run_id)
            finally:
                proxy_lease.release()

            with self._lock:
                self._worker_status.pop(worker_id, None)
            network_streak = self._record_finish(ok, category)
            self._broadcast("state", self._snapshot())
            self._broadcast("run_finished", {
                "worker_id": worker_id,
                "email": account["email"],
                "run_id": run_id,
                "ok": ok,
                "category": category,
                "registration_complete": ok,
                "registration_pending": category == "registration_pending",
            })

            # 冷却（每个 worker 自己的节奏）
            configured_success_cool_down = (
                float(self._options["cool_down_seconds"])
                if "cool_down_seconds" in self._options
                and self._options["cool_down_seconds"] is not None
                else 0.5
            )
            cool_down = result_cool_down_seconds(
                ok,
                category,
                network_streak,
                success_seconds=configured_success_cool_down,
            )
            self._wait_cool_down(cool_down)

    def _wait_run_finish(self, run_id: str, timeout: int = 2700) -> tuple[bool, str]:
        """轮询 runs 表，覆盖支持范围内约 2491 秒的合法最坏路径。"""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            con = db._conn()
            try:
                row = con.execute(
                    "SELECT status, error_category, result_json FROM runs WHERE run_id=?", (run_id,)
                ).fetchone()
            finally:
                con.close()
            if row:
                st = row["status"]
                if st == "done":
                    try:
                        outcome = json.loads(row["result_json"] or "null")
                    except (TypeError, ValueError):
                        outcome = None
                    if not isinstance(outcome, dict):
                        return False, "registration_outcome_unknown"
                    if db.registration_run_outcome(outcome)["registration_complete"]:
                        return True, ""
                    return False, "registration_pending"
                if st == "failed":
                    return False, (row["error_category"] or "")
            time.sleep(RUN_STATUS_POLL_SECONDS)
        logger.warning(f"run {run_id} 等了 {timeout}s 没结束，超时放弃")
        return False, ""


# 全局单例
CONTROLLER = AutoLoopController()
