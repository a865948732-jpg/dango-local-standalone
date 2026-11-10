"""FastAPI 主程序：路由 + SSE 流式日志。

启动:
    python -m webui.app
或者:
    python start_webui.py
"""
from __future__ import annotations

import asyncio
import base64
import json
import logging
import sqlite3
import sys
import time
import uuid
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from safe_diagnostics import safe_public_error, safe_response_summary

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from . import db, export_formats, registrar  # noqa: E402
from .qualification_api import router as qualification_router  # noqa: E402
from .proxy_screening_api import router as proxy_screening_router  # noqa: E402
from .roxy_proxy_sync import router as roxy_proxy_sync_router  # noqa: E402
from .roxy_status import router as roxy_status_router  # noqa: E402
from .roxy_settings_api import router as roxy_settings_router  # noqa: E402
from .refine_api import router as refine_router  # noqa: E402
from .roxy_settings import read_settings as read_roxy_settings, runtime_config_admission  # noqa: E402
from .proxy_screening import ProxyGenerationError  # noqa: E402
from .rebind_service import SERVICE as REBIND_SERVICE  # noqa: E402
from .auto_loop import CONTROLLER as AUTO_LOOP, validate_roxy_proxy_source  # noqa: E402
from .exporter import _decode_jwt_payload, _get_auth  # noqa: E402
from .roxy_config import (  # noqa: E402
    RoxyConfigurationError,
    require_roxy_configuration,
)
from mail_providers import (  # noqa: E402
    ImportValidationError,
    MailProviderError,
    create_mail_provider,
    get_provider_class,
    list_pooled_providers,
    list_providers,
)

# 启动时自动释放卡死的 in_use 号（上次进程崩溃 / 强退留下的）
try:
    _released = db.release_stale_in_use(stale_seconds=1800)
    if _released > 0:
        logging.getLogger("webui").info(f"[startup] 释放 {_released} 个卡死的 in_use 号")
except Exception as _e:
    logging.getLogger("webui").warning(f"[startup] release_stale 失败: {_e}")

try:
    _cancelled_runs = db.cancel_running_runs()
    if _cancelled_runs > 0:
        logging.getLogger("webui").info(
            f"[startup] 标记 {_cancelled_runs} 个上次进程遗留任务为已取消"
        )
except Exception as _e:
    logging.getLogger("webui").warning(f"[startup] cancel stale runs 失败: {_e}")

# 换绑 worker 只存在于当前进程内；重启后单独结束遗留换绑快照，
# 不复用也不修改上面的注册任务恢复流程。
try:
    _cancelled_rebind_runs = db.cancel_running_rebind_runs()
    if _cancelled_rebind_runs > 0:
        logging.getLogger("webui").info(
            f"[startup] 标记 {_cancelled_rebind_runs} 个上次进程遗留换绑任务为已取消"
        )
except Exception as _e:
    logging.getLogger("webui").warning(f"[startup] cancel stale rebind runs 失败: {_e}")


try:
    from .qualification_api import recover_interrupted_jobs

    _interrupted_jobs = recover_interrupted_jobs()
    if _interrupted_jobs > 0:
        logging.getLogger("webui").info(
            f"[startup] 标记 {_interrupted_jobs} 个支付资格任务为检测中断"
        )
except Exception as _e:
    logging.getLogger("webui").warning(f"[startup] recover interrupted qualification jobs 失败: {_e}")


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("webui")

STATIC_DIR = Path(__file__).resolve().parent / "static"

app = FastAPI(title="GPT Outlook Register WebUI", docs_url=None, redoc_url=None)
app.include_router(qualification_router)
app.include_router(proxy_screening_router)
app.include_router(roxy_proxy_sync_router)
app.include_router(roxy_status_router)
app.include_router(roxy_settings_router)
app.include_router(refine_router)


@app.middleware("http")
async def account_database_context(request: Request, call_next):
    """Route API work to the selected isolated workspace database."""
    if request.url.path.startswith("/api/"):
        account = request.headers.get("X-WebUI-Account") or request.query_params.get("account", "1")
        _, token = db.activate_database(account)
        try:
            return await call_next(request)
        finally:
            db.reset_database(token)
    return await call_next(request)


@app.get("/api/account")
def api_get_account(request: Request):
    account = db.normalize_account(request.headers.get("X-WebUI-Account", "1"))
    return {"ok": True, "account": account}


class AccountSelectReq(BaseModel):
    account: str = "1"


@app.post("/api/account/select")
def api_select_account(req: AccountSelectReq):
    account, token = db.activate_database(req.account)
    db.reset_database(token)
    return {"ok": True, "account": account}


@app.on_event("startup")
async def _start_deferred_rebind_maintenance() -> None:
    """Start historical rebind cleanup after the HTTP listener is ready."""
    async def run_maintenance() -> None:
        try:
            await asyncio.to_thread(REBIND_SERVICE.initialize_maintenance)
        except Exception:
            logger.exception("[startup] deferred rebind maintenance failed")

    app.state.rebind_maintenance_task = asyncio.create_task(run_maintenance())


def _require_healthy_roxy_egress() -> int:
    """Fail before mailbox claim when every known Roxy exit is unavailable."""
    try:
        from .roxy_bridge import (
            RoxyEgressHealthCheckError,
            available_roxy_egress_capacity,
        )

        capacity = available_roxy_egress_capacity(
            retired_profile_ids=set(db.list_retired_roxy_profile_ids()),
            retired_ip_tags=set(db.list_retired_roxy_ip_tags()),
        )
    except RoxyEgressHealthCheckError as exc:
        raise HTTPException(503, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(
            400,
            safe_public_error(exc, "Roxy 健康出口容量检查"),
        ) from exc
    if capacity < 1:
        raise HTTPException(400, "Roxy 当前没有通过隔离检查的健康出口；未占用邮箱")
    return capacity


# ──────────────────────── Pydantic 模型 ────────────────────────


REGISTRATION_OTP_TIMEOUT_DEFAULT_VERSION = 1


def _normalize_registration_request_otp_timeout(value, default_version=0) -> int:
    """Migrate the old implicit 60-second default without overriding new choices."""
    try:
        legacy_default = int(value) == 60
    except (TypeError, ValueError):
        legacy_default = False
    try:
        version = int(default_version or 0)
    except (TypeError, ValueError):
        version = 0
    if version < REGISTRATION_OTP_TIMEOUT_DEFAULT_VERSION and legacy_default:
        value = registrar.REGISTRATION_OTP_TIMEOUT_SECONDS
    return registrar.normalize_otp_timeout(value)


class ImportReq(BaseModel):
    text: str = Field(..., description="每行一个号，格式由 kind 决定")
    kind: str = Field(
        "",
        description="邮箱来源（outlook / ...）。留空则按段数猜，"
                    "但 Outlook 和 Gmail 都是 4 段，猜不出来，建议前端必填",
    )


class RebindMailboxImportReq(BaseModel):
    text: str = Field(..., description="每行一个换绑邮箱：邮箱----收信API")


class RebindStartReq(BaseModel):
    emails: list[str] = Field(default_factory=list, description="要换绑的已注册账号")
    proxy: str = ""
    proxies: list[str] = Field(default_factory=list, description="换绑专用代理列表")
    mail_timeout: float = Field(120.0, ge=10.0, le=600.0)
    concurrency: int = Field(3, ge=1, le=20)

class RebindExportSelection(BaseModel):
    run_id: str
    email: str


class RebindAuthorizationSelection(BaseModel):
    source_run_id: str
    old_email: str
    new_email: str


class RebindAuthorizationRetryReq(BaseModel):
    items: list[RebindAuthorizationSelection] = Field(default_factory=list)
    proxy: str = ""
    concurrency: int = Field(1, ge=1, le=20)


class ExportRebindReq(BaseModel):
    format: str = Field(..., description="格式 id，见 GET /api/rebind/export/formats")
    items: list[RebindExportSelection] = Field(default_factory=list)


class RegisterReq(BaseModel):
    email: Optional[str] = Field(None, description="留空 = 自动 claim 下一个 available")
    driver: str = Field("protocol", pattern="^(protocol|roxy)$", description="protocol 或 roxy")
    want_access_token: bool = True
    want_session_token: bool = True
    want_refresh_token: bool = False
    proxy: str = ""
    proxy_pool: str = ""
    roxy_proxy_pool: str = ""
    fixed_asn_config: Optional[dict] = None
    otp_timeout: int = registrar.REGISTRATION_OTP_TIMEOUT_SECONDS
    otp_timeout_default_version: int = 0
    allow_existing_login: bool = True
    # 生产契约：2FA 必须，Codex refresh token 可选。
    want_2fa: bool = True
    # Roxy password submit defaults to a native CDP pointer gesture. Protocol
    # registration never consumes this flag.
    native_pointer_submit: bool = True
    trusted_keyboard_submit: bool = True
    # Diagnostic-only Roxy email-submit variant. Keep it opt-in per request.
    async_email_submit: bool = False
    # Diagnostic-only protocol A/B: opt into the passwordless signup delivery endpoint.
    protocol_passwordless_send: bool = False
    # Diagnostic-only protocol A/B: allow a bounded pre-send OTP timestamp window.
    protocol_passwordless_relaxed_window: bool = False


class RetryFailedAttemptReq(BaseModel):
    email: str
    driver: str = Field("protocol", pattern="^(protocol|roxy)$")
    proxy: str = ""
    proxy_pool: str = ""
    roxy_proxy_pool: str = ""
    fixed_asn_config: Optional[dict] = None
    otp_timeout: int = registrar.REGISTRATION_OTP_TIMEOUT_SECONDS
    otp_timeout_default_version: int = 0
    native_pointer_submit: bool = True
    trusted_keyboard_submit: bool = True
    async_email_submit: bool = False
    roxy_system_direct: bool = False


def _roxy_registration_proxy_source(req, *, allow_legacy_single: bool = False) -> tuple[bool, str]:
    try:
        use_proxy_pool = read_roxy_settings().use_proxy_pool
    except Exception as exc:
        raise HTTPException(400, safe_public_error(exc, "Roxy 设置读取")) from exc
    if (req.proxy_pool or "").strip():
        raise HTTPException(400, "Roxy 不接受协议代理池参数，请使用 Roxy 代理来源")
    if (req.proxy or "").strip() and (use_proxy_pool or not allow_legacy_single):
        raise HTTPException(400, "Roxy 不接受单独协议代理参数，请使用 Roxy 代理来源")
    proxy_pool_text = (req.roxy_proxy_pool or "").strip()
    if use_proxy_pool:
        if getattr(req, "roxy_system_direct", False):
            raise HTTPException(400, "Roxy 内置代理已开启，不能使用系统直连")
        try:
            validate_roxy_proxy_source(proxy_pool_text, req.fixed_asn_config)
        except (TypeError, ValueError) as exc:
            raise HTTPException(400, safe_public_error(exc, "Roxy 代理配置")) from exc
    return use_proxy_pool, proxy_pool_text if use_proxy_pool else ""


# ──────────────────────── 换绑邮箱池 / 批量换绑 API ────────────────────────


@app.get("/api/rebind/pool")
def api_rebind_pool():
    return {
        "ok": True,
        "items": db.list_rebind_mailboxes(),
        "stats": db.rebind_mailbox_stats(),
    }


@app.post("/api/rebind/pool/import")
def api_rebind_pool_import(req: RebindMailboxImportReq):
    try:
        result = db.import_rebind_mailboxes(req.text)
    except ValueError as exc:
        try:
            errors = json.loads(str(exc))
        except (TypeError, ValueError, json.JSONDecodeError):
            errors = [{"line": 0, "error": str(exc)}]
        return JSONResponse(
            status_code=422,
            content={"ok": False, "message": "换绑邮箱导入失败，整批未写入", "errors": errors},
        )
    return {"ok": True, **result, "stats": db.rebind_mailbox_stats()}


@app.delete("/api/rebind/pool/{email}")
def api_rebind_pool_delete(email: str):
    if not db.delete_rebind_mailbox(email):
        raise HTTPException(409, "邮箱不存在或正在被换绑任务使用")
    return {"ok": True, "email": email.strip().lower()}


@app.post("/api/rebind/pool/{email}/release")
def api_rebind_pool_release(email: str):
    """Release only a mailbox confirmed to have failed before rebind submission."""
    if not db.release_failed_rebind_mailbox(email):
        raise HTTPException(409, "只能释放系统明确判定为“换绑提交前失败”的邮箱；待核验/待补授权邮箱禁止释放")
    return {"ok": True, "email": email.strip().lower(), "status": "available"}


@app.get("/api/rebind/runs")
def api_rebind_runs():
    return {"ok": True, "items": REBIND_SERVICE.list_runs()}

@app.get("/api/rebind/export/formats")
def api_rebind_export_formats():
    return {"ok": True, "formats": export_formats.list_formats()}


@app.post("/api/rebind/export")
def api_export_rebind(req: ExportRebindReq):
    fmt = export_formats.get_format(req.format)
    if fmt is None:
        raise HTTPException(400, f"未知导出格式: {req.format}")
    try:
        rows = REBIND_SERVICE.export_rows([item.model_dump() for item in req.items])
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc

    base = {
        "ok": True,
        "count": len(rows),
        "filename": fmt.filename,
        "label": fmt.label,
        "mode": fmt.mode,
        "mime": fmt.mime,
    }
    if fmt.mode == "download":
        blob = export_formats.render_bytes(rows, fmt)
        return {**base, "b64": base64.b64encode(blob).decode("ascii"), "size": len(blob)}
    return {**base, "text": export_formats.render_text(rows, fmt)}


@app.delete("/api/rebind/runs/{run_id}/items/{email}")
def api_rebind_result_delete(run_id: str, email: str):
    """Delete one archived rebind result without touching the account or mailbox."""
    if not REBIND_SERVICE.delete_result(run_id, email) and not db.delete_rebind_run_item(run_id, email):
        raise HTTPException(409, "结果不存在、任务仍在处理，或结果已被删除")
    return {"ok": True, "run_id": run_id, "email": email.strip().lower()}


@app.post("/api/rebind/start")
def api_rebind_start(req: RebindStartReq):
    # 换绑必须显式使用独立代理，避免误用注册代理池或意外直连。
    proxies = [str(value or "").strip() for value in (req.proxies or []) if str(value or "").strip()]
    proxy = (req.proxy or "").strip()
    if not proxies and not proxy:
        raise HTTPException(400, "请先配置至少一个换绑专用代理")
    try:
        result = REBIND_SERVICE.start(
            req.emails,
            proxy=proxy,
            proxies=proxies,
            mail_timeout=req.mail_timeout,
            concurrency=req.concurrency,
        )
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(500, safe_public_error(exc, "启动换绑任务")) from exc
    return {"ok": True, **result}


@app.post("/api/rebind/retry-authorization")
def api_rebind_authorization_retry(req: RebindAuthorizationRetryReq):
    try:
        result = REBIND_SERVICE.start_authorization_retry(
            [item.model_dump() for item in req.items],
            proxy=(req.proxy or "").strip(),
            concurrency=req.concurrency,
        )
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(500, safe_public_error(exc, "启动换绑补授权任务")) from exc
    return {"ok": True, **result}


@app.get("/api/rebind/authorization-status/{job_id}")
def api_rebind_authorization_status(job_id: str):
    result = REBIND_SERVICE.authorization_status(job_id)
    if result is None:
        raise HTTPException(404, "换绑补授权任务不存在或服务已重启")
    return {"ok": True, **result}


@app.post("/api/rebind/authorization/{job_id}/cancel")
def api_cancel_rebind_authorization(job_id: str):
    if not REBIND_SERVICE.cancel_authorization_retry(job_id):
        raise HTTPException(404, "任务不存在或已经结束")
    return {"ok": True, "run_id": job_id, "status": "cancelling"}


@app.get("/api/rebind/status/{run_id}")
def api_rebind_status(run_id: str):
    result = REBIND_SERVICE.status(run_id)
    if result is None:
        raise HTTPException(404, "换绑任务不存在或已重启清理")
    return {"ok": True, **result}


@app.post("/api/rebind/{run_id}/cancel")
def api_rebind_cancel(run_id: str):
    if not REBIND_SERVICE.cancel(run_id):
        raise HTTPException(404, "任务不存在或已经结束")
    return {"ok": True, "run_id": run_id, "status": "cancelling"}


# ──────────────────────── API ────────────────────────


@app.get("/api/health")
def health():
    roxy_egress_check_ok = True
    roxy_egress_error = None
    try:
        from .roxy_bridge import (
            PROFILE_POOL,
            RoxyEgressHealthCheckError,
            available_roxy_egress_capacity,
        )

        roxy_profile_pool = PROFILE_POOL.status()
    except Exception:  # noqa: BLE001 - health remains available without Roxy
        logger.warning("[health] Roxy Profile pool status unavailable")
        roxy_profile_pool = {
            "capacity": 5,
            "slots": 0,
            "in_use": 0,
            "available": False,
        }
        available_roxy_egress_capacity = None
    try:
        roxy_egress_capacity = (
            available_roxy_egress_capacity(
                retired_profile_ids=set(db.list_retired_roxy_profile_ids()),
                retired_ip_tags=set(db.list_retired_roxy_ip_tags()),
                refresh_stale=True,
            )
            if callable(available_roxy_egress_capacity)
            else 0
        )
    except RoxyEgressHealthCheckError as exc:
        logger.warning("[health] Roxy egress health check unavailable")
        roxy_egress_capacity = None
        roxy_egress_check_ok = False
        roxy_egress_error = str(exc)
    except Exception as exc:  # noqa: BLE001 - capacity is advisory health metadata
        logger.warning("[health] Roxy egress capacity unavailable")
        roxy_egress_capacity = None
        roxy_egress_check_ok = False
        roxy_egress_error = safe_public_error(exc, "Roxy 健康出口容量检查")
    return {
        "ok": True,
        "stats": db.stats(),
        "roxy_profile_pool": roxy_profile_pool,
        "roxy_egress_capacity": roxy_egress_capacity,
        "roxy_egress_check_ok": roxy_egress_check_ok,
        "roxy_egress_error": roxy_egress_error,
    }


@app.get("/api/ready")
def ready():
    """Cheap local readiness probe used by the desktop launcher."""
    return {"ok": True}


@app.post("/api/import")
def api_import(req: ImportReq):
    """批量导入号池。**有一行不合法就整批拒绝**，一个都不写库。

    非法时返回 422，body 里带每一行的行号和原因，前端直接展示即可：

        {"ok": false, "message": "...", "errors": [{"line": 3, "error": "..."}]}
    """
    try:
        result = db.import_accounts(req.text, kind=req.kind)
    except ImportValidationError as e:
        return JSONResponse(
            status_code=422,
            content={"ok": False, "message": str(e), "errors": e.errors},
        )
    except MailProviderError as e:
        raise HTTPException(400, str(e))
    return {"ok": True, **result, "stats": db.stats()}


@app.get("/api/accounts")
def api_accounts(status: str = "", limit: int = 50, offset: int = 0, kind: str = ""):
    items = db.list_accounts(status=status, limit=limit, offset=offset, kind=kind)
    total = db.count_accounts(status=status, kind=kind)
    return {
        "ok": True,
        "items": items,
        "total": total,
        "by_kind": db.stats_by_kind(),
    }


@app.delete("/api/accounts/{email}")
def api_delete_account(email: str):
    ok = db.delete_account(email)
    if not ok:
        raise HTTPException(404, "not found")
    return {"ok": True}


class BulkDeleteReq(BaseModel):
    status: Optional[str] = Field(None, description="available/in_use/done/failed/all")
    emails: Optional[list[str]] = Field(None, description="按 email 列表删")


@app.post("/api/accounts/bulk_delete")
def api_bulk_delete(req: BulkDeleteReq):
    """按状态或 email 列表批量删除号池。两个参数二选一（status 优先）。"""
    if req.status:
        n = db.delete_accounts_by_status(req.status)
        return {"ok": True, "deleted": n, "by": "status", "stats": db.stats()}
    if req.emails:
        n = db.delete_accounts_by_emails(req.emails)
        return {"ok": True, "deleted": n, "by": "emails", "stats": db.stats()}
    raise HTTPException(400, "需要 status 或 emails")


@app.post("/api/accounts/reset_failed")
def api_reset_failed():
    n = db.reset_failed_to_available()
    return {"ok": True, "reset": n, "stats": db.stats()}


@app.post("/api/accounts/reset/{email}")
def api_reset_account(email: str):
    """重置单个号：done / failed → available。"""
    ok = db.reset_to_available(email)
    if not ok:
        raise HTTPException(404, f"邮箱 {email} 不存在")
    return {"ok": True, "email": email}


class BulkResetReq(BaseModel):
    emails: list[str]


@app.post("/api/accounts/bulk_reset")
def api_bulk_reset(req: BulkResetReq):
    """批量重置：done / failed → available。"""
    if not req.emails:
        raise HTTPException(400, "emails 不能为空")
    n = db.bulk_reset_to_available(req.emails)
    return {"ok": True, "reset": n, "stats": db.stats()}


@app.post("/api/accounts/release_stale")
def api_release_stale(stale_seconds: int = 1800):
    n = db.release_stale_in_use(stale_seconds=stale_seconds)
    return {"ok": True, "released": n, "stats": db.stats()}


@app.get("/api/stats")
def api_stats():
    return {"ok": True, "stats": db.stats()}


# ──────────────────────── 代理连通性测试 ────────────────────────


class ProxyTestReq(BaseModel):
    proxies: list[str] = Field(..., description="要测试的代理列表")
    timeout: int = Field(8, description="每个代理超时秒数")
    test_url: str = Field("https://api.ipify.org?format=json",
                          description="测试目标 URL（默认返回出口 IP）")


@app.post("/api/proxy/test")
def api_proxy_test(req: ProxyTestReq):
    """并发测试代理连通性。复用真实注册流程的 create_http_session（含 socks5->socks5h
    标准化、trust_env=False），保证「测试正常」== 「跑号能用」。返回 ok / 延迟 / 出口 IP。

    协议说明：不写协议的 `ip:port` 被 curl 按 HTTP 代理处理；SOCKS5 需显式写 socks5://。
    """
    import sys as _sys
    ROOT_DIR = Path(__file__).resolve().parents[1]
    if str(ROOT_DIR) not in _sys.path:
        _sys.path.insert(0, str(ROOT_DIR))
    try:
        from http_client import create_http_session
    except Exception as e:  # noqa: BLE001
        raise HTTPException(500, f"加载 http_client 失败: {e}")

    import time as _t
    from concurrent.futures import ThreadPoolExecutor

    timeout = max(1, min(int(req.timeout or 8), 60))
    test_url = (req.test_url or "https://api.ipify.org?format=json").strip()

    proxies = [p.strip() for p in (req.proxies or []) if p and p.strip()]
    if not proxies:
        raise HTTPException(400, "proxies 不能为空")

    def _test_one(proxy: str):
        t0 = _t.perf_counter()
        try:
            sess = create_http_session(proxy=proxy)
            resp = sess.get(test_url, timeout=timeout)
            latency = int((_t.perf_counter() - t0) * 1000)
            if resp.status_code != 200:
                return {"ok": False, "latency_ms": latency, "error": f"HTTP {resp.status_code}"}
            ip = ""
            try:
                ip = resp.json().get("ip", "")
            except Exception:
                ip = (resp.text or "").strip()[:64]
            return {"ok": True, "latency_ms": latency, "ip": ip}
        except Exception as e:  # noqa: BLE001
            latency = int((_t.perf_counter() - t0) * 1000)
            return {"ok": False, "latency_ms": latency, "error": str(e)[:140]}

    results = {}
    with ThreadPoolExecutor(max_workers=min(20, len(proxies))) as ex:
        for proxy, res in zip(proxies, ex.map(_test_one, proxies)):
            results[proxy] = res
    return {"ok": True, "results": results}


@app.post("/api/register")
@runtime_config_admission
def api_register(req: RegisterReq):
    """启动注册任务，返回 run_id。前端拿 run_id 去 /api/runs/{run_id}/stream 订阅 SSE。"""
    driver = (req.driver or "protocol").strip().lower()
    roxy_use_proxy_pool = False
    roxy_proxy_pool_text = ""
    if driver == "roxy":
        roxy_use_proxy_pool, roxy_proxy_pool_text = _roxy_registration_proxy_source(req)
        try:
            require_roxy_configuration()
        except RoxyConfigurationError as exc:
            raise HTTPException(400, str(exc)) from exc
        if not roxy_use_proxy_pool:
            _require_healthy_roxy_egress()
    mail_source = db.get_setting("mail_source", "outlook")
    proxy_pool_text = (req.proxy_pool or "").strip()
    if roxy_use_proxy_pool:
        proxy_pool_text = roxy_proxy_pool_text
    if driver == "protocol" and not proxy_pool_text and not req.fixed_asn_config:
        # Legacy clients only sent the single `proxy` field. Treat that as a
        # one-resource pool, but never let an empty value fall through to a
        # direct protocol connection.
        proxy_pool_text = (req.proxy or "").strip()
    if driver == "protocol" and not proxy_pool_text and not req.fixed_asn_config:
        raise HTTPException(400, "纯协议注册必须走代理池，请先配置可用代理")
    try:
        provider_cls = get_provider_class(mail_source)
    except MailProviderError as e:
        raise HTTPException(400, str(e))

    # 注册显式选择代理来源时，先取得独占出口再 claim 邮箱。
    # 没有健康出口时不会白白占用账号，也绝不静默回退直连。
    proxy_lease = None
    lease_handed_off = False
    if driver == "protocol" or roxy_use_proxy_pool:
        try:
            proxy_lease = (
                AUTO_LOOP.acquire_protocol_proxy(proxy_pool_text, req.fixed_asn_config)
                if req.fixed_asn_config
                else AUTO_LOOP.acquire_protocol_proxy(proxy_pool_text)
            )
            if roxy_use_proxy_pool:
                validate_roxy_proxy_source(proxy_lease.proxy)
        except TimeoutError as exc:
            raise HTTPException(503, f"代理池暂无可用独占出口：{exc}") from exc
        except ValueError as exc:
            if proxy_lease is not None:
                proxy_lease.release()
            raise HTTPException(400, str(exc)) from exc
        except ProxyGenerationError as exc:
            raise HTTPException(503, str(exc)) from exc
        except RuntimeError as exc:
            raise HTTPException(409, str(exc)) from exc
        except Exception as exc:  # noqa: BLE001 - fail closed for pool errors
            raise HTTPException(503, safe_public_error(exc, "代理池独占出口")) from exc

    account = None
    claimed_email = ""
    try:
        # 要不要 claim 号池，由 provider 自己声明的 pooled 决定。
        if not provider_cls.pooled:
            # 非池化：地址由 provider 现造，用占位 account 走完后面的流程
            import time as _t
            account = {
                "email": f"{mail_source}_placeholder_{int(_t.time())}@placeholder.local",
                "password": "",
                "client_id": "",
                "refresh_token": "",
                "relay_url": "",
                "kind": mail_source,
            }
        elif req.email:
            account = db.claim_account(req.email)
            if not account:
                raise HTTPException(400, f"邮箱 {req.email} 不可用 (不存在 / 已 in_use / 已完成)")
            claimed_email = account["email"]
            if (account.get("kind") or "outlook") != mail_source:
                # 号池里混放多种邮箱，点名的号必须和当前来源一致，
                # 否则会拿 Outlook 的凭证去初始化 Gmail provider
                db.release_unused(account["email"])
                claimed_email = ""
                raise HTTPException(
                    400,
                    f"{req.email} 是 {account.get('kind')} 的号，"
                    f"当前邮箱来源是 {mail_source}，请先切换来源",
                )
        else:
            account = db.claim_next(kind=mail_source)
            if not account:
                raise HTTPException(
                    400,
                    f"号池里没有 available 的 {provider_cls.display_name} 账号；请先批量导入",
                )
            claimed_email = account["email"]

        options = {
            "driver": driver,
            "roxy_use_proxy_pool": roxy_use_proxy_pool,
            "mail_source": (account.get("kind") or mail_source).strip().lower(),
            "mail_settings_snapshot": db.get_mail_settings(),
            "want_access_token": req.want_access_token,
            "want_session_token": req.want_session_token,
            "want_refresh_token": req.want_refresh_token,
            # proxy_pool 优先于兼容旧版的单代理字段。
            "proxy": proxy_lease.proxy if proxy_lease is not None else req.proxy,
            "otp_timeout": _normalize_registration_request_otp_timeout(
                req.otp_timeout,
                req.otp_timeout_default_version,
            ),
            "allow_existing_login": req.allow_existing_login,
            "want_2fa": req.want_2fa,
            "native_pointer_submit": bool(req.native_pointer_submit)
            and (req.driver or "protocol").strip().lower() == "roxy",
            "trusted_keyboard_submit": bool(req.trusted_keyboard_submit)
            and (req.driver or "protocol").strip().lower() == "roxy",
            "async_email_submit": bool(req.async_email_submit)
            and (req.driver or "protocol").strip().lower() == "roxy",
            "protocol_passwordless_send": bool(req.protocol_passwordless_send)
            and (req.driver or "protocol").strip().lower() == "protocol",
            "protocol_passwordless_relaxed_window": bool(req.protocol_passwordless_relaxed_window)
            and (req.driver or "protocol").strip().lower() == "protocol",
        }
        screening = getattr(proxy_lease, "screening", None) if proxy_lease is not None else None
        if isinstance(screening, dict) and screening:
            options["proxy_screening"] = dict(screening)
            logger.info(
                "[run] 新 Session 代理已筛选通过：ASN=%s 质量分=%s 探测=%s次；筛选后才开始 claim/注册",
                screening.get("asn", "-"),
                screening.get("quality_score", 0),
                screening.get("probe_count", 0),
            )
        if proxy_lease is not None:
            options["proxy_pool"] = proxy_pool_text
            run_id = registrar.start_registration(
                account,
                options,
                on_finished=proxy_lease.release,
            )
            lease_handed_off = True
        else:
            run_id = registrar.start_registration(account, options)
        logger.info(f"[run] {run_id} -> {account['email']} (mail_source={mail_source})")
        return {"ok": True, "run_id": run_id, "email": account["email"]}
    except Exception:
        if claimed_email and provider_cls.pooled:
            try:
                db.release_unused(claimed_email)
            except Exception:
                logger.exception("释放单次注册 claim 失败: %s", claimed_email)
        if proxy_lease is not None and not lease_handed_off:
            proxy_lease.release()
        raise


@app.get("/api/runs/{run_id}/stream")
async def api_stream(run_id: str, request: Request):
    """SSE 实时推送日志 + 事件。"""
    q = registrar.get_run_queue(run_id)
    if q is None:
        raise HTTPException(404, "run_id not found or finished")

    async def event_gen():
        loop = asyncio.get_event_loop()
        try:
            while True:
                if await request.is_disconnected():
                    break
                # 从队列取消息（用 run_in_executor 避免阻塞 event loop）
                msg = await loop.run_in_executor(None, _safe_get, q)
                if msg is None:
                    # sentinel: 任务结束
                    yield "event: end\ndata: {}\n\n"
                    break
                if msg.startswith("__EVENT__:"):
                    yield f"event: status\ndata: {msg[len('__EVENT__:'):]}\n\n"
                else:
                    yield f"event: log\ndata: {json.dumps({'line': msg}, ensure_ascii=False)}\n\n"
        finally:
            registrar.remove_run_queue(run_id)

    return StreamingResponse(
        event_gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",  # 避免 nginx 缓冲
            "Connection": "keep-alive",
        },
    )


def _safe_get(q):
    try:
        return q.get(timeout=60)
    except Exception:
        return ""  # 心跳：返空串让 SSE 检查 disconnect


@app.get("/api/runs")
def api_runs(limit: int = 50):
    return {"ok": True, "items": db.list_runs(limit=limit)}


@app.get("/api/registered")
def api_registered(
    limit: int = 20,
    offset: int = 0,
    filter: str = "all",
    plus_filter: str = "all",
    pool_filter: str = "all",
    query: str = "",
):
    limit = max(1, min(int(limit), 100))
    offset = max(0, int(offset))
    plus_filter = (plus_filter or "all").strip().lower()
    if plus_filter not in {
        "all", "unchecked", "free", "plus", "plus_eligible", "plus_active",
        "abnormal", "token_invalid", "banned", "frozen", "error",
        "qualification_eligible",
    }:
        raise HTTPException(400, "未知 Plus 状态筛选")
    pool_filter = (pool_filter or "all").strip().lower()
    if pool_filter not in {"all", *db.ACCOUNT_POOL_VALUES}:
        raise HTTPException(400, "未知账户池筛选")
    page_kwargs = {
        "limit": limit,
        "offset": offset,
        "filter_rt": filter,
        "query": query,
        "plus_filter": plus_filter,
    }
    if pool_filter != "all":
        page_kwargs["pool_filter"] = pool_filter
    page = db.page_credential_registration_results(
        **page_kwargs,
    )
    if pool_filter != "all":
        page["pool_counts"] = {
            pool: db.count_registered(
                filter_rt=filter,
                query=query,
                plus_filter=plus_filter,
                pool_filter=pool,
            )
            for pool in db.ACCOUNT_POOL_VALUES
        }
    from .qualification_store import latest_results
    evidence = latest_results()
    for row in page.get("items", []):
        row["payment_qualification"] = evidence.get(str(row.get("email") or "").lower())
    return {"ok": True, **page}


@app.get("/api/registered/failed_attempts")
def api_registered_failed_attempts(
    limit: int = 20,
    offset: int = 0,
    query: str = "",
):
    page = db.page_failed_attempt_results(
        limit=limit,
        offset=offset,
        query=query,
    )
    return {"ok": True, **page}


def _has_same_identity_registration_progress(registered: dict) -> bool:
    """Return whether a saved row proves this identity reached registration."""
    extra = registered.get("extra") or {}
    if isinstance(extra, str):
        try:
            extra = json.loads(extra)
        except Exception:
            extra = {}
    if not isinstance(extra, dict):
        extra = {}
    # A missing marker is unknown, not proof of an accepted password.  A
    # known pending=false marker is explicit local evidence from the accepted
    # password boundary; auth/MFA fields are independent progress evidence.
    if extra.get("pending") is False:
        return True
    return any(
        bool((registered.get(field) or "").strip())
        for field in (
            "access_token",
            "session_token",
            "totp_secret",
            "totp_factor_id",
        )
    )


@app.post("/api/registered/failed_attempts/retry")
@runtime_config_admission
def api_retry_failed_attempt(req: RetryFailedAttemptReq):
    email = (req.email or "").strip().lower()
    failed = db.list_failed_attempt_results(limit=2, offset=0, query=email)
    exact = [row for row in failed if row.get("email") == email]
    operation_state = db.get_registered_operation_state(email)
    if len(exact) != 1 and not operation_state.get("authorized_pending"):
        raise HTTPException(409, "该账号当前不是可重试的失败尝试")

    registered = db.get_registered(email, include_pending_password=True) or {}
    has_password = bool((registered.get("password") or "").strip())
    has_registration_progress = _has_same_identity_registration_progress(registered)

    if db.has_completed_registration_evidence(registered):
        raise HTTPException(409, "该账号凭据已完整，不能从失败尝试重新注册")

    driver = (req.driver or "protocol").strip().lower()
    proxy = (req.proxy or "").strip()
    proxy_pool_text = (req.proxy_pool or "").strip()
    otp_timeout = _normalize_registration_request_otp_timeout(
        req.otp_timeout,
        req.otp_timeout_default_version,
    )
    # A password-pending credential row that is no longer a failed-attempt row
    # continues through the existing same-identity authorization path.
    if not exact and has_password and has_registration_progress:
        options = {
            "proxy": proxy,
            "otp_timeout": otp_timeout,
            "bind_missing_2fa": True,
            "2fa_max_attempts": 2,
            "2fa_retry_delay": 2.0,
            "reconcile_failed_continuation": True,
        }
        try:
            run_id = registrar.start_registered_reauthorization([email], options)
        except db.RegisteredIdentityUnavailableError:
            raise HTTPException(409, "该账号状态已变化或已在其他任务中")
        logger.info("[failed-retry] continuation %s -> %s", run_id, email)
        return {
            "ok": True,
            "run_id": run_id,
            "email": email,
            "route": "continuation",
        }

    proxy_lease = None
    lease_handed_off = False
    roxy_use_proxy_pool = False
    if driver == "protocol":
        if not proxy_pool_text and not req.fixed_asn_config:
            # Keep compatibility with callers that still send one proxy.
            proxy_pool_text = proxy
        if not proxy_pool_text and not req.fixed_asn_config:
            raise HTTPException(400, "纯协议注册必须走代理池，请先配置可用代理")
    else:
        roxy_use_proxy_pool, proxy_pool_text = _roxy_registration_proxy_source(
            req, allow_legacy_single=True,
        )
        try:
            require_roxy_configuration()
        except RoxyConfigurationError as exc:
            raise HTTPException(400, str(exc)) from exc
        if not roxy_use_proxy_pool and not req.roxy_system_direct:
            _require_healthy_roxy_egress()
    if driver == "protocol" or roxy_use_proxy_pool:
        try:
            proxy_lease = (
                AUTO_LOOP.acquire_protocol_proxy(proxy_pool_text, req.fixed_asn_config)
                if req.fixed_asn_config
                else AUTO_LOOP.acquire_protocol_proxy(proxy_pool_text)
            )
            if roxy_use_proxy_pool:
                validate_roxy_proxy_source(proxy_lease.proxy)
        except TimeoutError as exc:
            raise HTTPException(503, f"代理池暂无可用独占出口：{exc}") from exc
        except ValueError as exc:
            if proxy_lease is not None:
                proxy_lease.release()
            raise HTTPException(400, str(exc)) from exc
        except ProxyGenerationError as exc:
            raise HTTPException(503, str(exc)) from exc
        except RuntimeError as exc:
            raise HTTPException(409, str(exc)) from exc
        except Exception as exc:  # noqa: BLE001 - fail closed for pool errors
            raise HTTPException(503, safe_public_error(exc, "代理池独占出口")) from exc
    try:
        registered_extra = registered.get("extra") if isinstance(registered.get("extra"), dict) else {}
        password_confirmed = bool((registered.get("password") or "").strip()) and (
            registered_extra.get("pending") is False
        )
        claim_account_email = ""
        if password_confirmed:
            # A confirmed-password retry owns a registered identity lease. Read the
            # pool row without changing it, then let create_run claim it in the same
            # transaction as the run and lease so a delete/retry race cannot leave
            # an orphan run.
            account = db.get_account(email)
            if account:
                claim_account_email = email
        else:
            # A pending candidate has not yet proved server-side password acceptance.
            # Preserve its existing same-email registration claim behavior.
            account = db.claim_account(email)
        if not account:
            # Non-pooled/ephemeral providers derive the mailbox from configuration
            # rather than outlook_accounts. They still must retry the exact same
            # email; pooled providers fail closed when their mailbox row is gone.
            configured_kind = str(db.get_setting("mail_source", "outlook") or "outlook").strip().lower()
            try:
                provider_class = get_provider_class(configured_kind)
            except Exception:
                provider_class = None
            if provider_class is None or getattr(provider_class, "pooled", True):
                raise HTTPException(409, "该账号邮箱池记录缺失，无法安全启动同邮箱注册")
            account = {"email": email, "kind": configured_kind}
        if not account:
            raise HTTPException(409, "该账号已在处理中、已完成或状态已变化")
        options = {
            "driver": driver,
            "roxy_use_proxy_pool": roxy_use_proxy_pool,
            "want_access_token": True,
            "want_session_token": True,
            "want_refresh_token": False,
            "proxy": proxy_lease.proxy if proxy_lease is not None else proxy,
            "otp_timeout": otp_timeout,
            "allow_existing_login": True,
            "want_2fa": True,
            "native_pointer_submit": bool(req.native_pointer_submit) and driver == "roxy",
            "trusted_keyboard_submit": bool(req.trusted_keyboard_submit) and driver == "roxy",
            "async_email_submit": bool(req.async_email_submit) and driver == "roxy",
            "roxy_system_direct": bool(req.roxy_system_direct) and driver == "roxy",
        }
        if proxy_lease is not None:
            options["proxy_pool"] = proxy_pool_text
        try:
            run_id = registrar.start_registration(
                account,
                options,
                required_registered_emails=[email] if registered else None,
                claim_account_email=claim_account_email,
                on_finished=proxy_lease.release if proxy_lease is not None else None,
            )
            lease_handed_off = proxy_lease is not None
        except db.RegisteredIdentityUnavailableError:
            raise HTTPException(409, "该账号已被删除、状态已变化或已在其他任务中")
        except Exception:
            db.mark_failed(email, "重试任务启动失败")
            raise
        logger.info("[failed-retry] registration %s -> %s", run_id, email)
        return {
            "ok": True,
            "run_id": run_id,
            "email": email,
            "route": "registration",
        }
    finally:
        if proxy_lease is not None and not lease_handed_off:
            proxy_lease.release()

def _require_registered_operation_allowed(
    email: str,
    *,
    allow_failed_recovery: bool = False,
    reject_active: bool = False,
) -> dict:
    state = db.get_registered_operation_state(email)
    if reject_active and state.get("active"):
        raise HTTPException(409, "该身份仍有运行中的任务，暂不能删除")
    if state["unresolved_failed"] and not allow_failed_recovery:
        raise HTTPException(
            409,
            "该身份最新注册失败且凭据未完成；只能通过显式失败恢复流程处理",
        )
    return state


def _require_registered_batch_allowed(
    emails: list[str],
    *,
    allow_failed_recovery: bool = False,
    reject_active: bool = False,
) -> None:
    for email in emails or []:
        _require_registered_operation_allowed(
            email,
            allow_failed_recovery=allow_failed_recovery,
            reject_active=reject_active,
        )


def _require_registered_reauthorization_batch_allowed(emails: list[str]) -> None:
    """Allow the explicit reauthorization flow to recover prior failed runs.

    Reauthorization is itself the user-facing failed-state recovery action.  A
    previous registration/reauthorization failure must therefore not turn this
    endpoint into another 409 gate; the worker still validates the saved row,
    mailbox, login flow, and credentials.  Keep the passwordless MFA
    normalization first so those rows are classified as password recovery
    before the run starts.
    """
    for email in emails or []:
        db.normalize_authorized_passwordless_recovery(email)
        _require_registered_operation_allowed(
            email,
            allow_failed_recovery=True,
        )


def _require_registered_export_allowed(email: str) -> dict:
    """Allow exporting a saved credential row without changing registration state.

    Export is a read-only operation.  A pending password or an unresolved
    registration failure must not turn into ``complete`` merely because the
    row is being exported; it only needs an authoritative registered row and
    no active task owning that identity.
    """
    state = _require_registered_operation_allowed(
        email,
        allow_failed_recovery=True,
        reject_active=True,
    )
    if not state["exists"]:
        raise HTTPException(404, "该身份没有可导出的注册凭证")
    return state


def _require_registered_export_batch_allowed(emails: list[str]) -> None:
    normalized = list(dict.fromkeys(
        email.strip().lower()
        for email in (emails or [])
        if email and email.strip()
    ))
    if not normalized:
        raise HTTPException(400, "至少选择一个有注册凭证的账号")
    for email in normalized:
        _require_registered_export_allowed(email)



def _require_plus_check_allowed(emails: list[str]) -> None:
    """Allow read-only plan checks for failed identities only when an AT exists.

    A Plus result never completes registration or verifies the pending password.
    Mutating/export/credential endpoints keep using the stricter batch guard.
    """
    for email in emails or []:
        state = db.get_registered_operation_state(email)
        if not state["unresolved_failed"]:
            continue
        registered = db.get_registered(email, include_pending_password=True) or {}
        if not (registered.get("access_token") or "").strip():
            raise HTTPException(
                409,
                "该身份注册未完成且没有可用 Access Token；请先继续失败任务",
            )


class RefreshTokenBatchReq(BaseModel):
    emails: list[str] = Field(default_factory=list, description="要获取 Refresh Token 的账号")
    proxy: str = ""
    concurrency: int = Field(3, ge=1, le=5)


class PasswordResetBatchReq(BaseModel):
    """Start the server-generated-password protocol recovery workflow."""

    driver: str = "protocol"
    selection_only: bool = False
    client_run_id: str = Field("", pattern=r"^(?:[a-f0-9]{32})?$")

    emails: list[str] = Field(
        default_factory=list,
        description="留空则处理全部“已有账号 · 待重置”账号",
    )
    proxy: str = ""
    proxy_pool: str = ""
    roxy_proxy_pool: str = ""
    fixed_asn_config: Optional[dict] = None
    otp_timeout: int = registrar.REGISTRATION_OTP_TIMEOUT_SECONDS
    concurrency: int = Field(1, ge=1, le=3)


@app.post("/api/registered/password-reset")
def api_start_registered_password_reset(req: PasswordResetBatchReq):
    """Reset selected recovery-pending passwords through the official protocol API."""
    if (req.driver or "protocol").strip().lower() != "protocol":
        raise HTTPException(400, "密码重置只支持协议驱动，不能调用 Roxy")
    requested = registrar._normalize_reauthorization_emails(req.emails)
    if req.selection_only and not requested:
        raise HTTPException(400, "请先勾选至少一个已有账号·待重置")
    if not requested:
        requested = db.list_password_recovery_emails(limit=101)
    if len(requested) > 100:
        raise HTTPException(400, "单次最多自动重置 100 个账号")

    def existing_response():
        if not req.client_run_id:
            return None
        existing = registrar.get_registered_password_reset_snapshot(req.client_run_id)
        if existing is None:
            return None
        identities = [row['email'] for row in existing['accounts']]
        if not identities or not set(identities).issubset(requested):
            raise HTTPException(409, '该任务编号已被使用，请查询原任务')
        return {'ok':True, 'run_id':req.client_run_id, 'count':len(identities),
                'emails':identities, 'skipped':len(requested)-len(identities), 'reused':True}

    # The browser allocates its identity before POST. Replaying that identity
    # only retrieves the original task; the unique runs key prevents two workers.
    existing = existing_response()
    if existing is not None:
        return existing

    if req.selection_only:
        availability = db.page_password_reset_candidates(selected=requested)['selection_items']
        if any(not row['selectable'] for row in availability):
            raise HTTPException(409, '有选中账号已冻结、正在其他任务中或缺少接码记录，请刷新列表')

    eligible: list[str] = []
    for email in requested:
        status, _row = registrar.get_password_reset_eligibility(email)
        if status == "eligible":
            eligible.append(email)
    if not eligible:
        raise HTTPException(409, "当前没有待自动重置的账号")
    # This is an explicit recovery operation.  A previous failed attempt may
    # remain attached to the identity, but an active run is still rejected by
    # create_run's identity lease transaction below.
    try:
        _require_registered_batch_allowed(eligible, allow_failed_recovery=True)
    except HTTPException:
        existing = existing_response()
        if existing is not None:
            return existing
        raise

    proxy_pool_text = (req.proxy_pool or req.proxy or "").strip()
    use_protocol_proxy = bool(proxy_pool_text or req.fixed_asn_config)
    if not use_protocol_proxy:
        raise HTTPException(400, "纯协议密码重置必须走代理池或固定 ASN 配置")

    options = {
        "driver": "protocol",
        "protocol_use_proxy_pool": use_protocol_proxy,
        "proxy_pool": proxy_pool_text,
        "fixed_asn_config": req.fixed_asn_config,
        "otp_timeout": registrar.normalize_otp_timeout(req.otp_timeout),
        "concurrency": req.concurrency,
    }
    try:
        run_id = registrar.start_registered_password_reset_batch(eligible, options,
            **({'client_run_id':req.client_run_id} if req.client_run_id else {}))
    except db.RegisteredIdentityUnavailableError:
        existing = existing_response()
        if existing is not None:
            return existing
        raise HTTPException(409, "有账号状态已变化或已在其他任务中")
    except sqlite3.IntegrityError:
        existing = existing_response()
        if existing is not None:
            return existing
        raise HTTPException(409, '任务编号冲突，请核对运行记录')
    return {
        "ok": True,
        "run_id": run_id,
        "count": len(eligible),
        "skipped": len(requested) - len(eligible),
        "emails": eligible,
    }


@app.post("/api/registered/password-reset/{run_id}/cancel")
def api_cancel_registered_password_reset(run_id: str):
    if not registrar.cancel_registered_password_reset_batch(run_id):
        raise HTTPException(404, "任务不存在或已经结束")
    return {"ok": True, "run_id": run_id, "status": "cancelling"}


@app.get("/api/registered/password-reset/candidates")
def api_password_reset_candidates(limit: int = 100, offset: int = 0, query: str = "", selected: str = ""):
    emails = registrar._normalize_reauthorization_emails(selected.split(','))
    if len(emails) > 100:
        raise HTTPException(400, '最多核对 100 个选中账号')
    return {'ok':True, **db.page_password_reset_candidates(limit, offset, query, emails)}


@app.get("/api/registered/password-reset/{run_id}/status")
def api_password_reset_task(run_id: str):
    result = registrar.get_registered_password_reset_snapshot(run_id)
    if result is None:
        raise HTTPException(404, '当前工作区找不到该密码重置任务')
    return result


@app.post("/api/registered/refresh-token")
def api_acquire_registered_refresh_tokens(req: RefreshTokenBatchReq):
    emails = registrar._normalize_reauthorization_emails(req.emails)
    if not emails:
        raise HTTPException(400, "至少选择一个账号")
    if len(emails) > 100:
        raise HTTPException(400, "单次最多处理 100 个账号")

    eligible = [
        email
        for email in emails
        if registrar.get_refresh_token_eligibility(email)[0] == "eligible"
    ]
    if not eligible:
        raise HTTPException(409, "所选账号均不符合获取 Refresh Token 的条件")
    _require_registered_batch_allowed(eligible)

    options = {
        "proxy": (req.proxy or "").strip(),
        "concurrency": req.concurrency,
    }
    try:
        run_id = registrar.start_registered_refresh_token_batch(eligible, options)
    except db.RegisteredIdentityUnavailableError:
        raise HTTPException(409, "有账号状态已变化或已在其他任务中")
    return {
        "ok": True,
        "run_id": run_id,
        "count": len(eligible),
        "skipped": len(emails) - len(eligible),
    }


@app.post("/api/registered/refresh-token/{run_id}/cancel")
def api_cancel_registered_refresh_tokens(run_id: str):
    if not registrar.cancel_registered_refresh_token_batch(run_id):
        raise HTTPException(404, "任务不存在或已经结束")
    return {"ok": True, "run_id": run_id, "status": "cancelling"}


class ReauthorizeRegisteredReq(BaseModel):
    emails: list[str] = Field(default_factory=list, description="要重新授权的已注册账号")
    proxy: str = ""
    otp_timeout: int = registrar.REGISTERED_REAUTH_OTP_TIMEOUT_SECONDS
    bind_missing_2fa: bool = True
    concurrency: int = Field(5, ge=1, le=5)



@app.post("/api/registered/reauthorize")
def api_reauthorize_registered(req: ReauthorizeRegisteredReq):
    emails = registrar._normalize_reauthorization_emails(req.emails)
    if not emails:
        raise HTTPException(400, "至少选择一个账号")
    if len(emails) > 100:
        raise HTTPException(400, "单次最多处理 100 个账号")
    _require_registered_reauthorization_batch_allowed(emails)

    options = {
        "proxy": (req.proxy or "").strip(),
        "otp_timeout": registrar.normalize_otp_timeout(req.otp_timeout),
        "bind_missing_2fa": bool(req.bind_missing_2fa),
        "concurrency": req.concurrency,
        "2fa_max_attempts": 2,
        "2fa_retry_delay": 2.0,
    }
    try:
        run_id = registrar.start_registered_reauthorization(emails, options)
    except db.RegisteredIdentityUnavailableError:
        raise HTTPException(409, "有账号状态已变化或已在其他任务中")
    return {"ok": True, "run_id": run_id, "count": len(emails)}


@app.post("/api/registered/reauthorize/{run_id}/cancel")
def api_cancel_registered_reauthorization(run_id: str):
    if not registrar.cancel_registered_reauthorization(run_id):
        raise HTTPException(404, "任务不存在或已经结束")
    return {"ok": True, "run_id": run_id, "status": "cancelling"}


@app.get("/api/registered/{email}")
def api_registered_one(email: str):
    state = db.get_registered_operation_state(email)
    authorized_pending_done = bool(
        state.get("authorized_pending")
        and state.get("latest_registration_status") == "done"
    )
    _require_registered_operation_allowed(
        email,
        allow_failed_recovery=authorized_pending_done,
    )
    row = db.get_registered(email)
    if not row:
        raise HTTPException(404, "not found")
    return {"ok": True, "data": row}


@app.delete("/api/registered/{email}")
def api_delete_registered(email: str):
    _require_registered_operation_allowed(email, reject_active=True)
    try:
        ok = db.delete_registered(email)
    except db.ActiveIdentityDeleteError:
        raise HTTPException(409, "该身份刚刚启动了任务，暂不能删除")
    except db.ProtectedIdentityDeleteError:
        raise HTTPException(409, "该身份刚变为失败或待恢复状态，暂不能删除")
    if not ok:
        raise HTTPException(404, "not found")
    return {"ok": True}


class BulkDeleteRegisteredReq(BaseModel):
    emails: Optional[list[str]] = Field(None, description="按 email 列表删；留空 + all=true 则删全部")
    all: bool = False


@app.post("/api/registered/bulk_delete")
def api_bulk_delete_registered(req: BulkDeleteRegisteredReq):
    if req.all:
        if db.has_active_registered_run():
            raise HTTPException(409, "存在运行中的注册任务，暂不能全量删除")
        failed = db.list_registration_results(
            limit=1,
            offset=0,
            filter_rt="failed_attempt",
        )
        if failed:
            raise HTTPException(409, "存在未解决的注册失败；禁止全量删除")
        try:
            n = db.delete_all_registered()
        except db.ActiveIdentityDeleteError:
            raise HTTPException(409, "有身份刚刚启动了任务，暂不能全量删除")
        except db.ProtectedIdentityDeleteError:
            raise HTTPException(409, "存在刚变为失败或待恢复状态的身份，暂不能全量删除")
        return {"ok": True, "deleted": n, "by": "all"}
    if req.emails:
        emails = list(dict.fromkeys(
            email.strip().lower()
            for email in req.emails
            if email and email.strip()
        ))
        if not emails:
            raise HTTPException(400, "至少选择一个账号")
        if len(emails) > 100:
            raise HTTPException(400, "单次最多删除 100 个账号")
        _require_registered_batch_allowed(emails, reject_active=True)
        try:
            n = db.delete_registered_by_emails(emails)
        except db.ActiveIdentityDeleteError:
            raise HTTPException(409, "有选中身份刚刚启动了任务，暂不能删除")
        except db.ProtectedIdentityDeleteError:
            raise HTTPException(409, "有选中身份刚变为失败或待恢复状态，暂不能删除")
        return {"ok": True, "deleted": n, "by": "emails"}
    raise HTTPException(400, "需要 emails 或 all=true")


class ForceDeleteRegisteredReq(BaseModel):
    emails: list[str] = Field(default_factory=list, description="仅待确认/失败凭证身份")
    confirm: bool = Field(False, description="前端不可逆确认")


@app.post("/api/registered/force_delete")
def api_force_delete_registered(req: ForceDeleteRegisteredReq):
    if not req.confirm:
        raise HTTPException(400, "请先在强制删除确认弹窗中确认")
    emails = list(dict.fromkeys(
        email.strip().lower()
        for email in req.emails
        if email and email.strip()
    ))
    if not emails:
        raise HTTPException(400, "至少选择一个待确认/失败账号")
    if len(emails) > 100:
        raise HTTPException(400, "单次最多删除 100 个账号")
    try:
        deleted = db.force_delete_registered_by_emails(emails)
    except db.ActiveIdentityDeleteError:
        raise HTTPException(409, "有选中身份正在运行，未执行删除")
    except db.ForceDeleteNotEligibleError:
        raise HTTPException(
            409,
            "选中项包含不存在、已完成或状态已变化的身份；未执行删除",
        )
    return {"ok": True, "deleted": deleted, "by": "force"}


# ──────────────────────── 批量导出（文本） ────────────────────────
# ⚠️ 路由顺序：
#   - formats 是 4 段路径，不会被 3 段的 GET /api/registered/{email} 吃掉；
#   - export 是 POST，而 {email} 那两条是 GET / DELETE，也不冲突。
# 要加新格式只改 webui/export_formats.py，这里和前端都不用动。


@app.get("/api/registered/export/formats")
def api_export_formats():
    """导出格式清单，前端下拉菜单据此渲染。"""
    return {"ok": True, "formats": export_formats.list_formats()}


class ExportRegisteredReq(BaseModel):
    format: str = Field(..., description="格式 id，见 GET /api/registered/export/formats")
    emails: Optional[list[str]] = Field(None, description="要导出的 email 列表")
    all: bool = Field(False, description="true = 导出全部（跨页），忽略 emails")


@app.post("/api/registered/export")
def api_export_registered(req: ExportRegisteredReq):
    fmt = export_formats.get_format(req.format)
    if fmt is None:
        raise HTTPException(400, f"未知导出格式: {req.format}")

    if req.all:
        if db.has_active_registered_run():
            raise HTTPException(409, "存在运行中的注册任务；暂不能导出")
        # ``registered`` is the authoritative export source.  Unresolved
        # failed-attempt rows without a credential row are not exported, while
        # saved pending/incomplete rows remain exportable with empty fields.
        rows = db.list_registered_full(limit=100000)
    elif req.emails:
        _require_registered_export_batch_allowed(req.emails)
        rows = db.list_registered_by_emails(req.emails)
    else:
        raise HTTPException(400, "需要 emails 或 all=true")

    # 不跳行：勾了几个号就几行 / 几个文件，字段为空也照样出。
    # 手动导出**不做 refresh_token 刷新、不因为缺 rt 拦截**，这是和自动推送的区别。
    base = {
        "ok": True,
        "count": len(rows),
        "filename": fmt.filename,
        "label": fmt.label,
        "mode": fmt.mode,
        "mime": fmt.mime,
    }

    if fmt.mode == "download":
        # 二进制（zip / json 文件）走 base64，前端解出来直接存盘，不弹预览
        blob = export_formats.render_bytes(rows, fmt)
        return {**base, "b64": base64.b64encode(blob).decode("ascii"), "size": len(blob)}

    return {**base, "text": export_formats.render_text(rows, fmt)}


# ──────────────────────── 邮箱来源配置 ────────────────────────


@app.get("/api/mail/providers")
def api_mail_providers(pooled_only: bool = False):
    """列出所有已注册的邮箱 provider 及其能力 / 配置项声明。

    前端据此渲染「邮箱来源」单选和对应的动态表单 ——
    以后加邮箱，前端一行都不用改。

        pooled_only=true  只返回能导入号池的（导入页用）
    """
    return {
        "ok": True,
        "providers": list_pooled_providers() if pooled_only else list_providers(),
        "current": db.get_setting("mail_source", "outlook"),
    }


@app.get("/api/settings/mail")
def api_get_mail_config():
    return {"ok": True, "config": db.get_mail_config()}


class SaveMailConfigReq(BaseModel):
    """字段不再写死。

    mail_source 之外的配置项由各 provider 的 config_fields 声明，
    前端原样回传，db.save_mail_config 按声明逐项存 ——
    加 provider 时这个模型不用动。
    """

    model_config = {"extra": "allow"}

    mail_source: Optional[str] = None


@app.post("/api/settings/mail")
def api_save_mail_config(req: SaveMailConfigReq):
    try:
        db.save_mail_config(req.model_dump(exclude_none=True))
    except MailProviderError as e:
        raise HTTPException(400, str(e))
    return {"ok": True, "config": db.get_mail_config()}


@app.post("/api/settings/mail/test")
def api_test_mail():
    """测试当前邮箱来源的连通性，具体怎么测由 provider 的 self_test() 决定。

    原来这里写死了 CF 的 api_url/domain/token 三个字段，
    换成让 provider 自检 —— 加邮箱不用回来改这个路由。
    """
    mail_source = db.get_setting("mail_source", "outlook")
    try:
        provider_cls = get_provider_class(mail_source)
    except MailProviderError as e:
        raise HTTPException(400, str(e))

    # 池化 provider 的连通性绑定在具体某个号上，没号可测 ——
    # 它的"测试"就是导入时的格式校验 + 跑一次注册。
    if provider_cls.pooled:
        raise HTTPException(
            400,
            f"{provider_cls.display_name} 是号池类型，不需要单独测试；"
            f"导入时会校验格式",
        )

    try:
        provider = create_mail_provider(mail_source, db.get_mail_settings())
    except MailProviderError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        raise HTTPException(400, f"构造 {provider_cls.display_name} 失败: {e}")

    try:
        result = provider.self_test()
    except Exception as e:
        raise HTTPException(500, f"连接失败: {e}")
    if not result.get("ok"):
        raise HTTPException(500, result.get("message") or "连接失败")
    return {"ok": True, "message": result.get("message", "连接成功")}


# ──────────────────────── SMS 接码配置 ────────────────────────


@app.get("/api/settings/sms")
def api_get_sms_config():
    return {"ok": True, "config": db.get_sms_config()}


class SaveSmsConfigReq(BaseModel):
    sms_enabled: Optional[str] = None              # "0" / "1"
    sms_provider: Optional[str] = None             # smsbower / herosms
    sms_api_key: Optional[str] = None              # 传 '***' 表示不修改
    sms_country: Optional[str] = None              # ID 或国家代码（'52' / 'th'）
    sms_service: Optional[str] = None              # OpenAI = 'dr'
    sms_max_price: Optional[str] = None
    sms_reuse_phone: Optional[str] = None
    sms_phone_success_max: Optional[str] = None
    sms_auto_country: Optional[str] = None
    sms_strict_whitelist: Optional[str] = None
    sms_allowed_countries: Optional[str] = None    # 逗号分隔的 ID 列表，自动选号时只从这里挑
    sms_auto_min_stock: Optional[str] = None
    sms_auto_max_price: Optional[str] = None
    sms_max_phone_attempts: Optional[str] = None   # 空 = 用 provider 默认；>0 = 自定义
    sms_per_phone_timeout: Optional[str] = None    # 单号等待秒数（默认 80）


@app.post("/api/settings/sms")
def api_save_sms_config(req: SaveSmsConfigReq):
    db.save_sms_config(req.model_dump(exclude_none=True))
    return {"ok": True, "config": db.get_sms_config()}


@app.post("/api/settings/sms/test")
def api_test_sms():
    """测试 SMS provider 连通性：查询余额。"""
    cfg = db.get_sms_internal_config()
    if not cfg.get("sms_api_key"):
        raise HTTPException(400, "未配置 sms_api_key")

    import sys as _sys
    ROOT_DIR = Path(__file__).resolve().parents[1]
    if str(ROOT_DIR) not in _sys.path:
        _sys.path.insert(0, str(ROOT_DIR))
    from sms_provider import create_sms_provider
    try:
        provider = create_sms_provider(cfg["sms_provider"], cfg)
        balance = provider.get_balance()
        return {
            "ok": True,
            "provider": cfg["sms_provider"],
            "balance": balance,
            "message": f"连接成功，余额: {balance}",
        }
    except Exception as e:
        raise HTTPException(500, f"连接失败: {e}")


@app.get("/api/settings/sms/countries")
def api_sms_top_countries():
    """查询当前接码平台的国家排名（价格 + 库存）。"""
    cfg = db.get_sms_internal_config()
    if not cfg.get("sms_api_key"):
        raise HTTPException(400, "未配置 sms_api_key")

    import sys as _sys
    ROOT_DIR = Path(__file__).resolve().parents[1]
    if str(ROOT_DIR) not in _sys.path:
        _sys.path.insert(0, str(ROOT_DIR))
    from sms_provider import create_sms_provider, OPENAI_SMS_COUNTRIES, SMS_COUNTRY_NAMES_CN
    try:
        provider = create_sms_provider(cfg["sms_provider"], cfg)
        rows = provider.get_top_countries(service=cfg.get("sms_service") or "dr")
        for r in rows:
            cid = str(r.get("country"))
            r["openai_sms_safe"] = cid in OPENAI_SMS_COUNTRIES
            r["name_cn"] = SMS_COUNTRY_NAMES_CN.get(cid, "未知")
        return {"ok": True, "countries": rows[:30], "openai_sms_safe": list(OPENAI_SMS_COUNTRIES)}
    except Exception as e:
        raise HTTPException(500, f"查询失败: {e}")


@app.get("/api/settings/sms/all_countries")
def api_sms_all_countries(provider: str = ""):
    """返回当前平台实际有库存的国家（动态查询）；查询失败则 fallback 到静态字典。"""
    import sys as _sys
    ROOT_DIR = Path(__file__).resolve().parents[1]
    if str(ROOT_DIR) not in _sys.path:
        _sys.path.insert(0, str(ROOT_DIR))
    from sms_provider import SMS_COUNTRY_NAMES_CN, OPENAI_SMS_COUNTRIES, create_sms_provider

    cfg = db.get_sms_internal_config()
    if provider:
        cfg["sms_provider"] = provider

    # 尝试从平台 API 动态获取有库存的国家
    if cfg.get("sms_api_key"):
        try:
            p = create_sms_provider(cfg["sms_provider"], cfg)
            rows = p.get_top_countries(service=cfg.get("sms_service") or "dr")
            countries = []
            for r in rows:
                cid = str(r.get("country") or "")
                countries.append({
                    "id": cid,
                    "name_cn": SMS_COUNTRY_NAMES_CN.get(cid, f"国家{cid}"),
                    "openai_sms_safe": cid in OPENAI_SMS_COUNTRIES,
                    "price": r.get("price"),
                    "count": r.get("count"),
                })
            if countries:
                return {"ok": True, "countries": countries,
                        "openai_sms_safe": list(OPENAI_SMS_COUNTRIES), "source": "live"}
        except Exception:
            pass

    # fallback: 静态字典
    items = sorted(SMS_COUNTRY_NAMES_CN.items(), key=lambda kv: int(kv[0]) if kv[0].isdigit() else 9999)
    countries = [
        {"id": cid, "name_cn": name, "openai_sms_safe": cid in OPENAI_SMS_COUNTRIES}
        for cid, name in items
    ]
    return {"ok": True, "countries": countries,
            "openai_sms_safe": list(OPENAI_SMS_COUNTRIES), "source": "static"}


# ──────────────────────── 自动导出 (CPA / SUB2API) ────────────────────────


class SaveExportConfigReq(BaseModel):
    # CPA
    cpa_enabled: Optional[str] = None       # "0" / "1"
    cpa_url: Optional[str] = None
    cpa_mgmt_key: Optional[str] = None      # 传 '***' 表示不修改
    cpa_timeout: Optional[str] = None
    # SUB2API
    sub2api_enabled: Optional[str] = None
    sub2api_url: Optional[str] = None
    sub2api_api_key: Optional[str] = None   # '***' 不修改
    sub2api_group_ids: Optional[str] = None  # 逗号分隔，例 "2" 或 "1,2,3"
    sub2api_timeout: Optional[str] = None


@app.get("/api/settings/export")
def api_get_export_config():
    return {"ok": True, "config": db.get_export_config()}


@app.post("/api/settings/export")
def api_save_export_config(req: SaveExportConfigReq):
    db.save_export_config(req.model_dump(exclude_none=True))
    return {"ok": True, "config": db.get_export_config()}


class TestExportReq(BaseModel):
    target: str = Field(..., description="cpa 或 sub2api")


@app.post("/api/settings/export/test")
def api_test_export(req: TestExportReq):
    """测试 CPA / SUB2API 连通性。"""
    from . import exporter
    cfg = db.get_export_internal_config()
    target = (req.target or "").strip().lower()
    try:
        if target == "cpa":
            return exporter.test_cpa(cfg["cpa"])
        if target == "sub2api":
            return exporter.test_sub2api(cfg["sub2api"])
        raise HTTPException(400, f"未知 target: {target}")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"测试失败: {e}")


class ManualExportReq(BaseModel):
    email: str = Field(..., description="要导出的已注册账号邮箱")
    targets: list[str] = Field(default_factory=lambda: ["cpa", "sub2api"],
                                description="选择导出目标：cpa / sub2api")


@app.post("/api/registered/export_to_panel")
def api_manual_export_to_panel(req: ManualExportReq):
    """对一个已注册账号手动触发到面板的导出。

    targets 里选 cpa / sub2api 之一或全部。即使总开关未启用，本接口也会执行
    （只要 URL/密钥 等基础配置已填）。
    """
    from . import exporter
    _require_registered_operation_allowed(req.email)
    cred = db.get_registered(req.email)
    if not cred:
        raise HTTPException(404, f"未找到已注册账号: {req.email}")

    cfg = db.get_export_internal_config()
    out = {"email": req.email, "cpa": None, "sub2api": None}
    targets = {t.strip().lower() for t in (req.targets or []) if t}

    if "cpa" in targets:
        cpa_cfg = dict(cfg["cpa"])
        cpa_cfg["enabled"] = True  # 手动触发：强制启用
        try:
            out["cpa"] = exporter.export_to_cpa(cred, cpa_cfg)
        except Exception as e:
            out["cpa"] = {"ok": False, "error": safe_public_error(e, "CPA export")}
    if "sub2api" in targets:
        sub2api_cfg = dict(cfg["sub2api"])
        sub2api_cfg["enabled"] = True
        try:
            out["sub2api"] = exporter.export_to_sub2api(cred, sub2api_cfg)
        except Exception as e:
            out["sub2api"] = {
                "ok": False,
                "error": safe_public_error(e, "SUB2API export"),
            }

    return {"ok": True, **out}


class UpdateCredReq(BaseModel):
    email: str = Field(..., description="要修改的已注册账号邮箱")
    # None = 该字段不动；空串 = 主动清空。前端不填的字段就别传。
    password: Optional[str] = Field(None, description="新密码，None=不修改")
    totp_secret: Optional[str] = Field(None, description="新 TOTP secret，None=不修改")


class ConfirmResetPasswordReq(BaseModel):
    email: str = Field(..., description="已完成外部密码重置的账号邮箱")
    password: str = Field(..., description="待服务端验证的新密码")
    proxy: str = ""


class FreezeRegisteredReq(BaseModel):
    email: str = Field(..., description="要冻结或解冻的账号邮箱")
    frozen: bool = True


@app.post("/api/registered/freeze")
def api_freeze_registered(req: FreezeRegisteredReq):
    email = (req.email or "").strip().lower()
    if not email:
        raise HTTPException(400, "email 不能为空")
    if not db.set_registered_frozen(email, bool(req.frozen)):
        raise HTTPException(404, f"未找到已注册账号: {email}")
    return {"ok": True, "email": email, "frozen": bool(req.frozen)}


@app.post("/api/registered/confirm_reset_password")
def api_confirm_reset_password(req: ConfirmResetPasswordReq):
    """Verify an externally reset password before persisting it locally."""
    from password_verification import PasswordVerificationError, record_verification_failure

    email = (req.email or "").strip().lower()
    password = req.password if isinstance(req.password, str) else ""
    if not email:
        raise HTTPException(400, "email 不能为空")
    if not password or not password.strip():
        raise HTTPException(400, "密码不能为空")

    _require_registered_operation_allowed(
        email, allow_failed_recovery=True, reject_active=True
    )
    registered = db.get_registered(email, include_pending_password=True)
    if not registered:
        raise HTTPException(404, f"未找到已注册账号: {email}")
    extra = registered.get("extra") or {}
    if str(extra.get("pending_reason") or "") != db.PASSWORD_RECOVERY_REQUIRED:
        raise HTTPException(409, "该账号当前不处于密码需重置状态")

    try:
        verified = registrar.verify_registered_password(
            email, password, {"proxy": (req.proxy or "").strip()}
        )
        if not isinstance(verified, dict) or verified.get('ok') is not True:
            raise PasswordVerificationError('password_check', reason='unconfirmed')
    except Exception as exc:
        failure = exc if isinstance(exc, PasswordVerificationError) else PasswordVerificationError('verification_setup', exc)
        try:
            diagnostic_id = record_verification_failure(failure, registrar.LOG_DIR)
        except OSError:
            diagnostic_id = 'unavailable'
        logger.warning(
            '[password-verification] diagnostic_id=%s phase=%s cause=%s type=%s http_status=%s',
            diagnostic_id, failure.failure_phase, failure.failure_cause,
            failure.exception_type, failure.http_status,
        )
        detail = failure.public_message
        if diagnostic_id != 'unavailable':
            detail += f'（诊断号：{diagnostic_id}）'
        raise HTTPException(failure.api_status, detail) from exc

    if not db.mark_password_verified(
        email, password, allow_recovery_replace=True
    ):
        raise HTTPException(409, "账号状态已变化，密码未写入本地")

    logger.info("[registered] 重置密码已通过服务端验证 email=%s", email)
    return {"ok": True, "email": email}


@app.post("/api/registered/update_credentials")
def api_update_credentials(req: UpdateCredReq):
    """手动修正已注册账号的密码 / TOTP secret。

    ⚠️ 只改本地库，不会同步到 OpenAI。用途是把外部已知凭证补进来或修正记录。

    改完的值会被登录流程直接用上（registrar 的 account_callback 走
    db.get_registered，不区分数据来源），所以 totp_secret 必须过 base32
    校验 —— 脏值存进去要等真登录时才炸，那时根本看不出是手填填错的。
    """
    email = (req.email or "").strip().lower()
    if not email:
        raise HTTPException(400, "email 不能为空")
    if req.password is None and req.totp_secret is None:
        raise HTTPException(400, "没有要修改的字段")
    _require_registered_operation_allowed(email)
    try:
        ok = db.update_registered_manual(
            email, password=req.password, totp_secret=req.totp_secret
        )
    except ValueError as e:
        # 校验失败：把具体原因带给前端，别让用户猜哪里填错了
        raise HTTPException(400, str(e))
    if not ok:
        raise HTTPException(404, f"未找到已注册账号: {email}")

    changed = [n for n, v in (("密码", req.password), ("TOTP secret", req.totp_secret))
               if v is not None]
    logger.info(f"[registered] 手动修改凭证 email={email} 字段={'+'.join(changed)}")
    return {"ok": True, "email": email, "changed": changed}


# ──────────────────────── Plus 试用检查 ────────────────────────


class CheckPlusReq(BaseModel):
    emails: list[str] = Field(..., description="要检查的邮箱列表")
    proxy: str = Field("", description="查询代理，留空直连")


# 封号在 401/403 响应体里的措辞。OpenAI 不止一种写法，全部小写后子串匹配。
# 新措辞加在这里即可；日志会打出未匹配的 401/403 原文方便补充。
_DEACTIVATED_MARKERS = (
    "account_deactivated",
    "accountdeactivated",
    "deactivated",
    "has been deactivated",
    "disabled",
    "suspended",
    "banned",
    "violat",          # violating / violation of our policies
    "potential abuse",
    "terminated",
)


def _body_text(resp) -> str:
    """安全取响应体文本，任何异常都不许打断检测循环。"""
    try:
        return (resp.text or "").strip()
    except Exception:  # noqa: BLE001
        return ""


def _looks_deactivated(body: str) -> bool:
    return any(m in body.lower() for m in _DEACTIVATED_MARKERS)


@app.post("/api/registered/check_plus")
def api_check_plus(req: CheckPlusReq):
    """用 access_token 查询账号的 Plus 试用状态。"""
    _require_plus_check_allowed(req.emails)
    from http_client import create_http_session

    log = logging.getLogger("webui")
    url = "https://chatgpt.com/backend-api/accounts/check/v4-2023-04-27"
    ua = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/145.0.0.0 Safari/537.36"
    )

    # 走和注册流程同一个代理解析 + create_http_session，不再自己拼 proxies dict。
    # 它负责两件这里以前漏掉的事：
    #   1) socks5:// -> socks5h://，DNS 交给代理端解析。用本地 DNS 打
    #      chatgpt.com 经常握手失败，这是「填了 SOCKS5 就检测不出来」的真正原因。
    #   2) HTTP 客户端禁用了隐式 trust_env，所以这里必须像注册流程一样先显式
    #      解析标准代理环境变量。页面留空时自动使用 HTTPS_PROXY/HTTP_PROXY/
    #      ALL_PROXY；手动填写的代理仍然优先。
    from config import resolve_proxy

    proxy = resolve_proxy(req.proxy) or ""
    try:
        sess = create_http_session(proxy=proxy or None, impersonate="chrome110")
    except Exception as e:  # noqa: BLE001
        raise HTTPException(500, f"创建 HTTP 会话失败: {e}")

    note = ""

    def _check(access_token: str, account_id: str = "", device_id: str = ""):
        """打一次检测请求。

        ⚠️ 这里**不再自动降级直连**。原来的行为是：代理第一次报错就永久切直连，
        后面所有号都用主人的真实 IP 去打 chatgpt.com 的账号接口，而提示只是
        结果末尾一句小字。2026-08-10 实测踩到：主人改了代理池密码，这页却还在
        用 localStorage 里的旧代理 → curl:(97) 鉴权被拒 → 静默直连。
        检测失败重试一次就好，不值得拿真实 IP 换。

        请求头按 chatgpt.com 前端真实发的补齐（Origin/Referer/ChatGPT-Account-ID/
        OAI-Device-Id）。以前只发 Authorization，缺 Origin/Referer 属于典型的
        非浏览器特征，容易被风控挑出来；account_id 从 access_token 的 JWT 里解，
        不额外请求。
        """
        nonlocal note
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
            "User-Agent": ua,
            "Origin": "https://chatgpt.com",
            "Referer": "https://chatgpt.com/",
        }
        if account_id:
            headers["ChatGPT-Account-ID"] = account_id
        if device_id:
            headers["OAI-Device-Id"] = device_id
        try:
            return sess.get(url, headers=headers, timeout=15)
        except Exception as e:  # noqa: BLE001
            if proxy and not note:
                # 把 curl 的错误码带出来：(97)=SOCKS5 鉴权被拒，(7)=连不上，
                # 笼统一句「代理连不通」会让人以为是网络抖动，其实是密码/配额问题。
                msg = str(e)
                if "(97)" in msg or "rejected by the SOCKS5" in msg:
                    note = "代理认证被拒（SOCKS5 (97)）—— 检查代理账号密码/配额是否已变更"
                elif "(7)" in msg:
                    note = "代理连不上（curl (7)）—— 检查代理地址端口是否可达"
                else:
                    note = f"代理请求失败（{type(e).__name__}）—— 已保持代理，未改直连"
                log.warning(f"[check_plus] {note}: {msg[:140]}")
            raise

    results = {}
    for email in req.emails:
        cred = db.get_registered(email)
        if not cred:
            results[email] = {"status": "not_found", "label": "未找到"}
            continue
        at = (cred.get("access_token") or "").strip()
        if not at:
            results[email] = {"status": "no_at", "label": "无AT"}
            continue
        # account_id 直接从 AT 的 JWT payload 解（实测 12/12 都带），不发额外请求。
        auth_claims = _get_auth(_decode_jwt_payload(at))
        account_id = str(
            auth_claims.get("chatgpt_account_id") or auth_claims.get("account_id") or ""
        ).strip()
        # device_id 库里普遍是空的（注册时没落盘），按邮箱派生一个稳定 UUID：
        # 同一个号每次检测都是同一个 device，比每次随机更像正常客户端。
        device_id = (cred.get("device_id") or "").strip() or str(
            uuid.uuid5(uuid.NAMESPACE_DNS, f"dango-check-plus:{email}")
        )
        try:
            resp = _check(at, account_id, device_id)
        except Exception as e:  # noqa: BLE001
            results[email] = {"status": "error", "label": "网络失败"}
            log.warning("[check_plus] %s 请求失败: %s", email, safe_public_error(e, "plan check"))
            continue
        if resp.status_code in (401, 403):
            # 401/403 的**响应体必须看**。以前这里只看状态码就贴「凭证失效」，
            # 结果是封号号 100% 显示成凭证失效：账号被封时 access_token 会被一起
            # 吊销 → 请求在这里就 401 了 → 永远走不到下面 200 分支的 is_deactivated
            # 判据。2026-08-10 实测某个被封号：JWT exp 还有 239 小时、
            # 13:53 检测还是 plus_eligible，之后被封 → 同一个 token 直接 401。
            #
            # 未过期却失效 = 被吊销，而 OpenAI 会在响应体里写明原因，
            # 所以按响应体内容区分「封号」和「单纯的凭证过期/轮换」。
            body = _body_text(resp)
            if _looks_deactivated(body):
                results[email] = {"status": "banned", "label": "封号"}
                log.info(f"[check_plus] {email} 判定封号 (HTTP {resp.status_code})")
                continue
            if resp.status_code == 401:
                results[email] = {"status": "token_invalid", "label": "凭证失效"}
                log.info("[check_plus] %s 凭证失效: %s", email, safe_response_summary(resp, "plan check"))
                continue
            results[email] = {"status": "error", "label": f"HTTP {resp.status_code}"}
            log.info("[check_plus] %s 请求拒绝: %s", email, safe_response_summary(resp, "plan check"))
            continue
        if resp.status_code != 200:
            results[email] = {"status": "error", "label": f"HTTP {resp.status_code}"}
            continue
        try:
            data = resp.json()
        except Exception:  # noqa: BLE001
            results[email] = {"status": "error", "label": "响应非 JSON"}
            continue
        accts = data.get("accounts", {})
        if not accts:
            results[email] = {"status": "error", "label": "无账户数据"}
            continue
        info = next(iter(accts.values()))
        acct = info.get("account", {})
        ent = info.get("entitlement", {})
        promo = info.get("eligible_promo_campaigns", {})
        if acct.get("is_deactivated", False):
            results[email] = {"status": "banned", "label": "封号"}
            continue
        plan = acct.get("plan_type", "free")
        has_sub = ent.get("has_active_subscription", False)
        has_plus_promo = "plus" in promo and promo["plus"].get("id") == "plus-1-month-free"
        if plan == "plus" or has_sub:
            results[email] = {"status": "plus_active", "label": "Plus生效中"}
        elif has_plus_promo:
            results[email] = {"status": "plus_eligible", "label": "可领Plus试用"}
        else:
            results[email] = {"status": "free", "label": "Free"}

    try:
        sess.close()
    except Exception:  # noqa: BLE001
        pass

    checked_at = time.time()
    for email, info in results.items():
        # not_found / no_at / error 不写库：它们不是「检测结论」而是**没检测成**
        # （号不在库里、没凭证、代理挂了），写进去号就从 unchecked 过滤器里消失，
        # 看着像已经检测过。修好后重点一次即可。
        #
        # token_invalid **要写**（2026-08-10 改）。原先不写的理由是「凭证问题不是
        # 账号问题，换新凭证后该重查」，但实测下来：AT 没过期却 401 = 被吊销，
        # 大概率就是封号（2026-08-10 实测那个号即是）。不写库的实际后果是这号
        # 一直挂着上次的 plus_eligible，列表上显示「可领Plus试用」——比标成凭证
        # 失效误导得多。写库后 unchecked 过滤器会跳过它，正是想要的：它已经有结论了。
        if info["status"] not in ("not_found", "no_at", "error"):
            db.update_plus_check(email, {**info, "checked_at": checked_at})

    return {"ok": True, "results": results, "note": note}


# ──────────────────────── auto-loop ────────────────────────


class AutoLoopStartReq(BaseModel):
    """跟 RegisterReq 复用同样的字段，auto-loop 内部传给每个 run。"""
    driver: str = Field("protocol", pattern="^(protocol|roxy)$")
    want_access_token: bool = True
    want_session_token: bool = True
    want_refresh_token: bool = False
    proxy: str = ""              # 单代理（concurrency=1 + 无代理池时用）
    proxy_pool: str = ""         # 多代理池（每行一个）；优先于 proxy
    roxy_proxy_pool: str = ""
    fixed_asn_config: Optional[dict] = None
    concurrency: int = Field(4, ge=1, le=20)
    otp_timeout: int = registrar.REGISTRATION_OTP_TIMEOUT_SECONDS
    otp_timeout_default_version: int = 0
    allow_existing_login: bool = True
    cool_down_seconds: float = Field(0.5, ge=0, le=120)
    target_count: int = 0        # 目标成功数（0=不限量，达标自动停止）
    # 生产契约：2FA 必须，Codex refresh token 可选。
    want_2fa: bool = True
    native_pointer_submit: bool = True


@app.post("/api/auto/start")
@runtime_config_admission
def api_auto_start(req: AutoLoopStartReq):
    driver = (req.driver or "protocol").strip().lower()
    options = req.model_dump()
    options["roxy_use_proxy_pool"] = False
    if driver == "roxy":
        if read_roxy_settings().keep_browser_open:
            raise HTTPException(409, "保留浏览器模式仅支持单次注册；请关闭该设置后启动自动循环")
        use_proxy_pool, proxy_pool_text = _roxy_registration_proxy_source(req)
        options["roxy_use_proxy_pool"] = use_proxy_pool
        options["proxy_pool"] = proxy_pool_text
    if driver == "protocol" and not (req.proxy_pool or "").strip() and not req.fixed_asn_config:
        # Keep old single-proxy clients working as a one-item pool while
        # failing closed when neither form supplies an egress.
        options["proxy_pool"] = (req.proxy or "").strip()
    if driver == "protocol" and not options["proxy_pool"] and not req.fixed_asn_config:
        raise HTTPException(400, "协议自动循环必须走代理池，请先配置可用代理")
    options["native_pointer_submit"] = bool(req.native_pointer_submit) and driver == "roxy"
    if driver == "roxy":
        try:
            require_roxy_configuration()
        except RoxyConfigurationError as exc:
            raise HTTPException(400, str(exc)) from exc
        if not options["roxy_use_proxy_pool"]:
            options["_roxy_egress_capacity"] = _require_healthy_roxy_egress()
    options["mail_settings_snapshot"] = db.get_mail_settings()
    options["otp_timeout"] = _normalize_registration_request_otp_timeout(
        req.otp_timeout,
        req.otp_timeout_default_version,
    )
    res = AUTO_LOOP.start(options)
    if not res.get("ok"):
        raise HTTPException(400, res.get("error", "启动失败"))
    return res


@app.post("/api/auto/pause")
def api_auto_pause():
    res = AUTO_LOOP.pause()
    if not res.get("ok"):
        raise HTTPException(400, res.get("error", "暂停失败"))
    return res


@app.post("/api/auto/resume")
def api_auto_resume():
    res = AUTO_LOOP.resume()
    if not res.get("ok"):
        raise HTTPException(400, res.get("error", "恢复失败"))
    return res


@app.post("/api/auto/stop")
def api_auto_stop():
    res = AUTO_LOOP.stop()
    if not res.get("ok"):
        raise HTTPException(400, res.get("error", "停止失败"))
    return res


@app.get("/api/auto/status")
def api_auto_status():
    return {"ok": True, **AUTO_LOOP.status()}


@app.get("/api/auto/stream")
async def api_auto_stream(request: Request):
    """SSE 推送 auto-loop 状态变化 + run_started / run_finished 事件。"""
    q = AUTO_LOOP.subscribe()

    async def gen():
        loop = asyncio.get_event_loop()
        try:
            while True:
                if await request.is_disconnected():
                    break
                # 阻塞拿消息，但每 30s 心跳
                try:
                    msg = await loop.run_in_executor(None, lambda: q.get(timeout=30))
                except Exception:
                    yield ": heartbeat\n\n"
                    continue
                if msg is None:
                    break
                kind = msg.get("kind", "state")
                data = msg.get("data", {})
                yield f"event: {kind}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"
        finally:
            AUTO_LOOP.unsubscribe(q)

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


# ──────────────────────── 静态资源 ────────────────────────


@app.get("/")
def root():
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("webui.app:app", host="127.0.0.1", port=8765, reload=False)
