"""Local-only preference editing; reading teams never creates a profile."""
import sqlite3
from contextlib import closing

from fastapi import APIRouter, HTTPException, Request, Response
from starlette.concurrency import run_in_threadpool
import requests

from .roxy_settings import RoxySettings, read_settings, save_settings, RUNTIME_CONFIG_LOCK

router = APIRouter()


def _local(request: Request, response: Response):
    if (request.client is None or request.client.host not in {"127.0.0.1", "::1"}
            or request.url.hostname not in {"127.0.0.1", "localhost", "::1"}):
        raise HTTPException(403, "仅允许本机管理 Roxy 设置")
    origin = request.headers.get("origin")
    if (request.headers.get("sec-fetch-site") == "cross-site"
            or (origin and origin.rstrip("/") != str(request.base_url).rstrip("/"))):
        raise HTTPException(403, "仅允许同源页面管理 Roxy 设置")
    response.headers["Cache-Control"] = "no-store"


def _result(settings):
    return {"ok": True, "settings": settings.model_dump(), "credential_mode": "existing",
            "capabilities": {"codex_browser_callback": False}}


def _has_active_runs(db):
    for account in ("1", "2"):
        path = db.database_path_for(account)
        if not path.is_file():
            continue
        with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as connection:
            connection.execute("PRAGMA query_only=ON")
            if connection.execute(
                "SELECT 1 FROM runs WHERE status IN "
                "('running','pending','in_progress','cancelling') LIMIT 1"
            ).fetchone():
                return True
    return False


@router.get("/api/roxy/settings")
def get_roxy_settings(request: Request, response: Response):
    _local(request, response)
    return _result(read_settings())


@router.put("/api/roxy/settings")
async def put_roxy_settings(request: Request, response: Response):
    _local(request, response)
    try:
        settings = RoxySettings.model_validate(await request.json())
    except (ValueError, TypeError):
        raise HTTPException(422, "Roxy 设置无效，请检查字段格式及配置冲突") from None
    return await run_in_threadpool(_save_when_idle, settings)


def _save_when_idle(settings):
    from . import db, roxy_bridge
    from .auto_loop import CONTROLLER
    with RUNTIME_CONFIG_LOCK:
        roxy_bridge.refresh_retained_profile_slots()
        return _apply_settings(settings, roxy_bridge, db, CONTROLLER)


def _apply_settings(settings, roxy_bridge, db, controller):
    with roxy_bridge.PROFILE_POOL._condition:
        if (controller.status().get("state") != "stopped"
                or roxy_bridge.PROFILE_POOL.status()["in_use"]
                or roxy_bridge.PROFILE_POOL.retained_profile_ids
                or _has_active_runs(db)):
            raise HTTPException(409, "任务运行期间不能修改 Roxy 设置，请等待任务结束")
        settings = save_settings(settings)
        roxy_bridge.ROXY_API_BASE = settings.api_base
        roxy_bridge.ROXY_WORKSPACE_ID = int(settings.workspace_id)
        roxy_bridge.ROXY_PROJECT_ID = int(settings.project_id)
        roxy_bridge.PROFILE_POOL.max_size = settings.max_windows
        roxy_bridge.PROFILE_POOL._slots.clear()
        roxy_bridge.PROFILE_POOL._seeded = False
        with roxy_bridge._ROXY_PROXY_DETECTION_CACHE_LOCK:
            roxy_bridge._ROXY_PROXY_DETECTION_CACHE.clear()
    return _result(settings)


@router.get("/api/roxy/workspaces")
def get_roxy_workspaces(request: Request, response: Response):
    _local(request, response)
    settings = read_settings()
    try:
        with requests.Session() as session:
            session.trust_env = False
            reply = session.get(settings.api_base + settings.workspace_path,
                                timeout=(2, 5), allow_redirects=False)
            if reply.status_code in (401, 403):
                raise HTTPException(502, "Roxy API 要求认证；请在本机配置现有 Roxy 凭据")
            reply.raise_for_status()
            data = reply.json()
        if not isinstance(data, dict) or data.get("code") not in (0, "0", 200, "200"):
            raise ValueError()
        rows = data.get("data", {}).get("rows")
        if not isinstance(rows, list):
            raise ValueError()
        teams = []
        for row in rows[:100]:
            if not isinstance(row, dict):
                continue
            identity = str(row.get("id") or row.get("workspaceId") or "")
            if not identity.isdigit():
                continue
            projects = []
            for project in (row.get("project_details") or row.get("projectDetails") or [])[:100]:
                if not isinstance(project, dict):
                    continue
                project_id = str(project.get("projectId") or project.get("id") or "")
                if project_id.isdigit():
                    projects.append({"id": project_id,
                                     "name": str(project.get("projectName") or project_id)[:80]})
            teams.append({"id": identity, "name": str(row.get("workspaceName") or identity)[:80],
                          "projects": projects})
        return {"ok": True, "teams": teams}
    except HTTPException:
        raise
    except (requests.RequestException, ValueError, TypeError, AttributeError):
        raise HTTPException(502, "Roxy 团队列表读取失败；请检查本机 API、认证和接口路径") from None
