"""FastAPI endpoints for the isolated 711Proxy screening worker."""
from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from .proxy_screening import MANAGER

router = APIRouter(prefix="/api/proxy-screening", tags=["proxy-screening"])

class ScreeningCreate(BaseModel):
    country_code: str = Field(..., min_length=2, max_length=2)
    sample_count: int = Field(30, ge=1, le=100)
    session_minutes: Literal[10, 30, 60, 120, 180] = 60
    concurrency: int = Field(5, ge=1, le=10)
    proxy_template: str = Field(..., min_length=1)

class ExistingProxies(BaseModel):
    proxies: list[str] = Field(default_factory=list)

@router.post("/jobs")
def create_screening_job(req: ScreeningCreate):
    try:
        job = MANAGER.create_job(req.country_code, req.sample_count, req.session_minutes, req.concurrency, req.proxy_template)
    except RuntimeError as exc:
        raise HTTPException(409, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"ok": True, "job_id": job.job_id, "status": job.status, "created_at": job.created_at}

@router.get("/jobs/{job_id}")
def get_screening_job(job_id: str):
    job = MANAGER.get_job(job_id)
    if not job:
        raise HTTPException(404, "筛选任务不存在或服务已重启")
    return {"ok": True, **MANAGER.public_job(job)}

@router.post("/jobs/{job_id}/cancel")
def cancel_screening_job(job_id: str):
    if not MANAGER.cancel_job(job_id):
        raise HTTPException(404, "任务不存在或已经结束")
    return {"ok": True, "job_id": job_id, "status": "cancelling"}

@router.post("/jobs/{job_id}/import-preview")
def screening_import_preview(
    job_id: str,
    req: ExistingProxies,
    asn: str = Query(..., min_length=1),
):
    job = MANAGER.get_job(job_id)
    if not job:
        raise HTTPException(404, "筛选任务不存在或服务已重启")
    if job.status not in ("completed", "cancelled"):
        raise HTTPException(409, "筛选尚未完成")
    try:
        result = MANAGER.import_preview(job_id, asn, req.proxies)
    except KeyError as exc:
        raise HTTPException(404, str(exc)) from exc
    return {"ok": True, **result}
