"""Local UPI job endpoints; outbound work only begins at acknowledged POST."""
from __future__ import annotations

import json
from urllib.parse import urlsplit

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from .refine_service import RefineError, SERVICE
from .refine_input import MAX_BODY_BYTES, unique_object
from .refine_upstream import project_status


def create_refine_router(service=SERVICE):
    router = APIRouter(prefix='/api/refine', tags=['refine'])

    def workspace(request):
        value = request.headers.get('X-WebUI-Account', '1')
        if value not in {'1', '2'}:
            raise HTTPException(400, '工作区无效。')
        return value

    def respond(function, *args, **kwargs):
        try:
            return function(*args, **kwargs)
        except RefineError as error:
            return JSONResponse({'code': error.code, 'detail': error.message}, status_code=error.status)
        except Exception:
            return JSONResponse({'code': 'local_state_unavailable', 'detail': '无法读取本地提炼状态。'},
                                status_code=503)

    def json_response(value, status=200):
        if isinstance(value, JSONResponse):
            value.headers['Cache-Control'] = 'no-store'
            return value
        return JSONResponse(value, status_code=status, headers={'Cache-Control': 'no-store'})

    async def mutation_payload(request):
        origin = request.headers.get('Origin')
        if origin:
            try:
                parsed = urlsplit(origin)
                rejected = (parsed.scheme, parsed.netloc) != (request.url.scheme, request.url.netloc)
                rejected = rejected or bool(parsed.username is not None or parsed.password is not None
                                            or parsed.path not in {'', '/'} or parsed.query or parsed.fragment)
            except ValueError:
                rejected = True
            if rejected:
                return json_response({'code': 'origin_rejected', 'detail': '请求来源无效。'}, 403)
        if request.headers.get('Content-Type', '').split(';')[0].strip() != 'application/json':
            return json_response({'code': 'invalid_request', 'detail': '请求格式无效。'}, 400)
        body = bytearray()
        async for chunk in request.stream():
            if len(body) + len(chunk) > MAX_BODY_BYTES:
                return json_response({'code': 'request_too_large', 'detail': '请求内容过大。'}, 413)
            body.extend(chunk)
        try:
            return json.loads(body, object_pairs_hook=unique_object)
        except (ValueError, UnicodeError, RecursionError):
            return json_response({'code': 'invalid_request', 'detail': '请求格式无效。'}, 400)

    @router.get('/project')
    def project():
        return project_status()

    @router.get('/accounts')
    def accounts(request: Request, query: str = '', limit: int = 50, offset: int = 0):
        return respond(service.accounts, workspace(request), query=query, limit=limit, offset=offset)

    @router.get('/jobs')
    def jobs(request: Request):
        return json_response(respond(service.overview, workspace(request)))

    @router.get('/jobs/{job_id}')
    def job(job_id: str, request: Request):
        response = respond(service.get, workspace(request), job_id)
        return json_response(response)

    @router.get('/requests/{request_id}')
    def lookup_request(request_id: str, request: Request):
        return json_response(respond(service.get_request, workspace(request), request_id))

    @router.post('/jobs')
    async def start(request: Request):
        payload = await mutation_payload(request)
        if isinstance(payload, JSONResponse):
            return payload
        response = respond(service.start, workspace(request), payload)
        return json_response(response, 202)

    @router.post('/batches')
    async def start_batch(request: Request):
        payload = await mutation_payload(request)
        if isinstance(payload, JSONResponse):
            return payload
        return json_response(respond(service.start_batch, workspace(request), payload), 202)

    async def manage(request, job_id, operation):
        payload = await mutation_payload(request)
        if isinstance(payload, JSONResponse):
            return payload
        if (not isinstance(payload, dict) or payload.get('acknowledged') is not True
                or set(payload) != {'acknowledged'}):
            return json_response({'code': 'acknowledgement_required',
                                  'detail': '请确认任务操作。'}, 400)
        return json_response(respond(operation, workspace(request), job_id))

    @router.post('/jobs/{job_id}/cancel')
    async def cancel(job_id: str, request: Request):
        return await manage(request, job_id, service.cancel)

    @router.post('/jobs/{job_id}/clear')
    async def clear(job_id: str, request: Request):
        return await manage(request, job_id, service.clear)

    return router


router = create_refine_router()
