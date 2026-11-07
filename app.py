"""HTTP API for PolicyChecker."""

import logging
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

import config
from audit import audit_rejection
from classification_graph import ClassificationRejected, run_classification_graph
from models import ClassificationRequest, ClassificationResponse

logger = logging.getLogger("policychecker")

SECURITY_HEADERS = [
    (b"x-content-type-options", b"nosniff"),
    (b"cache-control", b"no-store"),
]


class GuardMiddleware:
    """Caps request body size (auditing oversized requests) and adds security headers.

    Written as plain ASGI middleware so the cap also applies to requests that
    don't declare a Content-Length.
    """

    def __init__(self, app, max_bytes: int):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                message.setdefault("headers", [])
                message["headers"] = list(message["headers"]) + SECURITY_HEADERS
            await send(message)

        if scope["method"] != "POST":
            await self.app(scope, receive, send_with_headers)
            return

        declared = dict(scope.get("headers", [])).get(b"content-length")
        if declared is not None and (not declared.isdigit() or int(declared) > self.max_bytes):
            await self._reject(scope, receive, send_with_headers, declared.decode(errors="replace"))
            return

        body = b""
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body += message.get("body", b"")
            if len(body) > self.max_bytes:
                await self._reject(scope, receive, send_with_headers, f">{self.max_bytes}")
                return
            if not message.get("more_body", False):
                break

        replayed = False

        async def replay():
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        await self.app(scope, replay, send_with_headers)

    async def _reject(self, scope, receive, send, size: str):
        audit_id = audit_rejection(
            "api", [f"Request body exceeds {self.max_bytes} bytes"], {"body_bytes": size}
        )
        response = JSONResponse(
            status_code=413,
            content={"detail": "Request body too large", "AuditLogId": audit_id},
        )
        await response(scope, receive, send)


app = FastAPI(
    title="Dataset Security Classification Service",
    version="1.2.0",
    docs_url="/docs" if config.ENABLE_DOCS else None,
    redoc_url="/redoc" if config.ENABLE_DOCS else None,
    openapi_url="/openapi.json" if config.ENABLE_DOCS else None,
)
app.add_middleware(GuardMiddleware, max_bytes=config.MAX_REQUEST_BYTES)


@app.exception_handler(RequestValidationError)
async def audit_invalid_request(request: Request, exc: RequestValidationError):
    errors = jsonable_encoder(exc.errors())
    audit_id = audit_rejection("api", errors, jsonable_encoder(exc.body))
    return JSONResponse(status_code=422, content={"detail": errors, "AuditLogId": audit_id})


@app.get("/health", summary="Liveness check")
def health() -> dict:
    return {"status": "ok"}


@app.post(
    "/classify",
    response_model=ClassificationResponse,
    summary="Compare datasets and compute resulting security classification",
)
def classify_datasets(request: ClassificationRequest) -> Any:
    # mode="json" turns URL objects into plain strings for the pipeline.
    datasets = [ds.model_dump(mode="json") for ds in request.Datasets]
    try:
        result = run_classification_graph(datasets)
    except ClassificationRejected as exc:
        return JSONResponse(
            status_code=400, content={"detail": exc.errors, "AuditLogId": exc.audit_log_id}
        )
    except Exception as exc:
        logger.exception("Unexpected error during classification")
        raise HTTPException(status_code=500, detail="Internal server error") from exc
    return ClassificationResponse(**result)
