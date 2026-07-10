from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.api.errors import ApiError
from app.api.health import router as health_router
from app.api.middleware import RequestBodyLimitMiddleware, RequestContextMiddleware
from app.api.v1.router import router as v1_router
from app.core.config import get_settings
from app.domain.errors import FilePolicyViolation, QuotaExceeded

logger = logging.getLogger("knowledge_base")
settings = get_settings()


def error_body(
    request: Request,
    *,
    code: str,
    message: str,
    details: Any = None,
) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if details is not None:
        error["details"] = details
    return {
        "error": error,
        "request_id": getattr(request.state, "request_id", None),
    }


def safe_validation_errors(error: RequestValidationError) -> list[dict[str, Any]]:
    """Return useful validation details without echoing credentials or raw request bodies."""
    safe: list[dict[str, Any]] = []
    for item in error.errors():
        detail = {
            "type": item.get("type"),
            "loc": item.get("loc"),
            "msg": item.get("msg"),
        }
        if item.get("ctx"):
            detail["ctx"] = {key: str(value) for key, value in item["ctx"].items()}
        safe.append(detail)
    return safe


def create_app() -> FastAPI:
    application = FastAPI(
        title=settings.app_name,
        version="0.1.0",
        debug=settings.debug,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )
    application.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=list(settings.trusted_hosts),
    )
    application.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.cors_origins),
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=[
            "Authorization",
            "Content-Type",
            "Idempotency-Key",
            "X-API-Key",
            "X-Request-ID",
        ],
        expose_headers=["X-Request-ID", "X-RateLimit-Limit", "X-RateLimit-Remaining"],
    )
    application.add_middleware(
        RequestBodyLimitMiddleware,
        max_bytes=settings.max_api_body_bytes,
    )
    application.add_middleware(RequestContextMiddleware)

    @application.exception_handler(ApiError)
    async def api_error_handler(request: Request, error: ApiError) -> JSONResponse:
        return JSONResponse(
            status_code=error.status_code,
            content=error_body(
                request,
                code=error.code,
                message=error.message,
                details=error.details,
            ),
            headers=error.headers,
        )

    @application.exception_handler(RequestValidationError)
    async def validation_error_handler(
        request: Request, error: RequestValidationError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content=error_body(
                request,
                code="validation_error",
                message="Request validation failed",
                details=safe_validation_errors(error),
            ),
        )

    @application.exception_handler(QuotaExceeded)
    async def quota_error_handler(request: Request, error: QuotaExceeded) -> JSONResponse:
        return JSONResponse(
            status_code=429,
            content=error_body(
                request,
                code="quota_exceeded",
                message="The requested operation exceeds the effective quota",
                details={
                    "limit": error.limit,
                    "remaining": error.remaining,
                    "requested": error.requested,
                },
            ),
        )

    @application.exception_handler(FilePolicyViolation)
    async def file_policy_handler(request: Request, error: FilePolicyViolation) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content=error_body(
                request,
                code="file_policy_violation",
                message=str(error),
            ),
        )

    @application.exception_handler(Exception)
    async def unexpected_error_handler(request: Request, error: Exception) -> JSONResponse:
        logger.exception(
            "Unhandled request failure",
            extra={"request_id": getattr(request.state, "request_id", None)},
        )
        return JSONResponse(
            status_code=500,
            content=error_body(
                request,
                code="internal_error",
                message="An unexpected error occurred",
            ),
        )

    application.include_router(health_router)
    application.include_router(v1_router, prefix=settings.api_prefix)
    return application


app = create_app()
