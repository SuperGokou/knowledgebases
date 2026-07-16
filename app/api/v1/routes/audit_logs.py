from __future__ import annotations

import csv
import io
import logging
from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, Response
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import DatabaseSession, require_authenticated_access, require_permission
from app.api.errors import ApiError
from app.schemas.audit import AuditLogPage, AuditLogRead, AuditResult
from app.services.access import AccessContext
from app.services.audit import AuditEventView, add_audit_event, list_audit_events

router = APIRouter()
logger = logging.getLogger("knowledge_base")
AUDIT_EXPORT_MAX_ROWS = 5000
AUDIT_CACHE_CONTROL = "no-store, private"
AUDIT_ERROR_HEADERS = {
    "Cache-Control": AUDIT_CACHE_CONTROL,
    "X-Content-Type-Options": "nosniff",
}

_CSV_HEADERS = (
    "id",
    "created_at",
    "result",
    "action",
    "actor_id",
    "resource_type",
    "resource_id",
    "request_id",
)
_EXPORT_FILTER_FIELDS = (
    "action",
    "actor_id",
    "resource_type",
    "resource_id",
    "result",
    "created_from",
    "created_to",
)


class _AuditExportFilters(BaseModel):
    """Strict internal validation that runs only after authentication and authorization."""

    model_config = ConfigDict(extra="forbid")

    actor_id: UUID | None = None
    action: str | None = Field(default=None, min_length=1, max_length=150)
    resource_type: str | None = Field(default=None, min_length=1, max_length=100)
    resource_id: str | None = Field(default=None, min_length=1, max_length=255)
    result: AuditResult | None = None
    created_from: AwareDatetime | None = None
    created_to: AwareDatetime | None = None


class _AuditExportQueryError(ValueError):
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def _validate_time_range(
    created_from: AwareDatetime | None,
    created_to: AwareDatetime | None,
) -> None:
    if created_from is not None and created_to is not None and created_from > created_to:
        raise ApiError(
            status_code=422,
            code="invalid_time_range",
            message="created_from must be earlier than or equal to created_to",
        )


def _selected_export_filter_fields(request: Request) -> list[str]:
    """Return only recognized field names; never persist attacker-controlled names or values."""

    present = set(request.query_params.keys())
    return [name for name in _EXPORT_FILTER_FIELDS if name in present]


def _validate_export_query_shape(request: Request) -> None:
    seen: set[str] = set()
    for name, _value in request.query_params.multi_items():
        if name not in _EXPORT_FILTER_FIELDS:
            raise _AuditExportQueryError("unknown_query_parameter")
        if name in seen:
            raise _AuditExportQueryError("duplicate_query_parameter")
        seen.add(name)


def _export_api_error(*, status_code: int, code: str, message: str) -> ApiError:
    return ApiError(
        status_code=status_code,
        code=code,
        message=message,
        headers=AUDIT_ERROR_HEADERS,
    )


async def _record_export_attempt(
    session: AsyncSession,
    *,
    access: AccessContext,
    request_id: str | None,
    result: AuditResult,
    filter_fields: list[str],
    reason: str | None = None,
    row_count: int | None = None,
) -> None:
    details: dict[str, object] = {
        "filter_fields": filter_fields,
        "max_rows": AUDIT_EXPORT_MAX_ROWS,
    }
    if reason is not None:
        details["reason"] = reason
    if row_count is not None:
        details["row_count"] = row_count

    try:
        add_audit_event(
            session,
            actor_id=access.user.id,
            action="audit.exported",
            result=result,
            resource_type="audit_log",
            request_id=request_id,
            details=details,
        )
        await session.commit()
    except Exception as error:
        try:
            await session.rollback()
        except Exception:
            logger.error(
                "Audit export rollback failed",
                extra={"request_id": request_id, "audit_result": result.value},
            )
        logger.error(
            "Audit export persistence failed",
            extra={"request_id": request_id, "audit_result": result.value},
        )
        raise _export_api_error(
            status_code=503,
            code="audit_persistence_failed",
            message="The audit export could not be recorded",
        ) from error


def _spreadsheet_safe(value: object | None) -> str:
    """Keep valid CSV while preventing formula execution in spreadsheet clients."""

    if value is None:
        return ""
    if isinstance(value, datetime):
        rendered = value.isoformat()
    elif isinstance(value, AuditResult):
        rendered = value.value
    else:
        rendered = str(value)
    first_non_space = rendered.lstrip()[:1]
    if rendered[:1] in {"\t", "\r", "\n"} or first_non_space in {"=", "+", "-", "@"}:
        return f"'{rendered}"
    return rendered


def _audit_csv(events: list[AuditEventView]) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.writer(output, dialect="excel", lineterminator="\r\n")
    writer.writerow(_CSV_HEADERS)
    for event in events:
        writer.writerow(
            _spreadsheet_safe(value)
            for value in (
                event.id,
                event.created_at,
                event.result,
                event.action,
                event.actor_id,
                event.resource_type,
                event.resource_id,
                event.request_id,
            )
        )
    return b"\xef\xbb\xbf" + output.getvalue().encode("utf-8")


@router.get("", response_model=AuditLogPage)
async def list_audit_logs(
    session: DatabaseSession,
    response: Response,
    _: Annotated[AccessContext, Depends(require_permission("audit:read"))],
    actor_id: Annotated[UUID | None, Query()] = None,
    action: Annotated[str | None, Query(min_length=1, max_length=150)] = None,
    resource_type: Annotated[str | None, Query(min_length=1, max_length=100)] = None,
    resource_id: Annotated[str | None, Query(min_length=1, max_length=255)] = None,
    result: Annotated[AuditResult | None, Query()] = None,
    created_from: Annotated[AwareDatetime | None, Query()] = None,
    created_to: Annotated[AwareDatetime | None, Query()] = None,
    cursor: Annotated[int | None, Query(ge=1)] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> AuditLogPage:
    response.headers["Cache-Control"] = AUDIT_CACHE_CONTROL
    _validate_time_range(created_from, created_to)

    events, next_cursor = await list_audit_events(
        session,
        actor_id=actor_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        result=result,
        created_from=created_from,
        created_to=created_to,
        cursor=cursor,
        limit=limit,
    )
    return AuditLogPage(
        items=[
            AuditLogRead(
                id=event.id,
                actor_id=event.actor_id,
                action=event.action,
                resource_type=event.resource_type,
                resource_id=event.resource_id,
                request_id=event.request_id,
                result=event.result,
                created_at=event.created_at,
            )
            for event in events
        ],
        next_cursor=next_cursor,
    )


@router.get("/export")
async def export_audit_logs(
    request: Request,
    session: DatabaseSession,
    access: Annotated[AccessContext, Depends(require_authenticated_access)],
    actor_id: Annotated[
        str | None,
        Query(description="Optional actor UUID; validated after authentication"),
    ] = None,
    action: Annotated[
        str | None,
        Query(description="Optional exact action, 1 to 150 characters"),
    ] = None,
    resource_type: Annotated[
        str | None,
        Query(description="Optional exact resource type, 1 to 100 characters"),
    ] = None,
    resource_id: Annotated[
        str | None,
        Query(description="Optional exact resource ID, 1 to 255 characters"),
    ] = None,
    result: Annotated[
        str | None,
        Query(description="Optional result: success, failure, or denied"),
    ] = None,
    created_from: Annotated[
        str | None,
        Query(description="Optional inclusive RFC 3339 timestamp with timezone"),
    ] = None,
    created_to: Annotated[
        str | None,
        Query(description="Optional inclusive RFC 3339 timestamp with timezone"),
    ] = None,
) -> Response:
    """Export one exact, redacted filter result as bounded RFC 4180 CSV."""

    request_id = getattr(request.state, "request_id", None)
    filter_fields = _selected_export_filter_fields(request)
    if not access.allows("audit:read"):
        await _record_export_attempt(
            session,
            access=access,
            request_id=request_id,
            result=AuditResult.DENIED,
            filter_fields=filter_fields,
            reason="permission_denied",
        )
        raise _export_api_error(
            status_code=403,
            code="permission_denied",
            message="Permission required: audit:read",
        )

    raw_filters = {
        name: value
        for name, value in (
            ("actor_id", actor_id),
            ("action", action),
            ("resource_type", resource_type),
            ("resource_id", resource_id),
            ("result", result),
            ("created_from", created_from),
            ("created_to", created_to),
        )
        if value is not None
    }
    try:
        _validate_export_query_shape(request)
        filters = _AuditExportFilters.model_validate(raw_filters)
    except _AuditExportQueryError as error:
        await _record_export_attempt(
            session,
            access=access,
            request_id=request_id,
            result=AuditResult.FAILURE,
            filter_fields=filter_fields,
            reason=error.reason,
        )
        raise _export_api_error(
            status_code=422,
            code="validation_error",
            message="Audit export query validation failed",
        ) from error
    except ValidationError as error:
        await _record_export_attempt(
            session,
            access=access,
            request_id=request_id,
            result=AuditResult.FAILURE,
            filter_fields=filter_fields,
            reason="invalid_query_value",
        )
        raise _export_api_error(
            status_code=422,
            code="validation_error",
            message="Audit export query validation failed",
        ) from error

    try:
        _validate_time_range(filters.created_from, filters.created_to)
    except ApiError as error:
        await _record_export_attempt(
            session,
            access=access,
            request_id=request_id,
            result=AuditResult.FAILURE,
            filter_fields=filter_fields,
            reason="invalid_time_range",
        )
        raise _export_api_error(
            status_code=error.status_code,
            code=error.code,
            message=error.message,
        ) from error

    events, next_cursor = await list_audit_events(
        session,
        actor_id=filters.actor_id,
        action=filters.action,
        resource_type=filters.resource_type,
        resource_id=filters.resource_id,
        result=filters.result,
        created_from=filters.created_from,
        created_to=filters.created_to,
        limit=AUDIT_EXPORT_MAX_ROWS,
    )
    if next_cursor is not None:
        await _record_export_attempt(
            session,
            access=access,
            request_id=request_id,
            result=AuditResult.FAILURE,
            filter_fields=filter_fields,
            reason="result_limit_exceeded",
        )
        raise _export_api_error(
            status_code=422,
            code="audit_export_too_large",
            message=(
                f"Audit export exceeds {AUDIT_EXPORT_MAX_ROWS} rows; narrow the filters and retry"
            ),
        )

    csv_content = _audit_csv(events)
    await _record_export_attempt(
        session,
        access=access,
        request_id=request_id,
        result=AuditResult.SUCCESS,
        filter_fields=filter_fields,
        row_count=len(events),
    )

    filename = datetime.now(UTC).strftime("audit-logs-%Y%m%dT%H%M%SZ.csv")
    return Response(
        content=csv_content,
        media_type="text/csv; charset=utf-8",
        headers={
            "Cache-Control": AUDIT_CACHE_CONTROL,
            "Content-Disposition": (
                f"attachment; filename=\"{filename}\"; filename*=UTF-8''{filename}"
            ),
            "X-Content-Type-Options": "nosniff",
        },
    )
