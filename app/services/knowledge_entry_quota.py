from __future__ import annotations

from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.services.quota import QuotaService, lifetime_window_start


def utf8_size(value: str) -> int:
    """Return the persisted UTF-8 size used by entry and platform quota policy."""
    return len(value.encode("utf-8"))


def positive_utf8_growth(*, previous_content: str | None, next_content: str) -> int:
    """Return chargeable growth; lifetime storage writes are never refunded."""
    previous_bytes = utf8_size(previous_content) if previous_content is not None else 0
    return max(utf8_size(next_content) - previous_bytes, 0)


async def consume_manual_entry_storage_quota(
    session: AsyncSession,
    *,
    user_id: UUID,
    storage_limit: int | None,
    previous_content: str | None,
    next_content: str,
) -> int:
    """Atomically meter a manual entry write in its caller-owned transaction.

    ``None`` means the role policy is unlimited, not that accounting is disabled.
    The counter update deliberately remains uncommitted here so a later entry or
    audit failure rolls it back with the rest of the request transaction.
    """
    charge_bytes = positive_utf8_growth(
        previous_content=previous_content,
        next_content=next_content,
    )
    if charge_bytes == 0:
        return 0

    await QuotaService().consume(
        session,
        user_id=user_id,
        key="storage_bytes",
        amount=charge_bytes,
        limit=storage_limit,
        window_start=lifetime_window_start(),
    )
    return charge_bytes
