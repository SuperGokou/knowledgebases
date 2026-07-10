from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import QuotaCounter, QuotaReservation, ReservationStatus
from app.domain.quota import check_and_calculate_reservation


@dataclass(frozen=True, slots=True)
class QuotaSpec:
    key: str
    amount: int
    limit: int | None
    window_start: datetime


def daily_window_start(now: datetime | None = None) -> datetime:
    current = now or datetime.now(UTC)
    return current.astimezone(UTC).replace(hour=0, minute=0, second=0, microsecond=0)


def lifetime_window_start() -> datetime:
    return datetime(1970, 1, 1, tzinfo=UTC)


class QuotaService:
    async def reserve_many(
        self,
        session: AsyncSession,
        *,
        user_id: UUID,
        upload_session_id: UUID,
        specs: list[QuotaSpec],
        expires_at: datetime,
    ) -> None:
        for spec in sorted(specs, key=lambda item: item.key):
            counter = await self._locked_counter(
                session,
                user_id=user_id,
                limit_key=spec.key,
                window_start=spec.window_start,
            )
            calculation = check_and_calculate_reservation(
                used=counter.used_value,
                reserved=counter.reserved_value,
                requested=spec.amount,
                limit=spec.limit,
            )
            counter.reserved_value = calculation.new_reserved
            session.add(
                QuotaReservation(
                    user_id=user_id,
                    upload_session_id=upload_session_id,
                    limit_key=spec.key,
                    window_start=spec.window_start,
                    amount=spec.amount,
                    status=ReservationStatus.HELD,
                    expires_at=expires_at,
                )
            )

    async def consume_upload_reservations(
        self,
        session: AsyncSession,
        *,
        upload_session_id: UUID,
    ) -> None:
        reservations = (
            await session.scalars(
                select(QuotaReservation)
                .where(
                    QuotaReservation.upload_session_id == upload_session_id,
                    QuotaReservation.status == ReservationStatus.HELD,
                )
                .order_by(QuotaReservation.limit_key)
                .with_for_update()
            )
        ).all()
        for reservation in reservations:
            counter = await self._locked_counter(
                session,
                user_id=reservation.user_id,
                limit_key=reservation.limit_key,
                window_start=reservation.window_start,
            )
            counter.reserved_value = max(counter.reserved_value - reservation.amount, 0)
            counter.used_value += reservation.amount
            reservation.status = ReservationStatus.CONSUMED

    async def release_upload_reservations(
        self,
        session: AsyncSession,
        *,
        upload_session_id: UUID,
        status: ReservationStatus = ReservationStatus.RELEASED,
    ) -> None:
        reservations = (
            await session.scalars(
                select(QuotaReservation)
                .where(
                    QuotaReservation.upload_session_id == upload_session_id,
                    QuotaReservation.status == ReservationStatus.HELD,
                )
                .order_by(QuotaReservation.limit_key)
                .with_for_update()
            )
        ).all()
        for reservation in reservations:
            counter = await self._locked_counter(
                session,
                user_id=reservation.user_id,
                limit_key=reservation.limit_key,
                window_start=reservation.window_start,
            )
            counter.reserved_value = max(counter.reserved_value - reservation.amount, 0)
            reservation.status = status

    async def consume(
        self,
        session: AsyncSession,
        *,
        user_id: UUID,
        key: str,
        amount: int,
        limit: int | None,
        window_start: datetime,
    ) -> None:
        counter = await self._locked_counter(
            session,
            user_id=user_id,
            limit_key=key,
            window_start=window_start,
        )
        calculation = check_and_calculate_reservation(
            used=counter.used_value,
            reserved=counter.reserved_value,
            requested=amount,
            limit=limit,
        )
        counter.used_value += amount
        if limit is not None and calculation.remaining_after_reservation is not None:
            # The domain calculation is deliberately reused for the same bound check.
            assert counter.used_value + counter.reserved_value <= limit  # noqa: S101

    async def _locked_counter(
        self,
        session: AsyncSession,
        *,
        user_id: UUID,
        limit_key: str,
        window_start: datetime,
    ) -> QuotaCounter:
        await session.execute(
            insert(QuotaCounter)
            .values(
                user_id=user_id,
                limit_key=limit_key,
                window_start=window_start,
                used_value=0,
                reserved_value=0,
            )
            .on_conflict_do_nothing(index_elements=["user_id", "limit_key", "window_start"])
        )
        counter = await session.scalar(
            select(QuotaCounter)
            .where(
                QuotaCounter.user_id == user_id,
                QuotaCounter.limit_key == limit_key,
                QuotaCounter.window_start == window_start,
            )
            .with_for_update()
        )
        if counter is None:  # Defensive: INSERT + SELECT must produce a row.
            raise RuntimeError("quota counter could not be created")
        return counter
