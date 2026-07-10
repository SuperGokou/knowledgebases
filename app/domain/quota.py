from __future__ import annotations

from dataclasses import dataclass

from app.domain.errors import QuotaExceeded


@dataclass(frozen=True, slots=True)
class ReservationCalculation:
    new_reserved: int
    remaining_after_reservation: int | None


def check_and_calculate_reservation(
    *,
    used: int,
    reserved: int,
    requested: int,
    limit: int | None,
) -> ReservationCalculation:
    """Calculate an atomic quota-row update after the caller obtains a DB lock."""
    values = (used, reserved, requested)
    if any(value < 0 for value in values) or (limit is not None and limit < 0):
        raise ValueError("quota values cannot be negative")

    new_reserved = reserved + requested
    if limit is None:
        return ReservationCalculation(new_reserved, None)

    remaining_before = max(limit - used - reserved, 0)
    if requested > remaining_before:
        raise QuotaExceeded(
            limit=limit,
            remaining=remaining_before,
            requested=requested,
        )

    return ReservationCalculation(
        new_reserved=new_reserved,
        remaining_after_reservation=limit - used - new_reserved,
    )
