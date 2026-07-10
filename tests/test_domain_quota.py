import pytest

from app.domain.errors import QuotaExceeded
from app.domain.quota import check_and_calculate_reservation


def test_quota_reservation_includes_existing_reservations() -> None:
    result = check_and_calculate_reservation(
        used=40,
        reserved=10,
        requested=20,
        limit=100,
    )

    assert result.new_reserved == 30
    assert result.remaining_after_reservation == 30


def test_concurrent_reservations_cannot_oversubscribe_logically() -> None:
    with pytest.raises(QuotaExceeded) as error:
        check_and_calculate_reservation(
            used=80,
            reserved=15,
            requested=10,
            limit=100,
        )

    assert error.value.limit == 100
    assert error.value.remaining == 5


def test_none_limit_means_unlimited() -> None:
    result = check_and_calculate_reservation(
        used=10**18,
        reserved=0,
        requested=10**18,
        limit=None,
    )

    assert result.remaining_after_reservation is None


@pytest.mark.parametrize("value", [-1, -100])
def test_negative_quota_inputs_are_rejected(value: int) -> None:
    with pytest.raises(ValueError):
        check_and_calculate_reservation(used=value, reserved=0, requested=1, limit=10)
