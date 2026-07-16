from __future__ import annotations

from collections.abc import Iterator

import pytest

from app.api.chat_deadline import _reset_chat_ingress_for_testing
from app.services.chat_safety import _reset_chat_safety_poison_for_testing


@pytest.fixture(autouse=True)
def _isolate_process_local_chat_safety_fence() -> Iterator[None]:
    _reset_chat_ingress_for_testing()
    _reset_chat_safety_poison_for_testing()
    try:
        yield
    finally:
        _reset_chat_ingress_for_testing()
        _reset_chat_safety_poison_for_testing()
