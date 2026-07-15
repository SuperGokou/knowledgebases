from __future__ import annotations

from typing import Annotated

from fastapi import Header

CHAT_IDEMPOTENCY_KEY_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]*$"


def require_chat_idempotency_key(
    idempotency_key: Annotated[
        str,
        Header(
            alias="Idempotency-Key",
            min_length=1,
            max_length=160,
            pattern=CHAT_IDEMPOTENCY_KEY_PATTERN,
            description=(
                "Stable, log-safe identifier for one logical chat operation. "
                "Reuse it only when retrying that same operation."
            ),
        ),
    ],
) -> str:
    return idempotency_key
