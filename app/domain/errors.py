from __future__ import annotations


class DomainError(Exception):
    """Base class for expected business-rule failures."""


class FilePolicyViolation(DomainError):
    """Raised when a requested file upload violates a configured policy."""


class QuotaExceeded(DomainError):
    """Raised when a quota reservation would exceed the effective limit."""

    def __init__(self, *, limit: int, remaining: int, requested: int) -> None:
        self.limit = limit
        self.remaining = remaining
        self.requested = requested
        super().__init__(
            f"quota exceeded: requested {requested}, remaining {remaining}, limit {limit}"
        )
