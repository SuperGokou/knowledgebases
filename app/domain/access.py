from __future__ import annotations

from collections.abc import Iterable, Mapping

LimitValue = int | None


def has_permission(granted_permissions: Iterable[str], required_permission: str) -> bool:
    """Return whether an exact, resource-wide, or global permission grants access."""
    granted = set(granted_permissions)
    if "*" in granted or required_permission in granted:
        return True

    resource, separator, _ = required_permission.partition(":")
    return bool(separator and f"{resource}:*" in granted)


def resolve_effective_limits(
    role_limits: Iterable[Mapping[str, LimitValue]],
    user_overrides: Mapping[str, LimitValue],
) -> dict[str, LimitValue]:
    """Merge role limits using max/unlimited semantics, then apply user overrides.

    ``None`` means unlimited. A user-level override is authoritative, including when
    it changes an unlimited role limit back to a finite value.
    """
    effective: dict[str, LimitValue] = {}
    for limits in role_limits:
        for key, value in limits.items():
            if key not in effective:
                effective[key] = value
                continue
            current = effective[key]
            if current is None or value is None:
                effective[key] = None
            else:
                effective[key] = max(current, value)

    effective.update(user_overrides)
    return effective
