from app.domain.access import has_permission, resolve_effective_limits


def test_exact_permission_is_granted() -> None:
    assert has_permission({"file:read", "file:upload"}, "file:upload")


def test_resource_wildcard_grants_only_its_resource() -> None:
    assert has_permission({"file:*"}, "file:delete")
    assert not has_permission({"file:*"}, "role:delete")


def test_global_wildcard_grants_every_permission() -> None:
    assert has_permission({"*"}, "role:manage")


def test_permission_prefix_does_not_accidentally_match() -> None:
    assert not has_permission({"file:read"}, "file:reader")


def test_role_limits_use_most_permissive_value() -> None:
    effective = resolve_effective_limits(
        [
            {"max_upload_bytes": 10, "requests_per_minute": 60},
            {"max_upload_bytes": 20, "daily_downloads": 5},
        ],
        {},
    )

    assert effective == {
        "max_upload_bytes": 20,
        "requests_per_minute": 60,
        "daily_downloads": 5,
    }


def test_unlimited_role_limit_wins_and_user_override_is_final() -> None:
    effective = resolve_effective_limits(
        [{"storage_bytes": 100}, {"storage_bytes": None}],
        {"storage_bytes": 500},
    )

    assert effective["storage_bytes"] == 500
