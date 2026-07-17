from __future__ import annotations

import inspect

from app.api.v1.routes.api_keys import revoke_api_key
from app.api.v1.routes.knowledge_bases import (
    delete_knowledge_base,
    replace_role_grants,
    update_knowledge_base,
)
from app.api.v1.routes.roles import replace_permissions, replace_policy
from app.api.v1.routes.users import replace_user_roles, reset_user_password, update_user


def test_every_mutating_authorization_entrypoint_uses_the_shared_egress_lease_guard() -> None:
    """Prevent a new revocation path from bypassing the provider-egress lease."""

    entrypoints = {
        update_knowledge_base: "knowledge_base_external_processing",
        delete_knowledge_base: "knowledge_base_delete",
        replace_role_grants: "knowledge_base_role_grants",
        update_user: "user_status",
        reset_user_password: "user_password",
        replace_user_roles: "user_roles",
        replace_permissions: "role_permissions",
        replace_policy: "role_policy",
        revoke_api_key: "api_key",
    }
    for entrypoint, revocation_scope in entrypoints.items():
        source = inspect.getsource(entrypoint)
        assert "deny_if_active_external_llm_egress(" in source, entrypoint.__name__
        assert f'revocation_scope="{revocation_scope}"' in source, entrypoint.__name__


def test_knowledge_base_delete_serializes_with_external_llm_egress() -> None:
    source = inspect.getsource(delete_knowledge_base)
    assert "with_for_update()" in source
    assert "deny_if_active_external_llm_egress(" in source
    assert 'revocation_scope="knowledge_base_delete"' in source
