from __future__ import annotations

import inspect

from app.api.v1.routes.api_keys import revoke_api_key
from app.api.v1.routes.knowledge_bases import replace_role_grants, update_knowledge_base
from app.api.v1.routes.roles import replace_permissions, replace_policy
from app.api.v1.routes.users import replace_user_roles, update_user


def test_every_mutating_authorization_entrypoint_uses_the_shared_egress_lease_guard() -> None:
    """Prevent a new revocation path from bypassing the provider-egress lease."""

    entrypoints = {
        update_knowledge_base: "knowledge_base_external_processing",
        replace_role_grants: "knowledge_base_role_grants",
        update_user: "user_status",
        replace_user_roles: "user_roles",
        replace_permissions: "role_permissions",
        replace_policy: "role_policy",
        revoke_api_key: "api_key",
    }
    for entrypoint, revocation_scope in entrypoints.items():
        source = inspect.getsource(entrypoint)
        assert "deny_if_active_external_llm_egress(" in source, entrypoint.__name__
        assert f'revocation_scope="{revocation_scope}"' in source, entrypoint.__name__


def test_knowledge_base_router_exposes_no_unserialized_delete_entrypoint() -> None:
    source = inspect.getsource(inspect.getmodule(update_knowledge_base))
    assert '@router.delete("/{knowledge_base_id}")' not in source
