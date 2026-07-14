from __future__ import annotations

from uuid import UUID, uuid4

from app.services.llm_egress_policy import llm_egress_lock_key


def test_advisory_lock_keys_are_stable_namespaced_signed_bigints() -> None:
    resource_id = UUID("50e7cf3a-234d-4fc3-9879-38320b42d9ab")

    first = llm_egress_lock_key("user", resource_id)
    assert first == llm_egress_lock_key("user", resource_id)
    assert -(2**63) <= first < 2**63
    assert first != llm_egress_lock_key("knowledge_base", resource_id)
    assert first != llm_egress_lock_key("user", uuid4())


def test_distinct_lock_scope_sample_has_no_collisions() -> None:
    resources = [uuid4() for _ in range(2_000)]
    keys = {
        llm_egress_lock_key(scope, resource_id)
        for scope in ("user", "role", "api_key", "knowledge_base")
        for resource_id in resources
    }
    assert len(keys) == len(resources) * 4
