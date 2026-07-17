from uuid import uuid4

from sqlalchemy.dialects import postgresql

from app.api.v1.routes.knowledge_bases import _locked_roles_for_grants_statement
from app.api.v1.routes.roles import _locked_role_for_delete_statement


def test_role_delete_uses_postgresql_for_update() -> None:
    compiled = str(
        _locked_role_for_delete_statement(uuid4()).compile(dialect=postgresql.dialect())
    ).upper()

    assert "FOR UPDATE" in compiled
    assert "FOR NO KEY UPDATE" not in compiled


def test_knowledge_base_grant_replacement_serializes_with_role_delete() -> None:
    compiled = str(
        _locked_roles_for_grants_statement({uuid4(), uuid4()}).compile(
            dialect=postgresql.dialect()
        )
    ).upper()

    assert "FOR KEY SHARE" in compiled
    assert "FOR NO KEY UPDATE" not in compiled
