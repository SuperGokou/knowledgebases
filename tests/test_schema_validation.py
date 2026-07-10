import pytest
from pydantic import ValidationError

from app.schemas.roles import RoleUpdate
from app.schemas.users import UserUpdate


def test_non_nullable_patch_fields_reject_explicit_null() -> None:
    with pytest.raises(ValidationError):
        RoleUpdate(name=None)
    with pytest.raises(ValidationError):
        RoleUpdate(priority=None)
    with pytest.raises(ValidationError):
        UserUpdate(status=None)
