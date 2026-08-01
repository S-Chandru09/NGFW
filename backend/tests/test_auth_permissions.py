from datetime import datetime, timezone

from bson import ObjectId

from core.auth_utils import ROLE_PERMISSIONS, has_permission
from models.user import UserPublic, UserRole


def _user(role: UserRole) -> UserPublic:
  now = datetime.now(timezone.utc)
  return UserPublic(
    _id=ObjectId(),
    email="analyst@example.com",
    username="analyst",
    full_name="Test Analyst",
    role=role,
    is_active=True,
    created_at=now,
    updated_at=now,
  )


def test_analyst_can_capture_and_read_dashboard() -> None:
  user = _user(UserRole.ANALYST)
  assert has_permission(user, "capture:write")
  assert has_permission(user, "dashboard:read")
  assert has_permission(user, "alerts:read")


def test_viewer_cannot_write_capture() -> None:
  user = _user(UserRole.VIEWER)
  assert has_permission(user, "capture:read")
  assert not has_permission(user, "capture:write")


def test_all_roles_define_permissions() -> None:
  for role in UserRole:
    assert role in ROLE_PERMISSIONS
    assert len(ROLE_PERMISSIONS[role]) > 0
