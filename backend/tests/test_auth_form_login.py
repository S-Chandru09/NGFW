from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

from bson import ObjectId

from models.user import UserInDB, UserRole


def _user() -> UserInDB:
  now = datetime.now(timezone.utc)
  return UserInDB(
    _id=ObjectId(),
    email="analyst@example.com",
    username="analyst",
    full_name="Test Analyst",
    role=UserRole.ANALYST,
    is_active=True,
    hashed_password="hashed",
    created_at=now,
    updated_at=now,
  )


def test_form_login_returns_oauth2_access_token_at_top_level(client) -> None:
  user = _user()

  with (
    patch("api.routes.auth.authenticate_user", new=AsyncMock(return_value=user)),
    patch("api.routes.auth.update_last_login", new=AsyncMock()),
    patch("api.routes.auth.session_service.register_session_from_tokens", new=AsyncMock()),
  ):
    response = client.post(
      "/api/v1/auth/login/form",
      data={"username": user.email, "password": "ValidPass1"},
    )

  assert response.status_code == 200
  body = response.json()
  assert "access_token" in body
  assert body["token_type"] == "bearer"
  assert "tokens" not in body
  assert len(body["access_token"].split(".")) == 3


def test_json_login_still_returns_auth_response(client) -> None:
  user = _user()

  with (
    patch("api.routes.auth.authenticate_user", new=AsyncMock(return_value=user)),
    patch("api.routes.auth.update_last_login", new=AsyncMock()),
    patch("api.routes.auth.session_service.register_session_from_tokens", new=AsyncMock()),
  ):
    response = client.post(
      "/api/v1/auth/login",
      json={"email": user.email, "password": "ValidPass1"},
    )

  assert response.status_code == 200
  body = response.json()
  assert "access_token" not in body
  assert body["success"] is True
  assert "tokens" in body
  assert body["tokens"]["access_token"]
  assert body["tokens"]["token_type"] == "bearer"
  assert body["user"]["email"] == user.email


def test_protected_endpoint_accepts_form_login_token(client) -> None:
  user = _user()

  with (
    patch("api.routes.auth.authenticate_user", new=AsyncMock(return_value=user)),
    patch("api.routes.auth.update_last_login", new=AsyncMock()),
    patch("api.routes.auth.session_service.register_session_from_tokens", new=AsyncMock()),
  ):
    login_response = client.post(
      "/api/v1/auth/login/form",
      data={"username": user.email, "password": "ValidPass1"},
    )

  token = login_response.json()["access_token"]

  with (
    patch("services.session_service.session_service.is_token_revoked", new=AsyncMock(return_value=False)),
    patch("core.auth_utils.get_user_by_id", new=AsyncMock(return_value=user)),
  ):
    me_response = client.get(
      "/api/v1/auth/me",
      headers={"Authorization": f"Bearer {token}"},
    )

  assert me_response.status_code == 200
  assert me_response.json()["user"]["email"] == user.email
