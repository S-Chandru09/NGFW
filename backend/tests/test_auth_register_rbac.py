from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from bson import ObjectId


VALID_PASSWORD = "ValidPass1"
REGISTER_BASE = {
  "email": "newuser@example.com",
  "username": "newuser",
  "full_name": "New User",
  "password": VALID_PASSWORD,
}


def _register(client, extra_fields: dict | None = None):
  payload = {**REGISTER_BASE, **(extra_fields or {})}
  inserted: dict = {}
  user_id = ObjectId()

  async def insert_one(document):
    inserted.clear()
    inserted.update(document)
    return SimpleNamespace(inserted_id=user_id)

  async def find_one(_query):
    return {"_id": user_id, **inserted}

  collection = MagicMock()
  collection.insert_one = AsyncMock(side_effect=insert_one)
  collection.find_one = AsyncMock(side_effect=find_one)

  with (
    patch("api.routes.auth.get_user_by_email", new=AsyncMock(return_value=None)),
    patch("api.routes.auth.get_user_by_username", new=AsyncMock(return_value=None)),
    patch("api.routes.auth.hash_password", return_value="hashed"),
    patch("api.routes.auth.get_users_collection", return_value=collection),
    patch(
      "api.routes.auth.session_service.register_session_from_tokens",
      new=AsyncMock(),
    ),
  ):
    response = client.post("/api/v1/auth/register", json=payload)

  return response, inserted


def test_public_registration_without_role_creates_viewer(client) -> None:
  response, inserted = _register(client)

  assert response.status_code == 201
  assert inserted["role"] == "viewer"
  assert response.json()["user"]["role"] == "viewer"


def test_public_registration_with_role_viewer_creates_viewer(client) -> None:
  response, inserted = _register(client, {"role": "viewer"})

  assert response.status_code == 201
  assert inserted["role"] == "viewer"
  assert response.json()["user"]["role"] == "viewer"


def test_public_registration_cannot_create_analyst(client) -> None:
  response, inserted = _register(client, {"role": "analyst"})

  assert response.status_code == 201
  assert inserted["role"] == "viewer"
  assert response.json()["user"]["role"] != "analyst"
  assert response.json()["user"]["role"] == "viewer"


def test_public_registration_cannot_create_admin(client) -> None:
  response, inserted = _register(client, {"role": "admin"})

  assert response.status_code == 201
  assert inserted["role"] == "viewer"
  assert response.json()["user"]["role"] != "admin"
  assert response.json()["user"]["role"] == "viewer"
