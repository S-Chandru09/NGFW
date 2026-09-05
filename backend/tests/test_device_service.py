from datetime import datetime, timezone
from inspect import getsource
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from bson import ObjectId
from fastapi import HTTPException
from pydantic import ValidationError

from core.auth_utils import get_current_active_user, has_permission
from models.device import DeviceCreate, DeviceDocument, DeviceUpdate
from models.user import UserPublic, UserRole
from services import device_service as device_service_module
from services.device_service import DeviceService


EXISTING_USER_ID = "507f1f77bcf86cd799439011"


def _empty_collection() -> AsyncMock:
  collection = AsyncMock()
  collection.find_one = AsyncMock(return_value=None)
  collection.insert_one = AsyncMock()
  collection.update_one = AsyncMock()
  collection.update_many = AsyncMock()
  collection.delete_one = AsyncMock()
  collection.count_documents = AsyncMock(return_value=0)
  return collection


def _user_document() -> dict:
  return {"_id": ObjectId(EXISTING_USER_ID), "username": "hello"}


def _device_document(**overrides) -> dict:
  now = datetime.now(timezone.utc)
  document = {
    "_id": ObjectId(),
    "device_id": "existing-device",
    "device_name": "Analyst Laptop",
    "device_type": "laptop",
    "os_type": "Windows",
    "ip_address": "192.168.1.101",
    "user_id": EXISTING_USER_ID,
    "is_trusted": False,
    "trust_score": 50.0,
    "is_compliant": True,
    "metadata": {},
    "last_seen_at": None,
    "created_at": now,
    "updated_at": now,
  }
  document.update(overrides)
  return document


def _cursor(documents: list[dict]) -> MagicMock:
  cursor = MagicMock()
  cursor.sort.return_value = cursor
  cursor.skip.return_value = cursor
  cursor.limit.return_value = cursor
  cursor.to_list = AsyncMock(return_value=documents)
  return cursor


def _public_user(role: UserRole) -> UserPublic:
  now = datetime.now(timezone.utc)
  return UserPublic(
    _id=ObjectId(),
    email=f"{role.value}@example.com",
    username=role.value,
    full_name=role.value.title(),
    role=role,
    is_active=True,
    created_at=now,
    updated_at=now,
  )


@pytest.fixture
def service() -> DeviceService:
  return DeviceService()


@pytest.mark.asyncio
async def test_create_device_with_valid_ip_and_existing_user(service: DeviceService) -> None:
  devices = _empty_collection()
  users = _empty_collection()
  created = _device_document()
  devices.insert_one = AsyncMock(return_value=MagicMock(inserted_id=created["_id"]))
  devices.find_one = AsyncMock(side_effect=[None, created])
  users.find_one = AsyncMock(return_value=_user_document())

  with (
    patch("services.device_service.get_devices_collection", return_value=devices),
    patch("services.device_service.get_users_collection", return_value=users),
  ):
    result = await service.create_device(
      DeviceCreate(
        device_name="Analyst Laptop",
        device_type="laptop",
        ip_address="192.168.1.101",
        user_id=EXISTING_USER_ID,
      )
    )

  inserted = devices.insert_one.await_args.args[0]
  assert result.success is True
  assert inserted["user_id"] == EXISTING_USER_ID
  assert inserted["ip_address"] == "192.168.1.101"
  assert inserted["trust_score"] == 50.0
  assert inserted["is_trusted"] is False
  assert inserted["last_seen_at"] is None
  users.insert_one.assert_not_called()


@pytest.mark.asyncio
async def test_create_device_without_user(service: DeviceService) -> None:
  devices = _empty_collection()
  created = _device_document(user_id=None, ip_address=None)
  devices.insert_one = AsyncMock(return_value=MagicMock(inserted_id=created["_id"]))
  devices.find_one = AsyncMock(return_value=created)
  users = _empty_collection()

  with (
    patch("services.device_service.get_devices_collection", return_value=devices),
    patch("services.device_service.get_users_collection", return_value=users),
  ):
    await service.create_device(DeviceCreate(device_name="Unassigned Printer", device_type="iot"))

  users.find_one.assert_not_called()
  assert devices.insert_one.await_args.args[0]["user_id"] is None


@pytest.mark.asyncio
async def test_create_rejects_unknown_user_id(service: DeviceService) -> None:
  with (
    patch("services.device_service.get_devices_collection", return_value=_empty_collection()),
    patch("services.device_service.get_users_collection", return_value=_empty_collection()),
  ):
    with pytest.raises(HTTPException) as exc_info:
      await service.create_device(
        DeviceCreate(device_name="Ghost Device", user_id=EXISTING_USER_ID)
      )

  assert exc_info.value.status_code == 400


def test_create_rejects_malformed_ip() -> None:
  with pytest.raises(ValidationError):
    DeviceCreate(device_name="Bad IP Device", ip_address="not-an-ip")


@pytest.mark.asyncio
async def test_create_rejects_duplicate_ip(service: DeviceService) -> None:
  devices = _empty_collection()
  devices.find_one = AsyncMock(return_value=_device_document())
  users = _empty_collection()
  users.find_one = AsyncMock(return_value=_user_document())

  with (
    patch("services.device_service.get_devices_collection", return_value=devices),
    patch("services.device_service.get_users_collection", return_value=users),
  ):
    with pytest.raises(HTTPException) as exc_info:
      await service.create_device(
        DeviceCreate(
          device_name="Second Device",
          ip_address="192.168.1.101",
          user_id=EXISTING_USER_ID,
        )
      )

  assert exc_info.value.status_code == 409
  devices.insert_one.assert_not_called()


def test_create_document_defaults() -> None:
  document = DeviceDocument.create_document(DeviceCreate(device_name="Defaults Device"))
  assert document["trust_score"] == 50.0
  assert document["is_trusted"] is False
  assert document["last_seen_at"] is None


def test_client_cannot_control_trust_fields() -> None:
  created = DeviceCreate.model_validate(
    {
      "device_name": "Locked Fields",
      "trust_score": 1,
      "is_trusted": True,
    }
  )
  document = DeviceDocument.create_document(created)
  assert "trust_score" not in DeviceCreate.model_fields
  assert "is_trusted" not in DeviceCreate.model_fields
  assert document["trust_score"] == 50.0
  assert document["is_trusted"] is False
  assert "trust_score" not in DeviceUpdate.model_fields
  assert "is_trusted" not in DeviceUpdate.model_fields


@pytest.mark.asyncio
async def test_list_and_get_device(service: DeviceService) -> None:
  document = _device_document()
  devices = _empty_collection()
  devices.count_documents = AsyncMock(return_value=1)
  devices.find = MagicMock(return_value=_cursor([document]))
  devices.find_one = AsyncMock(return_value=document)

  with patch("services.device_service.get_devices_collection", return_value=devices):
    listed = await service.list_devices()
    detail = await service.get_device("existing-device")

  assert listed.pagination.total_items == 1
  assert listed.items[0].device_id == "existing-device"
  assert detail.device.device_name == "Analyst Laptop"


@pytest.mark.asyncio
async def test_patch_device_ip(service: DeviceService) -> None:
  existing = _device_document()
  updated = _device_document(ip_address="10.0.0.8")
  devices = _empty_collection()
  devices.find_one = AsyncMock(side_effect=[existing, None, updated])

  with patch("services.device_service.get_devices_collection", return_value=devices):
    result = await service.update_device("existing-device", DeviceUpdate(ip_address="10.0.0.8"))

  assert result.device.ip_address == "10.0.0.8"
  assert "trust_score" not in devices.update_one.await_args.args[1]["$set"]
  assert "is_trusted" not in devices.update_one.await_args.args[1]["$set"]


@pytest.mark.asyncio
async def test_patch_user_id_with_existing_user(service: DeviceService) -> None:
  existing = _device_document(user_id=None)
  updated = _device_document()
  devices = _empty_collection()
  devices.find_one = AsyncMock(side_effect=[existing, updated])
  users = _empty_collection()
  users.find_one = AsyncMock(return_value=_user_document())

  with (
    patch("services.device_service.get_devices_collection", return_value=devices),
    patch("services.device_service.get_users_collection", return_value=users),
  ):
    result = await service.update_device("existing-device", DeviceUpdate(user_id=EXISTING_USER_ID))

  assert result.device.user_id == EXISTING_USER_ID
  users.insert_one.assert_not_called()


@pytest.mark.asyncio
async def test_patch_rejects_unknown_user(service: DeviceService) -> None:
  devices = _empty_collection()
  devices.find_one = AsyncMock(return_value=_device_document())

  with (
    patch("services.device_service.get_devices_collection", return_value=devices),
    patch("services.device_service.get_users_collection", return_value=_empty_collection()),
  ):
    with pytest.raises(HTTPException) as exc_info:
      await service.update_device("existing-device", DeviceUpdate(user_id=EXISTING_USER_ID))

  assert exc_info.value.status_code == 400
  devices.update_one.assert_not_called()


@pytest.mark.asyncio
async def test_delete_device_does_not_cascade(service: DeviceService) -> None:
  existing = _device_document()
  devices = _empty_collection()
  devices.find_one = AsyncMock(return_value=existing)
  flows = _empty_collection()
  threats = _empty_collection()
  scores = _empty_collection()

  with (
    patch("services.device_service.get_devices_collection", return_value=devices),
    patch("database.get_network_flows_collection", return_value=flows),
    patch("database.get_threat_alerts_collection", return_value=threats),
    patch("database.get_trust_scores_collection", return_value=scores),
  ):
    result = await service.delete_device("existing-device")

  assert result.device_id == "existing-device"
  devices.delete_one.assert_awaited_once()
  flows.update_one.assert_not_called()
  flows.update_many.assert_not_called()
  flows.delete_one.assert_not_called()
  threats.update_one.assert_not_called()
  threats.update_many.assert_not_called()
  threats.delete_one.assert_not_called()
  scores.update_one.assert_not_called()
  scores.update_many.assert_not_called()
  scores.delete_one.assert_not_called()


def test_service_does_not_call_trust_or_flow_modules() -> None:
  source = getsource(device_service_module)
  assert "calculate_trust_score" not in source
  assert "network_flow" not in source
  assert "firewall_engine" not in source
  assert "get_network_flows_collection" not in source
  assert "get_threat_alerts_collection" not in source
  assert "get_trust_scores_collection" not in source


def test_role_permissions_for_devices() -> None:
  assert has_permission(_public_user(UserRole.ADMIN), "devices:write")
  assert has_permission(_public_user(UserRole.ADMIN), "devices:read")
  assert not has_permission(_public_user(UserRole.ANALYST), "devices:write")
  assert has_permission(_public_user(UserRole.ANALYST), "devices:read")
  assert not has_permission(_public_user(UserRole.VIEWER), "devices:write")
  assert has_permission(_public_user(UserRole.VIEWER), "devices:read")


def test_analyst_cannot_create_device(client) -> None:
  from main import app

  app.dependency_overrides[get_current_active_user] = lambda: _public_user(UserRole.ANALYST)
  try:
    response = client.post(
      "/api/v1/devices",
      json={"device_name": "Analyst Device", "device_type": "laptop"},
    )
  finally:
    app.dependency_overrides.clear()

  assert response.status_code == 403


def test_viewer_cannot_create_device(client) -> None:
  from main import app

  app.dependency_overrides[get_current_active_user] = lambda: _public_user(UserRole.VIEWER)
  try:
    response = client.post(
      "/api/v1/devices",
      json={"device_name": "Viewer Device", "device_type": "laptop"},
    )
  finally:
    app.dependency_overrides.clear()

  assert response.status_code == 403


def test_admin_can_create_device(client) -> None:
  from main import app
  from schemas.device import DeviceCreateResponse

  created = DeviceDocument.to_public_from_mongo(_device_document())
  assert created is not None
  app.dependency_overrides[get_current_active_user] = lambda: _public_user(UserRole.ADMIN)
  try:
    with patch(
      "api.routes.devices.device_service.create_device",
      new=AsyncMock(
        return_value=DeviceCreateResponse(
          message="created",
          device=created,
        )
      ),
    ):
      response = client.post(
        "/api/v1/devices",
        json={
          "device_name": "Admin Device",
          "device_type": "laptop",
          "ip_address": "192.168.1.101",
          "user_id": EXISTING_USER_ID,
        },
      )
  finally:
    app.dependency_overrides.clear()

  assert response.status_code == 201
  assert response.json()["device"]["device_id"] == "existing-device"


def test_analyst_can_list_and_get_device(client) -> None:
  from main import app
  from schemas.device import DeviceDetailResponse, DeviceListResponse
  from schemas.log import PaginationMeta

  created = DeviceDocument.to_public_from_mongo(_device_document())
  assert created is not None
  app.dependency_overrides[get_current_active_user] = lambda: _public_user(UserRole.ANALYST)
  try:
    with (
      patch(
        "api.routes.devices.device_service.list_devices",
        new=AsyncMock(
          return_value=DeviceListResponse(
            message="listed",
            items=[created],
            pagination=PaginationMeta(
              page=1,
              page_size=20,
              total_items=1,
              total_pages=1,
              has_next=False,
              has_previous=False,
            ),
          )
        ),
      ),
      patch(
        "api.routes.devices.device_service.get_device",
        new=AsyncMock(return_value=DeviceDetailResponse(message="got", device=created)),
      ),
    ):
      listed = client.get("/api/v1/devices")
      detail = client.get("/api/v1/devices/existing-device")
  finally:
    app.dependency_overrides.clear()

  assert listed.status_code == 200
  assert detail.status_code == 200


def test_viewer_can_list_and_get_device(client) -> None:
  from main import app
  from schemas.device import DeviceDetailResponse, DeviceListResponse
  from schemas.log import PaginationMeta

  created = DeviceDocument.to_public_from_mongo(_device_document())
  assert created is not None
  app.dependency_overrides[get_current_active_user] = lambda: _public_user(UserRole.VIEWER)
  try:
    with (
      patch(
        "api.routes.devices.device_service.list_devices",
        new=AsyncMock(
          return_value=DeviceListResponse(
            message="listed",
            items=[created],
            pagination=PaginationMeta(
              page=1,
              page_size=20,
              total_items=1,
              total_pages=1,
              has_next=False,
              has_previous=False,
            ),
          )
        ),
      ),
      patch(
        "api.routes.devices.device_service.get_device",
        new=AsyncMock(return_value=DeviceDetailResponse(message="got", device=created)),
      ),
    ):
      listed = client.get("/api/v1/devices")
      detail = client.get("/api/v1/devices/existing-device")
  finally:
    app.dependency_overrides.clear()

  assert listed.status_code == 200
  assert detail.status_code == 200
