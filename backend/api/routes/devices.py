from typing import Optional

from fastapi import APIRouter, Depends, Query

from core.auth_utils import require_permission
from models.device import DeviceCreate, DeviceType, DeviceUpdate
from models.user import UserPublic
from schemas.device import (
  DeviceCreateResponse,
  DeviceDeleteResponse,
  DeviceDetailResponse,
  DeviceFilterParams,
  DeviceListResponse,
  DeviceUpdateResponse,
)
from services.device_service import device_service

router = APIRouter(prefix="/devices", tags=["Devices"])


@router.post(
  "",
  response_model=DeviceCreateResponse,
  status_code=201,
  summary="Register a device in inventory",
)
async def create_device(
  device_data: DeviceCreate,
  current_user: UserPublic = Depends(require_permission("devices:write")),
) -> DeviceCreateResponse:
  return await device_service.create_device(device_data)


@router.get(
  "",
  response_model=DeviceListResponse,
  summary="List registered devices",
)
async def list_devices(
  page: int = Query(default=1, ge=1),
  page_size: int = Query(default=20, ge=1, le=100),
  user_id: Optional[str] = Query(default=None),
  device_type: Optional[DeviceType] = Query(default=None),
  ip_address: Optional[str] = Query(default=None),
  sort_by: str = Query(default="created_at"),
  sort_order: str = Query(default="desc", pattern="^(asc|desc)$"),
  current_user: UserPublic = Depends(require_permission("devices:read")),
) -> DeviceListResponse:
  filters = DeviceFilterParams(
    user_id=user_id,
    device_type=device_type,
    ip_address=ip_address,
  )
  return await device_service.list_devices(
    page=page,
    page_size=page_size,
    filters=filters,
    sort_by=sort_by,
    sort_order=sort_order,
  )


@router.get(
  "/{device_id}",
  response_model=DeviceDetailResponse,
  summary="Retrieve a registered device",
)
async def get_device(
  device_id: str,
  current_user: UserPublic = Depends(require_permission("devices:read")),
) -> DeviceDetailResponse:
  return await device_service.get_device(device_id)


@router.patch(
  "/{device_id}",
  response_model=DeviceUpdateResponse,
  summary="Partially update a registered device",
)
async def patch_device(
  device_id: str,
  update_data: DeviceUpdate,
  current_user: UserPublic = Depends(require_permission("devices:write")),
) -> DeviceUpdateResponse:
  return await device_service.update_device(device_id, update_data)


@router.delete(
  "/{device_id}",
  response_model=DeviceDeleteResponse,
  summary="Delete a registered device without cascading related records",
)
async def delete_device(
  device_id: str,
  current_user: UserPublic = Depends(require_permission("devices:write")),
) -> DeviceDeleteResponse:
  return await device_service.delete_device(device_id)
