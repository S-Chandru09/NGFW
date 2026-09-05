from typing import Optional

from pydantic import BaseModel

from models.device import DeviceCreate, DevicePublic, DeviceType, DeviceUpdate
from schemas.log import PaginationMeta


class DeviceFilterParams(BaseModel):
  user_id: Optional[str] = None
  device_type: Optional[DeviceType] = None
  ip_address: Optional[str] = None


class DeviceListResponse(BaseModel):
  success: bool = True
  message: str
  items: list[DevicePublic]
  pagination: PaginationMeta


class DeviceDetailResponse(BaseModel):
  success: bool = True
  message: str
  device: DevicePublic


class DeviceCreateResponse(BaseModel):
  success: bool = True
  message: str
  device: DevicePublic


class DeviceUpdateResponse(BaseModel):
  success: bool = True
  message: str
  device: DevicePublic


class DeviceDeleteResponse(BaseModel):
  success: bool = True
  message: str
  device_id: str


DeviceResponse = DeviceDetailResponse

__all__ = [
  "DeviceCreate",
  "DeviceUpdate",
  "DevicePublic",
  "DeviceFilterParams",
  "DeviceListResponse",
  "DeviceDetailResponse",
  "DeviceResponse",
  "DeviceCreateResponse",
  "DeviceUpdateResponse",
  "DeviceDeleteResponse",
]
