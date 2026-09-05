import math
from typing import Any, Optional

from bson import ObjectId
from fastapi import HTTPException, status
from pymongo import ASCENDING, DESCENDING
from pymongo.errors import DuplicateKeyError

from database import get_devices_collection, get_users_collection
from models.device import DeviceCreate, DeviceDocument, DevicePublic, DeviceUpdate
from schemas.device import (
  DeviceCreateResponse,
  DeviceDeleteResponse,
  DeviceDetailResponse,
  DeviceFilterParams,
  DeviceListResponse,
  DeviceUpdateResponse,
)
from schemas.log import PaginationMeta


class DeviceService:
  def _build_pagination_meta(self, page: int, page_size: int, total_items: int) -> PaginationMeta:
    total_pages = math.ceil(total_items / page_size) if page_size > 0 else 0

    return PaginationMeta(
      page=page,
      page_size=page_size,
      total_items=total_items,
      total_pages=total_pages,
      has_next=page < total_pages,
      has_previous=page > 1 and total_pages > 0,
    )

  def _get_sort_direction(self, sort_order: str) -> int:
    return ASCENDING if sort_order.lower() == "asc" else DESCENDING

  def _build_filter_query(self, filters: DeviceFilterParams) -> dict[str, Any]:
    query: dict[str, Any] = {}

    if filters.user_id is not None:
      query["user_id"] = filters.user_id

    if filters.device_type is not None:
      query["device_type"] = filters.device_type.value

    if filters.ip_address is not None:
      query["ip_address"] = filters.ip_address

    return query

  async def _get_device_document(self, device_id: str) -> Optional[dict[str, Any]]:
    devices_collection = get_devices_collection()
    document = await devices_collection.find_one({"device_id": device_id})

    if document is None and ObjectId.is_valid(device_id):
      document = await devices_collection.find_one({"_id": ObjectId(device_id)})

    return document

  async def _resolve_existing_user_id(self, user_id: str) -> str:
    users_collection = get_users_collection()
    document = None

    if ObjectId.is_valid(user_id):
      document = await users_collection.find_one({"_id": ObjectId(user_id)})

    if document is None:
      document = await users_collection.find_one({"username": user_id.strip().lower()})

    if document is None:
      raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=f"User with id '{user_id}' not found",
      )

    return str(document["_id"])

  def _duplicate_ip_error(self) -> HTTPException:
    return HTTPException(
      status_code=status.HTTP_409_CONFLICT,
      detail="A device with this IP address already exists",
    )

  async def _ensure_unique_ip(self, ip_address: Optional[str], exclude_device_id: Optional[str] = None) -> None:
    if not ip_address:
      return

    devices_collection = get_devices_collection()
    query: dict[str, Any] = {"ip_address": ip_address}
    if exclude_device_id:
      query["device_id"] = {"$ne": exclude_device_id}

    existing = await devices_collection.find_one(query)
    if existing is not None:
      raise self._duplicate_ip_error()

  def _raise_duplicate_key(self, exc: DuplicateKeyError) -> None:
    error_text = str(exc).lower()
    if "ip_address" in error_text:
      raise self._duplicate_ip_error() from exc

    raise HTTPException(
      status_code=status.HTTP_409_CONFLICT,
      detail="Device already exists",
    ) from exc

  def _to_public_or_500(self, document: Optional[dict[str, Any]], action: str) -> DevicePublic:
    device = DeviceDocument.to_public_from_mongo(document)
    if device is None:
      raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail=f"Failed to {action} device",
      )
    return device

  async def create_device(self, device_data: DeviceCreate) -> DeviceCreateResponse:
    resolved_user_id = None
    if device_data.user_id:
      resolved_user_id = await self._resolve_existing_user_id(device_data.user_id)

    await self._ensure_unique_ip(device_data.ip_address)

    persist_data = device_data.model_copy(update={"user_id": resolved_user_id})
    device_document = DeviceDocument.create_document(persist_data)
    devices_collection = get_devices_collection()

    try:
      insert_result = await devices_collection.insert_one(device_document)
    except DuplicateKeyError as exc:
      self._raise_duplicate_key(exc)

    created_document = await devices_collection.find_one({"_id": insert_result.inserted_id})
    created_device = self._to_public_or_500(created_document, "create")

    return DeviceCreateResponse(
      success=True,
      message=f"Device '{created_device.device_name}' created successfully",
      device=created_device,
    )

  async def get_device(self, device_id: str) -> DeviceDetailResponse:
    document = await self._get_device_document(device_id)
    device = DeviceDocument.to_public_from_mongo(document)

    if device is None:
      raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Device with id '{device_id}' not found",
      )

    return DeviceDetailResponse(
      success=True,
      message="Device retrieved successfully",
      device=device,
    )

  async def list_devices(
    self,
    page: int = 1,
    page_size: int = 20,
    filters: Optional[DeviceFilterParams] = None,
    sort_by: str = "created_at",
    sort_order: str = "desc",
  ) -> DeviceListResponse:
    devices_collection = get_devices_collection()
    query = self._build_filter_query(filters or DeviceFilterParams())
    sort_field = sort_by if sort_by in {
      "created_at",
      "updated_at",
      "device_name",
      "ip_address",
      "trust_score",
      "last_seen_at",
    } else "created_at"
    sort_direction = self._get_sort_direction(sort_order)
    skip = (page - 1) * page_size

    total_items = await devices_collection.count_documents(query)
    cursor = (
      devices_collection.find(query)
      .sort(sort_field, sort_direction)
      .skip(skip)
      .limit(page_size)
    )
    documents = await cursor.to_list(length=page_size)
    items = [
      device
      for document in documents
      if (device := DeviceDocument.to_public_from_mongo(document)) is not None
    ]

    return DeviceListResponse(
      success=True,
      message="Devices retrieved successfully",
      items=items,
      pagination=self._build_pagination_meta(page, page_size, total_items),
    )

  async def update_device(self, device_id: str, update_data: DeviceUpdate) -> DeviceUpdateResponse:
    devices_collection = get_devices_collection()
    existing_document = await self._get_device_document(device_id)

    if existing_document is None:
      raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Device with id '{device_id}' not found",
      )

    update_fields = DeviceDocument.update_fields(update_data)

    if "user_id" in update_fields and update_fields["user_id"]:
      update_fields["user_id"] = await self._resolve_existing_user_id(str(update_fields["user_id"]))

    if "ip_address" in update_fields:
      await self._ensure_unique_ip(
        update_fields["ip_address"],
        exclude_device_id=existing_document.get("device_id"),
      )

    try:
      await devices_collection.update_one(
        {"_id": existing_document["_id"]},
        {"$set": update_fields},
      )
    except DuplicateKeyError as exc:
      self._raise_duplicate_key(exc)

    updated_document = await devices_collection.find_one({"_id": existing_document["_id"]})
    updated_device = self._to_public_or_500(updated_document, "update")

    return DeviceUpdateResponse(
      success=True,
      message=f"Device '{updated_device.device_name}' updated successfully",
      device=updated_device,
    )

  async def delete_device(self, device_id: str) -> DeviceDeleteResponse:
    devices_collection = get_devices_collection()
    existing_document = await self._get_device_document(device_id)

    if existing_document is None:
      raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Device with id '{device_id}' not found",
      )

    await devices_collection.delete_one({"_id": existing_document["_id"]})

    return DeviceDeleteResponse(
      success=True,
      message=f"Device '{existing_document.get('device_name', device_id)}' deleted successfully",
      device_id=str(existing_document.get("device_id", device_id)),
    )


device_service = DeviceService()
