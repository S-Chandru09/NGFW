import math
import re
from typing import Any, Optional

from bson import ObjectId
from fastapi import HTTPException, status
from pymongo import ASCENDING, DESCENDING

from database import get_audit_logs_collection
from models.log import LogCreate, LogDocument, LogPublic
from schemas.log import (
  LogCreateResponse,
  LogDeleteResponse,
  LogDetailResponse,
  LogFilterParams,
  LogListResponse,
  LogSearchParams,
  LogSearchResponse,
  PaginationMeta,
)


class LogService:
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

  def _build_filter_query(self, filters: LogFilterParams) -> dict[str, Any]:
    query: dict[str, Any] = {}

    if filters.event_type is not None:
      query["event_type"] = filters.event_type.value

    if filters.severity is not None:
      query["severity"] = filters.severity.value

    if filters.user_id is not None:
      query["user_id"] = filters.user_id

    if filters.username is not None:
      query["username"] = {"$regex": re.escape(filters.username), "$options": "i"}

    if filters.ip_address is not None:
      query["ip_address"] = filters.ip_address

    if filters.source is not None:
      query["source"] = {"$regex": re.escape(filters.source), "$options": "i"}

    if filters.resource_type is not None:
      query["resource_type"] = filters.resource_type

    if filters.resource_id is not None:
      query["resource_id"] = filters.resource_id

    if filters.date_from is not None or filters.date_to is not None:
      created_at_filter: dict[str, Any] = {}

      if filters.date_from is not None:
        created_at_filter["$gte"] = filters.date_from

      if filters.date_to is not None:
        created_at_filter["$lte"] = filters.date_to

      query["created_at"] = created_at_filter

    return query

  def _build_search_query(self, search_params: LogSearchParams) -> dict[str, Any]:
    query = self._build_filter_query(search_params)

    if search_params.q:
      search_regex = {"$regex": re.escape(search_params.q.strip()), "$options": "i"}
      search_conditions = [
        {"message": search_regex},
        {"description": search_regex},
        {"username": search_regex},
        {"ip_address": search_regex},
        {"source": search_regex},
        {"event_type": search_regex},
        {"resource_type": search_regex},
        {"resource_id": search_regex},
        {"log_id": search_regex},
      ]
      query["$or"] = search_conditions

    return query

  def _filters_to_dict(self, filters: LogFilterParams) -> dict[str, Any]:
    return filters.model_dump(exclude_none=True)

  async def create_log(self, log_data: LogCreate) -> LogCreateResponse:
    logs_collection = get_audit_logs_collection()
    log_document = LogDocument.create_document(log_data)

    insert_result = await logs_collection.insert_one(log_document)
    created_document = await logs_collection.find_one({"_id": insert_result.inserted_id})
    created_log = LogDocument.to_public_from_mongo(created_document)

    if created_log is None:
      raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="Failed to create log entry",
      )

    return LogCreateResponse(
      success=True,
      message="Log entry created successfully",
      log=created_log,
    )

  async def get_log_by_id(self, log_id: str) -> LogDetailResponse:
    logs_collection = get_audit_logs_collection()
    document = await logs_collection.find_one({"log_id": log_id})

    if document is None and ObjectId.is_valid(log_id):
      document = await logs_collection.find_one({"_id": ObjectId(log_id)})

    log = LogDocument.to_public_from_mongo(document)

    if log is None:
      raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Log with id '{log_id}' not found",
      )

    return LogDetailResponse(
      success=True,
      message="Log entry retrieved successfully",
      log=log,
    )

  async def list_logs(
    self,
    page: int = 1,
    page_size: int = 20,
    filters: Optional[LogFilterParams] = None,
    sort_by: str = "created_at",
    sort_order: str = "desc",
  ) -> LogListResponse:
    logs_collection = get_audit_logs_collection()
    filter_params = filters or LogFilterParams()
    query = self._build_filter_query(filter_params)
    skip = (page - 1) * page_size
    sort_direction = self._get_sort_direction(sort_order)

    total_items = await logs_collection.count_documents(query)
    cursor = (
      logs_collection.find(query)
      .sort(sort_by, sort_direction)
      .skip(skip)
      .limit(page_size)
    )
    documents = await cursor.to_list(length=page_size)

    items: list[LogPublic] = []
    for document in documents:
      log = LogDocument.to_public_from_mongo(document)
      if log is not None:
        items.append(log)

    return LogListResponse(
      success=True,
      message="Logs retrieved successfully",
      items=items,
      pagination=self._build_pagination_meta(page, page_size, total_items),
    )

  async def search_logs(
    self,
    search_params: LogSearchParams,
    page: int = 1,
    page_size: int = 20,
  ) -> LogSearchResponse:
    logs_collection = get_audit_logs_collection()
    query = self._build_search_query(search_params)
    skip = (page - 1) * page_size
    sort_direction = self._get_sort_direction(search_params.sort_order)

    total_items = await logs_collection.count_documents(query)
    cursor = (
      logs_collection.find(query)
      .sort(search_params.sort_by, sort_direction)
      .skip(skip)
      .limit(page_size)
    )
    documents = await cursor.to_list(length=page_size)

    items: list[LogPublic] = []
    for document in documents:
      log = LogDocument.to_public_from_mongo(document)
      if log is not None:
        items.append(log)

    return LogSearchResponse(
      success=True,
      message="Log search completed successfully",
      query=search_params.q,
      filters_applied=self._filters_to_dict(search_params),
      items=items,
      pagination=self._build_pagination_meta(page, page_size, total_items),
    )

  async def delete_log(self, log_id: str) -> LogDeleteResponse:
    logs_collection = get_audit_logs_collection()
    delete_filter = {"log_id": log_id}

    if ObjectId.is_valid(log_id):
      delete_result = await logs_collection.delete_one(
        {"$or": [{"log_id": log_id}, {"_id": ObjectId(log_id)}]}
      )
    else:
      delete_result = await logs_collection.delete_one(delete_filter)

    if delete_result.deleted_count == 0:
      raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Log with id '{log_id}' not found",
      )

    return LogDeleteResponse(
      success=True,
      message="Log entry deleted successfully",
      log_id=log_id,
    )


log_service = LogService()
