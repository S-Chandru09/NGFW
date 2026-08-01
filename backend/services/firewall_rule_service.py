import math
from datetime import datetime, timezone
from typing import Any, Optional

from bson import ObjectId
from fastapi import HTTPException, status
from pymongo import ASCENDING, DESCENDING
from pymongo.errors import DuplicateKeyError

from database import get_firewall_rules_collection
from models.firewall_rule import (
  FirewallRuleAction,
  FirewallRuleCreate,
  FirewallRuleDocument,
  FirewallRulePublic,
  FirewallRuleUpdate,
)
from schemas.firewall_rule import (
  FirewallRuleActionSummary,
  FirewallRuleCreateResponse,
  FirewallRuleDeleteResponse,
  FirewallRuleDetailResponse,
  FirewallRuleFilterParams,
  FirewallRuleListResponse,
  FirewallRuleStatsResponse,
  FirewallRuleUpdateResponse,
)
from schemas.log import PaginationMeta


class FirewallRuleService:
  async def _expire_temporary_rules(self) -> None:
    rules_collection = get_firewall_rules_collection()
    now = datetime.now(timezone.utc)

    await rules_collection.update_many(
      {
        "action": FirewallRuleAction.TEMPORARY_BLOCK.value,
        "expires_at": {"$lte": now},
        "is_expired": False,
      },
      {
        "$set": {
          "is_expired": True,
          "is_enabled": False,
          "updated_at": now,
        }
      },
    )

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

  def _build_filter_query(self, filters: FirewallRuleFilterParams) -> dict[str, Any]:
    query: dict[str, Any] = {}

    if filters.action is not None:
      query["action"] = filters.action.value

    if filters.protocol is not None:
      query["protocol"] = filters.protocol.value

    if filters.source_ip is not None:
      query["source_ip"] = filters.source_ip

    if filters.destination_ip is not None:
      query["destination_ip"] = filters.destination_ip

    if filters.is_enabled is not None:
      query["is_enabled"] = filters.is_enabled

    if filters.is_expired is not None:
      query["is_expired"] = filters.is_expired

    if filters.created_by is not None:
      query["created_by"] = filters.created_by

    return query

  async def _get_rule_document(self, rule_id: str) -> Optional[dict[str, Any]]:
    rules_collection = get_firewall_rules_collection()
    document = await rules_collection.find_one({"rule_id": rule_id})

    if document is None and ObjectId.is_valid(rule_id):
      document = await rules_collection.find_one({"_id": ObjectId(rule_id)})

    return document

  async def create_rule(
    self,
    rule_data: FirewallRuleCreate,
    created_by: Optional[str] = None,
  ) -> FirewallRuleCreateResponse:
    await self._expire_temporary_rules()
    rules_collection = get_firewall_rules_collection()

    existing_rule = await rules_collection.find_one({"name": rule_data.name})
    if existing_rule is not None:
      raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Firewall rule with this name already exists",
      )

    rule_document = FirewallRuleDocument.create_document(rule_data, created_by=created_by)

    try:
      insert_result = await rules_collection.insert_one(rule_document)
    except DuplicateKeyError as exc:
      raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Firewall rule with this name already exists",
      ) from exc

    created_document = await rules_collection.find_one({"_id": insert_result.inserted_id})
    created_rule = FirewallRuleDocument.to_public_from_mongo(created_document)

    if created_rule is None:
      raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="Failed to create firewall rule",
      )

    return FirewallRuleCreateResponse(
      success=True,
      message=f"Firewall rule '{created_rule.name}' created successfully",
      rule=created_rule,
    )

  async def get_rule(self, rule_id: str) -> FirewallRuleDetailResponse:
    await self._expire_temporary_rules()
    document = await self._get_rule_document(rule_id)
    rule = FirewallRuleDocument.to_public_from_mongo(document)

    if rule is None:
      raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Firewall rule with id '{rule_id}' not found",
      )

    return FirewallRuleDetailResponse(
      success=True,
      message="Firewall rule retrieved successfully",
      rule=rule,
    )

  async def list_rules(
    self,
    page: int = 1,
    page_size: int = 20,
    filters: Optional[FirewallRuleFilterParams] = None,
    sort_by: str = "priority",
    sort_order: str = "desc",
  ) -> FirewallRuleListResponse:
    await self._expire_temporary_rules()
    rules_collection = get_firewall_rules_collection()
    filter_params = filters or FirewallRuleFilterParams()
    query = self._build_filter_query(filter_params)
    skip = (page - 1) * page_size
    sort_direction = self._get_sort_direction(sort_order)

    total_items = await rules_collection.count_documents(query)
    cursor = (
      rules_collection.find(query)
      .sort(sort_by, sort_direction)
      .skip(skip)
      .limit(page_size)
    )
    documents = await cursor.to_list(length=page_size)

    items: list[FirewallRulePublic] = []
    for document in documents:
      rule = FirewallRuleDocument.to_public_from_mongo(document)
      if rule is not None:
        items.append(rule)

    return FirewallRuleListResponse(
      success=True,
      message="Firewall rules retrieved successfully",
      items=items,
      pagination=self._build_pagination_meta(page, page_size, total_items),
    )

  async def update_rule(
    self,
    rule_id: str,
    update_data: FirewallRuleUpdate,
    partial: bool = True,
  ) -> FirewallRuleUpdateResponse:
    await self._expire_temporary_rules()
    rules_collection = get_firewall_rules_collection()
    existing_document = await self._get_rule_document(rule_id)

    if existing_document is None:
      raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Firewall rule with id '{rule_id}' not found",
      )

    if update_data.name is not None:
      duplicate_rule = await rules_collection.find_one(
        {
          "name": update_data.name,
          "rule_id": {"$ne": existing_document.get("rule_id")},
        }
      )
      if duplicate_rule is not None:
        raise HTTPException(
          status_code=status.HTTP_400_BAD_REQUEST,
          detail="Firewall rule with this name already exists",
        )

    merged_action = update_data.action.value if update_data.action else existing_document.get("action")
    merged_expires_at = (
      update_data.expires_at
      if update_data.expires_at is not None
      else existing_document.get("expires_at")
    )

    if merged_action == FirewallRuleAction.TEMPORARY_BLOCK.value and merged_expires_at is None:
      raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="expires_at is required for temporary_block rules",
      )

    if merged_action != FirewallRuleAction.TEMPORARY_BLOCK.value and update_data.expires_at is not None:
      raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="expires_at is only allowed for temporary_block rules",
      )

    updated_document_data = FirewallRuleDocument.update_document(existing_document, update_data)

    await rules_collection.update_one(
      {"_id": existing_document["_id"]},
      {"$set": updated_document_data},
    )

    updated_document = await rules_collection.find_one({"_id": existing_document["_id"]})
    updated_rule = FirewallRuleDocument.to_public_from_mongo(updated_document)

    if updated_rule is None:
      raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="Failed to update firewall rule",
      )

    return FirewallRuleUpdateResponse(
      success=True,
      message=f"Firewall rule '{updated_rule.name}' updated successfully",
      rule=updated_rule,
    )

  async def delete_rule(self, rule_id: str) -> FirewallRuleDeleteResponse:
    rules_collection = get_firewall_rules_collection()

    if ObjectId.is_valid(rule_id):
      delete_result = await rules_collection.delete_one(
        {"$or": [{"rule_id": rule_id}, {"_id": ObjectId(rule_id)}]}
      )
    else:
      delete_result = await rules_collection.delete_one({"rule_id": rule_id})

    if delete_result.deleted_count == 0:
      raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Firewall rule with id '{rule_id}' not found",
      )

    return FirewallRuleDeleteResponse(
      success=True,
      message="Firewall rule deleted successfully",
      rule_id=rule_id,
    )

  async def get_stats(self) -> FirewallRuleStatsResponse:
    await self._expire_temporary_rules()
    rules_collection = get_firewall_rules_collection()

    total_rules = await rules_collection.count_documents({})
    enabled_rules = await rules_collection.count_documents({"is_enabled": True, "is_expired": False})
    disabled_rules = await rules_collection.count_documents({"is_enabled": False})
    expired_rules = await rules_collection.count_documents({"is_expired": True})

    pipeline = [
      {
        "$group": {
          "_id": "$action",
          "total": {"$sum": 1},
          "enabled": {
            "$sum": {
              "$cond": [
                {"$and": [{"$eq": ["$is_enabled", True]}, {"$eq": ["$is_expired", False]}]},
                1,
                0,
              ]
            }
          },
          "disabled": {
            "$sum": {
              "$cond": [{"$eq": ["$is_enabled", False]}, 1, 0]
            }
          },
          "expired": {
            "$sum": {
              "$cond": [{"$eq": ["$is_expired", True]}, 1, 0]
            }
          },
        }
      },
      {"$sort": {"_id": 1}},
    ]

    results = await rules_collection.aggregate(pipeline).to_list(length=20)
    action_summary = []

    for item in results:
      action_summary.append(
        FirewallRuleActionSummary(
          action=FirewallRuleAction(item["_id"]),
          total=item.get("total", 0),
          enabled=item.get("enabled", 0),
          disabled=item.get("disabled", 0),
          expired=item.get("expired", 0),
        )
      )

    return FirewallRuleStatsResponse(
      success=True,
      message="Firewall rule statistics retrieved successfully",
      total_rules=total_rules,
      enabled_rules=enabled_rules,
      disabled_rules=disabled_rules,
      expired_rules=expired_rules,
      action_summary=action_summary,
    )


firewall_rule_service = FirewallRuleService()
