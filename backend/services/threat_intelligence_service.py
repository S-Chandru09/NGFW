import math
import re
from datetime import datetime, timezone
from typing import Any, Optional

from bson import ObjectId
from fastapi import HTTPException, status
from pymongo import ASCENDING, DESCENDING
from pymongo.errors import DuplicateKeyError

from database import get_ioc_indicators_collection
from models.threat_intelligence import (
  IOCCreate,
  IOCDocument,
  IOCType,
  IOCUpdate,
  ThreatLevel,
  detect_hash_type,
)
from schemas.log import PaginationMeta
from schemas.threat_intelligence import (
  IOCCreateResponse,
  IOCDeleteResponse,
  IOCDetailResponse,
  IOCFilterParams,
  IOCListResponse,
  IOCLookupResponse,
  IOCLookupResult,
  IOCReputationCheckResponse,
  IOCSearchResponse,
  ThreatIntelligenceStatsResponse,
  IOCUpdateResponse,
)


class ThreatIntelligenceService:
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

  def _build_filter_query(self, filters: IOCFilterParams) -> dict[str, Any]:
    query: dict[str, Any] = {}

    if filters.ioc_type is not None:
      query["ioc_type"] = filters.ioc_type.value

    if filters.hash_type is not None:
      query["hash_type"] = filters.hash_type.value

    if filters.threat_level is not None:
      query["threat_level"] = filters.threat_level.value

    if filters.is_malicious is not None:
      query["is_malicious"] = filters.is_malicious

    if filters.is_active is not None:
      query["is_active"] = filters.is_active

    if filters.source is not None:
      query["source"] = {"$regex": re.escape(filters.source), "$options": "i"}

    if filters.country is not None:
      query["country"] = {"$regex": re.escape(filters.country), "$options": "i"}

    if filters.threat_category is not None:
      query["threat_categories"] = filters.threat_category.value

    if filters.tag is not None:
      query["tags"] = filters.tag

    if filters.min_reputation_score is not None or filters.max_reputation_score is not None:
      score_filter: dict[str, Any] = {}

      if filters.min_reputation_score is not None:
        score_filter["$gte"] = filters.min_reputation_score

      if filters.max_reputation_score is not None:
        score_filter["$lte"] = filters.max_reputation_score

      query["reputation_score"] = score_filter

    return query

  def _build_search_query(self, search_text: str, filters: IOCFilterParams) -> dict[str, Any]:
    query = self._build_filter_query(filters)
    search_regex = {"$regex": re.escape(search_text.strip()), "$options": "i"}

    search_conditions = [
      {"value": search_regex},
      {"description": search_regex},
      {"source": search_regex},
      {"country": search_regex},
      {"asn": search_regex},
      {"isp": search_regex},
      {"tags": search_regex},
      {"ioc_id": search_regex},
    ]

    if "$or" in query:
      query = {"$and": [query, {"$or": search_conditions}]}
    else:
      query["$or"] = search_conditions

    return query

  async def _get_ioc_document(self, identifier: str) -> Optional[dict[str, Any]]:
    collection = get_ioc_indicators_collection()
    document = await collection.find_one({"ioc_id": identifier})

    if document is None:
      document = await collection.find_one({"value": identifier})

    if document is None and ObjectId.is_valid(identifier):
      document = await collection.find_one({"_id": ObjectId(identifier)})

    return document

  async def _increment_hit_count(self, document: dict[str, Any]) -> None:
    collection = get_ioc_indicators_collection()
    now = datetime.now(timezone.utc)

    await collection.update_one(
      {"_id": document["_id"]},
      {
        "$inc": {"hit_count": 1},
        "$set": {"last_seen_at": now, "updated_at": now},
      },
    )

  async def create_ioc(
    self,
    ioc_data: IOCCreate,
    created_by: Optional[str] = None,
  ) -> IOCCreateResponse:
    collection = get_ioc_indicators_collection()
    ioc_document = IOCDocument.create_document(ioc_data, created_by=created_by)

    existing = await collection.find_one({"value_hash": ioc_document["value_hash"]})
    if existing is not None:
      raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=f"IOC already exists with value '{ioc_data.value}'",
      )

    try:
      insert_result = await collection.insert_one(ioc_document)
    except DuplicateKeyError as exc:
      raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="IOC with this value already exists",
      ) from exc

    created_document = await collection.find_one({"_id": insert_result.inserted_id})
    created_ioc = IOCDocument.to_public_from_mongo(created_document)

    if created_ioc is None:
      raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="Failed to create IOC entry",
      )

    return IOCCreateResponse(
      success=True,
      message="IOC entry created successfully",
      ioc=created_ioc,
    )

  async def get_ioc(self, ioc_id: str) -> IOCDetailResponse:
    document = await self._get_ioc_document(ioc_id)
    ioc = IOCDocument.to_public_from_mongo(document)

    if ioc is None:
      raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"IOC with id '{ioc_id}' not found",
      )

    return IOCDetailResponse(
      success=True,
      message="IOC entry retrieved successfully",
      ioc=ioc,
    )

  async def list_iocs(
    self,
    page: int = 1,
    page_size: int = 20,
    filters: Optional[IOCFilterParams] = None,
    sort_by: str = "reputation_score",
    sort_order: str = "desc",
  ) -> IOCListResponse:
    collection = get_ioc_indicators_collection()
    filter_params = filters or IOCFilterParams()
    query = self._build_filter_query(filter_params)
    skip = (page - 1) * page_size
    sort_direction = self._get_sort_direction(sort_order)

    total_items = await collection.count_documents(query)
    cursor = (
      collection.find(query)
      .sort(sort_by, sort_direction)
      .skip(skip)
      .limit(page_size)
    )
    documents = await cursor.to_list(length=page_size)

    items = []
    for document in documents:
      ioc = IOCDocument.to_public_from_mongo(document)
      if ioc is not None:
        items.append(ioc)

    return IOCListResponse(
      success=True,
      message="IOC entries retrieved successfully",
      items=items,
      pagination=self._build_pagination_meta(page, page_size, total_items),
    )

  async def search_iocs(
    self,
    search_text: str,
    page: int = 1,
    page_size: int = 20,
    filters: Optional[IOCFilterParams] = None,
    sort_by: str = "reputation_score",
    sort_order: str = "desc",
  ) -> IOCSearchResponse:
    collection = get_ioc_indicators_collection()
    filter_params = filters or IOCFilterParams()
    query = self._build_search_query(search_text, filter_params)
    skip = (page - 1) * page_size
    sort_direction = self._get_sort_direction(sort_order)

    total_items = await collection.count_documents(query)
    cursor = (
      collection.find(query)
      .sort(sort_by, sort_direction)
      .skip(skip)
      .limit(page_size)
    )
    documents = await cursor.to_list(length=page_size)

    items = []
    for document in documents:
      ioc = IOCDocument.to_public_from_mongo(document)
      if ioc is not None:
        items.append(ioc)

    return IOCSearchResponse(
      success=True,
      message="IOC search completed successfully",
      query=search_text,
      filters_applied=filter_params.model_dump(exclude_none=True),
      items=items,
      pagination=self._build_pagination_meta(page, page_size, total_items),
    )

  async def update_ioc(self, ioc_id: str, update_data: IOCUpdate) -> IOCUpdateResponse:
    collection = get_ioc_indicators_collection()
    existing_document = await self._get_ioc_document(ioc_id)

    if existing_document is None:
      raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"IOC with id '{ioc_id}' not found",
      )

    updated_document_data = IOCDocument.update_document(existing_document, update_data)

    await collection.update_one(
      {"_id": existing_document["_id"]},
      {"$set": updated_document_data},
    )

    updated_document = await collection.find_one({"_id": existing_document["_id"]})
    updated_ioc = IOCDocument.to_public_from_mongo(updated_document)

    if updated_ioc is None:
      raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="Failed to update IOC entry",
      )

    return IOCUpdateResponse(
      success=True,
      message="IOC entry updated successfully",
      ioc=updated_ioc,
    )

  async def delete_ioc(self, ioc_id: str) -> IOCDeleteResponse:
    collection = get_ioc_indicators_collection()
    existing_document = await self._get_ioc_document(ioc_id)

    if existing_document is None:
      raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"IOC with id '{ioc_id}' not found",
      )

    await collection.delete_one({"_id": existing_document["_id"]})

    return IOCDeleteResponse(
      success=True,
      message="IOC entry deleted successfully",
      ioc_id=existing_document.get("ioc_id", ioc_id),
    )

  async def check_reputation(
    self,
    value: str,
    ioc_type: Optional[IOCType] = None,
    increment_hit: bool = True,
  ) -> IOCReputationCheckResponse:
    collection = get_ioc_indicators_collection()
    query: dict[str, Any] = {"value": value.strip()}

    if ioc_type == IOCType.HASH:
      query["value"] = value.strip().lower()
    elif ioc_type == IOCType.DOMAIN:
      query["value"] = value.strip().lower()

    if ioc_type is not None:
      query["ioc_type"] = ioc_type.value

    document = await collection.find_one(query)

    if document is None and ioc_type == IOCType.HASH:
      detected_hash_type = detect_hash_type(value)
      if detected_hash_type is not None:
        document = await collection.find_one(
          {"ioc_type": IOCType.HASH.value, "value": value.strip().lower()}
        )

    if document is None:
      return IOCReputationCheckResponse(
        success=True,
        message="IOC not found in threat intelligence database",
        found=False,
        value=value,
        is_malicious=False,
        reputation_score=0,
        threat_level=ThreatLevel.SAFE,
      )

    if increment_hit:
      await self._increment_hit_count(document)
      document = await collection.find_one({"_id": document["_id"]})

    ioc = IOCDocument.to_public_from_mongo(document)

    return IOCReputationCheckResponse(
      success=True,
      message="IOC reputation check completed",
      found=True,
      value=value,
      ioc=ioc,
      is_malicious=ioc.is_malicious if ioc else False,
      reputation_score=ioc.reputation_score if ioc else 0,
      threat_level=ioc.threat_level if ioc else ThreatLevel.SAFE,
    )

  async def lookup_iocs(self, values: list[str]) -> IOCLookupResponse:
    results = []

    for value in values:
      check_result = await self.check_reputation(value=value, increment_hit=True)
      results.append(
        IOCLookupResult(
          value=value,
          found=check_result.found,
          is_malicious=check_result.is_malicious,
          reputation_score=check_result.reputation_score,
          threat_level=check_result.threat_level,
          ioc=check_result.ioc,
        )
      )

    return IOCLookupResponse(
      success=True,
      message="IOC lookup completed successfully",
      results=results,
    )

  async def get_stats(self) -> ThreatIntelligenceStatsResponse:
    collection = get_ioc_indicators_collection()
    now = datetime.now(timezone.utc)

    total_iocs = await collection.count_documents({})
    malicious_iocs = await collection.count_documents({"is_malicious": True})
    active_iocs = await collection.count_documents({"is_active": True})
    ip_count = await collection.count_documents({"ioc_type": IOCType.IP.value})
    hash_count = await collection.count_documents({"ioc_type": IOCType.HASH.value})
    domain_count = await collection.count_documents({"ioc_type": IOCType.DOMAIN.value})
    critical_threats = await collection.count_documents({"threat_level": ThreatLevel.CRITICAL.value})
    high_threats = await collection.count_documents({"threat_level": ThreatLevel.HIGH.value})

    return ThreatIntelligenceStatsResponse(
      success=True,
      message="Threat intelligence statistics retrieved successfully",
      total_iocs=total_iocs,
      malicious_iocs=malicious_iocs,
      active_iocs=active_iocs,
      ip_count=ip_count,
      hash_count=hash_count,
      domain_count=domain_count,
      critical_threats=critical_threats,
      high_threats=high_threats,
      generated_at=now,
    )

  async def list_by_type(
    self,
    ioc_type: IOCType,
    page: int = 1,
    page_size: int = 20,
    filters: Optional[IOCFilterParams] = None,
    sort_by: str = "reputation_score",
    sort_order: str = "desc",
  ) -> IOCListResponse:
    filter_params = filters or IOCFilterParams()
    filter_params.ioc_type = ioc_type

    return await self.list_iocs(
      page=page,
      page_size=page_size,
      filters=filter_params,
      sort_by=sort_by,
      sort_order=sort_order,
    )


threat_intelligence_service = ThreatIntelligenceService()
