import math
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import uuid4

from fastapi import HTTPException, status
from pymongo import ASCENDING, DESCENDING

from database import (
  get_ioc_indicators_collection,
  get_stix_objects_collection,
  get_taxii_collections_collection,
)
from models.stix_taxii import (
  API_ROOT_PATH,
  DEFAULT_COLLECTIONS,
  SEED_ATTACK_PATTERNS,
  SEED_MALWARE,
  SEED_THREAT_ACTORS,
  STIX_SPEC_VERSION,
  TAXII_VERSION,
  StixObjectDocument,
  TaxiiCollectionDocument,
  utc_now,
)
from schemas.log import PaginationMeta
from schemas.stix_taxii import (
  StixBundleResponse,
  StixObjectListResponse,
  StixObjectPublic,
  TaxiiApiRootResponse,
  TaxiiCollectionPublic,
  TaxiiCollectionsResponse,
  TaxiiDiscoveryResponse,
  TaxiiObjectsEnvelope,
  TaxiiSimulationStatsResponse,
  TaxiiSyncResponse,
)


class StixTaxiiService:
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

  def _serialize_collection(self, document: dict[str, Any]) -> TaxiiCollectionPublic:
    return TaxiiCollectionPublic(
      id=document["collection_id"],
      title=document["title"],
      description=document["description"],
      can_read=document.get("can_read", True),
      can_write=document.get("can_write", False),
      media_types=document.get("media_types", []),
      object_count=document.get("object_count", 0),
      last_synced_at=document.get("last_synced_at"),
    )

  def _serialize_stix_object(self, document: dict[str, Any]) -> StixObjectPublic:
    return StixObjectPublic(
      stix_id=document["stix_id"],
      collection_id=document["collection_id"],
      object_type=document["object_type"],
      name=document["name"],
      stix_payload=document["stix_payload"],
      source_ioc_id=document.get("source_ioc_id"),
      created_at=document["created_at"],
      modified=document["modified"],
    )

  async def ensure_default_collections(self) -> None:
    collections = get_taxii_collections_collection()

    for collection_data in DEFAULT_COLLECTIONS:
      existing = await collections.find_one({"collection_id": collection_data["collection_id"]})
      if existing is None:
        await collections.insert_one(TaxiiCollectionDocument.create_document(collection_data))

  async def _update_collection_counts(self) -> None:
    collections = get_taxii_collections_collection()
    objects = get_stix_objects_collection()

    async for collection in collections.find({}):
      count = await objects.count_documents({"collection_id": collection["collection_id"]})
      await collections.update_one(
        {"collection_id": collection["collection_id"]},
        {"$set": {"object_count": count, "updated_at": utc_now()}},
      )

  async def get_discovery(self) -> TaxiiDiscoveryResponse:
    await self.ensure_default_collections()

    return TaxiiDiscoveryResponse(
      title="AI-NGFW Threat Intelligence TAXII Server",
      description="Simulated TAXII 2.1 feed for STIX threat intelligence sharing",
      contact="security@ai-ngfw.local",
      default=API_ROOT_PATH,
      api_roots=[API_ROOT_PATH],
    )

  async def get_api_root(self) -> TaxiiApiRootResponse:
    return TaxiiApiRootResponse(
      title="AI-NGFW TAXII API Root",
      description="Primary API root for simulated STIX/TAXII collections",
      versions=[TAXII_VERSION],
      max_content_length=10485760,
    )

  async def list_taxii_collections(self) -> TaxiiCollectionsResponse:
    await self.ensure_default_collections()
    collections = get_taxii_collections_collection()

    items: list[TaxiiCollectionPublic] = []
    async for document in collections.find({"is_active": True}).sort("title", ASCENDING):
      items.append(self._serialize_collection(document))

    return TaxiiCollectionsResponse(collections=items)

  async def get_taxii_collection(self, collection_id: str) -> TaxiiCollectionPublic:
    collections = get_taxii_collections_collection()
    document = await collections.find_one({"collection_id": collection_id, "is_active": True})

    if document is None:
      raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"TAXII collection '{collection_id}' not found",
      )

    return self._serialize_collection(document)

  async def get_taxii_objects(
    self,
    collection_id: str,
    limit: int = 20,
    next_token: Optional[str] = None,
  ) -> TaxiiObjectsEnvelope:
    await self.get_taxii_collection(collection_id)

    objects_collection = get_stix_objects_collection()
    query: dict[str, Any] = {"collection_id": collection_id}

    if next_token:
      query["stix_id"] = {"$gt": next_token}

    cursor = objects_collection.find(query).sort("stix_id", ASCENDING).limit(limit + 1)
    documents = [document async for document in cursor]

    has_more = len(documents) > limit
    page_documents = documents[:limit]
    stix_objects = [document["stix_payload"] for document in page_documents]

    return TaxiiObjectsEnvelope(
      more=has_more,
      next=page_documents[-1]["stix_id"] if has_more else None,
      objects=stix_objects,
    )

  async def get_stix_bundle(self, collection_id: str, limit: int = 100) -> StixBundleResponse:
    envelope = await self.get_taxii_objects(collection_id=collection_id, limit=limit)

    return StixBundleResponse(
      type="bundle",
      id=f"bundle--{uuid4()}",
      objects=envelope.objects,
    )

  async def sync_simulation(self) -> TaxiiSyncResponse:
    await self.ensure_default_collections()

    objects_created = 0
    objects_updated = 0
    synced_at = utc_now()

    ioc_collection = get_ioc_indicators_collection()
    stix_collection = get_stix_objects_collection()

    async for ioc in ioc_collection.find({"is_active": True}):
      existing = await stix_collection.find_one({"source_ioc_id": ioc.get("ioc_id")})
      indicator_doc = StixObjectDocument.create_indicator_from_ioc(ioc, "malicious-indicators")

      if existing is None:
        await stix_collection.insert_one(indicator_doc)
        objects_created += 1
      else:
        indicator_doc["stix_id"] = existing["stix_id"]
        indicator_doc["stix_payload"]["id"] = existing["stix_id"]
        indicator_doc["created_at"] = existing["created_at"]
        await stix_collection.update_one(
          {"stix_id": existing["stix_id"]},
          {"$set": {
            "name": indicator_doc["name"],
            "stix_payload": indicator_doc["stix_payload"],
            "modified": synced_at,
          }},
        )
        objects_updated += 1

    for malware in SEED_MALWARE:
      existing = await stix_collection.find_one({
        "collection_id": "malware-families",
        "name": malware["name"],
      })
      if existing is None:
        await stix_collection.insert_one(
          StixObjectDocument.create_malware(
            malware["name"],
            malware["labels"],
            "malware-families",
          ),
        )
        objects_created += 1

    for actor in SEED_THREAT_ACTORS:
      existing = await stix_collection.find_one({
        "collection_id": "threat-actors",
        "name": actor["name"],
      })
      if existing is None:
        await stix_collection.insert_one(
          StixObjectDocument.create_threat_actor(
            actor["name"],
            actor["labels"],
            "threat-actors",
          ),
        )
        objects_created += 1

    for pattern in SEED_ATTACK_PATTERNS:
      existing = await stix_collection.find_one({
        "collection_id": "attack-patterns",
        "name": pattern["name"],
      })
      if existing is None:
        await stix_collection.insert_one(
          StixObjectDocument.create_attack_pattern(
            pattern["name"],
            pattern["external_id"],
            "attack-patterns",
          ),
        )
        objects_created += 1

    await self._update_collection_counts()

    taxii_collections = get_taxii_collections_collection()
    await taxii_collections.update_many(
      {},
      {"$set": {"last_synced_at": synced_at, "updated_at": synced_at}},
    )

    collections_synced = await taxii_collections.count_documents({"is_active": True})

    return TaxiiSyncResponse(
      success=True,
      message="STIX/TAXII simulation synchronized successfully",
      collections_synced=collections_synced,
      objects_created=objects_created,
      objects_updated=objects_updated,
      synced_at=synced_at,
    )

  async def get_simulation_stats(self) -> TaxiiSimulationStatsResponse:
    await self.ensure_default_collections()

    collections = get_taxii_collections_collection()
    objects = get_stix_objects_collection()

    collection_docs: list[TaxiiCollectionPublic] = []
    last_synced_at: Optional[datetime] = None

    async for document in collections.find({"is_active": True}).sort("title", ASCENDING):
      serialized = self._serialize_collection(document)
      collection_docs.append(serialized)

      synced_at = document.get("last_synced_at")
      if synced_at and (last_synced_at is None or synced_at > last_synced_at):
        last_synced_at = synced_at

    total_objects = await objects.count_documents({})
    indicator_count = await objects.count_documents({"object_type": "indicator"})
    malware_count = await objects.count_documents({"object_type": "malware"})
    threat_actor_count = await objects.count_documents({"object_type": "threat-actor"})
    attack_pattern_count = await objects.count_documents({"object_type": "attack-pattern"})

    object_type_distribution = {
      "indicator": indicator_count,
      "malware": malware_count,
      "threat-actor": threat_actor_count,
      "attack-pattern": attack_pattern_count,
    }

    return TaxiiSimulationStatsResponse(
      success=True,
      message="STIX/TAXII simulation statistics retrieved",
      taxii_version=TAXII_VERSION,
      stix_version=STIX_SPEC_VERSION,
      api_root=API_ROOT_PATH,
      total_collections=len(collection_docs),
      active_collections=len(collection_docs),
      total_objects=total_objects,
      indicator_count=indicator_count,
      malware_count=malware_count,
      threat_actor_count=threat_actor_count,
      attack_pattern_count=attack_pattern_count,
      last_synced_at=last_synced_at,
      collections=collection_docs,
      object_type_distribution=object_type_distribution,
      generated_at=utc_now(),
    )

  async def list_stix_objects(
    self,
    page: int = 1,
    page_size: int = 20,
    collection_id: Optional[str] = None,
    object_type: Optional[str] = None,
  ) -> StixObjectListResponse:
    objects = get_stix_objects_collection()
    query: dict[str, Any] = {}

    if collection_id:
      query["collection_id"] = collection_id

    if object_type:
      query["object_type"] = object_type

    total_items = await objects.count_documents(query)
    skip = (page - 1) * page_size

    cursor = (
      objects.find(query)
      .sort("modified", DESCENDING)
      .skip(skip)
      .limit(page_size)
    )

    items = [self._serialize_stix_object(document) async for document in cursor]

    return StixObjectListResponse(
      success=True,
      message="STIX objects retrieved",
      items=items,
      pagination=self._build_pagination_meta(page, page_size, total_items),
    )


stix_taxii_service = StixTaxiiService()
