from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field

from schemas.log import PaginationMeta


class TaxiiDiscoveryResponse(BaseModel):
  title: str
  description: str
  contact: str
  default: str
  api_roots: list[str]


class TaxiiApiRootResponse(BaseModel):
  title: str
  description: str
  versions: list[str]
  max_content_length: int


class TaxiiCollectionPublic(BaseModel):
  id: str
  title: str
  description: str
  can_read: bool = True
  can_write: bool = False
  media_types: list[str]
  object_count: int = 0
  last_synced_at: Optional[datetime] = None


class TaxiiCollectionsResponse(BaseModel):
  collections: list[TaxiiCollectionPublic]


class StixObjectPublic(BaseModel):
  stix_id: str
  collection_id: str
  object_type: str
  name: str
  stix_payload: dict[str, Any]
  source_ioc_id: Optional[str] = None
  created_at: datetime
  modified: datetime


class TaxiiObjectsEnvelope(BaseModel):
  more: bool
  next: Optional[str] = None
  objects: list[dict[str, Any]]


class StixBundleResponse(BaseModel):
  type: str = "bundle"
  id: str
  objects: list[dict[str, Any]]


class TaxiiSimulationStatsResponse(BaseModel):
  success: bool = True
  message: str
  taxii_version: str
  stix_version: str
  api_root: str
  total_collections: int
  active_collections: int
  total_objects: int
  indicator_count: int
  malware_count: int
  threat_actor_count: int
  attack_pattern_count: int
  last_synced_at: Optional[datetime] = None
  collections: list[TaxiiCollectionPublic]
  object_type_distribution: dict[str, int]
  generated_at: datetime


class TaxiiSyncResponse(BaseModel):
  success: bool = True
  message: str
  collections_synced: int
  objects_created: int
  objects_updated: int
  synced_at: datetime


class StixObjectListResponse(BaseModel):
  success: bool = True
  message: str
  items: list[StixObjectPublic]
  pagination: PaginationMeta
