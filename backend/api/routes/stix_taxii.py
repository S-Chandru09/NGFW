from typing import Optional

from fastapi import APIRouter, Depends, Query

from core.auth_utils import require_permission
from models.user import UserPublic
from schemas.stix_taxii import (
  StixBundleResponse,
  StixObjectListResponse,
  TaxiiApiRootResponse,
  TaxiiCollectionPublic,
  TaxiiCollectionsResponse,
  TaxiiDiscoveryResponse,
  TaxiiObjectsEnvelope,
  TaxiiSimulationStatsResponse,
  TaxiiSyncResponse,
)
from services.stix_taxii_service import stix_taxii_service

taxii_router = APIRouter(prefix="/taxii2", tags=["TAXII 2.1 Simulation"])
management_router = APIRouter(prefix="/stix-taxii", tags=["STIX/TAXII Dashboard"])


@taxii_router.get(
  "/",
  response_model=TaxiiDiscoveryResponse,
  summary="TAXII 2.1 discovery document",
)
async def taxii_discovery() -> TaxiiDiscoveryResponse:
  return await stix_taxii_service.get_discovery()


@taxii_router.get(
  "/root/",
  response_model=TaxiiApiRootResponse,
  summary="TAXII API root information",
)
async def taxii_api_root() -> TaxiiApiRootResponse:
  return await stix_taxii_service.get_api_root()


@taxii_router.get(
  "/root/collections/",
  response_model=TaxiiCollectionsResponse,
  summary="List TAXII collections",
)
async def taxii_list_collections() -> TaxiiCollectionsResponse:
  return await stix_taxii_service.list_taxii_collections()


@taxii_router.get(
  "/root/collections/{collection_id}/",
  response_model=TaxiiCollectionPublic,
  summary="Get TAXII collection metadata",
)
async def taxii_get_collection(collection_id: str) -> TaxiiCollectionPublic:
  return await stix_taxii_service.get_taxii_collection(collection_id)


@taxii_router.get(
  "/root/collections/{collection_id}/objects/",
  response_model=TaxiiObjectsEnvelope,
  summary="Get STIX objects from a TAXII collection",
)
async def taxii_get_objects(
  collection_id: str,
  limit: int = Query(default=20, ge=1, le=100),
  next: Optional[str] = Query(default=None),
) -> TaxiiObjectsEnvelope:
  return await stix_taxii_service.get_taxii_objects(
    collection_id=collection_id,
    limit=limit,
    next_token=next,
  )


@taxii_router.get(
  "/root/collections/{collection_id}/bundle/",
  response_model=StixBundleResponse,
  summary="Export collection as STIX 2.1 bundle",
)
async def taxii_get_bundle(
  collection_id: str,
  limit: int = Query(default=100, ge=1, le=500),
) -> StixBundleResponse:
  return await stix_taxii_service.get_stix_bundle(collection_id=collection_id, limit=limit)


@management_router.get(
  "/stats",
  response_model=TaxiiSimulationStatsResponse,
  summary="Get STIX/TAXII simulation dashboard statistics",
)
async def get_stix_taxii_stats(
  current_user: UserPublic = Depends(require_permission("threats:read")),
) -> TaxiiSimulationStatsResponse:
  return await stix_taxii_service.get_simulation_stats()


@management_router.post(
  "/sync",
  response_model=TaxiiSyncResponse,
  summary="Synchronize IOC database into STIX/TAXII simulation",
)
async def sync_stix_taxii_simulation(
  current_user: UserPublic = Depends(require_permission("threats:write")),
) -> TaxiiSyncResponse:
  return await stix_taxii_service.sync_simulation()


@management_router.get(
  "/objects",
  response_model=StixObjectListResponse,
  summary="List STIX objects with pagination",
)
async def list_stix_objects(
  page: int = Query(default=1, ge=1),
  page_size: int = Query(default=20, ge=1, le=100),
  collection_id: Optional[str] = Query(default=None),
  object_type: Optional[str] = Query(default=None),
  current_user: UserPublic = Depends(require_permission("threats:read")),
) -> StixObjectListResponse:
  return await stix_taxii_service.list_stix_objects(
    page=page,
    page_size=page_size,
    collection_id=collection_id,
    object_type=object_type,
  )
