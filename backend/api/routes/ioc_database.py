from typing import Optional

from fastapi import APIRouter, Depends, Query

from core.auth_utils import require_permission
from models.threat_intelligence import (
  HashReputationCreate,
  HashType,
  IOCType,
  IOCUpdate,
  IPReputationCreate,
  MaliciousDomainCreate,
  ThreatLevel,
)
from models.user import UserPublic
from schemas.threat_intelligence import (
  HashReputationListResponse,
  IOCCreateResponse,
  IOCDeleteResponse,
  IOCDetailResponse,
  IOCFilterParams,
  IOCListResponse,
  IOCLookupRequest,
  IOCLookupResponse,
  IOCReputationCheckResponse,
  IOCSearchResponse,
  IOCUpdateResponse,
  IPReputationListResponse,
  MaliciousDomainListResponse,
  ThreatIntelligenceStatsResponse,
)
from services.threat_intelligence_service import threat_intelligence_service

router = APIRouter(prefix="/ioc-database", tags=["IOC Database"])


@router.get(
  "/stats",
  response_model=ThreatIntelligenceStatsResponse,
  summary="Get IOC database statistics for IP, domain, and hash entries",
)
async def get_ioc_database_stats(
  current_user: UserPublic = Depends(require_permission("threats:read")),
) -> ThreatIntelligenceStatsResponse:
  return await threat_intelligence_service.get_stats()


@router.get(
  "/ip",
  response_model=IPReputationListResponse,
  summary="List IP indicators from MongoDB IOC database",
)
async def list_ip_indicators(
  page: int = Query(default=1, ge=1),
  page_size: int = Query(default=20, ge=1, le=100),
  is_malicious: Optional[bool] = Query(default=None),
  threat_level: Optional[ThreatLevel] = Query(default=None),
  country: Optional[str] = Query(default=None),
  current_user: UserPublic = Depends(require_permission("threats:read")),
) -> IPReputationListResponse:
  result = await threat_intelligence_service.list_by_type(
    ioc_type=IOCType.IP,
    page=page,
    page_size=page_size,
    filters=IOCFilterParams(
      is_malicious=is_malicious,
      threat_level=threat_level,
      country=country,
    ),
  )

  return IPReputationListResponse(
    message="IP indicators retrieved successfully",
    items=result.items,
    pagination=result.pagination,
  )


@router.post(
  "/ip",
  response_model=IOCCreateResponse,
  status_code=201,
  summary="Add IP indicator to MongoDB IOC database",
)
async def create_ip_indicator(
  ip_data: IPReputationCreate,
  current_user: UserPublic = Depends(require_permission("threats:write")),
) -> IOCCreateResponse:
  return await threat_intelligence_service.create_ioc(
    ioc_data=ip_data.to_ioc_create(),
    created_by=str(current_user.id),
  )


@router.get(
  "/ip/check/{ip_address}",
  response_model=IOCReputationCheckResponse,
  summary="Check IP against IOC database",
)
async def check_ip_indicator(
  ip_address: str,
  current_user: UserPublic = Depends(require_permission("threats:read")),
) -> IOCReputationCheckResponse:
  return await threat_intelligence_service.check_reputation(
    value=ip_address,
    ioc_type=IOCType.IP,
  )


@router.get(
  "/domain",
  response_model=MaliciousDomainListResponse,
  summary="List domain indicators from MongoDB IOC database",
)
async def list_domain_indicators(
  page: int = Query(default=1, ge=1),
  page_size: int = Query(default=20, ge=1, le=100),
  is_malicious: Optional[bool] = Query(default=None),
  threat_level: Optional[ThreatLevel] = Query(default=None),
  current_user: UserPublic = Depends(require_permission("threats:read")),
) -> MaliciousDomainListResponse:
  result = await threat_intelligence_service.list_by_type(
    ioc_type=IOCType.DOMAIN,
    page=page,
    page_size=page_size,
    filters=IOCFilterParams(
      is_malicious=is_malicious,
      threat_level=threat_level,
    ),
  )

  return MaliciousDomainListResponse(
    message="Domain indicators retrieved successfully",
    items=result.items,
    pagination=result.pagination,
  )


@router.post(
  "/domain",
  response_model=IOCCreateResponse,
  status_code=201,
  summary="Add domain indicator to MongoDB IOC database",
)
async def create_domain_indicator(
  domain_data: MaliciousDomainCreate,
  current_user: UserPublic = Depends(require_permission("threats:write")),
) -> IOCCreateResponse:
  return await threat_intelligence_service.create_ioc(
    ioc_data=domain_data.to_ioc_create(),
    created_by=str(current_user.id),
  )


@router.get(
  "/domain/check/{domain}",
  response_model=IOCReputationCheckResponse,
  summary="Check domain against IOC database",
)
async def check_domain_indicator(
  domain: str,
  current_user: UserPublic = Depends(require_permission("threats:read")),
) -> IOCReputationCheckResponse:
  return await threat_intelligence_service.check_reputation(
    value=domain.lower(),
    ioc_type=IOCType.DOMAIN,
  )


@router.get(
  "/hash",
  response_model=HashReputationListResponse,
  summary="List hash indicators from MongoDB IOC database",
)
async def list_hash_indicators(
  page: int = Query(default=1, ge=1),
  page_size: int = Query(default=20, ge=1, le=100),
  hash_type: Optional[HashType] = Query(default=None),
  is_malicious: Optional[bool] = Query(default=None),
  threat_level: Optional[ThreatLevel] = Query(default=None),
  current_user: UserPublic = Depends(require_permission("threats:read")),
) -> HashReputationListResponse:
  result = await threat_intelligence_service.list_by_type(
    ioc_type=IOCType.HASH,
    page=page,
    page_size=page_size,
    filters=IOCFilterParams(
      hash_type=hash_type,
      is_malicious=is_malicious,
      threat_level=threat_level,
    ),
  )

  return HashReputationListResponse(
    message="Hash indicators retrieved successfully",
    items=result.items,
    pagination=result.pagination,
  )


@router.post(
  "/hash",
  response_model=IOCCreateResponse,
  status_code=201,
  summary="Add hash indicator to MongoDB IOC database",
)
async def create_hash_indicator(
  hash_data: HashReputationCreate,
  current_user: UserPublic = Depends(require_permission("threats:write")),
) -> IOCCreateResponse:
  return await threat_intelligence_service.create_ioc(
    ioc_data=hash_data.to_ioc_create(),
    created_by=str(current_user.id),
  )


@router.get(
  "/hash/check/{hash_value}",
  response_model=IOCReputationCheckResponse,
  summary="Check file hash against IOC database",
)
async def check_hash_indicator(
  hash_value: str,
  current_user: UserPublic = Depends(require_permission("threats:read")),
) -> IOCReputationCheckResponse:
  return await threat_intelligence_service.check_reputation(
    value=hash_value.lower(),
    ioc_type=IOCType.HASH,
  )


@router.get(
  "/search",
  response_model=IOCSearchResponse,
  summary="Search IP, domain, and hash indicators",
)
async def search_ioc_database(
  q: str = Query(..., min_length=1, max_length=200),
  ioc_type: Optional[IOCType] = Query(default=None),
  page: int = Query(default=1, ge=1),
  page_size: int = Query(default=20, ge=1, le=100),
  current_user: UserPublic = Depends(require_permission("threats:read")),
) -> IOCSearchResponse:
  return await threat_intelligence_service.search_iocs(
    search_text=q,
    page=page,
    page_size=page_size,
    filters=IOCFilterParams(ioc_type=ioc_type),
  )


@router.post(
  "/lookup",
  response_model=IOCLookupResponse,
  summary="Bulk lookup values against IOC database",
)
async def lookup_ioc_values(
  lookup_data: IOCLookupRequest,
  current_user: UserPublic = Depends(require_permission("threats:read")),
) -> IOCLookupResponse:
  return await threat_intelligence_service.lookup_iocs(lookup_data.values)


@router.get(
  "",
  response_model=IOCListResponse,
  summary="List all IOC database entries",
)
async def list_all_iocs(
  page: int = Query(default=1, ge=1),
  page_size: int = Query(default=20, ge=1, le=100),
  ioc_type: Optional[IOCType] = Query(default=None),
  current_user: UserPublic = Depends(require_permission("threats:read")),
) -> IOCListResponse:
  return await threat_intelligence_service.list_iocs(
    page=page,
    page_size=page_size,
    filters=IOCFilterParams(ioc_type=ioc_type),
  )


@router.patch(
  "/{ioc_id}",
  response_model=IOCUpdateResponse,
  summary="Update IOC database entry",
)
async def update_ioc_entry(
  ioc_id: str,
  update_data: IOCUpdate,
  current_user: UserPublic = Depends(require_permission("threats:write")),
) -> IOCUpdateResponse:
  return await threat_intelligence_service.update_ioc(ioc_id, update_data)


@router.delete(
  "/{ioc_id}",
  response_model=IOCDeleteResponse,
  summary="Delete IOC database entry",
)
async def delete_ioc_entry(
  ioc_id: str,
  current_user: UserPublic = Depends(require_permission("threats:write")),
) -> IOCDeleteResponse:
  return await threat_intelligence_service.delete_ioc(ioc_id)


@router.get(
  "/{ioc_id}",
  response_model=IOCDetailResponse,
  summary="Get IOC database entry by ID",
)
async def get_ioc_entry(
  ioc_id: str,
  current_user: UserPublic = Depends(require_permission("threats:read")),
) -> IOCDetailResponse:
  return await threat_intelligence_service.get_ioc(ioc_id)
