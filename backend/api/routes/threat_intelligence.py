from typing import Optional

from fastapi import APIRouter, Depends, Query

from core.auth_utils import require_permission
from models.threat_intelligence import (
  HashReputationCreate,
  HashType,
  IOCCreate,
  IOCType,
  IOCUpdate,
  IPReputationCreate,
  MaliciousDomainCreate,
  ThreatCategory,
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

router = APIRouter(prefix="/threat-intelligence", tags=["Threat Intelligence"])


@router.post(
  "/iocs",
  response_model=IOCCreateResponse,
  status_code=201,
  summary="Create a new IOC entry",
)
async def create_ioc(
  ioc_data: IOCCreate,
  current_user: UserPublic = Depends(require_permission("threats:write")),
) -> IOCCreateResponse:
  return await threat_intelligence_service.create_ioc(
    ioc_data=ioc_data,
    created_by=str(current_user.id),
  )


@router.get(
  "/iocs",
  response_model=IOCListResponse,
  summary="List IOC database entries with pagination and filtering",
)
async def list_iocs(
  page: int = Query(default=1, ge=1),
  page_size: int = Query(default=20, ge=1, le=100),
  ioc_type: Optional[IOCType] = Query(default=None),
  threat_level: Optional[ThreatLevel] = Query(default=None),
  is_malicious: Optional[bool] = Query(default=None),
  is_active: Optional[bool] = Query(default=None),
  source: Optional[str] = Query(default=None),
  threat_category: Optional[ThreatCategory] = Query(default=None),
  tag: Optional[str] = Query(default=None),
  min_reputation_score: Optional[int] = Query(default=None, ge=0, le=100),
  max_reputation_score: Optional[int] = Query(default=None, ge=0, le=100),
  sort_by: str = Query(default="reputation_score"),
  sort_order: str = Query(default="desc", pattern="^(asc|desc)$"),
  current_user: UserPublic = Depends(require_permission("threats:read")),
) -> IOCListResponse:
  filters = IOCFilterParams(
    ioc_type=ioc_type,
    threat_level=threat_level,
    is_malicious=is_malicious,
    is_active=is_active,
    source=source,
    threat_category=threat_category,
    tag=tag,
    min_reputation_score=min_reputation_score,
    max_reputation_score=max_reputation_score,
  )

  return await threat_intelligence_service.list_iocs(
    page=page,
    page_size=page_size,
    filters=filters,
    sort_by=sort_by,
    sort_order=sort_order,
  )


@router.get(
  "/iocs/search",
  response_model=IOCSearchResponse,
  summary="Search IOC database",
)
async def search_iocs(
  q: str = Query(..., min_length=1, max_length=200),
  page: int = Query(default=1, ge=1),
  page_size: int = Query(default=20, ge=1, le=100),
  ioc_type: Optional[IOCType] = Query(default=None),
  threat_level: Optional[ThreatLevel] = Query(default=None),
  is_malicious: Optional[bool] = Query(default=None),
  is_active: Optional[bool] = Query(default=None),
  current_user: UserPublic = Depends(require_permission("threats:read")),
) -> IOCSearchResponse:
  filters = IOCFilterParams(
    ioc_type=ioc_type,
    threat_level=threat_level,
    is_malicious=is_malicious,
    is_active=is_active,
  )

  return await threat_intelligence_service.search_iocs(
    search_text=q,
    page=page,
    page_size=page_size,
    filters=filters,
  )


@router.post(
  "/iocs/lookup",
  response_model=IOCLookupResponse,
  summary="Bulk lookup IOC values against the database",
)
async def lookup_iocs(
  lookup_data: IOCLookupRequest,
  current_user: UserPublic = Depends(require_permission("threats:read")),
) -> IOCLookupResponse:
  return await threat_intelligence_service.lookup_iocs(lookup_data.values)


@router.get(
  "/iocs/stats",
  response_model=ThreatIntelligenceStatsResponse,
  summary="Get threat intelligence database statistics",
)
async def get_threat_intelligence_stats(
  current_user: UserPublic = Depends(require_permission("threats:read")),
) -> ThreatIntelligenceStatsResponse:
  return await threat_intelligence_service.get_stats()


@router.get(
  "/iocs/{ioc_id}",
  response_model=IOCDetailResponse,
  summary="Get IOC entry by ID",
)
async def get_ioc(
  ioc_id: str,
  current_user: UserPublic = Depends(require_permission("threats:read")),
) -> IOCDetailResponse:
  return await threat_intelligence_service.get_ioc(ioc_id)


@router.put(
  "/iocs/{ioc_id}",
  response_model=IOCUpdateResponse,
  summary="Update IOC entry",
)
async def update_ioc(
  ioc_id: str,
  update_data: IOCUpdate,
  current_user: UserPublic = Depends(require_permission("threats:write")),
) -> IOCUpdateResponse:
  return await threat_intelligence_service.update_ioc(ioc_id, update_data)


@router.delete(
  "/iocs/{ioc_id}",
  response_model=IOCDeleteResponse,
  summary="Delete IOC entry",
)
async def delete_ioc(
  ioc_id: str,
  current_user: UserPublic = Depends(require_permission("threats:write")),
) -> IOCDeleteResponse:
  return await threat_intelligence_service.delete_ioc(ioc_id)


@router.post(
  "/ip-reputation",
  response_model=IOCCreateResponse,
  status_code=201,
  summary="Add IP to reputation database",
)
async def create_ip_reputation(
  ip_data: IPReputationCreate,
  current_user: UserPublic = Depends(require_permission("threats:write")),
) -> IOCCreateResponse:
  return await threat_intelligence_service.create_ioc(
    ioc_data=ip_data.to_ioc_create(),
    created_by=str(current_user.id),
  )


@router.get(
  "/ip-reputation",
  response_model=IPReputationListResponse,
  summary="List IP reputation entries",
)
async def list_ip_reputation(
  page: int = Query(default=1, ge=1),
  page_size: int = Query(default=20, ge=1, le=100),
  is_malicious: Optional[bool] = Query(default=None),
  threat_level: Optional[ThreatLevel] = Query(default=None),
  country: Optional[str] = Query(default=None),
  min_reputation_score: Optional[int] = Query(default=None, ge=0, le=100),
  sort_order: str = Query(default="desc", pattern="^(asc|desc)$"),
  current_user: UserPublic = Depends(require_permission("threats:read")),
) -> IPReputationListResponse:
  filters = IOCFilterParams(
    ioc_type=IOCType.IP,
    is_malicious=is_malicious,
    threat_level=threat_level,
    country=country,
    min_reputation_score=min_reputation_score,
  )

  result = await threat_intelligence_service.list_iocs(
    page=page,
    page_size=page_size,
    filters=filters,
    sort_by="reputation_score",
    sort_order=sort_order,
  )

  return IPReputationListResponse(
    success=result.success,
    message="IP reputation entries retrieved successfully",
    items=result.items,
    pagination=result.pagination,
  )


@router.get(
  "/ip-reputation/check/{ip_address}",
  response_model=IOCReputationCheckResponse,
  summary="Check IP reputation",
)
async def check_ip_reputation(
  ip_address: str,
  current_user: UserPublic = Depends(require_permission("threats:read")),
) -> IOCReputationCheckResponse:
  return await threat_intelligence_service.check_reputation(
    value=ip_address,
    ioc_type=IOCType.IP,
  )


@router.get(
  "/ip-reputation/{ip_address}",
  response_model=IOCDetailResponse,
  summary="Get IP reputation details",
)
async def get_ip_reputation(
  ip_address: str,
  current_user: UserPublic = Depends(require_permission("threats:read")),
) -> IOCDetailResponse:
  return await threat_intelligence_service.get_ioc(ip_address)


@router.post(
  "/hash-reputation",
  response_model=IOCCreateResponse,
  status_code=201,
  summary="Add file hash to reputation database",
)
async def create_hash_reputation(
  hash_data: HashReputationCreate,
  current_user: UserPublic = Depends(require_permission("threats:write")),
) -> IOCCreateResponse:
  return await threat_intelligence_service.create_ioc(
    ioc_data=hash_data.to_ioc_create(),
    created_by=str(current_user.id),
  )


@router.get(
  "/hash-reputation",
  response_model=HashReputationListResponse,
  summary="List hash reputation entries",
)
async def list_hash_reputation(
  page: int = Query(default=1, ge=1),
  page_size: int = Query(default=20, ge=1, le=100),
  hash_type: Optional[HashType] = Query(default=None),
  is_malicious: Optional[bool] = Query(default=None),
  threat_level: Optional[ThreatLevel] = Query(default=None),
  min_reputation_score: Optional[int] = Query(default=None, ge=0, le=100),
  sort_order: str = Query(default="desc", pattern="^(asc|desc)$"),
  current_user: UserPublic = Depends(require_permission("threats:read")),
) -> HashReputationListResponse:
  filters = IOCFilterParams(
    ioc_type=IOCType.HASH,
    hash_type=hash_type,
    is_malicious=is_malicious,
    threat_level=threat_level,
    min_reputation_score=min_reputation_score,
  )

  result = await threat_intelligence_service.list_iocs(
    page=page,
    page_size=page_size,
    filters=filters,
    sort_by="reputation_score",
    sort_order=sort_order,
  )

  return HashReputationListResponse(
    success=result.success,
    message="Hash reputation entries retrieved successfully",
    items=result.items,
    pagination=result.pagination,
  )


@router.get(
  "/hash-reputation/check/{hash_value}",
  response_model=IOCReputationCheckResponse,
  summary="Check file hash reputation",
)
async def check_hash_reputation(
  hash_value: str,
  current_user: UserPublic = Depends(require_permission("threats:read")),
) -> IOCReputationCheckResponse:
  return await threat_intelligence_service.check_reputation(
    value=hash_value,
    ioc_type=IOCType.HASH,
  )


@router.get(
  "/hash-reputation/{hash_value}",
  response_model=IOCDetailResponse,
  summary="Get hash reputation details",
)
async def get_hash_reputation(
  hash_value: str,
  current_user: UserPublic = Depends(require_permission("threats:read")),
) -> IOCDetailResponse:
  return await threat_intelligence_service.get_ioc(hash_value.lower())


@router.post(
  "/malicious-domains",
  response_model=IOCCreateResponse,
  status_code=201,
  summary="Add malicious domain to database",
)
async def create_malicious_domain(
  domain_data: MaliciousDomainCreate,
  current_user: UserPublic = Depends(require_permission("threats:write")),
) -> IOCCreateResponse:
  return await threat_intelligence_service.create_ioc(
    ioc_data=domain_data.to_ioc_create(),
    created_by=str(current_user.id),
  )


@router.get(
  "/malicious-domains",
  response_model=MaliciousDomainListResponse,
  summary="List malicious domain entries",
)
async def list_malicious_domains(
  page: int = Query(default=1, ge=1),
  page_size: int = Query(default=20, ge=1, le=100),
  is_malicious: Optional[bool] = Query(default=True),
  threat_level: Optional[ThreatLevel] = Query(default=None),
  threat_category: Optional[ThreatCategory] = Query(default=None),
  min_reputation_score: Optional[int] = Query(default=None, ge=0, le=100),
  sort_order: str = Query(default="desc", pattern="^(asc|desc)$"),
  current_user: UserPublic = Depends(require_permission("threats:read")),
) -> MaliciousDomainListResponse:
  filters = IOCFilterParams(
    ioc_type=IOCType.DOMAIN,
    is_malicious=is_malicious,
    threat_level=threat_level,
    threat_category=threat_category,
    min_reputation_score=min_reputation_score,
  )

  result = await threat_intelligence_service.list_iocs(
    page=page,
    page_size=page_size,
    filters=filters,
    sort_by="reputation_score",
    sort_order=sort_order,
  )

  return MaliciousDomainListResponse(
    success=result.success,
    message="Malicious domain entries retrieved successfully",
    items=result.items,
    pagination=result.pagination,
  )


@router.get(
  "/malicious-domains/check/{domain}",
  response_model=IOCReputationCheckResponse,
  summary="Check if domain is malicious",
)
async def check_malicious_domain(
  domain: str,
  current_user: UserPublic = Depends(require_permission("threats:read")),
) -> IOCReputationCheckResponse:
  return await threat_intelligence_service.check_reputation(
    value=domain.lower(),
    ioc_type=IOCType.DOMAIN,
  )


@router.get(
  "/malicious-domains/{domain}",
  response_model=IOCDetailResponse,
  summary="Get malicious domain details",
)
async def get_malicious_domain(
  domain: str,
  current_user: UserPublic = Depends(require_permission("threats:read")),
) -> IOCDetailResponse:
  return await threat_intelligence_service.get_ioc(domain.lower())
