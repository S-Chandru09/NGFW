from typing import Optional

from fastapi import APIRouter, Depends, Query

from core.auth_utils import require_permission
from models.incident_response import IncidentCreate, IncidentSeverity, IncidentStatus, IncidentUpdate
from models.user import UserPublic
from schemas.incident_response import (
  BlockIPRequest,
  BlockIPResponse,
  GenerateReportRequest,
  GenerateReportResponse,
  IncidentCreateRequest,
  IncidentCreateResponse,
  IncidentDetailResponse,
  IncidentListResponse,
  IncidentStatsResponse,
  IncidentUpdateRequest,
  IncidentUpdateResponse,
  KillSessionRequest,
  KillSessionResponse,
)
from services.incident_response_service import incident_response_service

router = APIRouter(prefix="/incident-response", tags=["Incident Response"])


@router.get(
  "/stats",
  response_model=IncidentStatsResponse,
  summary="Get incident response statistics",
)
async def get_incident_stats(
  current_user: UserPublic = Depends(require_permission("incidents:read")),
) -> IncidentStatsResponse:
  return await incident_response_service.get_stats()


@router.get(
  "/incidents",
  response_model=IncidentListResponse,
  summary="List security incidents",
)
async def list_incidents(
  page: int = Query(default=1, ge=1),
  page_size: int = Query(default=20, ge=1, le=100),
  status_filter: Optional[IncidentStatus] = Query(default=None, alias="status"),
  severity_filter: Optional[IncidentSeverity] = Query(default=None, alias="severity"),
  search: Optional[str] = Query(default=None),
  current_user: UserPublic = Depends(require_permission("incidents:read")),
) -> IncidentListResponse:
  return await incident_response_service.list_incidents(
    page=page,
    page_size=page_size,
    status_filter=status_filter,
    severity_filter=severity_filter,
    search=search,
  )


@router.post(
  "/incidents",
  response_model=IncidentCreateResponse,
  summary="Create a new security incident",
)
async def create_incident(
  incident_data: IncidentCreateRequest,
  current_user: UserPublic = Depends(require_permission("incidents:write")),
) -> IncidentCreateResponse:
  return await incident_response_service.create_incident(
    IncidentCreate(**incident_data.model_dump()),
    created_by=current_user.id,
    actor_username=current_user.username,
  )


@router.get(
  "/incidents/{incident_id}",
  response_model=IncidentDetailResponse,
  summary="Get incident details",
)
async def get_incident(
  incident_id: str,
  current_user: UserPublic = Depends(require_permission("incidents:read")),
) -> IncidentDetailResponse:
  return await incident_response_service.get_incident(incident_id)


@router.patch(
  "/incidents/{incident_id}",
  response_model=IncidentUpdateResponse,
  summary="Update incident details or status",
)
async def update_incident(
  incident_id: str,
  update_data: IncidentUpdateRequest,
  current_user: UserPublic = Depends(require_permission("incidents:write")),
) -> IncidentUpdateResponse:
  return await incident_response_service.update_incident(
    incident_id=incident_id,
    update_data=IncidentUpdate(**update_data.model_dump(exclude_none=True)),
    actor_id=current_user.id,
    actor_username=current_user.username,
  )


@router.post(
  "/incidents/{incident_id}/block-ip",
  response_model=BlockIPResponse,
  summary="Block IP address as incident containment action",
)
async def block_incident_ip(
  incident_id: str,
  request: BlockIPRequest,
  current_user: UserPublic = Depends(require_permission("incidents:respond")),
) -> BlockIPResponse:
  return await incident_response_service.block_ip(
    incident_id=incident_id,
    request=request,
    actor_id=current_user.id,
    actor_username=current_user.username,
  )


@router.post(
  "/incidents/{incident_id}/kill-session",
  response_model=KillSessionResponse,
  summary="Terminate active sessions as incident containment action",
)
async def kill_incident_session(
  incident_id: str,
  request: KillSessionRequest,
  current_user: UserPublic = Depends(require_permission("incidents:respond")),
) -> KillSessionResponse:
  return await incident_response_service.kill_session(
    incident_id=incident_id,
    request=request,
    actor_id=current_user.id,
    actor_username=current_user.username,
  )


@router.post(
  "/incidents/{incident_id}/report",
  response_model=GenerateReportResponse,
  summary="Generate incident response report",
)
async def generate_incident_report(
  incident_id: str,
  request: GenerateReportRequest = GenerateReportRequest(),
  current_user: UserPublic = Depends(require_permission("incidents:read")),
) -> GenerateReportResponse:
  return await incident_response_service.generate_report(
    incident_id=incident_id,
    request=request,
    actor_id=current_user.id,
    actor_username=current_user.username,
  )
