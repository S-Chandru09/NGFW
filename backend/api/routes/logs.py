from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, Query

from core.auth_utils import require_permission, require_roles
from models.log import LogEventType, LogSeverity
from models.user import UserPublic, UserRole
from schemas.log import (
  LogCreateRequest,
  LogCreateResponse,
  LogDeleteResponse,
  LogDetailResponse,
  LogFilterParams,
  LogListResponse,
  LogSearchParams,
  LogSearchResponse,
)
from services.log_service import log_service

router = APIRouter(prefix="/logs", tags=["Logs"])


@router.post(
  "",
  response_model=LogCreateResponse,
  status_code=201,
  summary="Create a new log entry",
)
async def create_log(
  log_data: LogCreateRequest,
  current_user: UserPublic = Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST)),
) -> LogCreateResponse:
  return await log_service.create_log(log_data)


@router.get(
  "",
  response_model=LogListResponse,
  summary="List logs with pagination and filtering",
)
async def list_logs(
  page: int = Query(default=1, ge=1),
  page_size: int = Query(default=20, ge=1, le=100),
  event_type: Optional[LogEventType] = Query(default=None),
  severity: Optional[LogSeverity] = Query(default=None),
  user_id: Optional[str] = Query(default=None),
  username: Optional[str] = Query(default=None),
  ip_address: Optional[str] = Query(default=None),
  source: Optional[str] = Query(default=None),
  resource_type: Optional[str] = Query(default=None),
  resource_id: Optional[str] = Query(default=None),
  date_from: Optional[datetime] = Query(default=None),
  date_to: Optional[datetime] = Query(default=None),
  sort_by: str = Query(default="created_at"),
  sort_order: str = Query(default="desc", pattern="^(asc|desc)$"),
  current_user: UserPublic = Depends(require_permission("audit:read")),
) -> LogListResponse:
  filters = LogFilterParams(
    event_type=event_type,
    severity=severity,
    user_id=user_id,
    username=username,
    ip_address=ip_address,
    source=source,
    resource_type=resource_type,
    resource_id=resource_id,
    date_from=date_from,
    date_to=date_to,
  )

  return await log_service.list_logs(
    page=page,
    page_size=page_size,
    filters=filters,
    sort_by=sort_by,
    sort_order=sort_order,
  )


@router.get(
  "/search",
  response_model=LogSearchResponse,
  summary="Search logs with text query, filters, and pagination",
)
async def search_logs(
  q: Optional[str] = Query(default=None, min_length=1, max_length=200),
  page: int = Query(default=1, ge=1),
  page_size: int = Query(default=20, ge=1, le=100),
  event_type: Optional[LogEventType] = Query(default=None),
  severity: Optional[LogSeverity] = Query(default=None),
  user_id: Optional[str] = Query(default=None),
  username: Optional[str] = Query(default=None),
  ip_address: Optional[str] = Query(default=None),
  source: Optional[str] = Query(default=None),
  resource_type: Optional[str] = Query(default=None),
  resource_id: Optional[str] = Query(default=None),
  date_from: Optional[datetime] = Query(default=None),
  date_to: Optional[datetime] = Query(default=None),
  sort_by: str = Query(default="created_at"),
  sort_order: str = Query(default="desc", pattern="^(asc|desc)$"),
  current_user: UserPublic = Depends(require_permission("audit:read")),
) -> LogSearchResponse:
  search_params = LogSearchParams(
    q=q,
    event_type=event_type,
    severity=severity,
    user_id=user_id,
    username=username,
    ip_address=ip_address,
    source=source,
    resource_type=resource_type,
    resource_id=resource_id,
    date_from=date_from,
    date_to=date_to,
    sort_by=sort_by,
    sort_order=sort_order,
  )

  return await log_service.search_logs(
    search_params=search_params,
    page=page,
    page_size=page_size,
  )


@router.get(
  "/{log_id}",
  response_model=LogDetailResponse,
  summary="Get a single log entry by log ID",
)
async def get_log(
  log_id: str,
  current_user: UserPublic = Depends(require_permission("audit:read")),
) -> LogDetailResponse:
  return await log_service.get_log_by_id(log_id)


@router.delete(
  "/{log_id}",
  response_model=LogDeleteResponse,
  summary="Delete a log entry by log ID",
)
async def delete_log(
  log_id: str,
  current_user: UserPublic = Depends(require_roles(UserRole.ADMIN)),
) -> LogDeleteResponse:
  return await log_service.delete_log(log_id)
