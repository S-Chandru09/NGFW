from typing import Optional

from fastapi import APIRouter, Depends, Query

from core.auth_utils import require_permission
from models.user import UserPublic, UserRole
from schemas.user import UserFilterParams, UserListResponse
from services.user_service import user_service

router = APIRouter(prefix="/users", tags=["Users"])


@router.get(
  "",
  response_model=UserListResponse,
  summary="List users with pagination and filtering",
)
async def list_users(
  page: int = Query(default=1, ge=1),
  page_size: int = Query(default=20, ge=1, le=100),
  role: Optional[UserRole] = Query(default=None),
  is_active: Optional[bool] = Query(default=None),
  search: Optional[str] = Query(default=None, min_length=1, max_length=100),
  sort_by: str = Query(default="created_at"),
  sort_order: str = Query(default="desc", pattern="^(asc|desc)$"),
  current_user: UserPublic = Depends(require_permission("users:read")),
) -> UserListResponse:
  filters = UserFilterParams(role=role, is_active=is_active, search=search)

  return await user_service.list_users(
    page=page,
    page_size=page_size,
    filters=filters,
    sort_by=sort_by,
    sort_order=sort_order,
  )
