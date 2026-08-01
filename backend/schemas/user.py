from typing import Optional

from pydantic import BaseModel

from models.user import UserPublic, UserRole
from schemas.log import PaginationMeta


class UserFilterParams(BaseModel):
  role: Optional[UserRole] = None
  is_active: Optional[bool] = None
  search: Optional[str] = None


class UserListResponse(BaseModel):
  success: bool = True
  message: str
  items: list[UserPublic]
  pagination: PaginationMeta
