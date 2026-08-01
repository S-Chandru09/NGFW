from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field

from models.log import LogCreate, LogEventType, LogPublic, LogSeverity


class PaginationMeta(BaseModel):
  page: int
  page_size: int
  total_items: int
  total_pages: int
  has_next: bool
  has_previous: bool


class LogFilterParams(BaseModel):
  event_type: Optional[LogEventType] = None
  severity: Optional[LogSeverity] = None
  user_id: Optional[str] = None
  username: Optional[str] = None
  ip_address: Optional[str] = None
  source: Optional[str] = None
  resource_type: Optional[str] = None
  resource_id: Optional[str] = None
  date_from: Optional[datetime] = None
  date_to: Optional[datetime] = None


class LogSearchParams(LogFilterParams):
  q: Optional[str] = Field(default=None, min_length=1, max_length=200)
  sort_by: str = Field(default="created_at")
  sort_order: str = Field(default="desc")


class LogListResponse(BaseModel):
  success: bool = True
  message: str
  items: list[LogPublic]
  pagination: PaginationMeta


class LogDetailResponse(BaseModel):
  success: bool = True
  message: str
  log: LogPublic


class LogCreateResponse(BaseModel):
  success: bool = True
  message: str
  log: LogPublic


class LogDeleteResponse(BaseModel):
  success: bool = True
  message: str
  log_id: str


class LogSearchResponse(BaseModel):
  success: bool = True
  message: str
  query: Optional[str] = None
  filters_applied: dict[str, Any]
  items: list[LogPublic]
  pagination: PaginationMeta


class LogCreateRequest(LogCreate):
  pass
