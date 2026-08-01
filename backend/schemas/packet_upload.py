from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field

from models.packet_upload import PacketUploadPublic, PacketUploadStatus, AIEngineStatus
from schemas.log import PaginationMeta


class PacketUploadResponse(BaseModel):
  success: bool = True
  message: str
  upload: PacketUploadPublic


class PacketUploadListResponse(BaseModel):
  success: bool = True
  message: str
  items: list[PacketUploadPublic]
  pagination: PaginationMeta


class PacketUploadStatusResponse(BaseModel):
  success: bool = True
  message: str
  upload_id: str
  status: PacketUploadStatus
  ai_engine_status: AIEngineStatus
  ai_engine_job_id: Optional[str] = None
  ai_engine_response: Optional[dict[str, Any]] = None
  ai_engine_error: Optional[str] = None
  updated_at: datetime
