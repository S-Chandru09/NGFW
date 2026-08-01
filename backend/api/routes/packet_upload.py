from typing import Optional

from fastapi import APIRouter, Depends, File, Query, UploadFile

from core.auth_utils import require_permission
from models.packet_upload import PacketUploadStatus
from models.user import UserPublic
from schemas.packet_upload import (
  PacketUploadListResponse,
  PacketUploadResponse,
  PacketUploadStatusResponse,
)
from services.packet_upload_service import packet_upload_service

router = APIRouter(prefix="/packet-upload", tags=["Packet Upload"])


@router.post(
  "",
  response_model=PacketUploadResponse,
  status_code=201,
  summary="Upload PCAP file for validation, storage, and AI analysis",
)
async def upload_pcap_file(
  file: UploadFile = File(..., description="PCAP or PCAPNG file to upload"),
  current_user: UserPublic = Depends(require_permission("capture:write")),
) -> PacketUploadResponse:
  return await packet_upload_service.upload_pcap(
    file=file,
    uploaded_by=str(current_user.id),
  )


@router.get(
  "",
  response_model=PacketUploadListResponse,
  summary="List uploaded PCAP files",
)
async def list_pcap_uploads(
  page: int = Query(default=1, ge=1),
  page_size: int = Query(default=20, ge=1, le=100),
  status_filter: Optional[PacketUploadStatus] = Query(default=None, alias="status"),
  current_user: UserPublic = Depends(require_permission("capture:read")),
) -> PacketUploadListResponse:
  return await packet_upload_service.list_uploads(
    page=page,
    page_size=page_size,
    status_filter=status_filter,
  )


@router.get(
  "/{upload_id}/status",
  response_model=PacketUploadStatusResponse,
  summary="Get PCAP upload and AI Engine processing status",
)
async def get_pcap_upload_status(
  upload_id: str,
  current_user: UserPublic = Depends(require_permission("capture:read")),
) -> PacketUploadStatusResponse:
  return await packet_upload_service.get_upload_status(upload_id)


@router.get(
  "/{upload_id}",
  response_model=PacketUploadResponse,
  summary="Get PCAP upload details",
)
async def get_pcap_upload(
  upload_id: str,
  current_user: UserPublic = Depends(require_permission("capture:read")),
) -> PacketUploadResponse:
  return await packet_upload_service.get_upload(upload_id)
