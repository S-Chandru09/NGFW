import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from bson import ObjectId
from fastapi import HTTPException, UploadFile, status

from config import settings
from database import get_packet_uploads_collection
from models.packet_upload import (
  AIEngineStatus,
  PacketUploadDocument,
  PacketUploadPublic,
  PacketUploadStatus,
)
from schemas.log import PaginationMeta
from schemas.packet_upload import (
  PacketUploadListResponse,
  PacketUploadResponse,
  PacketUploadStatusResponse,
)
from services.ai_engine_client import ai_engine_client
from services.packet_validator import PacketValidator


class PacketUploadService:
  def __init__(self) -> None:
    self.validator = PacketValidator(max_file_size_mb=settings.pcap_max_file_size_mb)
    self.storage_path = Path(settings.pcap_storage_path)
    self.storage_path.mkdir(parents=True, exist_ok=True)

  def _build_pagination_meta(self, page: int, page_size: int, total_items: int) -> PaginationMeta:
    total_pages = math.ceil(total_items / page_size) if page_size > 0 else 0

    return PaginationMeta(
      page=page,
      page_size=page_size,
      total_items=total_items,
      total_pages=total_pages,
      has_next=page < total_pages,
      has_previous=page > 1 and total_pages > 0,
    )

  def _sanitize_filename(self, filename: str) -> str:
    cleaned = Path(filename).name
    return cleaned.replace(" ", "_")

  def _build_storage_path(self, upload_id: str, stored_filename: str) -> Path:
    upload_directory = self.storage_path / upload_id
    upload_directory.mkdir(parents=True, exist_ok=True)
    return upload_directory / stored_filename

  async def _get_upload_document(self, upload_id: str) -> Optional[dict]:
    collection = get_packet_uploads_collection()
    document = await collection.find_one({"upload_id": upload_id})

    if document is None and ObjectId.is_valid(upload_id):
      document = await collection.find_one({"_id": ObjectId(upload_id)})

    return document

  def _resolve_upload_statuses(
    self,
    ai_result: dict,
  ) -> tuple[PacketUploadStatus, AIEngineStatus, Optional[str]]:
    ai_status = str(ai_result.get("status", "")).lower()
    ai_engine_error = None

    if ai_status == "skipped":
      return PacketUploadStatus.STORED, AIEngineStatus.SKIPPED, None

    if not ai_result.get("success"):
      ai_engine_error = ai_result.get("error") or ai_result.get("message")
      return PacketUploadStatus.FAILED, AIEngineStatus.FAILED, ai_engine_error

    if ai_status == "completed":
      return PacketUploadStatus.COMPLETED, AIEngineStatus.COMPLETED, None

    if ai_status == "queued":
      return PacketUploadStatus.PROCESSING, AIEngineStatus.QUEUED, None

    if ai_status == "processing":
      return PacketUploadStatus.PROCESSING, AIEngineStatus.PROCESSING, None

    if ai_status == "failed":
      ai_engine_error = ai_result.get("error") or ai_result.get("message")
      return PacketUploadStatus.FAILED, AIEngineStatus.FAILED, ai_engine_error

    return PacketUploadStatus.PROCESSING, AIEngineStatus.PROCESSING, None

  def _build_upload_success_message(
    self,
    upload_status: PacketUploadStatus,
    ai_engine_status: AIEngineStatus,
  ) -> str:
    if ai_engine_status == AIEngineStatus.COMPLETED:
      return "PCAP file uploaded and AI analysis completed successfully"

    if ai_engine_status == AIEngineStatus.SKIPPED:
      return "PCAP file uploaded and stored successfully (AI Engine skipped)"

    if ai_engine_status == AIEngineStatus.FAILED:
      return "PCAP file uploaded, but AI analysis failed"

    if ai_engine_status == AIEngineStatus.QUEUED:
      return "PCAP file uploaded and queued for AI analysis"

    return "PCAP file uploaded and sent to AI Engine for analysis"

  async def upload_pcap(
    self,
    file: UploadFile,
    uploaded_by: Optional[str] = None,
  ) -> PacketUploadResponse:
    if file.filename is None:
      raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Filename is required",
      )

    file_content = await file.read()

    if not file_content:
      raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Uploaded file is empty",
      )

    sanitized_filename = self._sanitize_filename(file.filename)
    temp_validation = self.validator.validate_pcap_file(
      filename=sanitized_filename,
      file_content=file_content,
    )

    if not temp_validation.is_valid:
      raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail={
          "message": "PCAP file validation failed",
          "errors": temp_validation.errors,
          "warnings": temp_validation.warnings,
        },
      )

    upload_document_data = PacketUploadDocument.create_document(
      original_filename=file.filename,
      stored_filename=sanitized_filename,
      file_path="",
      validation_result=temp_validation,
      uploaded_by=uploaded_by,
    )

    upload_id = upload_document_data["upload_id"]
    stored_file_path = self._build_storage_path(upload_id, sanitized_filename)
    stored_file_path.write_bytes(file_content)

    final_validation = self.validator.validate_pcap_file(
      filename=sanitized_filename,
      file_content=file_content,
      file_path=stored_file_path,
    )

    if not final_validation.is_valid:
      stored_file_path.unlink(missing_ok=True)
      raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail={
          "message": "PCAP file validation failed after storage",
          "errors": final_validation.errors,
          "warnings": final_validation.warnings,
        },
      )

    upload_document_data["file_path"] = str(stored_file_path.resolve())
    upload_document_data["validation_result"] = final_validation.model_dump()
    upload_document_data["packet_count"] = final_validation.packet_count
    upload_document_data["status"] = PacketUploadStatus.STORED.value
    upload_document_data["file_hash"] = final_validation.file_hash
    upload_document_data["file_type"] = final_validation.file_type.value

    collection = get_packet_uploads_collection()
    insert_result = await collection.insert_one(upload_document_data)
    created_document = await collection.find_one({"_id": insert_result.inserted_id})

    ai_result = await ai_engine_client.submit_pcap_for_analysis(
      upload_id=upload_id,
      file_path=str(stored_file_path.resolve()),
      original_filename=file.filename,
      file_hash=final_validation.file_hash,
      packet_count=final_validation.packet_count,
      uploaded_by=uploaded_by,
    )

    now = datetime.now(timezone.utc)
    upload_status, ai_engine_status, ai_engine_error = self._resolve_upload_statuses(ai_result)

    await collection.update_one(
      {"_id": insert_result.inserted_id},
      {
        "$set": {
          "status": upload_status.value,
          "ai_engine_status": ai_engine_status.value,
          "ai_engine_job_id": ai_result.get("job_id"),
          "ai_engine_response": ai_result.get("response"),
          "ai_engine_error": ai_engine_error,
          "updated_at": now,
        }
      },
    )

    updated_document = await collection.find_one({"_id": insert_result.inserted_id})
    upload_public = PacketUploadDocument.to_public_from_mongo(updated_document)

    if upload_public is None:
      raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="Failed to process PCAP upload",
      )

    return PacketUploadResponse(
      success=True,
      message=self._build_upload_success_message(upload_status, ai_engine_status),
      upload=upload_public,
    )

  async def get_upload(self, upload_id: str) -> PacketUploadResponse:
    document = await self._get_upload_document(upload_id)
    upload = PacketUploadDocument.to_public_from_mongo(document)

    if upload is None:
      raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Packet upload with id '{upload_id}' not found",
      )

    return PacketUploadResponse(
      success=True,
      message="Packet upload retrieved successfully",
      upload=upload,
    )

  async def get_upload_status(self, upload_id: str) -> PacketUploadStatusResponse:
    document = await self._get_upload_document(upload_id)

    if document is None:
      raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Packet upload with id '{upload_id}' not found",
      )

    return PacketUploadStatusResponse(
      success=True,
      message="Packet upload status retrieved successfully",
      upload_id=document["upload_id"],
      status=PacketUploadStatus(document["status"]),
      ai_engine_status=AIEngineStatus(document["ai_engine_status"]),
      ai_engine_job_id=document.get("ai_engine_job_id"),
      ai_engine_response=document.get("ai_engine_response"),
      ai_engine_error=document.get("ai_engine_error"),
      updated_at=document["updated_at"],
    )

  async def list_uploads(
    self,
    page: int = 1,
    page_size: int = 20,
    uploaded_by: Optional[str] = None,
    status_filter: Optional[PacketUploadStatus] = None,
  ) -> PacketUploadListResponse:
    collection = get_packet_uploads_collection()
    query: dict = {}

    if uploaded_by is not None:
      query["uploaded_by"] = uploaded_by

    if status_filter is not None:
      query["status"] = status_filter.value

    skip = (page - 1) * page_size
    total_items = await collection.count_documents(query)
    cursor = (
      collection.find(query)
      .sort("created_at", -1)
      .skip(skip)
      .limit(page_size)
    )
    documents = await cursor.to_list(length=page_size)

    items: list[PacketUploadPublic] = []
    for document in documents:
      upload = PacketUploadDocument.to_public_from_mongo(document)
      if upload is not None:
        items.append(upload)

    return PacketUploadListResponse(
      success=True,
      message="Packet uploads retrieved successfully",
      items=items,
      pagination=self._build_pagination_meta(page, page_size, total_items),
    )


packet_upload_service = PacketUploadService()
