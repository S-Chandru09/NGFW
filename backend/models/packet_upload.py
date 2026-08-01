from datetime import datetime, timezone
from enum import Enum
from typing import Annotated, Any, Optional
from uuid import uuid4

from bson import ObjectId
from pydantic import BaseModel, BeforeValidator, ConfigDict, Field


class PacketUploadStatus(str, Enum):
  PENDING = "pending"
  VALIDATING = "validating"
  VALIDATED = "validated"
  STORED = "stored"
  PROCESSING = "processing"
  COMPLETED = "completed"
  FAILED = "failed"


class AIEngineStatus(str, Enum):
  PENDING = "pending"
  QUEUED = "queued"
  PROCESSING = "processing"
  COMPLETED = "completed"
  FAILED = "failed"
  SKIPPED = "skipped"


class PcapFileType(str, Enum):
  PCAP = "pcap"
  PCAPNG = "pcapng"
  UNKNOWN = "unknown"


def validate_object_id(value: Any) -> str:
  if isinstance(value, ObjectId):
    return str(value)

  if isinstance(value, str) and ObjectId.is_valid(value):
    return value

  raise ValueError("Invalid ObjectId")


PyObjectId = Annotated[str, BeforeValidator(validate_object_id)]


class PacketValidationResult(BaseModel):
  is_valid: bool
  file_type: PcapFileType
  packet_count: int = 0
  file_size: int
  file_hash: str
  errors: list[str] = Field(default_factory=list)
  warnings: list[str] = Field(default_factory=list)


class PacketUploadInDB(BaseModel):
  model_config = ConfigDict(populate_by_name=True)

  id: PyObjectId = Field(alias="_id")
  upload_id: str
  original_filename: str
  stored_filename: str
  file_path: str
  file_size: int
  file_hash: str
  file_type: PcapFileType
  packet_count: int
  status: PacketUploadStatus
  validation_result: PacketValidationResult
  ai_engine_status: AIEngineStatus
  ai_engine_job_id: Optional[str] = None
  ai_engine_response: Optional[dict[str, Any]] = None
  ai_engine_error: Optional[str] = None
  uploaded_by: Optional[str] = None
  created_at: datetime
  updated_at: datetime


class PacketUploadPublic(BaseModel):
  model_config = ConfigDict(populate_by_name=True)

  id: PyObjectId = Field(alias="_id")
  upload_id: str
  original_filename: str
  stored_filename: str
  file_path: str
  file_size: int
  file_hash: str
  file_type: PcapFileType
  packet_count: int
  status: PacketUploadStatus
  validation_result: PacketValidationResult
  ai_engine_status: AIEngineStatus
  ai_engine_job_id: Optional[str] = None
  ai_engine_response: Optional[dict[str, Any]] = None
  ai_engine_error: Optional[str] = None
  uploaded_by: Optional[str] = None
  created_at: datetime
  updated_at: datetime


class PacketUploadDocument:
  @staticmethod
  def _utc_now() -> datetime:
    return datetime.now(timezone.utc)

  @staticmethod
  def create_document(
    original_filename: str,
    stored_filename: str,
    file_path: str,
    validation_result: PacketValidationResult,
    uploaded_by: Optional[str] = None,
  ) -> dict[str, Any]:
    now = PacketUploadDocument._utc_now()
    status = PacketUploadStatus.VALIDATED if validation_result.is_valid else PacketUploadStatus.FAILED

    return {
      "upload_id": str(uuid4()),
      "original_filename": original_filename,
      "stored_filename": stored_filename,
      "file_path": file_path,
      "file_size": validation_result.file_size,
      "file_hash": validation_result.file_hash,
      "file_type": validation_result.file_type.value,
      "packet_count": validation_result.packet_count,
      "status": status.value,
      "validation_result": validation_result.model_dump(),
      "ai_engine_status": AIEngineStatus.PENDING.value,
      "ai_engine_job_id": None,
      "ai_engine_response": None,
      "ai_engine_error": None,
      "uploaded_by": uploaded_by,
      "created_at": now,
      "updated_at": now,
    }

  @staticmethod
  def from_mongo(document: Optional[dict[str, Any]]) -> Optional[PacketUploadInDB]:
    if document is None:
      return None

    document_copy = dict(document)
    document_copy["_id"] = str(document_copy["_id"])
    document_copy["validation_result"] = PacketValidationResult(**document_copy["validation_result"])
    return PacketUploadInDB(**document_copy)

  @staticmethod
  def to_public(upload: PacketUploadInDB) -> PacketUploadPublic:
    return PacketUploadPublic(
      _id=upload.id,
      upload_id=upload.upload_id,
      original_filename=upload.original_filename,
      stored_filename=upload.stored_filename,
      file_path=upload.file_path,
      file_size=upload.file_size,
      file_hash=upload.file_hash,
      file_type=upload.file_type,
      packet_count=upload.packet_count,
      status=upload.status,
      validation_result=upload.validation_result,
      ai_engine_status=upload.ai_engine_status,
      ai_engine_job_id=upload.ai_engine_job_id,
      ai_engine_response=upload.ai_engine_response,
      ai_engine_error=upload.ai_engine_error,
      uploaded_by=upload.uploaded_by,
      created_at=upload.created_at,
      updated_at=upload.updated_at,
    )

  @staticmethod
  def to_public_from_mongo(document: Optional[dict[str, Any]]) -> Optional[PacketUploadPublic]:
    upload = PacketUploadDocument.from_mongo(document)
    if upload is None:
      return None
    return PacketUploadDocument.to_public(upload)
