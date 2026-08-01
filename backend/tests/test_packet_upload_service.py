from models.packet_upload import AIEngineStatus, PacketUploadStatus
from services.packet_upload_service import PacketUploadService


def test_resolve_upload_statuses_completed() -> None:
  service = PacketUploadService()
  upload_status, ai_status, error = service._resolve_upload_statuses(
    {"success": True, "status": "completed"},
  )

  assert upload_status == PacketUploadStatus.COMPLETED
  assert ai_status == AIEngineStatus.COMPLETED
  assert error is None


def test_resolve_upload_statuses_failed() -> None:
  service = PacketUploadService()
  upload_status, ai_status, error = service._resolve_upload_statuses(
    {"success": False, "status": "failed", "error": "timeout"},
  )

  assert upload_status == PacketUploadStatus.FAILED
  assert ai_status == AIEngineStatus.FAILED
  assert error == "timeout"


def test_build_upload_success_message_completed() -> None:
  service = PacketUploadService()
  message = service._build_upload_success_message(
    PacketUploadStatus.COMPLETED,
    AIEngineStatus.COMPLETED,
  )
  assert "completed successfully" in message.lower()
