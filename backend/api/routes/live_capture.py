from fastapi import APIRouter, Depends

from core.auth_utils import require_permission
from models.user import UserPublic
from schemas.live_capture import (
  LiveCaptureCapabilitiesResponse,
  LiveCaptureRequest,
  LiveCaptureResponse,
)
from services.live_capture_service import live_capture_service

router = APIRouter(prefix="/capture", tags=["Live Capture"])


@router.get(
  "/live/capabilities",
  response_model=LiveCaptureCapabilitiesResponse,
  summary="Get live capture capabilities from the AI engine",
)
async def get_live_capture_capabilities(
  current_user: UserPublic = Depends(require_permission("capture:read")),
) -> LiveCaptureCapabilitiesResponse:
  return await live_capture_service.get_capabilities()


@router.post(
  "/live",
  response_model=LiveCaptureResponse,
  summary="Run a bounded live packet capture and ML threat detection session",
)
async def run_live_capture(
  request: LiveCaptureRequest,
  current_user: UserPublic = Depends(require_permission("capture:write")),
) -> LiveCaptureResponse:
  return await live_capture_service.run_capture(request)
