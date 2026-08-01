import logging
from typing import Any

import httpx
from fastapi import HTTPException, status

from config import settings
from schemas.live_capture import (
  LiveCaptureCapabilitiesResponse,
  LiveCaptureRequest,
  LiveCaptureResponse,
)

logger = logging.getLogger("ai-ngfw.live_capture")


class LiveCaptureService:
  async def get_capabilities(self) -> LiveCaptureCapabilitiesResponse:
    if not settings.ai_engine_enabled:
      return LiveCaptureCapabilitiesResponse(
        success=True,
        message="AI Engine is disabled",
        enabled=False,
        default_interface=settings.capture_interface,
        default_bpf_filter=settings.capture_bpf_filter,
        default_packet_count=50,
        default_timeout_seconds=30,
        send_to_backend=False,
        models_loaded=[],
        notes=["AI Engine integration is disabled."],
      )

    endpoint = f"{settings.ai_engine_url.rstrip('/')}/api/v1/analyze/live/capabilities"

    try:
      async with httpx.AsyncClient(timeout=settings.ai_engine_timeout_seconds) as client:
        response = await client.get(endpoint)
        response.raise_for_status()
        payload = response.json()
    except httpx.HTTPError as exc:
      logger.error("Failed to fetch live capture capabilities: %s", exc)
      raise HTTPException(
        status_code=status.HTTP_502_BAD_GATEWAY,
        detail="Unable to reach AI engine live capture service",
      ) from exc

    return LiveCaptureCapabilitiesResponse(
      success=True,
      message=payload.get("message", "Live capture capabilities retrieved successfully"),
      enabled=bool(payload.get("enabled", False)),
      default_interface=payload.get("default_interface") or settings.capture_interface,
      default_bpf_filter=payload.get("default_bpf_filter", settings.capture_bpf_filter),
      default_packet_count=int(payload.get("default_packet_count", 50)),
      default_timeout_seconds=int(payload.get("default_timeout_seconds", 30)),
      send_to_backend=bool(payload.get("send_to_backend", True)),
      models_loaded=list(payload.get("models_loaded", [])),
      notes=list(payload.get("notes", [])),
    )

  async def run_capture(self, request: LiveCaptureRequest) -> LiveCaptureResponse:
    if not settings.network_capture_enabled:
      raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Network capture is disabled on the backend",
      )

    if not settings.ai_engine_enabled:
      raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="AI Engine is disabled",
      )

    endpoint = f"{settings.ai_engine_url.rstrip('/')}{settings.ai_engine_live_endpoint}"
    payload = request.model_dump()

    if payload.get("interface") is None:
      payload["interface"] = settings.capture_interface

    if not payload.get("bpf_filter"):
      payload["bpf_filter"] = settings.capture_bpf_filter

    timeout_seconds = max(
      settings.ai_engine_timeout_seconds,
      int(payload.get("timeout_seconds", 30)) + 30,
    )

    try:
      async with httpx.AsyncClient(timeout=timeout_seconds) as client:
        response = await client.post(endpoint, json=payload)
        response.raise_for_status()
        data: dict[str, Any] = response.json()
    except httpx.TimeoutException as exc:
      raise HTTPException(
        status_code=status.HTTP_504_GATEWAY_TIMEOUT,
        detail="Live capture request timed out",
      ) from exc
    except httpx.HTTPStatusError as exc:
      detail = exc.response.text
      try:
        error_payload = exc.response.json()
        detail = error_payload.get("detail", detail)
      except ValueError:
        pass

      status_code = exc.response.status_code
      if status_code == 409:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=detail) from exc
      if status_code == 403:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=detail) from exc
      if status_code == 400:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail) from exc

      raise HTTPException(
        status_code=status.HTTP_502_BAD_GATEWAY,
        detail=f"AI Engine live capture failed: {detail}",
      ) from exc
    except httpx.RequestError as exc:
      raise HTTPException(
        status_code=status.HTTP_502_BAD_GATEWAY,
        detail="Could not connect to AI Engine for live capture",
      ) from exc

    return LiveCaptureResponse(
      success=bool(data.get("success", True)),
      message=data.get("message", "Live capture completed successfully"),
      session_id=data.get("session_id", ""),
      status=data.get("status", "completed"),
      interface=data.get("interface"),
      bpf_filter=data.get("bpf_filter", payload["bpf_filter"]),
      packets_processed=int(data.get("packets_processed", 0)),
      predictions_generated=int(data.get("predictions_generated", 0)),
      threats_detected=int(data.get("threats_detected", 0)),
      summary=data.get("summary", {}),
      detections=data.get("detections", []),
      backend_delivery=data.get("backend_delivery"),
      completed_at=data.get("completed_at", ""),
      job_id=data.get("job_id"),
    )


live_capture_service = LiveCaptureService()
