import asyncio
import logging
import os
import threading
from contextlib import asynccontextmanager
from typing import Any, Optional
from uuid import uuid4

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from ml.predict import AttackPredictor, load_predictor
from services.live_capture import LiveCaptureConfig, LiveCaptureRequest, LiveCaptureService
from services.pcap_analysis import PcapAnalysisConfig, PcapAnalyzer

logging.basicConfig(
  level=getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper(), logging.INFO),
  format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger("ai-engine")

_predictor: Optional[AttackPredictor] = None
_pcap_analyzer: Optional[PcapAnalyzer] = None
_live_capture_service: Optional[LiveCaptureService] = None
_live_capture_lock = threading.Lock()


def get_predictor() -> AttackPredictor:
  if _predictor is None:
    raise RuntimeError("ML models are not loaded")
  return _predictor


def get_pcap_analyzer() -> PcapAnalyzer:
  if _pcap_analyzer is None:
    raise RuntimeError("PCAP analyzer is not initialized")
  return _pcap_analyzer


def get_live_capture_service() -> LiveCaptureService:
  if _live_capture_service is None:
    raise RuntimeError("Live capture service is not initialized")
  return _live_capture_service


class LiveCaptureRequestBody(BaseModel):
  interface: Optional[str] = Field(default=None, description="Network interface (e.g. eth0, Wi-Fi)")
  bpf_filter: str = Field(default="ip or ip6", description="Berkeley Packet Filter expression")
  packet_count: int = Field(default=50, ge=1, le=5000)
  timeout_seconds: int = Field(default=30, ge=1, le=300)
  min_packets_before_predict: int = Field(default=2, ge=1, le=100)
  send_to_backend: bool = Field(default=True, description="Forward flows and threats to backend API")
  session_id: Optional[str] = Field(default=None, description="Optional session identifier")


@asynccontextmanager
async def lifespan(_: FastAPI):
  global _predictor, _pcap_analyzer, _live_capture_service

  logger.info("Starting AI engine and loading ML models")
  _predictor = load_predictor()
  _pcap_analyzer = PcapAnalyzer(
    predictor=_predictor,
    config=PcapAnalysisConfig(),
  )
  _live_capture_service = LiveCaptureService(
    predictor=_predictor,
    config=LiveCaptureConfig(),
  )
  logger.info("AI engine ready for PCAP analysis and live capture")

  yield

  _predictor = None
  _pcap_analyzer = None
  _live_capture_service = None
  logger.info("AI engine shutdown complete")


app = FastAPI(
  title="AI-NGFW AI Engine",
  description="ML inference, PCAP analysis, and live capture service",
  version="1.0.0",
  lifespan=lifespan,
)

app.add_middleware(
  CORSMiddleware,
  allow_origins=["*"],
  allow_credentials=True,
  allow_methods=["*"],
  allow_headers=["*"],
)


@app.get("/health")
async def health_check() -> dict[str, Any]:
  models_loaded = _predictor is not None and bool(_predictor.loaded_models)
  live_capture_enabled = _live_capture_service.config.enabled if _live_capture_service else False
  return {
    "status": "healthy",
    "service": "ai-engine",
    "models_loaded": models_loaded,
    "loaded_models": _predictor.loaded_models if _predictor else [],
    "live_capture_enabled": live_capture_enabled,
  }


@app.get("/api/v1/analyze/live/capabilities")
async def get_live_capture_capabilities() -> dict[str, Any]:
  service = get_live_capture_service()
  return {
    "success": True,
    "message": "Live capture capabilities retrieved successfully",
    **service.get_capabilities(),
  }


@app.post("/api/v1/analyze/live")
async def analyze_live_traffic(request: LiveCaptureRequestBody) -> dict[str, Any]:
  service = get_live_capture_service()

  if not service.config.enabled:
    raise HTTPException(status_code=503, detail="Live capture is disabled on this AI engine instance")

  if not _live_capture_lock.acquire(blocking=False):
    raise HTTPException(
      status_code=409,
      detail="Another live capture session is already running",
    )

  capture_request = LiveCaptureRequest(
    interface=request.interface,
    bpf_filter=request.bpf_filter,
    packet_count=request.packet_count,
    timeout_seconds=request.timeout_seconds,
    min_packets_before_predict=request.min_packets_before_predict,
    send_to_backend=request.send_to_backend,
    session_id=request.session_id,
  )

  try:
    report = await asyncio.to_thread(service.run_capture, capture_request)
  except PermissionError as exc:
    raise HTTPException(
      status_code=403,
      detail="Packet capture permission denied. Run with admin/root or install Npcap.",
    ) from exc
  except OSError as exc:
    raise HTTPException(
      status_code=400,
      detail=f"Unable to open network interface for capture: {exc}",
    ) from exc
  except RuntimeError as exc:
    raise HTTPException(status_code=503, detail=str(exc)) from exc
  except Exception as exc:
    logger.exception("Live capture failed | session_id=%s", capture_request.session_id)
    raise HTTPException(status_code=500, detail=f"Live capture failed: {exc}") from exc
  finally:
    _live_capture_lock.release()

  response = report.to_dict()
  response.update(
    {
      "success": True,
      "message": "Live capture completed successfully",
      "job_id": report.session_id,
    }
  )
  return response


@app.post("/api/v1/analyze/pcap")
async def analyze_pcap(
  upload_id: str = Form(...),
  file_hash: str = Form(...),
  packet_count: str = Form(default="0"),
  uploaded_by: str | None = Form(default=None),
  file: UploadFile | None = File(default=None),
) -> dict[str, Any]:
  filename = file.filename if file is not None else "unknown.pcap"
  job_id = str(uuid4())

  if file is None:
    raise HTTPException(status_code=400, detail="PCAP file is required for analysis")

  file_content = await file.read()
  if not file_content:
    raise HTTPException(status_code=400, detail="Uploaded PCAP file is empty")

  logger.info(
    "PCAP analysis started | upload_id=%s | file=%s | packets=%s | hash=%s",
    upload_id,
    filename,
    packet_count,
    file_hash,
  )

  try:
    analyzer = get_pcap_analyzer()
    report = await asyncio.to_thread(
      analyzer.analyze_bytes,
      file_content,
      upload_id,
      filename,
      job_id,
    )
  except FileNotFoundError as exc:
    logger.error("PCAP analysis failed | upload_id=%s | error=%s", upload_id, exc)
    raise HTTPException(status_code=404, detail=str(exc)) from exc
  except Exception as exc:
    logger.exception("PCAP analysis failed | upload_id=%s", upload_id)
    raise HTTPException(status_code=500, detail=f"PCAP analysis failed: {exc}") from exc

  response = report.to_dict()
  response.update(
    {
      "message": "PCAP analysis completed successfully",
      "job_id": job_id,
      "analysis_id": report.analysis_id,
      "file_hash": file_hash,
      "uploaded_by": uploaded_by or "",
      "expected_packet_count": packet_count,
    }
  )

  logger.info(
    "PCAP analysis completed | upload_id=%s | flows=%s | threats=%s",
    upload_id,
    report.flows_analyzed,
    report.threats_detected,
  )
  return response


if __name__ == "__main__":
  import uvicorn

  host = os.getenv("HOST", "0.0.0.0")
  port = int(os.getenv("PORT", "8001"))

  uvicorn.run("main:app", host=host, port=port, reload=False)
