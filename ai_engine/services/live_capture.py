"""
Live network capture and real-time ML threat detection service.

Captures packets from a network interface, builds flows, runs ensemble prediction,
and optionally forwards results to the backend dashboard API.
"""

from __future__ import annotations

import logging
import os
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import uuid4

from ml.predict import AttackPredictor
from network.flow_generator import NetworkFlow
from network.real_time_detector import RealTimeDetectionReport, RealTimeDetectionResult, RealTimeDetector, RealTimeDetectorConfig
from network.sender import FeatureSender, SenderConfig

logger = logging.getLogger("ai-engine.live_capture")

DEFAULT_PACKET_COUNT = int(os.getenv("LIVE_CAPTURE_PACKET_COUNT", "50"))
DEFAULT_TIMEOUT_SECONDS = int(os.getenv("LIVE_CAPTURE_TIMEOUT_SECONDS", "30"))
DEFAULT_BPF_FILTER = os.getenv("CAPTURE_BPF_FILTER", "ip or ip6")
DEFAULT_INTERFACE = os.getenv("CAPTURE_INTERFACE") or None


@dataclass
class LiveCaptureRequest:
  interface: Optional[str] = None
  bpf_filter: str = DEFAULT_BPF_FILTER
  packet_count: int = DEFAULT_PACKET_COUNT
  timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS
  min_packets_before_predict: int = 2
  send_to_backend: bool = os.getenv("BACKEND_SENDER_ENABLED", "true").lower() == "true"
  session_id: Optional[str] = None


@dataclass
class LiveFlowDetection:
  flow_id: str
  source_ip: Optional[str]
  destination_ip: Optional[str]
  source_port: Optional[int]
  destination_port: Optional[int]
  protocol: str
  total_packets: int
  prediction: dict[str, Any]
  detected_at: str

  def to_dict(self) -> dict[str, Any]:
    return asdict(self)


@dataclass
class LiveCaptureReport:
  session_id: str
  status: str
  interface: Optional[str]
  bpf_filter: str
  packets_processed: int
  predictions_generated: int
  threats_detected: int
  summary: dict[str, Any]
  detections: list[LiveFlowDetection] = field(default_factory=list)
  backend_delivery: Optional[dict[str, Any]] = None
  completed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

  def to_dict(self) -> dict[str, Any]:
    payload = asdict(self)
    payload["detections"] = [detection.to_dict() for detection in self.detections]
    return payload


@dataclass
class LiveCaptureConfig:
  default_interface: Optional[str] = DEFAULT_INTERFACE
  send_to_backend: bool = os.getenv("BACKEND_SENDER_ENABLED", "true").lower() == "true"
  enabled: bool = os.getenv("LIVE_CAPTURE_ENABLED", "true").lower() == "true"


class LiveCaptureService:
  """Run a bounded live capture session and return ML detections."""

  def __init__(
    self,
    predictor: AttackPredictor,
    config: Optional[LiveCaptureConfig] = None,
    sender_config: Optional[SenderConfig] = None,
  ) -> None:
    self.predictor = predictor
    self.config = config or LiveCaptureConfig()
    self.sender = FeatureSender(sender_config or SenderConfig.from_env())

  @staticmethod
  def _scoped_flow_id(session_id: str, flow_id: str) -> str:
    return f"live:{session_id}:{flow_id}"

  def _build_detection(self, detection: RealTimeDetectionResult) -> LiveFlowDetection:
    flow = detection.flow
    return LiveFlowDetection(
      flow_id=flow.flow_id,
      source_ip=flow.src_ip,
      destination_ip=flow.dst_ip,
      source_port=flow.source_port,
      destination_port=flow.destination_port,
      protocol=flow.protocol,
      total_packets=flow.total_packets,
      prediction=detection.prediction.to_dict(),
      detected_at=detection.detected_at,
    )

  def _summarize_detections(self, detections: list[LiveFlowDetection]) -> dict[str, Any]:
    attack_counts: dict[str, int] = {}
    threat_levels: dict[str, int] = {"low": 0, "medium": 0, "high": 0}

    for detection in detections:
      prediction = detection.prediction
      if not prediction.get("is_attack"):
        continue

      attack_label = str(prediction.get("attack_label", "UNKNOWN"))
      attack_counts[attack_label] = attack_counts.get(attack_label, 0) + 1

      threat_level = str(prediction.get("threat_level", "low")).lower()
      if threat_level in threat_levels:
        threat_levels[threat_level] += 1

    top_threat = None
    if attack_counts:
      top_label, top_count = max(attack_counts.items(), key=lambda item: item[1])
      top_threat = {"attack_label": top_label, "count": top_count}

    return {
      "attack_counts": attack_counts,
      "threat_levels": threat_levels,
      "top_threat": top_threat,
      "benign_flows": sum(1 for detection in detections if not detection.prediction.get("is_attack")),
      "malicious_flows": sum(1 for detection in detections if detection.prediction.get("is_attack")),
    }

  def _send_to_backend(
    self,
    session_id: str,
    detections: list[LiveFlowDetection],
    detector_report: RealTimeDetectionReport,
  ) -> dict[str, Any]:
    if not self.config.send_to_backend:
      return {"enabled": False, "message": "Backend sender disabled"}

    flow_map = {detection.flow_id: detection for detection in detections}
    detection_results = {
      item.flow_id: item
      for item in detector_report.detections
      if item.flow_id in flow_map
    }

    scoped_flows: list[NetworkFlow] = []
    scoped_predictions: dict[str, dict[str, Any]] = {}

    for flow_id, detection_result in detection_results.items():
      flow = detection_result.flow
      scoped_flow_id = self._scoped_flow_id(session_id, flow.flow_id)
      scoped_flows.append(replace(flow, flow_id=scoped_flow_id))
      scoped_predictions[scoped_flow_id] = detection_result.prediction.to_dict()

    if not scoped_flows:
      return {
        "enabled": True,
        "success": True,
        "message": "No flows available for backend delivery",
        "total_flows": 0,
        "sent_count": 0,
        "failed_count": 0,
      }

    threat_flows = [flow for flow in scoped_flows if scoped_predictions.get(flow.flow_id, {}).get("is_attack")]
    benign_flows = [flow for flow in scoped_flows if not scoped_predictions.get(flow.flow_id, {}).get("is_attack")]
    flows_to_send = threat_flows + benign_flows

    extra_metadata = {
      "analysis_source": "live_capture",
      "session_id": session_id,
      "capture_mode": "real_time",
    }
    batch_metadata = {
      "analysis_source": "live_capture",
      "session_id": session_id,
      "capture_mode": "real_time",
      "threat_flows": len(threat_flows),
      "benign_flows": len(benign_flows),
    }

    batch_result = self.sender.send_flows(
      flows=flows_to_send,
      predictions=scoped_predictions,
      use_batch_endpoint=True,
      extra_metadata=extra_metadata,
      batch_metadata=batch_metadata,
    )
    result = batch_result.to_dict()
    result["enabled"] = True
    result["threat_flows_sent"] = len(threat_flows)
    result["benign_flows_sent"] = len(benign_flows)
    return result

  def run_capture(self, request: LiveCaptureRequest) -> LiveCaptureReport:
    if not self.config.enabled:
      raise RuntimeError("Live capture is disabled on this AI engine instance")

    session_id = request.session_id or str(uuid4())
    interface = request.interface or self.config.default_interface

    detector = RealTimeDetector(
      RealTimeDetectorConfig(
        interface=interface,
        bpf_filter=request.bpf_filter,
        packet_count=request.packet_count,
        timeout_seconds=request.timeout_seconds,
        min_packets_before_predict=request.min_packets_before_predict,
      ),
      predictor=self.predictor,
    )
    detector.initialize()

    logger.info(
      "Live capture started | session_id=%s | interface=%s | packets=%s | timeout=%ss",
      session_id,
      interface or "default",
      request.packet_count,
      request.timeout_seconds,
    )

    detector_report = detector.capture_and_detect()
    detections = [self._build_detection(detection) for detection in detector_report.detections]
    summary = self._summarize_detections(detections)
    threats_detected = int(summary.get("malicious_flows", 0))

    backend_delivery = None
    if request.send_to_backend and detections:
      try:
        backend_delivery = self._send_to_backend(session_id, detections, detector_report)
      except Exception as exc:
        logger.exception("Failed to deliver live capture results to backend")
        backend_delivery = {
          "enabled": True,
          "success": False,
          "error": str(exc),
        }

    logger.info(
      "Live capture completed | session_id=%s | packets=%s | predictions=%s | threats=%s",
      session_id,
      detector_report.packets_processed,
      detector_report.predictions_generated,
      threats_detected,
    )

    return LiveCaptureReport(
      session_id=session_id,
      status="completed",
      interface=interface,
      bpf_filter=request.bpf_filter,
      packets_processed=detector_report.packets_processed,
      predictions_generated=detector_report.predictions_generated,
      threats_detected=threats_detected,
      summary=summary,
      detections=detections,
      backend_delivery=backend_delivery,
      completed_at=detector_report.completed_at,
    )

  def get_capabilities(self) -> dict[str, Any]:
    return {
      "enabled": self.config.enabled,
      "default_interface": self.config.default_interface,
      "default_bpf_filter": DEFAULT_BPF_FILTER,
      "default_packet_count": DEFAULT_PACKET_COUNT,
      "default_timeout_seconds": DEFAULT_TIMEOUT_SECONDS,
      "send_to_backend": self.config.send_to_backend,
      "models_loaded": self.predictor.loaded_models.copy(),
      "notes": [
        "Requires packet capture permissions (CAP_NET_RAW on Linux, Npcap on Windows).",
        "Docker containers need host networking and elevated privileges for live capture.",
      ],
    }
