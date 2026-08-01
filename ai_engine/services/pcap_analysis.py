"""
PCAP analysis pipeline for the AI-NGFW AI engine.

Reads uploaded PCAP files, generates network flows, runs ensemble ML prediction,
and optionally forwards results to the backend API.
"""

from __future__ import annotations

import logging
import os
import tempfile
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from uuid import uuid4

from ml.predict import AttackPredictionResult, AttackPredictor
from network.flow_generator import FlowGenerator, FlowGeneratorConfig, NetworkFlow
from network.packet_capture import PacketCapturer, PacketCaptureReport
from network.sender import FeatureSender, SenderConfig

logger = logging.getLogger("ai-engine.pcap_analysis")

DEFAULT_MAX_PACKETS = int(os.getenv("PCAP_MAX_PACKETS", "50000"))
DEFAULT_MAX_FLOWS = int(os.getenv("PCAP_MAX_FLOWS", "1000"))
DEFAULT_MIN_PACKETS_PER_FLOW = int(os.getenv("PCAP_MIN_PACKETS_PER_FLOW", "1"))


@dataclass
class FlowAnalysisResult:
  flow_id: str
  source_ip: Optional[str]
  destination_ip: Optional[str]
  source_port: Optional[int]
  destination_port: Optional[int]
  protocol: str
  total_packets: int
  prediction: dict[str, Any]

  def to_dict(self) -> dict[str, Any]:
    return asdict(self)


@dataclass
class PcapAnalysisReport:
  analysis_id: str
  upload_id: str
  original_filename: str
  status: str
  packets_processed: int
  flows_generated: int
  flows_analyzed: int
  threats_detected: int
  summary: dict[str, Any]
  detections: list[FlowAnalysisResult] = field(default_factory=list)
  backend_delivery: Optional[dict[str, Any]] = None
  analyzed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

  def to_dict(self) -> dict[str, Any]:
    payload = asdict(self)
    payload["detections"] = [detection.to_dict() for detection in self.detections]
    return payload


@dataclass
class PcapAnalysisConfig:
  max_packets: int = DEFAULT_MAX_PACKETS
  max_flows: int = DEFAULT_MAX_FLOWS
  min_packets_per_flow: int = DEFAULT_MIN_PACKETS_PER_FLOW
  send_to_backend: bool = os.getenv("BACKEND_SENDER_ENABLED", "true").lower() == "true"


class PcapAnalyzer:
  """Analyze PCAP files and run ML-based threat detection."""

  def __init__(
    self,
    predictor: AttackPredictor,
    config: Optional[PcapAnalysisConfig] = None,
    sender_config: Optional[SenderConfig] = None,
  ) -> None:
    self.predictor = predictor
    self.config = config or PcapAnalysisConfig()
    self.sender = FeatureSender(sender_config or SenderConfig.from_env())

  def _build_feature_payload(self, flow: NetworkFlow) -> dict[str, Any]:
    feature_payload = flow.to_dict()
    feature_payload.update(flow.features)
    return feature_payload

  def _read_packets(self, pcap_path: Path) -> PacketCaptureReport:
    capturer = PacketCapturer()
    return capturer.read_pcap_file(
      pcap_path=pcap_path,
      max_packets=self.config.max_packets,
    )

  def _generate_flows(self, capture_report: PacketCaptureReport) -> list[NetworkFlow]:
    flow_generator = FlowGenerator(
      FlowGeneratorConfig(min_packets_per_flow=self.config.min_packets_per_flow)
    )
    flow_generator.add_capture_report(capture_report)
    flow_report = flow_generator.generate_flows()
    return flow_report.flows

  def _summarize_detections(self, detections: list[FlowAnalysisResult]) -> dict[str, Any]:
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

  def _analyze_flows(self, flows: list[NetworkFlow]) -> list[FlowAnalysisResult]:
    if not self.predictor.loaded_models:
      self.predictor.load_all_models()

    flows_to_analyze = flows[: self.config.max_flows]
    detections: list[FlowAnalysisResult] = []

    for flow in flows_to_analyze:
      feature_payload = self._build_feature_payload(flow)
      prediction = self.predictor.predict(feature_payload)
      detections.append(self._build_detection(flow, prediction))

    return detections

  @staticmethod
  def _build_detection(flow: NetworkFlow, prediction: AttackPredictionResult) -> FlowAnalysisResult:
    return FlowAnalysisResult(
      flow_id=flow.flow_id,
      source_ip=flow.src_ip,
      destination_ip=flow.dst_ip,
      source_port=flow.source_port,
      destination_port=flow.destination_port,
      protocol=flow.protocol,
      total_packets=flow.total_packets,
      prediction=prediction.to_dict(),
    )

  def _scoped_flow_id(self, upload_id: str, flow_id: str) -> str:
    return f"{upload_id}:{flow_id}"

  def _prepare_flows_for_backend(
    self,
    flows: list[NetworkFlow],
    upload_id: str,
  ) -> tuple[list[NetworkFlow], dict[str, str]]:
    scoped_flows: list[NetworkFlow] = []
    flow_id_map: dict[str, str] = {}

    for flow in flows:
      scoped_flow_id = self._scoped_flow_id(upload_id, flow.flow_id)
      scoped_flows.append(replace(flow, flow_id=scoped_flow_id))
      flow_id_map[flow.flow_id] = scoped_flow_id

    return scoped_flows, flow_id_map

  def _send_to_backend(
    self,
    flows: list[NetworkFlow],
    detections: list[FlowAnalysisResult],
    upload_id: str,
    original_filename: str,
    analysis_id: str,
  ) -> dict[str, Any]:
    if not self.config.send_to_backend:
      return {"enabled": False, "message": "Backend sender disabled"}

    prediction_map = {
      detection.flow_id: detection.prediction
      for detection in detections
    }
    flow_map = {flow.flow_id: flow for flow in flows}
    selected_flows = [flow_map[flow_id] for flow_id in prediction_map if flow_id in flow_map]
    scoped_flows, flow_id_map = self._prepare_flows_for_backend(selected_flows, upload_id)
    scoped_predictions = {
      flow_id_map[flow_id]: prediction
      for flow_id, prediction in prediction_map.items()
      if flow_id in flow_id_map
    }

    threat_flows = [
      flow
      for flow in scoped_flows
      if scoped_predictions.get(flow.flow_id, {}).get("is_attack")
    ]
    benign_flows = [
      flow
      for flow in scoped_flows
      if not scoped_predictions.get(flow.flow_id, {}).get("is_attack")
    ]
    flows_to_send = threat_flows + benign_flows

    extra_metadata = {
      "analysis_source": "pcap_upload",
      "upload_id": upload_id,
      "analysis_id": analysis_id,
      "original_filename": original_filename,
    }
    batch_metadata = {
      "analysis_source": "pcap_upload",
      "upload_id": upload_id,
      "analysis_id": analysis_id,
      "original_filename": original_filename,
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

  def analyze_file(
    self,
    pcap_path: Path,
    upload_id: str,
    original_filename: str,
    analysis_id: Optional[str] = None,
  ) -> PcapAnalysisReport:
    capture_report = self._read_packets(pcap_path)
    flows = self._generate_flows(capture_report)
    detections = self._analyze_flows(flows)
    summary = self._summarize_detections(detections)
    threats_detected = int(summary.get("malicious_flows", 0))
    resolved_analysis_id = analysis_id or str(uuid4())

    backend_delivery = None
    if flows and detections:
      try:
        backend_delivery = self._send_to_backend(
          flows=flows,
          detections=detections,
          upload_id=upload_id,
          original_filename=original_filename,
          analysis_id=resolved_analysis_id,
        )
      except Exception as exc:
        logger.exception("Failed to deliver PCAP analysis results to backend")
        backend_delivery = {
          "enabled": True,
          "success": False,
          "error": str(exc),
        }

    return PcapAnalysisReport(
      analysis_id=resolved_analysis_id,
      upload_id=upload_id,
      original_filename=original_filename,
      status="completed",
      packets_processed=capture_report.packets_captured,
      flows_generated=len(flows),
      flows_analyzed=len(detections),
      threats_detected=threats_detected,
      summary=summary,
      detections=detections,
      backend_delivery=backend_delivery,
    )

  def analyze_bytes(
    self,
    file_content: bytes,
    upload_id: str,
    original_filename: str,
    analysis_id: Optional[str] = None,
  ) -> PcapAnalysisReport:
    suffix = Path(original_filename).suffix or ".pcap"

    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as temp_file:
      temp_file.write(file_content)
      temp_path = Path(temp_file.name)

    try:
      return self.analyze_file(
        pcap_path=temp_path,
        upload_id=upload_id,
        original_filename=original_filename,
        analysis_id=analysis_id,
      )
    finally:
      temp_path.unlink(missing_ok=True)
