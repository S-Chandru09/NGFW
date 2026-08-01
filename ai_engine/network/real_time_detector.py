"""
Real-time network attack detector.

Reads packets, extracts flow features, runs ML prediction, and returns
attack labels with confidence scores.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional, Union

from scapy.packet import Packet

from ml.predict import AttackPredictionResult, AttackPredictor, PredictorConfig
from network.flow_generator import FlowGenerator, FlowGeneratorConfig, NetworkFlow
from network.packet_capture import (
  CapturedPacket,
  PacketCaptureConfig,
  PacketCaptureReport,
  PacketCapturer,
)

logger = logging.getLogger("ai-engine.real_time_detector")

DEFAULT_MIN_PACKETS_BEFORE_PREDICT = 2
DEFAULT_REPREDICT_EVERY_N_PACKETS = 5
DEFAULT_CAPTURE_PACKET_COUNT = 50
DEFAULT_CAPTURE_TIMEOUT_SECONDS = 30


@dataclass
class RealTimeDetectorConfig:
  interface: Optional[str] = None
  bpf_filter: str = "ip or ip6"
  packet_count: int = DEFAULT_CAPTURE_PACKET_COUNT
  timeout_seconds: int = DEFAULT_CAPTURE_TIMEOUT_SECONDS
  min_packets_before_predict: int = DEFAULT_MIN_PACKETS_BEFORE_PREDICT
  repredict_every_n_packets: int = DEFAULT_REPREDICT_EVERY_N_PACKETS
  flow_duration_unit: str = "microseconds"
  predictor_config: Optional[PredictorConfig] = None


@dataclass
class RealTimeDetectionResult:
  flow_id: str
  attack_label: str
  confidence: float
  is_attack: bool
  threat_level: str
  packet: CapturedPacket
  flow: NetworkFlow
  features: dict[str, float | int | str]
  prediction: AttackPredictionResult
  detected_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

  def to_dict(self) -> dict:
    return {
      "flow_id": self.flow_id,
      "attack_label": self.attack_label,
      "confidence": self.confidence,
      "is_attack": self.is_attack,
      "threat_level": self.threat_level,
      "packet": self.packet.to_dict(),
      "flow": self.flow.to_dict(),
      "features": self.features,
      "prediction": self.prediction.to_dict(),
      "detected_at": self.detected_at,
    }


@dataclass
class RealTimeDetectionReport:
  packets_processed: int
  predictions_generated: int
  detections: list[RealTimeDetectionResult] = field(default_factory=list)
  completed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

  def to_dict(self) -> dict:
    payload = asdict(self)
    payload["detections"] = [detection.to_dict() for detection in self.detections]
    return payload


class RealTimeDetector:
  """Read packets, extract features, predict attacks, and return results."""

  def __init__(
    self,
    config: Optional[RealTimeDetectorConfig] = None,
    predictor: Optional[AttackPredictor] = None,
  ) -> None:
    self.config = config or RealTimeDetectorConfig()
    self.packet_capturer = PacketCapturer(
      PacketCaptureConfig(
        interface=self.config.interface,
        packet_count=self.config.packet_count,
        timeout_seconds=self.config.timeout_seconds,
        bpf_filter=self.config.bpf_filter,
        store_packets=False,
      )
    )
    self.flow_generator = FlowGenerator(
      FlowGeneratorConfig(
        min_packets_per_flow=1,
        duration_unit=self.config.flow_duration_unit,
      )
    )
    self.predictor = predictor or AttackPredictor(config=self.config.predictor_config)
    self._flow_packet_counts: dict[str, int] = {}
    self._last_prediction_packet_count: dict[str, int] = {}
    self._initialized = False

  def initialize(self) -> list[str]:
    """Load ML models required for prediction."""
    if self.predictor.loaded_models:
      self._initialized = True
      logger.info(
        "Real-time detector using preloaded models: %s",
        ", ".join(self.predictor.loaded_models),
      )
      return self.predictor.loaded_models.copy()

    loaded_models = self.predictor.load_all_models()
    self._initialized = True
    logger.info("Real-time detector initialized with models: %s", ", ".join(loaded_models))
    return loaded_models

  def _ensure_initialized(self) -> None:
    if not self._initialized:
      self.initialize()

  def read_packet(self, packet: Union[Packet, CapturedPacket]) -> CapturedPacket:
    """Read and normalize a packet from Scapy or a captured packet object."""
    if isinstance(packet, CapturedPacket):
      return packet

    return self.packet_capturer.parse_packet(packet)

  def _build_feature_payload(self, flow: NetworkFlow) -> dict[str, float | int | str]:
    feature_payload = flow.to_dict()
    feature_payload.update(flow.features)
    return feature_payload

  def _should_predict(self, flow_key: str) -> bool:
    packet_count = self._flow_packet_counts.get(flow_key, 0)

    if packet_count < self.config.min_packets_before_predict:
      return False

    last_prediction_count = self._last_prediction_packet_count.get(flow_key, 0)
    packets_since_last_prediction = packet_count - last_prediction_count

    if last_prediction_count == 0:
      return True

    return packets_since_last_prediction >= self.config.repredict_every_n_packets

  def _find_flow_by_id(self, flow_id: str) -> Optional[NetworkFlow]:
    flow_report = self.flow_generator.generate_flows()

    for flow in flow_report.flows:
      if flow.flow_id == flow_id:
        return flow

    return None

  def extract_features(self, flow_key: str) -> Optional[NetworkFlow]:
    """Extract flow features for a buffered flow."""
    return self._find_flow_by_id(flow_key)

  def predict_flow(self, flow: NetworkFlow) -> AttackPredictionResult:
    """Run ML prediction on extracted flow features."""
    self._ensure_initialized()
    feature_payload = self._build_feature_payload(flow)
    return self.predictor.predict(feature_payload)

  def process_packet(self, packet: Union[Packet, CapturedPacket]) -> Optional[RealTimeDetectionResult]:
    """
    Read a packet, update flow state, extract features when ready, and predict.
    """
    captured_packet = self.read_packet(packet)
    flow_key = self.flow_generator.add_packet(captured_packet)

    if flow_key is None:
      logger.debug("Skipped packet without valid flow key")
      return None

    self._flow_packet_counts[flow_key] = self._flow_packet_counts.get(flow_key, 0) + 1

    if not self._should_predict(flow_key):
      return None

    flow = self.extract_features(flow_key)
    if flow is None:
      logger.warning("Flow features could not be extracted for flow_id=%s", flow_key)
      return None

    prediction = self.predict_flow(flow)
    self._last_prediction_packet_count[flow_key] = self._flow_packet_counts[flow_key]

    return RealTimeDetectionResult(
      flow_id=flow.flow_id,
      attack_label=prediction.attack_label,
      confidence=prediction.confidence,
      is_attack=prediction.is_attack,
      threat_level=prediction.threat_level,
      packet=captured_packet,
      flow=flow,
      features=flow.features,
      prediction=prediction,
    )

  def detect_from_packet(self, packet: Union[Packet, CapturedPacket]) -> RealTimeDetectionResult:
    """Force feature extraction and prediction for the packet's flow."""
    captured_packet = self.read_packet(packet)
    flow_key = self.flow_generator.add_packet(captured_packet)

    if flow_key is None:
      raise ValueError("Packet does not contain enough metadata to build a flow")

    self._flow_packet_counts[flow_key] = self._flow_packet_counts.get(flow_key, 0) + 1

    flow = self.extract_features(flow_key)
    if flow is None:
      raise ValueError(f"Unable to extract features for flow_id={flow_key}")

    prediction = self.predict_flow(flow)
    self._last_prediction_packet_count[flow_key] = self._flow_packet_counts[flow_key]

    return RealTimeDetectionResult(
      flow_id=flow.flow_id,
      attack_label=prediction.attack_label,
      confidence=prediction.confidence,
      is_attack=prediction.is_attack,
      threat_level=prediction.threat_level,
      packet=captured_packet,
      flow=flow,
      features=flow.features,
      prediction=prediction,
    )

  def capture_and_detect(self) -> RealTimeDetectionReport:
    """Capture live packets, extract features, and return predictions."""
    self._ensure_initialized()
    self.reset()

    capture_report = self.packet_capturer.capture()
    return self.detect_from_capture_report(capture_report)

  def detect_from_capture_report(self, report: PacketCaptureReport) -> RealTimeDetectionReport:
    """Process an existing capture report and return predictions."""
    self._ensure_initialized()

    detections: list[RealTimeDetectionResult] = []

    for packet in report.packets:
      detection = self.process_packet(packet)
      if detection is not None:
        detections.append(detection)

    remaining_flow_keys = set(self._flow_packet_counts.keys()) - {
      detection.flow_id for detection in detections
    }

    for flow_key in remaining_flow_keys:
      if self._flow_packet_counts.get(flow_key, 0) < self.config.min_packets_before_predict:
        continue

      flow = self.extract_features(flow_key)
      if flow is None:
        continue

      prediction = self.predict_flow(flow)
      last_packet = flow.packets[-1]

      captured_packet = CapturedPacket(
        timestamp=datetime.fromtimestamp(last_packet.timestamp_epoch, tz=timezone.utc).isoformat(),
        src_ip=last_packet.src_ip,
        dst_ip=last_packet.dst_ip,
        src_mac=last_packet.src_mac,
        dst_mac=last_packet.dst_mac,
        src_port=last_packet.src_port,
        dst_port=last_packet.dst_port,
        protocol=last_packet.protocol,
        packet_length=last_packet.packet_length,
      )

      detections.append(
        RealTimeDetectionResult(
          flow_id=flow.flow_id,
          attack_label=prediction.attack_label,
          confidence=prediction.confidence,
          is_attack=prediction.is_attack,
          threat_level=prediction.threat_level,
          packet=captured_packet,
          flow=flow,
          features=flow.features,
          prediction=prediction,
        )
      )

    detection_report = RealTimeDetectionReport(
      packets_processed=len(report.packets),
      predictions_generated=len(detections),
      detections=detections,
    )

    logger.info(
      "Real-time detection completed | packets=%s | predictions=%s",
      detection_report.packets_processed,
      detection_report.predictions_generated,
    )
    return detection_report

  def run_with_callback(
    self,
    callback: Callable[[RealTimeDetectionResult], None],
    packet_count: Optional[int] = None,
    timeout_seconds: Optional[int] = None,
  ) -> RealTimeDetectionReport:
    """Capture packets and invoke a callback for each detection."""
    self._ensure_initialized()

    original_packet_count = self.packet_capturer.config.packet_count
    original_timeout = self.packet_capturer.config.timeout_seconds

    if packet_count is not None:
      self.packet_capturer.config.packet_count = packet_count

    if timeout_seconds is not None:
      self.packet_capturer.config.timeout_seconds = timeout_seconds

    report = self.capture_and_detect()

    for detection in report.detections:
      callback(detection)

    self.packet_capturer.config.packet_count = original_packet_count
    self.packet_capturer.config.timeout_seconds = original_timeout
    return report

  def reset(self) -> None:
    """Clear buffered packets, flow state, and prediction tracking."""
    self.flow_generator.reset()
    self.packet_capturer.reset()
    self._flow_packet_counts.clear()
    self._last_prediction_packet_count.clear()


def create_real_time_detector(
  interface: Optional[str] = None,
  bpf_filter: str = "ip or ip6",
  min_packets_before_predict: int = DEFAULT_MIN_PACKETS_BEFORE_PREDICT,
  packet_count: int = DEFAULT_CAPTURE_PACKET_COUNT,
  timeout_seconds: int = DEFAULT_CAPTURE_TIMEOUT_SECONDS,
) -> RealTimeDetector:
  """Create and initialize a real-time detector."""
  detector = RealTimeDetector(
    RealTimeDetectorConfig(
      interface=interface,
      bpf_filter=bpf_filter,
      min_packets_before_predict=min_packets_before_predict,
      packet_count=packet_count,
      timeout_seconds=timeout_seconds,
    )
  )
  detector.initialize()
  return detector


def detect_from_packet(
  packet: Union[Packet, CapturedPacket],
  interface: Optional[str] = None,
) -> RealTimeDetectionResult:
  """Convenience helper to detect an attack from a single packet."""
  detector = create_real_time_detector(interface=interface)
  return detector.detect_from_packet(packet)


if __name__ == "__main__":
  logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
  )

  detector = create_real_time_detector()
  report = detector.capture_and_detect()

  for detection in report.detections:
    print(json.dumps(detection.to_dict(), indent=2))
