"""
Network flow feature generator.

Aggregates captured packets into bidirectional flows and calculates
flow duration, packets/sec, bytes/sec, and CICIDS-style flow features.
"""

from __future__ import annotations

import json
import logging
import statistics
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Optional

import numpy as np
import pandas as pd

from network.packet_capture import CapturedPacket, PacketCaptureReport

logger = logging.getLogger("ai-engine.flow_generator")

DEFAULT_FLOW_IDLE_TIMEOUT_SECONDS = 120.0
MICROSECONDS_PER_SECOND = 1_000_000


def _empty_tcp_flags() -> dict[str, int]:
  return {
    "fin": 0,
    "syn": 0,
    "rst": 0,
    "psh": 0,
    "ack": 0,
    "urg": 0,
    "ece": 0,
    "cwe": 0,
  }


@dataclass
class FlowGeneratorConfig:
  idle_timeout_seconds: float = DEFAULT_FLOW_IDLE_TIMEOUT_SECONDS
  min_packets_per_flow: int = 1
  duration_unit: str = "microseconds"


@dataclass
class FlowPacketRecord:
  timestamp_epoch: float
  packet_length: int
  direction: str
  src_ip: Optional[str]
  dst_ip: Optional[str]
  src_mac: Optional[str]
  dst_mac: Optional[str]
  src_port: Optional[int]
  dst_port: Optional[int]
  protocol: str
  tcp_flags: dict[str, int] = field(default_factory=dict)


@dataclass
class NetworkFlow:
  flow_id: str
  src_ip: Optional[str]
  dst_ip: Optional[str]
  src_mac: Optional[str]
  dst_mac: Optional[str]
  source_port: Optional[int]
  destination_port: Optional[int]
  protocol: str
  flow_start_time: str
  flow_end_time: str
  flow_duration: float
  flow_packets_s: float
  flow_bytes_s: float
  total_packets: int
  total_bytes: int
  total_fwd_packets: int
  total_backward_packets: int
  total_length_of_fwd_packets: int
  total_length_of_bwd_packets: int
  features: dict[str, float | int | str]
  packets: list[FlowPacketRecord] = field(default_factory=list)

  def to_dict(self) -> dict:
    payload = asdict(self)
    payload.pop("packets", None)
    payload.update(self.features)
    return payload

  def get_feature_vector(self, feature_columns: Optional[list[str]] = None) -> list[float]:
    if feature_columns:
      return [float(self.features.get(column, 0.0)) for column in feature_columns]

    numeric_features = {
      key: value
      for key, value in self.features.items()
      if isinstance(value, (int, float, np.number))
    }
    return [float(value) for value in numeric_features.values()]


@dataclass
class FlowGenerationReport:
  flows_generated: int
  packets_processed: int
  packets_skipped: int
  generated_at: str
  flows: list[NetworkFlow] = field(default_factory=list)


class FlowGenerator:
  """Aggregate packets into flows and calculate flow-level features."""

  FEATURE_COLUMNS = [
    "flow_duration",
    "total_fwd_packets",
    "total_backward_packets",
    "total_length_of_fwd_packets",
    "total_length_of_bwd_packets",
    "fwd_packet_length_max",
    "fwd_packet_length_min",
    "fwd_packet_length_mean",
    "fwd_packet_length_std",
    "bwd_packet_length_max",
    "bwd_packet_length_min",
    "bwd_packet_length_mean",
    "bwd_packet_length_std",
    "flow_bytes_s",
    "flow_packets_s",
    "flow_iat_mean",
    "flow_iat_std",
    "flow_iat_max",
    "flow_iat_min",
    "fwd_iat_total",
    "fwd_iat_mean",
    "fwd_iat_std",
    "fwd_iat_max",
    "fwd_iat_min",
    "bwd_iat_total",
    "bwd_iat_mean",
    "bwd_iat_std",
    "bwd_iat_max",
    "bwd_iat_min",
    "packet_length_mean",
    "packet_length_std",
    "packet_length_variance",
    "packet_length_max",
    "packet_length_min",
    "fin_flag_count",
    "syn_flag_count",
    "rst_flag_count",
    "psh_flag_count",
    "ack_flag_count",
    "urg_flag_count",
    "cwe_flag_count",
    "ece_flag_count",
    "down_up_ratio",
    "average_packet_size",
    "subflow_fwd_packets",
    "subflow_bwd_packets",
    "subflow_fwd_bytes",
    "subflow_bwd_bytes",
    "destination_port",
    "source_port",
  ]

  def __init__(self, config: Optional[FlowGeneratorConfig] = None) -> None:
    self.config = config or FlowGeneratorConfig()
    self._flow_buckets: dict[str, list[FlowPacketRecord]] = {}
    self._flow_metadata: dict[str, dict] = {}
    self.packets_processed = 0
    self.packets_skipped = 0

  @staticmethod
  def _parse_timestamp(timestamp_value: str) -> float:
    normalized_timestamp = timestamp_value.replace("Z", "+00:00")
    parsed_time = datetime.fromisoformat(normalized_timestamp)
    if parsed_time.tzinfo is None:
      parsed_time = parsed_time.replace(tzinfo=timezone.utc)
    return parsed_time.timestamp()

  @staticmethod
  def _safe_stats(values: list[float | int]) -> dict[str, float]:
    if not values:
      return {"mean": 0.0, "std": 0.0, "max": 0.0, "min": 0.0, "variance": 0.0, "total": 0.0}

    if len(values) == 1:
      single_value = float(values[0])
      return {
        "mean": single_value,
        "std": 0.0,
        "max": single_value,
        "min": single_value,
        "variance": 0.0,
        "total": single_value,
      }

    return {
      "mean": float(statistics.mean(values)),
      "std": float(statistics.pstdev(values)),
      "max": float(max(values)),
      "min": float(min(values)),
      "variance": float(statistics.pvariance(values)),
      "total": float(sum(values)),
    }

  def _build_flow_key(self, packet: CapturedPacket) -> Optional[str]:
    if not packet.src_ip or not packet.dst_ip:
      return None

    endpoint_a = (packet.src_ip, packet.src_port or 0)
    endpoint_b = (packet.dst_ip, packet.dst_port or 0)
    ordered_endpoints = tuple(sorted([endpoint_a, endpoint_b]))
    return f"{ordered_endpoints[0][0]}:{ordered_endpoints[0][1]}|" \
           f"{ordered_endpoints[1][0]}:{ordered_endpoints[1][1]}|{packet.protocol}"

  def _resolve_direction(
    self,
    packet: CapturedPacket,
    forward_src_ip: str,
    forward_src_port: int,
  ) -> str:
    packet_src_port = packet.src_port or 0
    if packet.src_ip == forward_src_ip and packet_src_port == forward_src_port:
      return "forward"
    return "backward"

  def add_packet(self, packet: CapturedPacket) -> Optional[str]:
    """Add a captured packet to its corresponding flow bucket."""
    flow_key = self._build_flow_key(packet)
    if flow_key is None:
      self.packets_skipped += 1
      return None

    timestamp_epoch = self._parse_timestamp(packet.timestamp)

    if flow_key not in self._flow_metadata:
      self._flow_metadata[flow_key] = {
        "forward_src_ip": packet.src_ip,
        "forward_dst_ip": packet.dst_ip,
        "forward_src_mac": packet.src_mac,
        "forward_dst_mac": packet.dst_mac,
        "forward_src_port": packet.src_port or 0,
        "forward_dst_port": packet.dst_port or 0,
        "protocol": packet.protocol,
      }

    metadata = self._flow_metadata[flow_key]
    direction = self._resolve_direction(
      packet=packet,
      forward_src_ip=metadata["forward_src_ip"],
      forward_src_port=metadata["forward_src_port"],
    )

    flow_packet = FlowPacketRecord(
      timestamp_epoch=timestamp_epoch,
      packet_length=int(packet.packet_length),
      direction=direction,
      src_ip=packet.src_ip,
      dst_ip=packet.dst_ip,
      src_mac=packet.src_mac,
      dst_mac=packet.dst_mac,
      src_port=packet.src_port,
      dst_port=packet.dst_port,
      protocol=packet.protocol,
      tcp_flags=packet.tcp_flags or _empty_tcp_flags(),
    )

    self._flow_buckets.setdefault(flow_key, []).append(flow_packet)
    self.packets_processed += 1
    return flow_key

  def add_packets(self, packets: list[CapturedPacket]) -> int:
    added_count = 0
    for packet in packets:
      if self.add_packet(packet) is not None:
        added_count += 1
    return added_count

  def add_capture_report(self, report: PacketCaptureReport) -> int:
    return self.add_packets(report.packets)

  def _duration_to_configured_unit(self, duration_seconds: float) -> float:
    if self.config.duration_unit == "seconds":
      return duration_seconds
    return duration_seconds * MICROSECONDS_PER_SECOND

  def _calculate_iat_series(self, timestamps: list[float]) -> list[float]:
    if len(timestamps) < 2:
      return []

    sorted_timestamps = sorted(timestamps)
    return [
      (sorted_timestamps[index] - sorted_timestamps[index - 1]) * MICROSECONDS_PER_SECOND
      for index in range(1, len(sorted_timestamps))
    ]

  def _calculate_flow_features(
    self,
    flow_key: str,
    packets: list[FlowPacketRecord],
  ) -> NetworkFlow:
    metadata = self._flow_metadata[flow_key]
    sorted_packets = sorted(packets, key=lambda packet: packet.timestamp_epoch)

    start_epoch = sorted_packets[0].timestamp_epoch
    end_epoch = sorted_packets[-1].timestamp_epoch
    duration_seconds = max(end_epoch - start_epoch, 1e-6)
    duration_value = self._duration_to_configured_unit(duration_seconds)

    forward_packets = [packet for packet in sorted_packets if packet.direction == "forward"]
    backward_packets = [packet for packet in sorted_packets if packet.direction == "backward"]

    forward_lengths = [packet.packet_length for packet in forward_packets]
    backward_lengths = [packet.packet_length for packet in backward_packets]
    all_lengths = [packet.packet_length for packet in sorted_packets]

    total_fwd_packets = len(forward_packets)
    total_backward_packets = len(backward_packets)
    total_length_of_fwd_packets = int(sum(forward_lengths))
    total_length_of_bwd_packets = int(sum(backward_lengths))
    total_packets = len(sorted_packets)
    total_bytes = int(sum(all_lengths))

    flow_packets_s = total_packets / duration_seconds
    flow_bytes_s = total_bytes / duration_seconds

    forward_stats = self._safe_stats(forward_lengths)
    backward_stats = self._safe_stats(backward_lengths)
    packet_stats = self._safe_stats(all_lengths)

    flow_iat_values = self._calculate_iat_series([packet.timestamp_epoch for packet in sorted_packets])
    fwd_iat_values = self._calculate_iat_series([packet.timestamp_epoch for packet in forward_packets])
    bwd_iat_values = self._calculate_iat_series([packet.timestamp_epoch for packet in backward_packets])

    flow_iat_stats = self._safe_stats(flow_iat_values)
    fwd_iat_stats = self._safe_stats(fwd_iat_values)
    bwd_iat_stats = self._safe_stats(bwd_iat_values)

    down_up_ratio = (
      total_length_of_bwd_packets / total_length_of_fwd_packets
      if total_length_of_fwd_packets > 0
      else 0.0
    )

    flow_start_time = datetime.fromtimestamp(start_epoch, tz=timezone.utc).isoformat()
    flow_end_time = datetime.fromtimestamp(end_epoch, tz=timezone.utc).isoformat()

    flag_totals = _empty_tcp_flags()
    for packet in sorted_packets:
      packet_flags = packet.tcp_flags or _empty_tcp_flags()
      for flag_name, flag_value in packet_flags.items():
        flag_totals[flag_name] = flag_totals.get(flag_name, 0) + int(flag_value)

    features: dict[str, float | int | str] = {
      "flow_duration": float(duration_value),
      "total_fwd_packets": int(total_fwd_packets),
      "total_backward_packets": int(total_backward_packets),
      "total_length_of_fwd_packets": int(total_length_of_fwd_packets),
      "total_length_of_bwd_packets": int(total_length_of_bwd_packets),
      "fwd_packet_length_max": float(forward_stats["max"]),
      "fwd_packet_length_min": float(forward_stats["min"]),
      "fwd_packet_length_mean": float(forward_stats["mean"]),
      "fwd_packet_length_std": float(forward_stats["std"]),
      "bwd_packet_length_max": float(backward_stats["max"]),
      "bwd_packet_length_min": float(backward_stats["min"]),
      "bwd_packet_length_mean": float(backward_stats["mean"]),
      "bwd_packet_length_std": float(backward_stats["std"]),
      "flow_bytes_s": float(flow_bytes_s),
      "flow_packets_s": float(flow_packets_s),
      "flow_iat_mean": float(flow_iat_stats["mean"]),
      "flow_iat_std": float(flow_iat_stats["std"]),
      "flow_iat_max": float(flow_iat_stats["max"]),
      "flow_iat_min": float(flow_iat_stats["min"]),
      "fwd_iat_total": float(fwd_iat_stats["total"]),
      "fwd_iat_mean": float(fwd_iat_stats["mean"]),
      "fwd_iat_std": float(fwd_iat_stats["std"]),
      "fwd_iat_max": float(fwd_iat_stats["max"]),
      "fwd_iat_min": float(fwd_iat_stats["min"]),
      "bwd_iat_total": float(bwd_iat_stats["total"]),
      "bwd_iat_mean": float(bwd_iat_stats["mean"]),
      "bwd_iat_std": float(bwd_iat_stats["std"]),
      "bwd_iat_max": float(bwd_iat_stats["max"]),
      "bwd_iat_min": float(bwd_iat_stats["min"]),
      "packet_length_mean": float(packet_stats["mean"]),
      "packet_length_std": float(packet_stats["std"]),
      "packet_length_variance": float(packet_stats["variance"]),
      "packet_length_max": float(packet_stats["max"]),
      "packet_length_min": float(packet_stats["min"]),
      "fin_flag_count": int(flag_totals["fin"]),
      "syn_flag_count": int(flag_totals["syn"]),
      "rst_flag_count": int(flag_totals["rst"]),
      "psh_flag_count": int(flag_totals["psh"]),
      "ack_flag_count": int(flag_totals["ack"]),
      "urg_flag_count": int(flag_totals["urg"]),
      "cwe_flag_count": int(flag_totals["cwe"]),
      "ece_flag_count": int(flag_totals["ece"]),
      "down_up_ratio": float(down_up_ratio),
      "average_packet_size": float(packet_stats["mean"]),
      "subflow_fwd_packets": int(total_fwd_packets),
      "subflow_bwd_packets": int(total_backward_packets),
      "subflow_fwd_bytes": int(total_length_of_fwd_packets),
      "subflow_bwd_bytes": int(total_length_of_bwd_packets),
      "destination_port": int(metadata["forward_dst_port"]),
      "source_port": int(metadata["forward_src_port"]),
      "protocol": metadata["protocol"],
    }

    return NetworkFlow(
      flow_id=flow_key,
      src_ip=metadata["forward_src_ip"],
      dst_ip=metadata["forward_dst_ip"],
      src_mac=metadata["forward_src_mac"],
      dst_mac=metadata["forward_dst_mac"],
      source_port=int(metadata["forward_src_port"]),
      destination_port=int(metadata["forward_dst_port"]),
      protocol=metadata["protocol"],
      flow_start_time=flow_start_time,
      flow_end_time=flow_end_time,
      flow_duration=float(duration_value),
      flow_packets_s=float(flow_packets_s),
      flow_bytes_s=float(flow_bytes_s),
      total_packets=total_packets,
      total_bytes=total_bytes,
      total_fwd_packets=total_fwd_packets,
      total_backward_packets=total_backward_packets,
      total_length_of_fwd_packets=total_length_of_fwd_packets,
      total_length_of_bwd_packets=total_length_of_bwd_packets,
      features=features,
      packets=sorted_packets.copy(),
    )

  def generate_flows(self) -> FlowGenerationReport:
    """Generate flow records and calculated features from buffered packets."""
    flows: list[NetworkFlow] = []

    for flow_key, packets in self._flow_buckets.items():
      if len(packets) < self.config.min_packets_per_flow:
        self.packets_skipped += len(packets)
        continue

      flows.append(self._calculate_flow_features(flow_key, packets))

    report = FlowGenerationReport(
      flows_generated=len(flows),
      packets_processed=self.packets_processed,
      packets_skipped=self.packets_skipped,
      generated_at=datetime.now(timezone.utc).isoformat(),
      flows=flows,
    )

    logger.info(
      "Generated %s flows from %s packets",
      report.flows_generated,
      report.packets_processed,
    )
    return report

  def to_dataframe(self, flows: Optional[list[NetworkFlow]] = None) -> pd.DataFrame:
    """Convert generated flows into a pandas DataFrame."""
    flow_records = flows if flows is not None else self.generate_flows().flows
    rows = [flow.to_dict() for flow in flow_records]
    return pd.DataFrame(rows)

  def reset(self) -> None:
    """Clear buffered packets and flow metadata."""
    self._flow_buckets.clear()
    self._flow_metadata.clear()
    self.packets_processed = 0
    self.packets_skipped = 0


def generate_flows_from_packets(
  packets: list[CapturedPacket],
  min_packets_per_flow: int = 1,
  duration_unit: str = "microseconds",
) -> FlowGenerationReport:
  """Convenience helper to generate flows from captured packets."""
  generator = FlowGenerator(
    FlowGeneratorConfig(
      min_packets_per_flow=min_packets_per_flow,
      duration_unit=duration_unit,
    )
  )
  generator.add_packets(packets)
  return generator.generate_flows()


def generate_flows_from_capture(
  report: PacketCaptureReport,
  min_packets_per_flow: int = 1,
  duration_unit: str = "microseconds",
) -> FlowGenerationReport:
  """Convenience helper to generate flows from a packet capture report."""
  generator = FlowGenerator(
    FlowGeneratorConfig(
      min_packets_per_flow=min_packets_per_flow,
      duration_unit=duration_unit,
    )
  )
  generator.add_capture_report(report)
  return generator.generate_flows()


if __name__ == "__main__":
  logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
  )

  sample_packets = [
    CapturedPacket(
      timestamp=datetime.now(timezone.utc).isoformat(),
      src_ip="192.168.1.10",
      dst_ip="8.8.8.8",
      src_mac="AA:BB:CC:DD:EE:01",
      dst_mac="AA:BB:CC:DD:EE:02",
      src_port=44321,
      dst_port=443,
      protocol="TCP",
      packet_length=120,
    ),
    CapturedPacket(
      timestamp=datetime.now(timezone.utc).isoformat(),
      src_ip="8.8.8.8",
      dst_ip="192.168.1.10",
      src_mac="AA:BB:CC:DD:EE:02",
      dst_mac="AA:BB:CC:DD:EE:01",
      src_port=443,
      dst_port=44321,
      protocol="TCP",
      packet_length=80,
    ),
  ]

  report = generate_flows_from_packets(sample_packets)
  for flow in report.flows:
    print(json.dumps(flow.to_dict(), indent=2))
