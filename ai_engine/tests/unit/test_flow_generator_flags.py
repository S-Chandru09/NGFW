from network.flow_generator import FlowGenerator, _empty_tcp_flags
from network.packet_capture import CapturedPacket


def _build_packet(
  *,
  src_ip: str,
  dst_ip: str,
  src_port: int,
  dst_port: int,
  protocol: str,
  tcp_flags: dict[str, int] | None = None,
  timestamp: str = "2026-01-01T00:00:00+00:00",
) -> CapturedPacket:
  return CapturedPacket(
    timestamp=timestamp,
    src_ip=src_ip,
    dst_ip=dst_ip,
    src_port=src_port,
    dst_port=dst_port,
    protocol=protocol,
    packet_length=100,
    tcp_flags=tcp_flags or _empty_tcp_flags(),
  )


def test_flow_generator_aggregates_tcp_flags() -> None:
  generator = FlowGenerator()
  generator.add_packet(
    _build_packet(
      src_ip="10.0.0.1",
      dst_ip="10.0.0.2",
      src_port=12345,
      dst_port=80,
      protocol="TCP",
      tcp_flags={"fin": 0, "syn": 1, "rst": 0, "psh": 0, "ack": 0, "urg": 0, "ece": 0, "cwe": 0},
    )
  )
  generator.add_packet(
    _build_packet(
      src_ip="10.0.0.1",
      dst_ip="10.0.0.2",
      src_port=12345,
      dst_port=80,
      protocol="TCP",
      tcp_flags={"fin": 0, "syn": 0, "rst": 0, "psh": 0, "ack": 1, "urg": 0, "ece": 0, "cwe": 0},
      timestamp="2026-01-01T00:00:01+00:00",
    )
  )

  report = generator.generate_flows()
  assert report.flows_generated == 1

  flow = report.flows[0]
  assert flow.features["syn_flag_count"] == 1
  assert flow.features["ack_flag_count"] == 1
  assert flow.features["fin_flag_count"] == 0


def test_non_tcp_flows_have_zero_tcp_flags() -> None:
  generator = FlowGenerator()
  generator.add_packet(
    _build_packet(
      src_ip="10.0.0.1",
      dst_ip="10.0.0.2",
      src_port=53,
      dst_port=5353,
      protocol="UDP",
    )
  )
  generator.add_packet(
    _build_packet(
      src_ip="10.0.0.1",
      dst_ip="10.0.0.2",
      src_port=53,
      dst_port=5353,
      protocol="UDP",
      timestamp="2026-01-01T00:00:01+00:00",
    )
  )

  flow = generator.generate_flows().flows[0]
  assert flow.features["syn_flag_count"] == 0
  assert flow.features["ack_flag_count"] == 0
