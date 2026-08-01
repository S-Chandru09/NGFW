"""
Live packet capture module using Scapy.

Captures network packets and extracts:
- IP addresses
- MAC addresses
- Ports
- Protocol
- Packet length
"""

from __future__ import annotations

import json
import logging
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from scapy.all import ICMP, IP, TCP, UDP, Ether, sniff
from scapy.packet import Packet
from scapy.utils import PcapReader, wrpcap

logger = logging.getLogger("ai-engine.packet_capture")

DEFAULT_INTERFACE = None
DEFAULT_PACKET_COUNT = 100
DEFAULT_TIMEOUT_SECONDS = 30
DEFAULT_BPF_FILTER = ""
DEFAULT_PCAP_OUTPUT_DIR = Path(__file__).resolve().parent / "pcap" / "incoming"


@dataclass
class PacketCaptureConfig:
  interface: Optional[str] = DEFAULT_INTERFACE
  packet_count: int = DEFAULT_PACKET_COUNT
  timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS
  bpf_filter: str = DEFAULT_BPF_FILTER
  promiscuous: bool = True
  store_packets: bool = True
  save_pcap: bool = False
  pcap_output_path: Optional[Path] = None


@dataclass
class CapturedPacket:
  timestamp: str
  src_ip: Optional[str] = None
  dst_ip: Optional[str] = None
  src_mac: Optional[str] = None
  dst_mac: Optional[str] = None
  src_port: Optional[int] = None
  dst_port: Optional[int] = None
  protocol: str = "UNKNOWN"
  packet_length: int = 0
  tcp_flags: dict[str, int] = field(default_factory=dict)

  def to_dict(self) -> dict:
    return asdict(self)


@dataclass
class PacketCaptureReport:
  interface: Optional[str]
  packets_captured: int
  capture_started_at: str
  capture_completed_at: str
  bpf_filter: str
  pcap_file_path: Optional[str] = None
  packets: list[CapturedPacket] = field(default_factory=list)


class PacketCapturer:
  """Capture live network packets and extract flow metadata."""

  PROTOCOL_MAP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
  }

  def __init__(self, config: Optional[PacketCaptureConfig] = None) -> None:
    self.config = config or PacketCaptureConfig()
    self._stop_event = threading.Event()
    self._capture_thread: Optional[threading.Thread] = None
    self._raw_packets: list[Packet] = []
    self._captured_packets: list[CapturedPacket] = []
    self._packet_callbacks: list[Callable[[CapturedPacket], None]] = []

  def register_callback(self, callback: Callable[[CapturedPacket], None]) -> None:
    self._packet_callbacks.append(callback)

  def _notify_callbacks(self, captured_packet: CapturedPacket) -> None:
    for callback in self._packet_callbacks:
      callback(captured_packet)

  def _format_mac(self, mac_value: Optional[str]) -> Optional[str]:
    if not mac_value:
      return None
    return mac_value.upper()

  def _resolve_protocol(self, packet: Packet) -> str:
    if packet.haslayer(TCP):
      return "TCP"

    if packet.haslayer(UDP):
      return "UDP"

    if packet.haslayer(ICMP):
      return "ICMP"

    if packet.haslayer(IP):
      ip_layer = packet[IP]
      return self.PROTOCOL_MAP.get(int(ip_layer.proto), f"IP-{ip_layer.proto}")

    if packet.haslayer(Ether):
      ether_type = int(packet[Ether].type)
      if ether_type == 0x0806:
        return "ARP"
      if ether_type == 0x86DD:
        return "IPv6"

    return packet.lastlayer().name if packet.lastlayer() else "UNKNOWN"

  def _extract_ports(self, packet: Packet) -> tuple[Optional[int], Optional[int]]:
    if packet.haslayer(TCP):
      tcp_layer = packet[TCP]
      return int(tcp_layer.sport), int(tcp_layer.dport)

    if packet.haslayer(UDP):
      udp_layer = packet[UDP]
      return int(udp_layer.sport), int(udp_layer.dport)

    return None, None

  @staticmethod
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

  def _extract_tcp_flags(self, packet: Packet) -> dict[str, int]:
    flags = self._empty_tcp_flags()
    if not packet.haslayer(TCP):
      return flags

    flag_value = int(packet[TCP].flags)
    flags["fin"] = int(bool(flag_value & 0x01))
    flags["syn"] = int(bool(flag_value & 0x02))
    flags["rst"] = int(bool(flag_value & 0x04))
    flags["psh"] = int(bool(flag_value & 0x08))
    flags["ack"] = int(bool(flag_value & 0x10))
    flags["urg"] = int(bool(flag_value & 0x20))
    flags["ece"] = int(bool(flag_value & 0x40))
    flags["cwe"] = int(bool(flag_value & 0x80))
    return flags

  def _extract_ip_addresses(self, packet: Packet) -> tuple[Optional[str], Optional[str]]:
    if packet.haslayer(IP):
      ip_layer = packet[IP]
      return str(ip_layer.src), str(ip_layer.dst)

    if packet.haslayer("IPv6"):
      ipv6_layer = packet["IPv6"]
      return str(ipv6_layer.src), str(ipv6_layer.dst)

    return None, None

  def _extract_mac_addresses(self, packet: Packet) -> tuple[Optional[str], Optional[str]]:
    if packet.haslayer(Ether):
      ether_layer = packet[Ether]
      return (
        self._format_mac(ether_layer.src),
        self._format_mac(ether_layer.dst),
      )

    return None, None

  def _packet_timestamp(self, packet: Packet) -> str:
    packet_time = getattr(packet, "time", None)
    if packet_time is not None:
      return datetime.fromtimestamp(float(packet_time), tz=timezone.utc).isoformat()
    return datetime.now(timezone.utc).isoformat()

  def parse_packet(self, packet: Packet) -> CapturedPacket:
    """Extract IP, MAC, ports, protocol, and packet length from a Scapy packet."""
    src_ip, dst_ip = self._extract_ip_addresses(packet)
    src_mac, dst_mac = self._extract_mac_addresses(packet)
    src_port, dst_port = self._extract_ports(packet)
    protocol = self._resolve_protocol(packet)
    packet_length = int(len(packet))
    tcp_flags = self._extract_tcp_flags(packet)

    captured_packet = CapturedPacket(
      timestamp=self._packet_timestamp(packet),
      src_ip=src_ip,
      dst_ip=dst_ip,
      src_mac=src_mac,
      dst_mac=dst_mac,
      src_port=src_port,
      dst_port=dst_port,
      protocol=protocol,
      packet_length=packet_length,
      tcp_flags=tcp_flags,
    )
    return captured_packet

  def _handle_packet(self, packet: Packet) -> None:
    captured_packet = self.parse_packet(packet)
    self._captured_packets.append(captured_packet)

    if self.config.store_packets:
      self._raw_packets.append(packet)

    self._notify_callbacks(captured_packet)

  def _should_stop(self, packet: Packet) -> bool:
    return self._stop_event.is_set()

  def stop_capture(self) -> None:
    """Signal an active capture session to stop."""
    self._stop_event.set()
    logger.info("Packet capture stop requested")

  def reset(self) -> None:
    """Clear captured packet buffers."""
    self._raw_packets.clear()
    self._captured_packets.clear()
    self._stop_event.clear()

  def _save_pcap(self, started_at: str) -> Optional[Path]:
    if not self.config.save_pcap or not self._raw_packets:
      return None

    output_dir = self.config.pcap_output_path or DEFAULT_PCAP_OUTPUT_DIR
    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = started_at.replace(":", "").replace("-", "").replace("+00:00", "Z")
    output_file = output_dir / f"capture_{timestamp}.pcap"
    wrpcap(str(output_file), self._raw_packets)
    logger.info("Saved captured packets to %s", output_file)
    return output_file

  def capture(self) -> PacketCaptureReport:
    """Capture packets synchronously and return parsed metadata."""
    self.reset()
    started_at = datetime.now(timezone.utc).isoformat()

    logger.info(
      "Starting packet capture | interface=%s | count=%s | timeout=%s | filter=%s",
      self.config.interface or "default",
      self.config.packet_count,
      self.config.timeout_seconds,
      self.config.bpf_filter or "none",
    )

    sniff(
      iface=self.config.interface,
      prn=self._handle_packet,
      count=self.config.packet_count,
      timeout=self.config.timeout_seconds,
      filter=self.config.bpf_filter or None,
      store=False,
      promisc=self.config.promiscuous,
      stop_filter=self._should_stop,
    )

    completed_at = datetime.now(timezone.utc).isoformat()
    pcap_file = self._save_pcap(started_at)

    report = PacketCaptureReport(
      interface=self.config.interface,
      packets_captured=len(self._captured_packets),
      capture_started_at=started_at,
      capture_completed_at=completed_at,
      bpf_filter=self.config.bpf_filter,
      pcap_file_path=str(pcap_file) if pcap_file else None,
      packets=self._captured_packets.copy(),
    )

    logger.info("Packet capture completed | packets=%s", report.packets_captured)
    return report

  def capture_async(self) -> threading.Thread:
    """Start packet capture on a background thread."""
    if self._capture_thread and self._capture_thread.is_alive():
      raise RuntimeError("Packet capture is already running")

    self.reset()
    self._capture_thread = threading.Thread(target=self.capture, daemon=True)
    self._capture_thread.start()
    logger.info("Async packet capture started")
    return self._capture_thread

  def wait_for_capture(self, timeout: Optional[float] = None) -> bool:
    """Wait for an async capture thread to finish."""
    if self._capture_thread is None:
      return True

    self._capture_thread.join(timeout=timeout)
    return not self._capture_thread.is_alive()

  def get_captured_packets(self) -> list[CapturedPacket]:
    return self._captured_packets.copy()

  def read_pcap_file(
    self,
    pcap_path: Path | str,
    max_packets: Optional[int] = None,
  ) -> PacketCaptureReport:
    """Read packets from a PCAP/PCAPNG file and return parsed metadata."""
    self.reset()
    started_at = datetime.now(timezone.utc).isoformat()
    packet_path = Path(pcap_path)

    if not packet_path.exists():
      raise FileNotFoundError(f"PCAP file not found: {packet_path}")

    logger.info("Reading PCAP file: %s", packet_path.name)

    with PcapReader(str(packet_path)) as packet_reader:
      for packet_index, packet in enumerate(packet_reader):
        if max_packets is not None and packet_index >= max_packets:
          break
        self._handle_packet(packet)

    completed_at = datetime.now(timezone.utc).isoformat()
    report = PacketCaptureReport(
      interface=None,
      packets_captured=len(self._captured_packets),
      capture_started_at=started_at,
      capture_completed_at=completed_at,
      bpf_filter="file",
      pcap_file_path=str(packet_path.resolve()),
      packets=self._captured_packets.copy(),
    )

    logger.info(
      "PCAP file processed | file=%s | packets=%s",
      packet_path.name,
      report.packets_captured,
    )
    return report


def read_pcap_file(
  pcap_path: Path | str,
  max_packets: Optional[int] = None,
) -> PacketCaptureReport:
  """Convenience helper to parse packets from a PCAP file."""
  capturer = PacketCapturer()
  return capturer.read_pcap_file(pcap_path=pcap_path, max_packets=max_packets)


def capture_packets(
  interface: Optional[str] = None,
  packet_count: int = DEFAULT_PACKET_COUNT,
  timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
  bpf_filter: str = DEFAULT_BPF_FILTER,
  save_pcap: bool = False,
  pcap_output_path: Optional[str] = None,
) -> PacketCaptureReport:
  """Convenience helper to capture packets and return parsed metadata."""
  config = PacketCaptureConfig(
    interface=interface,
    packet_count=packet_count,
    timeout_seconds=timeout_seconds,
    bpf_filter=bpf_filter,
    save_pcap=save_pcap,
    pcap_output_path=Path(pcap_output_path) if pcap_output_path else None,
  )
  capturer = PacketCapturer(config=config)
  return capturer.capture()


if __name__ == "__main__":
  logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
  )

  report = capture_packets(packet_count=10, timeout_seconds=15)
  for packet in report.packets:
    print(json.dumps(packet.to_dict(), indent=2))
