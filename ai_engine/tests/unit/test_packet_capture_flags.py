from scapy.all import IP, TCP, Ether

from network.packet_capture import PacketCapturer


def test_extract_tcp_flags_from_syn_packet() -> None:
  capturer = PacketCapturer()
  packet = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80, flags="S")

  flags = capturer._extract_tcp_flags(packet)

  assert flags["syn"] == 1
  assert flags["ack"] == 0
  assert flags["fin"] == 0


def test_parse_packet_includes_tcp_flags() -> None:
  capturer = PacketCapturer()
  packet = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80, flags="SA")

  captured = capturer.parse_packet(packet)

  assert captured.protocol == "TCP"
  assert captured.tcp_flags["syn"] == 1
  assert captured.tcp_flags["ack"] == 1
