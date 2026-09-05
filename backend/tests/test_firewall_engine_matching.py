from models.firewall_rule import FirewallProtocol, FirewallRuleCreate
from schemas.firewall_engine import FirewallFlowRequest
from services.firewall_engine import FirewallEngine


HTTPS_FLOW = FirewallFlowRequest(
  source_ip="192.168.1.101",
  destination_ip="51.132.193.105",
  source_port=54199,
  destination_port=443,
  protocol=FirewallProtocol.TCP,
  flow_id="test-https-flow",
)


def _block_https_rule(**overrides) -> dict:
  rule = {
    "rule_id": "e2e-block-https",
    "name": "E2E Test Block HTTPS",
    "action": "block",
    "source_ip": "Any",
    "destination_ip": "51.132.193.105",
    "source_port": None,
    "destination_port": 443,
    "protocol": "tcp",
    "priority": 1,
    "is_enabled": True,
    "is_expired": False,
  }
  rule.update(overrides)
  return rule


def test_schema_normalizes_any_and_star_ip_to_none() -> None:
  for wildcard in ("Any", "*", "any", ""):
    rule = FirewallRuleCreate(
      name="Wildcard Rule",
      action="block",
      source_ip=wildcard,
      destination_ip=wildcard,
      protocol="Any",
    )
    assert rule.source_ip is None
    assert rule.destination_ip is None
    assert rule.protocol == FirewallProtocol.ANY

  tcp_rule = FirewallRuleCreate(
    name="TCP Rule",
    action="block",
    protocol="TCP",
  )
  assert tcp_rule.protocol == FirewallProtocol.TCP


def test_source_ip_any_matches_any_source() -> None:
  engine = FirewallEngine()
  matched, fields = engine._rule_matches_flow(_block_https_rule(source_ip="Any"), HTTPS_FLOW, None, None)

  assert matched is True
  assert "destination_ip" in fields
  assert "destination_port" in fields
  assert "protocol" in fields
  assert "source_ip" not in fields


def test_source_ip_star_matches_any_source() -> None:
  engine = FirewallEngine()
  matched, _ = engine._rule_matches_flow(_block_https_rule(source_ip="*"), HTTPS_FLOW, None, None)
  assert matched is True


def test_source_ip_null_matches_any_source() -> None:
  engine = FirewallEngine()
  matched, _ = engine._rule_matches_flow(_block_https_rule(source_ip=None), HTTPS_FLOW, None, None)
  assert matched is True


def test_real_source_ip_matches_exactly() -> None:
  engine = FirewallEngine()
  matching = _block_https_rule(source_ip="192.168.1.101")
  other = _block_https_rule(source_ip="10.0.0.1")

  assert engine._ip_matches("192.168.1.101", "192.168.1.101") is True
  assert engine._rule_matches_flow(matching, HTTPS_FLOW, None, None)[0] is True
  assert engine._rule_matches_flow(other, HTTPS_FLOW, None, None)[0] is False


def test_cidr_source_still_matches() -> None:
  engine = FirewallEngine()
  assert engine._ip_matches("192.168.1.0/24", "192.168.1.101") is True
  assert engine._ip_matches("192.168.1.0/24", "10.0.0.1") is False


def test_destination_ip_and_port_must_match() -> None:
  engine = FirewallEngine()
  wrong_ip = FirewallFlowRequest(
    source_ip="192.168.1.101",
    destination_ip="8.8.8.8",
    source_port=54199,
    destination_port=443,
    protocol=FirewallProtocol.TCP,
  )
  wrong_port = FirewallFlowRequest(
    source_ip="192.168.1.101",
    destination_ip="51.132.193.105",
    source_port=54199,
    destination_port=80,
    protocol=FirewallProtocol.TCP,
  )

  assert engine._rule_matches_flow(_block_https_rule(), HTTPS_FLOW, None, None)[0] is True
  assert engine._rule_matches_flow(_block_https_rule(), wrong_ip, None, None)[0] is False
  assert engine._rule_matches_flow(_block_https_rule(), wrong_port, None, None)[0] is False


def test_protocol_matching_is_case_insensitive() -> None:
  engine = FirewallEngine()
  udp_flow = HTTPS_FLOW.model_copy(update={"protocol": FirewallProtocol.UDP})

  assert engine._protocol_matches("tcp", "TCP") is True
  assert engine._protocol_matches("Any", "tcp") is True
  assert engine._rule_matches_flow(_block_https_rule(), udp_flow, None, None)[0] is False


def test_port_and_protocol_wildcards_match_any() -> None:
  engine = FirewallEngine()
  rule = _block_https_rule(source_port="Any", destination_port="*", protocol="*")

  assert engine._rule_matches_flow(rule, HTTPS_FLOW, None, None)[0] is True
  assert engine._port_matches(None, 54199) is True
  assert engine._port_matches("Any", 443) is True
