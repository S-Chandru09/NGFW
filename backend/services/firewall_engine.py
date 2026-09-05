import ipaddress
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from core.firewall_wildcards import is_unrestricted_value
from database import get_firewall_rules_collection
from models.firewall_engine import AutomaticRuleAction, AutomaticRuleTrigger, FirewallDecision
from models.firewall_rule import (
  FirewallProtocol,
  FirewallRuleAction,
  FirewallRuleCreate,
  FirewallRuleDocument,
  FirewallRulePublic,
)
from schemas.firewall_engine import (
  AutomaticRuleRequest,
  AutomaticRuleResponse,
  CountrySimulationRequest,
  CountrySimulationResponse,
  FirewallBatchEvaluationResponse,
  FirewallEvaluationResponse,
  FirewallEvaluationResult,
  FirewallFlowBatchRequest,
  FirewallFlowRequest,
  FirewallMatchDetail,
  SupportedCountryResponse,
)
from services.country_simulation import (
  get_country_name,
  get_sample_ip_for_country,
  list_supported_countries,
  resolve_country_from_ip,
)
from services.firewall_rule_service import firewall_rule_service


class FirewallEngine:
  DEFAULT_DECISION = FirewallDecision.ALLOW

  def _utc_now(self) -> datetime:
    return datetime.now(timezone.utc)

  def _ip_matches(self, rule_ip: Optional[str], flow_ip: str) -> bool:
    if is_unrestricted_value(rule_ip):
      return True

    try:
      if "/" in str(rule_ip):
        return ipaddress.ip_address(flow_ip) in ipaddress.ip_network(str(rule_ip), strict=False)

      return ipaddress.ip_address(flow_ip) == ipaddress.ip_address(str(rule_ip))
    except ValueError:
      return str(rule_ip) == flow_ip

  def _port_matches(self, rule_port: Optional[int], flow_port: Optional[int]) -> bool:
    if is_unrestricted_value(rule_port):
      return True

    return flow_port is not None and int(rule_port) == int(flow_port)

  def _protocol_matches(self, rule_protocol: str, flow_protocol: str) -> bool:
    if is_unrestricted_value(rule_protocol) or str(rule_protocol).lower() == FirewallProtocol.ANY.value:
      return True

    return str(rule_protocol).lower() == str(flow_protocol).lower()

  def _country_matches(self, rule_country: Optional[str], flow_country: Optional[str]) -> bool:
    if rule_country is None:
      return True

    if flow_country is None:
      return False

    return rule_country.upper() == flow_country.upper()

  def _rule_matches_flow(
    self,
    rule: dict[str, Any],
    flow: FirewallFlowRequest,
    source_country: Optional[str],
    destination_country: Optional[str],
  ) -> tuple[bool, list[str]]:
    if not rule.get("is_enabled", True) or rule.get("is_expired", False):
      return False, []

    matched_fields: list[str] = []

    if not self._ip_matches(rule.get("source_ip"), flow.source_ip):
      return False, []

    if not is_unrestricted_value(rule.get("source_ip")):
      matched_fields.append("source_ip")

    if not self._ip_matches(rule.get("destination_ip"), flow.destination_ip):
      return False, []

    if not is_unrestricted_value(rule.get("destination_ip")):
      matched_fields.append("destination_ip")

    if not self._port_matches(rule.get("source_port"), flow.source_port):
      return False, []

    if not is_unrestricted_value(rule.get("source_port")):
      matched_fields.append("source_port")

    if not self._port_matches(rule.get("destination_port"), flow.destination_port):
      return False, []

    if not is_unrestricted_value(rule.get("destination_port")):
      matched_fields.append("destination_port")

    if not self._protocol_matches(rule.get("protocol", FirewallProtocol.ANY.value), flow.protocol.value):
      return False, []

    if not is_unrestricted_value(rule.get("protocol")) and str(rule.get("protocol", "")).lower() != FirewallProtocol.ANY.value:
      matched_fields.append("protocol")

    if not self._country_matches(rule.get("source_country"), source_country):
      return False, []

    if rule.get("source_country") is not None:
      matched_fields.append("source_country")

    if not self._country_matches(rule.get("destination_country"), destination_country):
      return False, []

    if rule.get("destination_country") is not None:
      matched_fields.append("destination_country")

    return True, matched_fields

  def _decision_from_action(self, action: str) -> tuple[str, bool]:
    if action in {
      FirewallRuleAction.ALLOW.value,
      FirewallRuleAction.WHITELIST.value,
    }:
      return action, True

    if action in {
      FirewallRuleAction.BLOCK.value,
      FirewallRuleAction.BLACKLIST.value,
      FirewallRuleAction.TEMPORARY_BLOCK.value,
    }:
      return action, False

    return self.DEFAULT_DECISION.value, True

  async def _load_active_rules(self) -> list[dict[str, Any]]:
    await firewall_rule_service._expire_temporary_rules()
    rules_collection = get_firewall_rules_collection()
    now = self._utc_now()

    cursor = rules_collection.find(
      {
        "is_enabled": True,
        "is_expired": False,
        "$or": [
          {"expires_at": None},
          {"expires_at": {"$gt": now}},
        ],
      }
    ).sort("priority", -1)

    return await cursor.to_list(length=5000)

  async def evaluate_flow(self, flow: FirewallFlowRequest) -> FirewallEvaluationResult:
    source_country = resolve_country_from_ip(flow.source_ip)
    destination_country = resolve_country_from_ip(flow.destination_ip)
    rules = await self._load_active_rules()

    match_details: list[FirewallMatchDetail] = []
    matched_rule_public: Optional[FirewallRulePublic] = None
    final_decision = self.DEFAULT_DECISION.value
    is_allowed = True

    for rule in rules:
      is_match, matched_fields = self._rule_matches_flow(
        rule,
        flow,
        source_country,
        destination_country,
      )

      if not is_match:
        continue

      action = rule.get("action", FirewallRuleAction.ALLOW.value)
      decision, allowed = self._decision_from_action(action)

      match_details.append(
        FirewallMatchDetail(
          rule_id=rule.get("rule_id"),
          rule_name=rule.get("name"),
          action=action,
          priority=rule.get("priority"),
          matched_on=matched_fields,
        )
      )

      matched_rule_public = FirewallRuleDocument.to_public_from_mongo(rule)
      final_decision = decision
      is_allowed = allowed
      break

    return FirewallEvaluationResult(
      flow_id=flow.flow_id,
      source_ip=flow.source_ip,
      destination_ip=flow.destination_ip,
      source_port=flow.source_port,
      destination_port=flow.destination_port,
      protocol=flow.protocol,
      source_country=source_country,
      destination_country=destination_country,
      decision=final_decision,
      is_allowed=is_allowed,
      matched_rule=matched_rule_public,
      match_details=match_details,
      evaluated_at=self._utc_now(),
    )

  async def evaluate_batch(self, batch: FirewallFlowBatchRequest) -> FirewallBatchEvaluationResponse:
    results = [await self.evaluate_flow(flow) for flow in batch.flows]
    allowed_count = sum(1 for result in results if result.is_allowed)
    blocked_count = len(results) - allowed_count

    return FirewallBatchEvaluationResponse(
      message="Batch firewall evaluation completed",
      results=results,
      allowed_count=allowed_count,
      blocked_count=blocked_count,
    )

  async def simulate_country(
    self,
    simulation: CountrySimulationRequest,
    created_by: Optional[str] = None,
  ) -> CountrySimulationResponse:
    country_code = simulation.country_code.upper()
    country_name = get_country_name(country_code)

    if country_name is None:
      from fastapi import HTTPException, status

      raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Unsupported country code '{country_code}' for simulation",
      )

    simulated_source_ip = simulation.source_ip or get_sample_ip_for_country(country_code)

    if simulated_source_ip is None:
      from fastapi import HTTPException, status

      raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=f"Unable to resolve sample IP for country '{country_code}'",
      )

    auto_rule_created = None

    if simulation.create_country_rule:
      rule_response = await self.create_automatic_rule(
        AutomaticRuleRequest(
          trigger=AutomaticRuleTrigger.COUNTRY_BLOCK,
          country_code=country_code,
          action=AutomaticRuleAction.BLOCK,
          reference_id=f"country-sim-{country_code}",
          priority=250,
        ),
        created_by=created_by,
      )
      auto_rule_created = rule_response.rule

    flow = FirewallFlowRequest(
      source_ip=simulated_source_ip,
      destination_ip=simulation.destination_ip,
      source_port=simulation.source_port,
      destination_port=simulation.destination_port,
      protocol=simulation.protocol,
      flow_id=f"country-sim-{country_code}",
    )

    evaluation = await self.evaluate_flow(flow)

    return CountrySimulationResponse(
      message=f"Country simulation completed for {country_name}",
      country_code=country_code,
      country_name=country_name,
      simulated_source_ip=simulated_source_ip,
      evaluation=evaluation,
      auto_rule_created=auto_rule_created,
    )

  async def create_automatic_rule(
    self,
    request: AutomaticRuleRequest,
    created_by: Optional[str] = None,
  ) -> AutomaticRuleResponse:
    expires_at = None
    action = FirewallRuleAction.TEMPORARY_BLOCK

    if request.action == AutomaticRuleAction.BLOCK:
      action = FirewallRuleAction.BLOCK
    elif request.action == AutomaticRuleAction.BLACKLIST:
      action = FirewallRuleAction.BLACKLIST
    elif request.action == AutomaticRuleAction.TEMPORARY_BLOCK:
      action = FirewallRuleAction.TEMPORARY_BLOCK
      expires_at = self._utc_now() + timedelta(hours=request.duration_hours)

    name_suffix = request.reference_id or self._utc_now().strftime("%Y%m%d%H%M%S%f")
    description_parts = [f"Automatically generated from {request.trigger.value}"]

    if request.threat_type:
      description_parts.append(f"threat={request.threat_type}")

    if request.trust_score is not None:
      description_parts.append(f"trust_score={request.trust_score}")

    if request.country_code:
      description_parts.append(f"country={request.country_code.upper()}")

    rule_create = FirewallRuleCreate(
      name=f"auto-{request.trigger.value}-{name_suffix}"[:100],
      description=" | ".join(description_parts),
      action=action,
      source_ip=request.source_ip,
      destination_ip=request.destination_ip,
      source_country=request.country_code.upper() if request.trigger == AutomaticRuleTrigger.COUNTRY_BLOCK else None,
      protocol=FirewallProtocol.ANY,
      priority=request.priority,
      is_enabled=True,
      expires_at=expires_at,
      is_automatic=True,
      trigger_source=request.trigger.value,
      trigger_reference_id=request.reference_id,
    )

    if request.trigger == AutomaticRuleTrigger.THREAT_DETECTED and request.source_ip:
      rule_create.action = FirewallRuleAction.TEMPORARY_BLOCK
      rule_create.expires_at = self._utc_now() + timedelta(hours=request.duration_hours)

    if request.trigger == AutomaticRuleTrigger.LOW_TRUST_SCORE and request.source_ip:
      rule_create.action = FirewallRuleAction.TEMPORARY_BLOCK
      rule_create.expires_at = self._utc_now() + timedelta(hours=request.duration_hours)
      rule_create.priority = max(request.priority, 350)

    if request.trigger == AutomaticRuleTrigger.ATTACK_PATTERN and request.source_ip:
      rule_create.action = FirewallRuleAction.BLACKLIST
      rule_create.expires_at = None

    if request.trigger == AutomaticRuleTrigger.COUNTRY_BLOCK and request.country_code:
      rule_create.source_country = request.country_code.upper()
      rule_create.source_ip = None
      rule_create.action = FirewallRuleAction.BLOCK

    rule_response = await firewall_rule_service.create_rule(rule_create, created_by=created_by)

    evaluation_preview = None

    if request.source_ip:
      evaluation_preview = await self.evaluate_flow(
        FirewallFlowRequest(
          source_ip=request.source_ip,
          destination_ip=request.destination_ip or "10.0.0.1",
          protocol=FirewallProtocol.ANY,
        )
      )
    elif request.country_code:
      sample_ip = get_sample_ip_for_country(request.country_code)
      if sample_ip:
        evaluation_preview = await self.evaluate_flow(
          FirewallFlowRequest(
            source_ip=sample_ip,
            destination_ip=request.destination_ip or "10.0.0.1",
            protocol=FirewallProtocol.ANY,
          )
        )

    return AutomaticRuleResponse(
      message="Automatic firewall rule created successfully",
      rule=rule_response.rule,
      trigger=request.trigger,
      evaluation_preview=evaluation_preview,
    )

  def list_countries(self) -> SupportedCountryResponse:
    return SupportedCountryResponse(
      message="Supported simulation countries retrieved successfully",
      countries=list_supported_countries(),
    )


firewall_engine = FirewallEngine()
