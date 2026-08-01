from fastapi import APIRouter, Depends

from core.auth_utils import require_permission
from models.user import UserPublic
from schemas.firewall_engine import (
  AutomaticRuleRequest,
  AutomaticRuleResponse,
  CountrySimulationRequest,
  CountrySimulationResponse,
  FirewallBatchEvaluationResponse,
  FirewallEvaluationResponse,
  FirewallFlowBatchRequest,
  FirewallFlowRequest,
  SupportedCountryResponse,
)
from services.firewall_engine import firewall_engine

router = APIRouter(prefix="/firewall-engine", tags=["Firewall Engine"])


@router.post(
  "/evaluate",
  response_model=FirewallEvaluationResponse,
  summary="Evaluate a network flow against firewall rules",
)
async def evaluate_flow(
  flow: FirewallFlowRequest,
  current_user: UserPublic = Depends(require_permission("firewall:read")),
) -> FirewallEvaluationResponse:
  result = await firewall_engine.evaluate_flow(flow)

  return FirewallEvaluationResponse(
    message="Firewall flow evaluated successfully",
    result=result,
  )


@router.post(
  "/evaluate/batch",
  response_model=FirewallBatchEvaluationResponse,
  summary="Evaluate multiple network flows against firewall rules",
)
async def evaluate_flow_batch(
  batch: FirewallFlowBatchRequest,
  current_user: UserPublic = Depends(require_permission("firewall:read")),
) -> FirewallBatchEvaluationResponse:
  return await firewall_engine.evaluate_batch(batch)


@router.post(
  "/simulate/country",
  response_model=CountrySimulationResponse,
  summary="Simulate firewall decision for traffic from a specific country",
)
async def simulate_country_traffic(
  simulation: CountrySimulationRequest,
  current_user: UserPublic = Depends(require_permission("firewall:write")),
) -> CountrySimulationResponse:
  return await firewall_engine.simulate_country(
    simulation,
    created_by=str(current_user.id),
  )


@router.post(
  "/automatic-rules",
  response_model=AutomaticRuleResponse,
  status_code=201,
  summary="Generate an automatic firewall rule from a security trigger",
)
async def create_automatic_rule(
  request: AutomaticRuleRequest,
  current_user: UserPublic = Depends(require_permission("firewall:write")),
) -> AutomaticRuleResponse:
  return await firewall_engine.create_automatic_rule(
    request,
    created_by=str(current_user.id),
  )


@router.get(
  "/countries",
  response_model=SupportedCountryResponse,
  summary="List countries supported for firewall country simulation",
)
async def list_simulation_countries(
  current_user: UserPublic = Depends(require_permission("firewall:read")),
) -> SupportedCountryResponse:
  return firewall_engine.list_countries()
