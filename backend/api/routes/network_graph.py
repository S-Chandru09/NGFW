from fastapi import APIRouter, Depends, Query

from core.auth_utils import require_permission
from models.user import UserPublic
from schemas.network_graph import NetworkGraphResponse
from services.network_graph_service import network_graph_service

router = APIRouter(prefix="/network-graph", tags=["Network Graph"])


@router.get(
  "",
  response_model=NetworkGraphResponse,
  summary="Get NetworkX network graph data",
)
async def get_network_graph(
  period_hours: int = Query(default=24, ge=1, le=168),
  max_nodes: int = Query(default=40, ge=5, le=100),
  current_user: UserPublic = Depends(require_permission("network:read")),
) -> NetworkGraphResponse:
  return await network_graph_service.build_network_graph(
    period_hours=period_hours,
    max_nodes=max_nodes,
  )
