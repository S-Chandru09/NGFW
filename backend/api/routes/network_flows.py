from fastapi import APIRouter, Depends

from core.auth_utils import require_network_ingest
from schemas.network_flow import (
  NetworkFlowBatchIngestRequest,
  NetworkFlowBatchIngestResponse,
  NetworkFlowIngestRequest,
  NetworkFlowIngestResponse,
)
from services.network_flow_service import network_flow_service

router = APIRouter(prefix="/network", tags=["Network Flows"])


@router.post(
  "/flows",
  response_model=NetworkFlowIngestResponse,
  status_code=201,
  summary="Ingest a network flow from the AI engine",
)
async def ingest_network_flow(
  flow_data: NetworkFlowIngestRequest,
  _: None = Depends(require_network_ingest),
) -> NetworkFlowIngestResponse:
  return await network_flow_service.ingest_flow(flow_data)


@router.post(
  "/flows/batch",
  response_model=NetworkFlowBatchIngestResponse,
  status_code=201,
  summary="Ingest multiple network flows from the AI engine",
)
async def ingest_network_flows_batch(
  batch_data: NetworkFlowBatchIngestRequest,
  _: None = Depends(require_network_ingest),
) -> NetworkFlowBatchIngestResponse:
  return await network_flow_service.ingest_flows_batch(batch_data)
