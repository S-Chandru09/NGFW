from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, Field


class NetworkGraphNode(BaseModel):
  id: str
  label: str
  ip: str
  node_type: str = "external"
  is_threat: bool = False
  threat_count: int = 0
  flow_count: int = 0
  total_bytes: int = 0
  x: float = 0.0
  y: float = 0.0


class NetworkGraphEdge(BaseModel):
  id: str
  source: str
  target: str
  weight: int = 1
  protocol: str = "unknown"
  is_threat: bool = False
  total_bytes: int = 0


class NetworkGraphMetadata(BaseModel):
  directed: bool = True
  multigraph: bool = False
  layout_algorithm: str = "spring"
  node_count: int
  edge_count: int
  period_hours: int
  generated_at: datetime


class NetworkGraphData(BaseModel):
  nodes: list[NetworkGraphNode]
  links: list[NetworkGraphEdge]
  metadata: NetworkGraphMetadata


class NetworkGraphResponse(BaseModel):
  success: bool = True
  message: str
  data: NetworkGraphData
  networkx_format: dict[str, Any] = Field(
    default_factory=dict,
    description="Raw NetworkX node-link export for interoperability",
  )
