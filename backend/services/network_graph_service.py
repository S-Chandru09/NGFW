from datetime import datetime, timedelta, timezone

import networkx as nx
from networkx.readwrite import json_graph

from database import get_network_flows_collection
from schemas.network_graph import (
  NetworkGraphData,
  NetworkGraphEdge,
  NetworkGraphMetadata,
  NetworkGraphNode,
  NetworkGraphResponse,
)


def _utc_now() -> datetime:
  return datetime.now(timezone.utc)


def _hours_ago(hours: int) -> datetime:
  return _utc_now() - timedelta(hours=hours)


class NetworkGraphService:
  async def build_network_graph(
    self,
    period_hours: int = 24,
    max_nodes: int = 40,
  ) -> NetworkGraphResponse:
    flows_collection = get_network_flows_collection()
    since = _hours_ago(period_hours)

    pipeline = [
      {"$match": {"captured_at": {"$gte": since}}},
      {
        "$group": {
          "_id": {
            "source_ip": {"$ifNull": ["$source_ip", "unknown"]},
            "destination_ip": {"$ifNull": ["$destination_ip", "unknown"]},
            "protocol": {"$ifNull": ["$protocol", "unknown"]},
          },
          "flow_count": {"$sum": 1},
          "total_bytes": {"$sum": {"$ifNull": ["$total_bytes", 0]}},
          "threat_count": {
            "$sum": {
              "$cond": [{"$eq": ["$is_threat", True]}, 1, 0],
            },
          },
        }
      },
      {"$sort": {"flow_count": -1}},
      {"$limit": max_nodes * 3},
    ]

    flow_edges = await flows_collection.aggregate(pipeline).to_list(length=max_nodes * 3)

    graph = nx.DiGraph()
    node_stats: dict[str, dict[str, int | bool]] = {}

    for edge in flow_edges:
      edge_id = edge.get("_id", {})
      source_ip = str(edge_id.get("source_ip", "unknown"))
      destination_ip = str(edge_id.get("destination_ip", "unknown"))
      protocol = str(edge_id.get("protocol", "unknown"))
      flow_count = int(edge.get("flow_count", 0) or 0)
      total_bytes = int(edge.get("total_bytes", 0) or 0)
      threat_count = int(edge.get("threat_count", 0) or 0)
      is_threat = threat_count > 0

      if source_ip not in node_stats:
        node_stats[source_ip] = {
          "flow_count": 0,
          "total_bytes": 0,
          "threat_count": 0,
          "is_threat": False,
        }

      if destination_ip not in node_stats:
        node_stats[destination_ip] = {
          "flow_count": 0,
          "total_bytes": 0,
          "threat_count": 0,
          "is_threat": False,
        }

      for ip in (source_ip, destination_ip):
        node_stats[ip]["flow_count"] = int(node_stats[ip]["flow_count"]) + flow_count
        node_stats[ip]["total_bytes"] = int(node_stats[ip]["total_bytes"]) + total_bytes
        node_stats[ip]["threat_count"] = int(node_stats[ip]["threat_count"]) + threat_count
        if is_threat:
          node_stats[ip]["is_threat"] = True

      if graph.has_edge(source_ip, destination_ip):
        existing_data = graph[source_ip][destination_ip]
        existing_data["weight"] += flow_count
        existing_data["total_bytes"] += total_bytes
        existing_data["threat_count"] += threat_count
        existing_data["is_threat"] = existing_data["is_threat"] or is_threat
        existing_data["protocol"] = protocol
      else:
        graph.add_edge(
          source_ip,
          destination_ip,
          weight=flow_count,
          protocol=protocol,
          total_bytes=total_bytes,
          threat_count=threat_count,
          is_threat=is_threat,
        )

    if graph.number_of_nodes() > max_nodes:
      top_nodes = sorted(
        node_stats.items(),
        key=lambda item: int(item[1]["flow_count"]),
        reverse=True,
      )[:max_nodes]
      allowed_nodes = {node_id for node_id, _ in top_nodes}
      graph = graph.subgraph(allowed_nodes).copy()

    if graph.number_of_nodes() == 0:
      return NetworkGraphResponse(
        success=True,
        message="No network flow data available for graph generation",
        data=NetworkGraphData(
          nodes=[],
          links=[],
          metadata=NetworkGraphMetadata(
            directed=True,
            multigraph=False,
            layout_algorithm="spring",
            node_count=0,
            edge_count=0,
            period_hours=period_hours,
            generated_at=_utc_now(),
          ),
        ),
        networkx_format={"directed": True, "multigraph": False, "graph": {}, "nodes": [], "links": []},
      )

    layout_positions = nx.spring_layout(graph, seed=42, dim=2)

    nodes: list[NetworkGraphNode] = []
    for node_id in graph.nodes:
      stats = node_stats.get(node_id, {})
      position = layout_positions.get(node_id, (0.0, 0.0))
      is_private = node_id.startswith(("10.", "172.", "192.168."))

      nodes.append(
        NetworkGraphNode(
          id=node_id,
          label=node_id,
          ip=node_id,
          node_type="internal" if is_private else "external",
          is_threat=bool(stats.get("is_threat", False)),
          threat_count=int(stats.get("threat_count", 0) or 0),
          flow_count=int(stats.get("flow_count", 0) or 0),
          total_bytes=int(stats.get("total_bytes", 0) or 0),
          x=float(position[0]),
          y=float(position[1]),
        )
      )

    links: list[NetworkGraphEdge] = []
    for source, target, edge_data in graph.edges(data=True):
      links.append(
        NetworkGraphEdge(
          id=f"{source}->{target}",
          source=source,
          target=target,
          weight=int(edge_data.get("weight", 1) or 1),
          protocol=str(edge_data.get("protocol", "unknown")),
          is_threat=bool(edge_data.get("is_threat", False)),
          total_bytes=int(edge_data.get("total_bytes", 0) or 0),
        )
      )

    networkx_payload = json_graph.node_link_data(graph)

    for node in networkx_payload.get("nodes", []):
      node_id = node.get("id")
      if node_id in layout_positions:
        node["x"] = float(layout_positions[node_id][0])
        node["y"] = float(layout_positions[node_id][1])

    metadata = NetworkGraphMetadata(
      directed=True,
      multigraph=False,
      layout_algorithm="spring",
      node_count=len(nodes),
      edge_count=len(links),
      period_hours=period_hours,
      generated_at=_utc_now(),
    )

    return NetworkGraphResponse(
      success=True,
      message="Network graph generated successfully using NetworkX",
      data=NetworkGraphData(nodes=nodes, links=links, metadata=metadata),
      networkx_format=networkx_payload,
    )


network_graph_service = NetworkGraphService()
