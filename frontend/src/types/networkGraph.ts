export interface NetworkGraphNode {
  id: string;
  label: string;
  ip: string;
  node_type: string;
  is_threat: boolean;
  threat_count: number;
  flow_count: number;
  total_bytes: number;
  x: number;
  y: number;
}

export interface NetworkGraphEdge {
  id: string;
  source: string;
  target: string;
  weight: number;
  protocol: string;
  is_threat: boolean;
  total_bytes: number;
}

export interface NetworkGraphMetadata {
  directed: boolean;
  multigraph: boolean;
  layout_algorithm: string;
  node_count: number;
  edge_count: number;
  period_hours: number;
  generated_at: string;
}

export interface NetworkGraphData {
  nodes: NetworkGraphNode[];
  links: NetworkGraphEdge[];
  metadata: NetworkGraphMetadata;
}

export interface NetworkGraphResponse {
  success: boolean;
  message: string;
  data: NetworkGraphData;
  networkx_format: {
    directed?: boolean;
    multigraph?: boolean;
    graph?: Record<string, unknown>;
    nodes?: Array<Record<string, unknown>>;
    links?: Array<Record<string, unknown>>;
  };
}
