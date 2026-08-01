import { apiService } from "@/services/api";
import type { NetworkGraphResponse } from "@/types/networkGraph";

export async function fetchNetworkGraph(
  periodHours = 24,
  maxNodes = 40,
): Promise<NetworkGraphResponse> {
  return apiService.get<NetworkGraphResponse>("/network-graph", {
    params: {
      period_hours: periodHours,
      max_nodes: maxNodes,
    },
  });
}
