import { apiService } from "@/services/api";
import type {
  StixObjectListResponse,
  StixObjectTypeFilter,
  TaxiiSimulationStats,
  TaxiiSyncResponse,
} from "@/types/stixTaxii";

export async function fetchTaxiiStats() {
  return apiService.get<TaxiiSimulationStats>("/stix-taxii/stats");
}

export async function syncTaxiiSimulation() {
  return apiService.post<TaxiiSyncResponse>("/stix-taxii/sync");
}

export async function fetchStixObjects(params: {
  page?: number;
  page_size?: number;
  collection_id?: string;
  object_type?: Exclude<StixObjectTypeFilter, "all">;
}) {
  return apiService.get<StixObjectListResponse>("/stix-taxii/objects", { params });
}
