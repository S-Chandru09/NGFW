import type { PaginationMeta } from "@/types/admin";

export interface TaxiiCollection {
  id: string;
  title: string;
  description: string;
  can_read: boolean;
  can_write: boolean;
  media_types: string[];
  object_count: number;
  last_synced_at: string | null;
}

export interface StixObject {
  stix_id: string;
  collection_id: string;
  object_type: string;
  name: string;
  stix_payload: Record<string, unknown>;
  source_ioc_id: string | null;
  created_at: string;
  modified: string;
}

export interface TaxiiSimulationStats {
  success: boolean;
  message: string;
  taxii_version: string;
  stix_version: string;
  api_root: string;
  total_collections: number;
  active_collections: number;
  total_objects: number;
  indicator_count: number;
  malware_count: number;
  threat_actor_count: number;
  attack_pattern_count: number;
  last_synced_at: string | null;
  collections: TaxiiCollection[];
  object_type_distribution: Record<string, number>;
  generated_at: string;
}

export interface TaxiiSyncResponse {
  success: boolean;
  message: string;
  collections_synced: number;
  objects_created: number;
  objects_updated: number;
  synced_at: string;
}

export interface StixObjectListResponse {
  success: boolean;
  message: string;
  items: StixObject[];
  pagination: PaginationMeta;
}

export type StixObjectTypeFilter = "all" | "indicator" | "malware" | "threat-actor" | "attack-pattern";
