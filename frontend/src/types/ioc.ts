import type { PaginationMeta } from "@/types/admin";

export type IOCType = "ip" | "domain" | "hash";
export type HashType = "md5" | "sha1" | "sha256";
export type ThreatLevel = "safe" | "low" | "medium" | "high" | "critical";
export type ThreatCategory =
  | "malware"
  | "phishing"
  | "c2"
  | "botnet"
  | "spam"
  | "exploit"
  | "ransomware"
  | "data_exfiltration"
  | "brute_force"
  | "unknown";

export interface IOCIndicator {
  id: string;
  ioc_id: string;
  ioc_type: IOCType | "url" | "email";
  value: string;
  hash_type?: HashType | null;
  reputation_score: number;
  threat_level: ThreatLevel;
  is_malicious: boolean;
  threat_categories: ThreatCategory[];
  source: string;
  description?: string | null;
  country?: string | null;
  asn?: string | null;
  isp?: string | null;
  tags: string[];
  is_active: boolean;
  hit_count: number;
  first_seen_at: string;
  last_seen_at: string;
  created_at: string;
  updated_at: string;
}

export interface IOCListResponse {
  success: boolean;
  message: string;
  items: IOCIndicator[];
  pagination: PaginationMeta;
}

export interface IOCDetailResponse {
  success: boolean;
  message: string;
  ioc: IOCIndicator;
}

export interface IOCStatsResponse {
  success: boolean;
  message: string;
  total_iocs: number;
  malicious_iocs: number;
  active_iocs: number;
  ip_count: number;
  hash_count: number;
  domain_count: number;
  critical_threats: number;
  high_threats: number;
  generated_at: string;
}

export interface IOCFormData {
  value: string;
  reputation_score: number;
  is_malicious: boolean;
  source: string;
  description: string;
  country: string;
  tags: string;
  is_active: boolean;
}

export const EMPTY_IOC_FORM: IOCFormData = {
  value: "",
  reputation_score: 50,
  is_malicious: false,
  source: "internal",
  description: "",
  country: "",
  tags: "",
  is_active: true,
};

export type IOCDatabaseTab = "ip" | "domain" | "hash";
