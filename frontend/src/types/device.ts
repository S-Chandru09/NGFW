import type { PaginationMeta } from "@/types/admin";

export const DEVICE_TYPES = [
  "laptop",
  "desktop",
  "mobile",
  "tablet",
  "server",
  "iot",
  "unknown",
] as const;

export type DeviceType = (typeof DEVICE_TYPES)[number];

export const DEVICE_SORT_FIELDS = [
  "created_at",
  "updated_at",
  "device_name",
  "ip_address",
  "trust_score",
  "last_seen_at",
] as const;

export type DeviceSortField = (typeof DEVICE_SORT_FIELDS)[number];

export type DeviceSortOrder = "asc" | "desc";

export interface Device {
  id: string;
  device_id: string;
  device_name: string;
  device_type: DeviceType;
  os_type?: string | null;
  ip_address?: string | null;
  user_id?: string | null;
  is_trusted: boolean;
  trust_score: number;
  is_compliant: boolean;
  last_seen_at?: string | null;
  created_at: string;
  updated_at: string;
}

export interface DeviceListParams {
  page?: number;
  page_size?: number;
  user_id?: string;
  device_type?: DeviceType;
  ip_address?: string;
  sort_by?: DeviceSortField;
  sort_order?: DeviceSortOrder;
}

export interface DeviceListResponse {
  success: boolean;
  message: string;
  items: Device[];
  pagination: PaginationMeta;
}

export interface DeviceMutationResponse {
  success: boolean;
  message: string;
  device: Device;
}

export interface DeviceDeleteResponse {
  success: boolean;
  message: string;
  device_id: string;
}

export interface DeviceFormData {
  device_name: string;
  device_type: DeviceType;
  os_type: string;
  ip_address: string;
  user_id: string;
  is_compliant: boolean;
}

export interface DeviceCreatePayload {
  device_name: string;
  device_type: DeviceType;
  os_type?: string;
  ip_address?: string;
  user_id?: string;
}

export interface DeviceUpdatePayload {
  device_name?: string;
  device_type?: DeviceType;
  os_type?: string | null;
  ip_address?: string | null;
  user_id?: string | null;
  is_compliant?: boolean;
}

export const EMPTY_DEVICE_FORM: DeviceFormData = {
  device_name: "",
  device_type: "unknown",
  os_type: "",
  ip_address: "",
  user_id: "",
  is_compliant: true,
};

export function deviceToFormData(device: Device): DeviceFormData {
  return {
    device_name: device.device_name,
    device_type: device.device_type,
    os_type: device.os_type ?? "",
    ip_address: device.ip_address ?? "",
    user_id: device.user_id ?? "",
    is_compliant: device.is_compliant,
  };
}

export function buildDeviceCreatePayload(form: DeviceFormData): DeviceCreatePayload {
  const payload: DeviceCreatePayload = {
    device_name: form.device_name.trim(),
    device_type: form.device_type,
  };

  const osType = form.os_type.trim();
  if (osType) {
    payload.os_type = osType;
  }

  const ipAddress = form.ip_address.trim();
  if (ipAddress) {
    payload.ip_address = ipAddress;
  }

  if (form.user_id) {
    payload.user_id = form.user_id;
  }

  return payload;
}

export function buildDeviceUpdatePayload(form: DeviceFormData): DeviceUpdatePayload {
  return {
    device_name: form.device_name.trim(),
    device_type: form.device_type,
    os_type: form.os_type.trim() || null,
    ip_address: form.ip_address.trim() || null,
    user_id: form.user_id || null,
    is_compliant: form.is_compliant,
  };
}
