import { apiService } from "@/services/api";
import type {
  DeviceCreatePayload,
  DeviceDeleteResponse,
  DeviceListParams,
  DeviceListResponse,
  DeviceMutationResponse,
  DeviceUpdatePayload,
} from "@/types/device";

export async function fetchDevices(params: DeviceListParams = {}) {
  return apiService.get<DeviceListResponse>("/devices", {
    params: {
      page: params.page,
      page_size: params.page_size,
      user_id: params.user_id,
      device_type: params.device_type,
      ip_address: params.ip_address,
      sort_by: params.sort_by,
      sort_order: params.sort_order,
    },
  });
}

export async function createDevice(payload: DeviceCreatePayload) {
  return apiService.post<DeviceMutationResponse>("/devices", payload);
}

export async function updateDevice(deviceId: string, payload: DeviceUpdatePayload) {
  return apiService.patch<DeviceMutationResponse>(`/devices/${deviceId}`, payload);
}

export async function deleteDevice(deviceId: string) {
  return apiService.delete<DeviceDeleteResponse>(`/devices/${deviceId}`);
}
