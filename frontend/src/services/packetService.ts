import { apiClient } from "@/services/api/apiClient";
import { apiService } from "@/services/api/apiService";
import type {
  PacketUploadListResponse,
  PacketUploadResponse,
  PacketUploadStatus,
  PacketUploadStatusResponse,
} from "@/types/packetUpload";

export async function fetchPacketUploads(params: {
  page?: number;
  page_size?: number;
  status?: PacketUploadStatus;
} = {}) {
  return apiService.get<PacketUploadListResponse>("/packet-upload", { params });
}

export async function uploadPcapFile(file: File) {
  const formData = new FormData();
  formData.append("file", file);

  const response = await apiClient.post<PacketUploadResponse>("/packet-upload", formData, {
    headers: {
      "Content-Type": "multipart/form-data",
    },
  });

  return response.data;
}

export async function fetchPacketUploadStatus(uploadId: string) {
  return apiService.get<PacketUploadStatusResponse>(`/packet-upload/${uploadId}/status`);
}

export async function fetchPacketUpload(uploadId: string) {
  return apiService.get<PacketUploadResponse>(`/packet-upload/${uploadId}`);
}
