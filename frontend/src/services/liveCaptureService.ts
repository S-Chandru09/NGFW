import { apiService } from "@/services/api";
import type {
  LiveCaptureCapabilitiesResponse,
  LiveCaptureRequest,
  LiveCaptureResponse,
} from "@/types/liveCapture";

export async function fetchLiveCaptureCapabilities(): Promise<LiveCaptureCapabilitiesResponse> {
  return apiService.get<LiveCaptureCapabilitiesResponse>("/capture/live/capabilities");
}

export async function runLiveCapture(
  request: LiveCaptureRequest = {},
): Promise<LiveCaptureResponse> {
  return apiService.post<LiveCaptureResponse>("/capture/live", request);
}
