import { apiService } from "@/services/api";
import type {
  AuthResponse,
  LoginRequest,
  MessageResponse,
  UserProfileResponse,
} from "@/types";
import { clearAuthTokens, setAccessToken, setRefreshToken } from "@/utils";

export async function loginUser(credentials: LoginRequest): Promise<AuthResponse> {
  const response = await apiService.post<AuthResponse>("/auth/login", credentials, {
    skipAuth: true,
  });

  setAccessToken(response.tokens.access_token);
  setRefreshToken(response.tokens.refresh_token);

  return response;
}

export async function fetchCurrentUser(): Promise<UserProfileResponse> {
  return apiService.get<UserProfileResponse>("/auth/me");
}

export async function logoutUser(): Promise<MessageResponse> {
  try {
    return await apiService.post<MessageResponse>("/auth/logout");
  } finally {
    clearAuthTokens();
  }
}

export function clearSession(): void {
  clearAuthTokens();
}
