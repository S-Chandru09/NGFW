export type UserRole = "admin" | "analyst" | "viewer";

export type ThreatLevel = "low" | "medium" | "high" | "critical";

export interface ApiResponse<T> {
  data: T;
  message?: string;
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

export interface AuthTokens {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
}

export interface UserProfile {
  id: string;
  email: string;
  username: string;
  full_name: string;
  role: UserRole;
  is_active: boolean;
  created_at: string;
  updated_at: string;
  last_login_at: string | null;
}

export interface LoginRequest {
  email: string;
  password: string;
}

export interface AuthResponse {
  success: boolean;
  message: string;
  user: UserProfile;
  tokens: AuthTokens;
}

export interface UserProfileResponse {
  success: boolean;
  message: string;
  user: UserProfile;
}

export interface MessageResponse {
  success: boolean;
  message: string;
}

export type {
  ApiErrorPayload,
  ApiRequestConfig,
  ApiValidationErrorItem,
  HttpMethod,
} from "@/types/api";
