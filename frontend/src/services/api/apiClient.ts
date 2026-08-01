import axios from "axios";
import { API_BASE_URL, REQUEST_TIMEOUT_MS } from "@/config/env";
import { setupRequestInterceptor, setupResponseInterceptor } from "@/services/api/interceptors";

export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: REQUEST_TIMEOUT_MS,
  headers: {
    "Content-Type": "application/json",
    Accept: "application/json",
  },
});

setupRequestInterceptor(apiClient);
setupResponseInterceptor(apiClient);
