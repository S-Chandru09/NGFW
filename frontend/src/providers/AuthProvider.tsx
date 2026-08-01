import { useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { AuthContext } from "@/context/AuthContext";
import { getApiErrorMessage } from "@/services/apiClient";
import {
  clearSession,
  fetchCurrentUser,
  loginUser,
  logoutUser,
} from "@/services/authService";
import type { LoginRequest, UserProfile } from "@/types";
import { getAccessToken } from "@/utils";

interface AuthProviderProps {
  children: ReactNode;
}

export function AuthProvider({ children }: AuthProviderProps) {
  const [user, setUser] = useState<UserProfile | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const bootstrapSession = useCallback(async () => {
    const token = getAccessToken();

    if (!token) {
      setUser(null);
      setIsLoading(false);
      return;
    }

    try {
      const response = await fetchCurrentUser();
      setUser(response.user);
    } catch {
      clearSession();
      setUser(null);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    bootstrapSession();
  }, [bootstrapSession]);

  const login = useCallback(async (credentials: LoginRequest) => {
    setIsSubmitting(true);
    setError(null);

    try {
      const response = await loginUser(credentials);
      setUser(response.user);
    } catch (loginError) {
      const message = getApiErrorMessage(loginError, "Login failed");
      setError(message);
      throw loginError;
    } finally {
      setIsSubmitting(false);
    }
  }, []);

  const logout = useCallback(async () => {
    setIsSubmitting(true);

    try {
      await logoutUser();
    } catch {
      clearSession();
    } finally {
      setUser(null);
      setIsSubmitting(false);
    }
  }, []);

  const clearError = useCallback(() => {
    setError(null);
  }, []);

  const value = useMemo(
    () => ({
      user,
      isAuthenticated: Boolean(user),
      isLoading,
      isSubmitting,
      error,
      login,
      logout,
      clearError,
    }),
    [user, isLoading, isSubmitting, error, login, logout, clearError],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);

  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }

  return context;
}
