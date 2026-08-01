import { BrowserRouter } from "react-router-dom";
import type { ReactNode } from "react";
import { AuthProvider } from "@/providers/AuthProvider";

interface AppProvidersProps {
  children: ReactNode;
}

export function AppProviders({ children }: AppProvidersProps) {
  return (
    <BrowserRouter>
      <AuthProvider>{children}</AuthProvider>
    </BrowserRouter>
  );
}
