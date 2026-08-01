import { Navigate, Route, Routes } from "react-router-dom";
import { useAuth } from "@/hooks/useAuth";
import DashboardLayout from "@/layouts/DashboardLayout";
import LoginPage from "@/pages/LoginPage";
import DashboardHomePage from "@/pages/DashboardHomePage";
import ThreatAnalyticsPage from "@/pages/ThreatAnalyticsPage";
import NetworkGraphPage from "@/pages/NetworkGraphPage";
import AdminPanelPage from "@/pages/AdminPanelPage";
import ZeroTrustDashboardPage from "@/pages/ZeroTrustDashboardPage";
import FirewallPage from "@/pages/FirewallPage";
import IOCDatabasePage from "@/pages/IOCDatabasePage";
import StixTaxiiPage from "@/pages/StixTaxiiPage";
import IncidentDashboardPage from "@/pages/IncidentDashboardPage";
import AnalyticsDashboardPage from "@/pages/AnalyticsDashboardPage";
import LogsPage from "@/pages/LogsPage";
import PacketUploadPage from "@/pages/PacketUploadPage";
import SettingsPage from "@/pages/SettingsPage";

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-slate-950">
        <div className="h-10 w-10 animate-spin rounded-full border-2 border-primary-500 border-t-transparent" />
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  return children;
}

function AdminRoute({ children }: { children: React.ReactNode }) {
  const { user, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-slate-950">
        <div className="h-10 w-10 animate-spin rounded-full border-2 border-primary-500 border-t-transparent" />
      </div>
    );
  }

  if (!user || user.role !== "admin") {
    return <Navigate to="/" replace />;
  }

  return children;
}

function PublicRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-slate-950">
        <div className="h-10 w-10 animate-spin rounded-full border-2 border-primary-500 border-t-transparent" />
      </div>
    );
  }

  if (isAuthenticated) {
    return <Navigate to="/" replace />;
  }

  return children;
}

export function AppRoutes() {
  return (
    <Routes>
      <Route
        path="/login"
        element={
          <PublicRoute>
            <LoginPage />
          </PublicRoute>
        }
      />

      <Route
        element={
          <ProtectedRoute>
            <DashboardLayout />
          </ProtectedRoute>
        }
      >
        <Route index element={<DashboardHomePage />} />
        <Route path="zero-trust" element={<ZeroTrustDashboardPage />} />
        <Route path="firewall" element={<FirewallPage />} />
        <Route path="ioc-database" element={<IOCDatabasePage />} />
        <Route path="stix-taxii" element={<StixTaxiiPage />} />
        <Route path="incidents" element={<IncidentDashboardPage />} />
        <Route path="analytics" element={<AnalyticsDashboardPage />} />
        <Route path="network" element={<NetworkGraphPage />} />
        <Route path="threats" element={<ThreatAnalyticsPage />} />
        <Route path="logs" element={<LogsPage />} />
        <Route path="packets" element={<PacketUploadPage />} />
        <Route path="settings" element={<SettingsPage />} />
        <Route
          path="admin"
          element={
            <AdminRoute>
              <AdminPanelPage />
            </AdminRoute>
          }
        />
      </Route>

      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
