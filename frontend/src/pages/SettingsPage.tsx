import { useEffect, useState } from "react";
import StatusBadge from "@/components/admin/StatusBadge";
import { API_BASE_URL, APP_NAME, APP_VERSION } from "@/config/env";
import { useAuth } from "@/hooks/useAuth";
import { getApiErrorMessage } from "@/services/apiClient";
import { fetchLiveCaptureCapabilities } from "@/services/liveCaptureService";
import type { LiveCaptureCapabilitiesResponse } from "@/types/liveCapture";

const PROJECT_MODULES = [
  { name: "Backend API", status: "Complete", variant: "success" as const },
  { name: "Frontend Dashboard", status: "Complete", variant: "success" as const },
  { name: "ML Training Pipeline", status: "Complete", variant: "success" as const },
  { name: "PCAP Upload + Analysis", status: "Complete", variant: "success" as const },
  { name: "PCAP → Dashboard Alerts", status: "Complete", variant: "success" as const },
  { name: "Live Capture API", status: "Complete", variant: "success" as const },
  { name: "TCP Flag Features", status: "Complete", variant: "success" as const },
  { name: "WebSocket Alerts", status: "Complete", variant: "success" as const },
  { name: "Automated Test Suite", status: "Complete", variant: "success" as const },
  { name: "CI/CD Pipeline", status: "Complete", variant: "success" as const },
];

export default function SettingsPage() {
  const { user } = useAuth();
  const [capabilities, setCapabilities] = useState<LiveCaptureCapabilitiesResponse | null>(null);
  const [capabilitiesError, setCapabilitiesError] = useState<string | null>(null);
  const [isLoadingCapabilities, setIsLoadingCapabilities] = useState(true);

  useEffect(() => {
    let isMounted = true;

    const loadCapabilities = async () => {
      setIsLoadingCapabilities(true);
      setCapabilitiesError(null);

      try {
        const response = await fetchLiveCaptureCapabilities();
        if (isMounted) {
          setCapabilities(response);
        }
      } catch (error) {
        if (isMounted) {
          setCapabilitiesError(getApiErrorMessage(error, "Failed to load live capture settings"));
        }
      } finally {
        if (isMounted) {
          setIsLoadingCapabilities(false);
        }
      }
    };

    loadCapabilities();
    return () => {
      isMounted = false;
    };
  }, []);

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-semibold text-white">Settings</h2>
        <p className="mt-1 text-sm text-slate-400">
          Application configuration, integration status, and project health
        </p>
      </div>

      <div className="rounded-2xl border border-slate-800 bg-slate-950/60 p-5 sm:p-6">
        <h3 className="text-sm font-medium text-white">Application</h3>
        <dl className="mt-4 grid gap-4 sm:grid-cols-2">
          <div>
            <dt className="text-xs uppercase tracking-wide text-slate-500">Name</dt>
            <dd className="mt-1 text-sm text-white">{APP_NAME}</dd>
          </div>
          <div>
            <dt className="text-xs uppercase tracking-wide text-slate-500">Version</dt>
            <dd className="mt-1 text-sm text-white">{APP_VERSION}</dd>
          </div>
          <div className="sm:col-span-2">
            <dt className="text-xs uppercase tracking-wide text-slate-500">API Base URL</dt>
            <dd className="mt-1 break-all font-mono text-sm text-slate-200">{API_BASE_URL}</dd>
          </div>
        </dl>
      </div>

      {user ? (
        <div className="rounded-2xl border border-slate-800 bg-slate-950/60 p-5 sm:p-6">
          <h3 className="text-sm font-medium text-white">Signed-in User</h3>
          <dl className="mt-4 grid gap-4 sm:grid-cols-2">
            <div>
              <dt className="text-xs uppercase tracking-wide text-slate-500">Email</dt>
              <dd className="mt-1 text-sm text-white">{user.email}</dd>
            </div>
            <div>
              <dt className="text-xs uppercase tracking-wide text-slate-500">Role</dt>
              <dd className="mt-1">
                <StatusBadge label={user.role} variant="info" />
              </dd>
            </div>
          </dl>
        </div>
      ) : null}

      <div className="rounded-2xl border border-slate-800 bg-slate-950/60 p-5 sm:p-6">
        <h3 className="text-sm font-medium text-white">Live Capture Integration</h3>
        {isLoadingCapabilities ? (
          <p className="mt-4 text-sm text-slate-400">Loading AI engine capture settings...</p>
        ) : capabilitiesError ? (
          <p className="mt-4 text-sm text-red-300">{capabilitiesError}</p>
        ) : capabilities ? (
          <dl className="mt-4 grid gap-4 sm:grid-cols-2">
            <div>
              <dt className="text-xs uppercase tracking-wide text-slate-500">Status</dt>
              <dd className="mt-1">
                <StatusBadge
                  label={capabilities.enabled ? "Enabled" : "Disabled"}
                  variant={capabilities.enabled ? "success" : "warning"}
                />
              </dd>
            </div>
            <div>
              <dt className="text-xs uppercase tracking-wide text-slate-500">Default Interface</dt>
              <dd className="mt-1 text-sm text-white">
                {capabilities.default_interface || "System default"}
              </dd>
            </div>
            <div>
              <dt className="text-xs uppercase tracking-wide text-slate-500">BPF Filter</dt>
              <dd className="mt-1 font-mono text-sm text-slate-200">
                {capabilities.default_bpf_filter}
              </dd>
            </div>
            <div>
              <dt className="text-xs uppercase tracking-wide text-slate-500">Capture Defaults</dt>
              <dd className="mt-1 text-sm text-slate-200">
                {capabilities.default_packet_count} packets / {capabilities.default_timeout_seconds}s
              </dd>
            </div>
            <div className="sm:col-span-2">
              <dt className="text-xs uppercase tracking-wide text-slate-500">Loaded Models</dt>
              <dd className="mt-2 flex flex-wrap gap-2">
                {capabilities.models_loaded.length > 0 ? (
                  capabilities.models_loaded.map((model) => (
                    <StatusBadge key={model} label={model} variant="muted" />
                  ))
                ) : (
                  <span className="text-sm text-slate-400">No models reported by AI engine</span>
                )}
              </dd>
            </div>
            {capabilities.notes.length > 0 ? (
              <div className="sm:col-span-2">
                <dt className="text-xs uppercase tracking-wide text-slate-500">Notes</dt>
                <dd className="mt-2 space-y-1 text-sm text-slate-400">
                  {capabilities.notes.map((note) => (
                    <p key={note}>{note}</p>
                  ))}
                </dd>
              </div>
            ) : null}
          </dl>
        ) : null}
      </div>

      <div className="rounded-2xl border border-slate-800 bg-slate-950/60 p-5 sm:p-6">
        <h3 className="text-sm font-medium text-white">Project Module Status</h3>
        <p className="mt-1 text-sm text-slate-400">
          High-level completion status for major AI-NGFW components
        </p>
        <div className="mt-4 space-y-3">
          {PROJECT_MODULES.map((module) => (
            <div
              key={module.name}
              className="flex items-center justify-between rounded-xl border border-slate-800 bg-slate-900/50 px-4 py-3"
            >
              <span className="text-sm text-slate-200">{module.name}</span>
              <StatusBadge label={module.status} variant={module.variant} />
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
