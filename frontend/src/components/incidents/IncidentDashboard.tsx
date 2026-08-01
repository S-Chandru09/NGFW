import { useCallback, useEffect, useState } from "react";
import IncidentDetailPanel from "@/components/incidents/IncidentDetailPanel";
import IncidentFormModal from "@/components/incidents/IncidentFormModal";
import IncidentListTable, { IncidentListFilters } from "@/components/incidents/IncidentListTable";
import IncidentSeverityPanel from "@/components/incidents/IncidentSeverityPanel";
import IncidentStatsCards from "@/components/incidents/IncidentStatsCards";
import IncidentTimeline from "@/components/incidents/IncidentTimeline";
import { useAuth } from "@/hooks/useAuth";
import { getApiErrorMessage } from "@/services/apiClient";
import {
  blockIncidentIP,
  createIncident,
  fetchIncident,
  fetchIncidents,
  fetchIncidentStats,
  generateIncidentReport,
  killIncidentSession,
} from "@/services/incidentService";
import type { PaginationMeta } from "@/types/admin";
import type {
  Incident,
  IncidentDashboardTab,
  IncidentFormData,
  IncidentSeverity,
  IncidentStats,
  IncidentStatus,
} from "@/types/incident";
import { EMPTY_INCIDENT_FORM } from "@/types/incident";
import { cn, formatDateTime } from "@/utils";

const tabs: Array<{ id: IncidentDashboardTab; label: string }> = [
  { id: "list", label: "Incident List" },
  { id: "severity", label: "Severity" },
  { id: "timeline", label: "Timeline" },
];

export default function IncidentDashboard() {
  const { user } = useAuth();
  const canRespond = user?.role === "admin" || user?.role === "analyst";
  const canCreate = canRespond;

  const [activeTab, setActiveTab] = useState<IncidentDashboardTab>("list");
  const [stats, setStats] = useState<IncidentStats | null>(null);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [pagination, setPagination] = useState<PaginationMeta | null>(null);
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState<IncidentStatus | "all">("all");
  const [severityFilter, setSeverityFilter] = useState<IncidentSeverity | "all">("all");
  const [isLoading, setIsLoading] = useState(true);
  const [isActionLoading, setIsActionLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [actionMessage, setActionMessage] = useState<string | null>(null);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [form, setForm] = useState<IncidentFormData>(EMPTY_INCIDENT_FORM);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  const loadData = useCallback(async () => {
    setIsLoading(true);
    setError(null);

    try {
      const [statsResponse, incidentsResponse] = await Promise.all([
        fetchIncidentStats(),
        fetchIncidents({
          page,
          page_size: 10,
          status: statusFilter === "all" ? undefined : statusFilter,
          severity: severityFilter === "all" ? undefined : severityFilter,
          search: search.trim() || undefined,
        }),
      ]);

      setStats(statsResponse);
      setIncidents(incidentsResponse.items);
      setPagination(incidentsResponse.pagination);
    } catch (loadError) {
      setError(getApiErrorMessage(loadError, "Failed to load incident dashboard"));
    } finally {
      setIsLoading(false);
    }
  }, [page, search, severityFilter, statusFilter]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleSelectIncident = async (incident: Incident) => {
    setSelectedIncident(incident);

    try {
      const detailResponse = await fetchIncident(incident.incident_id);
      setSelectedIncident(detailResponse.incident);
    } catch {
      setSelectedIncident(incident);
    }
  };

  const refreshSelectedIncident = async (incidentId: string) => {
    const detailResponse = await fetchIncident(incidentId);
    setSelectedIncident(detailResponse.incident);
    await loadData();
  };

  const handleBlockIP = async () => {
    if (!selectedIncident) {
      return;
    }

    setIsActionLoading(true);
    setActionMessage(null);
    setError(null);

    try {
      const response = await blockIncidentIP(selectedIncident.incident_id, {
        reason: "Incident response containment",
        action: "blacklist",
      });
      setActionMessage(`Blocked IP ${response.blocked_ip} via rule ${response.firewall_rule_name}`);
      await refreshSelectedIncident(selectedIncident.incident_id);
    } catch (actionError) {
      setError(getApiErrorMessage(actionError, "Failed to block IP"));
    } finally {
      setIsActionLoading(false);
    }
  };

  const handleKillSession = async () => {
    if (!selectedIncident) {
      return;
    }

    setIsActionLoading(true);
    setActionMessage(null);
    setError(null);

    try {
      const response = await killIncidentSession(selectedIncident.incident_id, {
        kill_all_for_user: Boolean(selectedIncident.affected_user_id),
        user_id: selectedIncident.affected_user_id ?? undefined,
        ip_address: selectedIncident.source_ip ?? undefined,
        reason: "Incident response session termination",
      });
      setActionMessage(`Killed ${response.sessions_killed} session(s)`);
      await refreshSelectedIncident(selectedIncident.incident_id);
    } catch (actionError) {
      setError(getApiErrorMessage(actionError, "Failed to kill session"));
    } finally {
      setIsActionLoading(false);
    }
  };

  const handleGenerateReport = async () => {
    if (!selectedIncident) {
      return;
    }

    setIsActionLoading(true);
    setActionMessage(null);
    setError(null);

    try {
      const response = await generateIncidentReport(selectedIncident.incident_id, {
        include_audit_logs: true,
        include_firewall_rules: true,
        include_ioc_enrichment: true,
        include_session_history: true,
      });
      setActionMessage(`Report generated: ${response.report.title}`);
      await refreshSelectedIncident(selectedIncident.incident_id);
    } catch (actionError) {
      setError(getApiErrorMessage(actionError, "Failed to generate report"));
    } finally {
      setIsActionLoading(false);
    }
  };

  const handleCreateIncident = async () => {
    setIsSubmitting(true);
    setFormError(null);

    try {
      const response = await createIncident(form);
      setActionMessage(`Incident "${response.incident.title}" created`);
      setIsModalOpen(false);
      setForm(EMPTY_INCIDENT_FORM);
      setSelectedIncident(response.incident);
      setActiveTab("timeline");
      setPage(1);
      await loadData();
    } catch (submitError) {
      setFormError(getApiErrorMessage(submitError, "Failed to create incident"));
    } finally {
      setIsSubmitting(false);
    }
  };

  if (isLoading && !stats) {
    return (
      <div className="flex min-h-[320px] items-center justify-center rounded-2xl border border-slate-800 bg-slate-900/40">
        <div className="h-10 w-10 animate-spin rounded-full border-2 border-primary-500 border-t-transparent" />
      </div>
    );
  }

  if (error && !stats) {
    return (
      <div className="rounded-2xl border border-red-500/30 bg-red-500/10 p-6">
        <h3 className="text-lg font-semibold text-red-300">Unable to load incident dashboard</h3>
        <p className="mt-2 text-sm text-red-200/80">{error}</p>
        <button
          type="button"
          onClick={loadData}
          className="mt-4 rounded-lg bg-red-500/20 px-4 py-2 text-sm font-medium text-red-200 transition hover:bg-red-500/30"
        >
          Retry
        </button>
      </div>
    );
  }

  if (!stats) {
    return null;
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h2 className="text-xl font-semibold text-white">Incident Response Dashboard</h2>
          <p className="mt-1 text-sm text-slate-400">
            Monitor incidents, analyze severity, and track response timelines
          </p>
        </div>

        <div className="flex items-center gap-3">
          <p className="text-xs text-slate-500">Updated {formatDateTime(stats.generated_at)}</p>
          <button
            type="button"
            onClick={loadData}
            disabled={isLoading}
            className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200 transition hover:bg-slate-800 disabled:opacity-50"
          >
            {isLoading ? "Refreshing..." : "Refresh"}
          </button>
          {canCreate ? (
            <button
              type="button"
              onClick={() => {
                setForm(EMPTY_INCIDENT_FORM);
                setFormError(null);
                setIsModalOpen(true);
              }}
              className="rounded-lg bg-primary-500 px-4 py-2 text-sm font-medium text-white transition hover:bg-primary-400"
            >
              New Incident
            </button>
          ) : null}
        </div>
      </div>

      {actionMessage ? (
        <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-200">
          {actionMessage}
        </div>
      ) : null}

      {error ? (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-200">
          {error}
        </div>
      ) : null}

      <IncidentStatsCards stats={stats} />

      <div className="flex flex-wrap gap-2 border-b border-slate-800 pb-1">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            type="button"
            onClick={() => setActiveTab(tab.id)}
            className={cn(
              "rounded-t-lg px-4 py-2 text-sm font-medium transition",
              activeTab === tab.id
                ? "bg-slate-900 text-primary-300 ring-1 ring-inset ring-primary-500/30"
                : "text-slate-400 hover:text-slate-200",
            )}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {activeTab === "list" ? (
        <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_320px]">
          <div className="space-y-4 rounded-2xl border border-slate-800 bg-slate-900/40 p-5">
            <IncidentListFilters
              search={search}
              statusFilter={statusFilter}
              severityFilter={severityFilter}
              onSearchChange={(value) => {
                setSearch(value);
                setPage(1);
              }}
              onStatusChange={(value) => {
                setStatusFilter(value);
                setPage(1);
              }}
              onSeverityChange={(value) => {
                setSeverityFilter(value);
                setPage(1);
              }}
            />
            <IncidentListTable
              incidents={incidents}
              pagination={pagination}
              selectedIncidentId={selectedIncident?.incident_id ?? null}
              isLoading={isLoading}
              onPageChange={setPage}
              onSelect={handleSelectIncident}
            />
          </div>

          <IncidentDetailPanel
            incident={selectedIncident}
            canRespond={canRespond}
            isActionLoading={isActionLoading}
            onBlockIP={handleBlockIP}
            onKillSession={handleKillSession}
            onGenerateReport={handleGenerateReport}
          />
        </div>
      ) : null}

      {activeTab === "severity" ? <IncidentSeverityPanel stats={stats} /> : null}

      {activeTab === "timeline" ? (
        <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_320px]">
          <IncidentTimeline incident={selectedIncident} />
          <div className="space-y-4">
            <div className="rounded-2xl border border-slate-800 bg-slate-900/40 p-5">
              <h3 className="text-sm font-semibold text-white">Select Incident</h3>
              <div className="mt-3 space-y-2">
                {incidents.length === 0 ? (
                  <p className="text-sm text-slate-500">No incidents available</p>
                ) : (
                  incidents.map((incident) => (
                    <button
                      key={incident.incident_id}
                      type="button"
                      onClick={() => handleSelectIncident(incident)}
                      className={cn(
                        "w-full rounded-lg border px-3 py-2 text-left transition",
                        selectedIncident?.incident_id === incident.incident_id
                          ? "border-primary-500/40 bg-primary-500/10"
                          : "border-slate-800 bg-slate-950/60 hover:bg-slate-900",
                      )}
                    >
                      <p className="text-sm font-medium text-white">{incident.title}</p>
                      <p className="mt-0.5 text-xs text-slate-500">
                        {incident.severity} · {incident.actions_taken.length} actions
                      </p>
                    </button>
                  ))
                )}
              </div>
            </div>

            <IncidentDetailPanel
              incident={selectedIncident}
              canRespond={canRespond}
              isActionLoading={isActionLoading}
              onBlockIP={handleBlockIP}
              onKillSession={handleKillSession}
              onGenerateReport={handleGenerateReport}
            />
          </div>
        </div>
      ) : null}

      <IncidentFormModal
        isOpen={isModalOpen}
        form={form}
        isSubmitting={isSubmitting}
        error={formError}
        onChange={setForm}
        onClose={() => setIsModalOpen(false)}
        onSubmit={handleCreateIncident}
      />
    </div>
  );
}
