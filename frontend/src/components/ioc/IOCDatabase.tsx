import { useCallback, useEffect, useState } from "react";
import DataTable, { type Column } from "@/components/admin/DataTable";
import Pagination from "@/components/admin/Pagination";
import StatusBadge, { threatLevelBadgeVariant } from "@/components/admin/StatusBadge";
import IOCFormModal from "@/components/ioc/IOCFormModal";
import IOCStatsCards from "@/components/ioc/IOCStatsCards";
import { getApiErrorMessage } from "@/services/apiClient";
import {
  createDomainIndicator,
  createHashIndicator,
  createIPIndicator,
  deleteIOCIndicator,
  fetchIOCIndicators,
  fetchIOCStats,
  updateIOCIndicator,
} from "@/services/iocService";
import type { PaginationMeta } from "@/types/admin";
import type { IOCFormData, IOCIndicator, IOCDatabaseTab, IOCStatsResponse } from "@/types/ioc";
import { EMPTY_IOC_FORM as defaultForm } from "@/types/ioc";
import { cn, formatDateTime } from "@/utils";

const tabs: Array<{ id: IOCDatabaseTab; label: string }> = [
  { id: "ip", label: "IP" },
  { id: "domain", label: "Domain" },
  { id: "hash", label: "Hash" },
];

export default function IOCDatabase() {
  const [activeTab, setActiveTab] = useState<IOCDatabaseTab>("ip");
  const [indicators, setIndicators] = useState<IOCIndicator[]>([]);
  const [stats, setStats] = useState<IOCStatsResponse | null>(null);
  const [pagination, setPagination] = useState<PaginationMeta | null>(null);
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState("");
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionMessage, setActionMessage] = useState<string | null>(null);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [form, setForm] = useState<IOCFormData>(defaultForm);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  const loadData = useCallback(async () => {
    setIsLoading(true);
    setError(null);

    try {
      const [indicatorResponse, statsResponse] = await Promise.all([
        fetchIOCIndicators(activeTab, { page, page_size: 10, search: search || undefined }),
        fetchIOCStats(),
      ]);

      setIndicators(indicatorResponse.items);
      setPagination(indicatorResponse.pagination);
      setStats(statsResponse);
    } catch (loadError) {
      setError(getApiErrorMessage(loadError, "Failed to load IOC database"));
    } finally {
      setIsLoading(false);
    }
  }, [activeTab, page, search]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const openCreateModal = () => {
    setForm(defaultForm);
    setFormError(null);
    setIsModalOpen(true);
  };

  const closeModal = () => {
    setIsModalOpen(false);
    setFormError(null);
  };

  const handleCreate = async () => {
    setIsSubmitting(true);
    setFormError(null);

    try {
      if (activeTab === "ip") {
        await createIPIndicator(form);
      } else if (activeTab === "domain") {
        await createDomainIndicator(form);
      } else {
        await createHashIndicator(form);
      }

      setActionMessage(`IOC "${form.value}" added to ${activeTab.toUpperCase()} database.`);
      closeModal();
      await loadData();
    } catch (submitError) {
      setFormError(getApiErrorMessage(submitError, "Failed to add IOC"));
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleToggleActive = async (indicator: IOCIndicator) => {
    try {
      await updateIOCIndicator(indicator.id, { is_active: !indicator.is_active });
      setActionMessage(`IOC "${indicator.value}" ${indicator.is_active ? "deactivated" : "activated"}.`);
      await loadData();
    } catch (toggleError) {
      setError(getApiErrorMessage(toggleError, "Failed to update IOC status"));
    }
  };

  const handleDelete = async (indicator: IOCIndicator) => {
    if (!window.confirm(`Delete IOC "${indicator.value}"?`)) {
      return;
    }

    try {
      await deleteIOCIndicator(indicator.id);
      setActionMessage(`IOC "${indicator.value}" deleted.`);
      await loadData();
    } catch (deleteError) {
      setError(getApiErrorMessage(deleteError, "Failed to delete IOC"));
    }
  };

  const columns: Column<IOCIndicator>[] = [
    {
      key: "value",
      header: "Indicator",
      render: (indicator) => (
        <div>
          <p className="max-w-[220px] truncate font-medium text-white" title={indicator.value}>
            {indicator.value}
          </p>
          <p className="text-xs text-slate-500">{indicator.ioc_id}</p>
        </div>
      ),
    },
    {
      key: "threat_level",
      header: "Threat Level",
      render: (indicator) => (
        <StatusBadge
          label={indicator.threat_level}
          variant={threatLevelBadgeVariant(indicator.threat_level)}
        />
      ),
    },
    {
      key: "reputation",
      header: "Reputation",
      render: (indicator) => (
        <div>
          <p className="font-medium text-white">{indicator.reputation_score}/100</p>
          <StatusBadge
            label={indicator.is_malicious ? "Malicious" : "Benign"}
            variant={indicator.is_malicious ? "danger" : "success"}
          />
        </div>
      ),
    },
    {
      key: "source",
      header: "Source",
      render: (indicator) => indicator.source,
    },
    {
      key: "country",
      header: "Country",
      render: (indicator) => indicator.country || "—",
    },
    {
      key: "hits",
      header: "Hits",
      render: (indicator) => indicator.hit_count,
    },
    {
      key: "status",
      header: "Status",
      render: (indicator) => (
        <StatusBadge
          label={indicator.is_active ? "Active" : "Inactive"}
          variant={indicator.is_active ? "success" : "muted"}
        />
      ),
    },
    {
      key: "last_seen",
      header: "Last Seen",
      render: (indicator) => formatDateTime(indicator.last_seen_at),
    },
    {
      key: "actions",
      header: "Actions",
      render: (indicator) => (
        <div className="flex gap-2">
          <button
            type="button"
            onClick={() => handleToggleActive(indicator)}
            className="rounded-md border border-slate-700 px-2 py-1 text-xs text-slate-200 transition hover:bg-slate-800"
          >
            {indicator.is_active ? "Deactivate" : "Activate"}
          </button>
          <button
            type="button"
            onClick={() => handleDelete(indicator)}
            className="rounded-md border border-red-500/30 px-2 py-1 text-xs text-red-300 transition hover:bg-red-500/10"
          >
            Delete
          </button>
        </div>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h2 className="text-xl font-semibold text-white">IOC Database</h2>
          <p className="mt-1 text-sm text-slate-400">
            MongoDB-backed indicators of compromise for IP, domain, and hash
          </p>
        </div>

        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            onClick={openCreateModal}
            className="rounded-lg bg-primary-500 px-4 py-2 text-sm font-medium text-white transition hover:bg-primary-600"
          >
            Add {activeTab.toUpperCase()} IOC
          </button>
          <button
            type="button"
            onClick={loadData}
            className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200 transition hover:bg-slate-800"
          >
            Refresh
          </button>
        </div>
      </div>

      {stats ? <IOCStatsCards stats={stats} /> : null}

      <div className="rounded-2xl border border-slate-800 bg-slate-900/40 p-1">
        <div className="grid grid-cols-3 gap-1">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              type="button"
              onClick={() => {
                setActiveTab(tab.id);
                setPage(1);
              }}
              className={cn(
                "rounded-xl px-4 py-3 text-sm font-semibold transition",
                activeTab === tab.id
                  ? "bg-primary-500/15 text-primary-300 ring-1 ring-primary-500/30"
                  : "text-slate-400 hover:bg-slate-800/60 hover:text-slate-200",
              )}
            >
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      <div className="flex flex-wrap gap-2">
        <input
          type="search"
          value={search}
          onChange={(event) => {
            setSearch(event.target.value);
            setPage(1);
          }}
          placeholder={`Search ${activeTab} indicators...`}
          className="min-w-[240px] flex-1 rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200 placeholder:text-slate-500 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
        />
      </div>

      {error ? (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-200">
          {error}
        </div>
      ) : null}

      {actionMessage ? (
        <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-200">
          {actionMessage}
        </div>
      ) : null}

      <DataTable
        columns={columns}
        data={indicators}
        rowKey={(indicator) => indicator.id}
        isLoading={isLoading}
        emptyMessage={`No ${activeTab} indicators found. Add your first IOC or run the seed script.`}
      />

      {pagination ? <Pagination pagination={pagination} onPageChange={setPage} /> : null}

      <IOCFormModal
        isOpen={isModalOpen}
        type={activeTab}
        form={form}
        isSubmitting={isSubmitting}
        error={formError}
        onChange={setForm}
        onClose={closeModal}
        onSubmit={handleCreate}
      />
    </div>
  );
}
