import { useCallback, useEffect, useState } from "react";
import DataTable, { type Column } from "@/components/admin/DataTable";
import Pagination from "@/components/admin/Pagination";
import StatusBadge, { actionBadgeVariant } from "@/components/admin/StatusBadge";
import FirewallRuleFormModal from "@/components/firewall/FirewallRuleFormModal";
import FirewallStatsCards from "@/components/firewall/FirewallStatsCards";
import { getApiErrorMessage } from "@/services/apiClient";
import {
  createFirewallRule,
  deleteFirewallRule,
  fetchFirewallRuleStats,
  fetchFirewallRules,
  ruleToFormData,
  toggleFirewallRule,
  updateFirewallRule,
} from "@/services/firewallService";
import type { PaginationMeta } from "@/types/admin";
import type {
  FirewallRule,
  FirewallRuleAction,
  FirewallRuleFormData,
  FirewallRuleStatsResponse,
} from "@/types/firewall";
import { EMPTY_FIREWALL_RULE_FORM as defaultForm } from "@/types/firewall";
import { formatDateTime } from "@/utils";

type StatusFilter = "" | "enabled" | "disabled" | "expired";

export default function FirewallRulesManager() {
  const [rules, setRules] = useState<FirewallRule[]>([]);
  const [stats, setStats] = useState<FirewallRuleStatsResponse | null>(null);
  const [pagination, setPagination] = useState<PaginationMeta | null>(null);
  const [page, setPage] = useState(1);
  const [actionFilter, setActionFilter] = useState<FirewallRuleAction | "">("");
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("");
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionMessage, setActionMessage] = useState<string | null>(null);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [modalMode, setModalMode] = useState<"create" | "edit">("create");
  const [editingRule, setEditingRule] = useState<FirewallRule | null>(null);
  const [form, setForm] = useState<FirewallRuleFormData>(defaultForm);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  const loadData = useCallback(async () => {
    setIsLoading(true);
    setError(null);

    try {
      const [rulesResponse, statsResponse] = await Promise.all([
        fetchFirewallRules({
          page,
          page_size: 10,
          action: actionFilter || undefined,
          is_enabled:
            statusFilter === "enabled" ? true : statusFilter === "disabled" ? false : undefined,
          is_expired: statusFilter === "expired" ? true : undefined,
        }),
        fetchFirewallRuleStats(),
      ]);

      setRules(rulesResponse.items);
      setPagination(rulesResponse.pagination);
      setStats(statsResponse);
    } catch (loadError) {
      setError(getApiErrorMessage(loadError, "Failed to load firewall rules"));
    } finally {
      setIsLoading(false);
    }
  }, [actionFilter, page, statusFilter]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const openCreateModal = () => {
    setModalMode("create");
    setEditingRule(null);
    setForm(defaultForm);
    setFormError(null);
    setIsModalOpen(true);
  };

  const openEditModal = (rule: FirewallRule) => {
    setModalMode("edit");
    setEditingRule(rule);
    setForm(ruleToFormData(rule));
    setFormError(null);
    setIsModalOpen(true);
  };

  const closeModal = () => {
    setIsModalOpen(false);
    setEditingRule(null);
    setFormError(null);
  };

  const handleSubmit = async () => {
    setIsSubmitting(true);
    setFormError(null);

    try {
      if (modalMode === "create") {
        await createFirewallRule(form);
        setActionMessage(`Rule "${form.name}" created successfully.`);
      } else if (editingRule) {
        await updateFirewallRule(editingRule.id, form);
        setActionMessage(`Rule "${form.name}" updated successfully.`);
      }

      closeModal();
      await loadData();
    } catch (submitError) {
      setFormError(getApiErrorMessage(submitError, "Failed to save firewall rule"));
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleToggle = async (rule: FirewallRule) => {
    setActionMessage(null);

    try {
      await toggleFirewallRule(rule.id, !rule.is_enabled);
      setActionMessage(`Rule "${rule.name}" ${rule.is_enabled ? "disabled" : "enabled"}.`);
      await loadData();
    } catch (toggleError) {
      setError(getApiErrorMessage(toggleError, "Failed to update rule status"));
    }
  };

  const handleDelete = async (rule: FirewallRule) => {
    if (!window.confirm(`Delete rule "${rule.name}"?`)) {
      return;
    }

    setActionMessage(null);

    try {
      await deleteFirewallRule(rule.id);
      setActionMessage(`Rule "${rule.name}" deleted.`);
      await loadData();
    } catch (deleteError) {
      setError(getApiErrorMessage(deleteError, "Failed to delete rule"));
    }
  };

  const columns: Column<FirewallRule>[] = [
    {
      key: "name",
      header: "Rule",
      render: (rule) => (
        <div>
          <p className="font-medium text-white">{rule.name}</p>
          <p className="text-xs text-slate-500">{rule.rule_id}</p>
          {rule.is_automatic ? (
            <span className="mt-1 inline-block text-xs text-sky-400">Automatic</span>
          ) : null}
        </div>
      ),
    },
    {
      key: "action",
      header: "Action",
      render: (rule) => (
        <StatusBadge label={rule.action.replace("_", " ")} variant={actionBadgeVariant(rule.action)} />
      ),
    },
    {
      key: "traffic",
      header: "Match Criteria",
      render: (rule) => (
        <div className="text-xs text-slate-300">
          <p>
            {rule.source_ip || rule.source_country || "Any"} →{" "}
            {rule.destination_ip || rule.destination_country || "Any"}
          </p>
          <p className="text-slate-500">
            {rule.protocol.toUpperCase()}
            {rule.destination_port ? ` :${rule.destination_port}` : ""}
          </p>
        </div>
      ),
    },
    {
      key: "priority",
      header: "Priority",
      render: (rule) => rule.priority,
    },
    {
      key: "status",
      header: "Status",
      render: (rule) => (
        <StatusBadge
          label={rule.is_expired ? "Expired" : rule.is_enabled ? "Enabled" : "Disabled"}
          variant={rule.is_expired ? "warning" : rule.is_enabled ? "success" : "muted"}
        />
      ),
    },
    {
      key: "updated_at",
      header: "Updated",
      render: (rule) => formatDateTime(rule.updated_at),
    },
    {
      key: "actions",
      header: "Actions",
      className: "whitespace-normal",
      render: (rule) => (
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            onClick={() => openEditModal(rule)}
            className="rounded-md border border-slate-700 px-2 py-1 text-xs text-slate-200 transition hover:bg-slate-800"
          >
            Edit
          </button>
          <button
            type="button"
            onClick={() => handleToggle(rule)}
            disabled={rule.is_expired}
            className="rounded-md border border-slate-700 px-2 py-1 text-xs text-slate-200 transition hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-40"
          >
            {rule.is_enabled ? "Disable" : "Enable"}
          </button>
          <button
            type="button"
            onClick={() => handleDelete(rule)}
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
          <h2 className="text-xl font-semibold text-white">Firewall Rules</h2>
          <p className="mt-1 text-sm text-slate-400">
            Create, update, and manage network access control policies
          </p>
        </div>

        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            onClick={openCreateModal}
            className="rounded-lg bg-primary-500 px-4 py-2 text-sm font-medium text-white transition hover:bg-primary-600"
          >
            Create Rule
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

      {stats ? <FirewallStatsCards stats={stats} /> : null}

      <div className="flex flex-wrap gap-2">
        <select
          value={actionFilter}
          onChange={(event) => {
            setActionFilter(event.target.value as FirewallRuleAction | "");
            setPage(1);
          }}
          className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
        >
          <option value="">All actions</option>
          <option value="allow">Allow</option>
          <option value="block">Block</option>
          <option value="whitelist">Whitelist</option>
          <option value="blacklist">Blacklist</option>
          <option value="temporary_block">Temporary Block</option>
        </select>

        <select
          value={statusFilter}
          onChange={(event) => {
            setStatusFilter(event.target.value as StatusFilter);
            setPage(1);
          }}
          className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
        >
          <option value="">All statuses</option>
          <option value="enabled">Enabled</option>
          <option value="disabled">Disabled</option>
          <option value="expired">Expired</option>
        </select>
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
        data={rules}
        rowKey={(rule) => rule.id}
        isLoading={isLoading}
        emptyMessage="No firewall rules found. Create your first rule to get started."
      />

      {pagination ? <Pagination pagination={pagination} onPageChange={setPage} /> : null}

      <FirewallRuleFormModal
        isOpen={isModalOpen}
        mode={modalMode}
        form={form}
        isSubmitting={isSubmitting}
        error={formError}
        onChange={setForm}
        onClose={closeModal}
        onSubmit={handleSubmit}
      />
    </div>
  );
}
