import { useCallback, useEffect, useState } from "react";
import DataTable, { type Column } from "@/components/admin/DataTable";
import Pagination from "@/components/admin/Pagination";
import StatusBadge, { actionBadgeVariant } from "@/components/admin/StatusBadge";
import { getApiErrorMessage } from "@/services/apiClient";
import { deleteFirewallRule, fetchFirewallRules, toggleFirewallRule } from "@/services/adminService";
import type { FirewallRule, FirewallRuleAction, PaginationMeta } from "@/types/admin";
import { formatDateTime } from "@/utils";

export default function RulesPanel() {
  const [rules, setRules] = useState<FirewallRule[]>([]);
  const [pagination, setPagination] = useState<PaginationMeta | null>(null);
  const [page, setPage] = useState(1);
  const [actionFilter, setActionFilter] = useState<FirewallRuleAction | "">("");
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionMessage, setActionMessage] = useState<string | null>(null);

  const loadRules = useCallback(async () => {
    setIsLoading(true);
    setError(null);

    try {
      const response = await fetchFirewallRules({
        page,
        page_size: 10,
        action: actionFilter || undefined,
      });

      setRules(response.items);
      setPagination(response.pagination);
    } catch (loadError) {
      setError(getApiErrorMessage(loadError, "Failed to load firewall rules"));
    } finally {
      setIsLoading(false);
    }
  }, [actionFilter, page]);

  useEffect(() => {
    loadRules();
  }, [loadRules]);

  const handleToggle = async (rule: FirewallRule) => {
    setActionMessage(null);

    try {
      await toggleFirewallRule(rule.id, !rule.is_enabled);
      setActionMessage(`Rule "${rule.name}" ${rule.is_enabled ? "disabled" : "enabled"}.`);
      await loadRules();
    } catch (toggleError) {
      setError(getApiErrorMessage(toggleError, "Failed to update rule"));
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
      await loadRules();
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
        </div>
      ),
    },
    {
      key: "action",
      header: "Action",
      render: (rule) => (
        <StatusBadge
          label={rule.action.replace("_", " ")}
          variant={actionBadgeVariant(rule.action)}
        />
      ),
    },
    {
      key: "traffic",
      header: "Traffic",
      render: (rule) => (
        <div className="text-xs text-slate-300">
          <p>{rule.source_ip || "Any"} → {rule.destination_ip || "Any"}</p>
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
      key: "created_at",
      header: "Created",
      render: (rule) => formatDateTime(rule.created_at),
    },
    {
      key: "actions",
      header: "Actions",
      render: (rule) => (
        <div className="flex gap-2">
          <button
            type="button"
            onClick={() => handleToggle(rule)}
            className="rounded-md border border-slate-700 px-2 py-1 text-xs text-slate-200 transition hover:bg-slate-800"
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
    <div className="space-y-4">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h3 className="text-lg font-semibold text-white">Firewall Rules</h3>
          <p className="text-sm text-slate-400">Manage allow, block, whitelist, and blacklist policies</p>
        </div>

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
          <button
            type="button"
            onClick={loadRules}
            className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200 transition hover:bg-slate-800"
          >
            Refresh
          </button>
        </div>
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
        emptyMessage="No firewall rules found."
      />

      {pagination ? (
        <Pagination pagination={pagination} onPageChange={setPage} />
      ) : null}
    </div>
  );
}
