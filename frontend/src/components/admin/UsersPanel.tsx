import { useCallback, useEffect, useState } from "react";
import DataTable, { type Column } from "@/components/admin/DataTable";
import Pagination from "@/components/admin/Pagination";
import StatusBadge, { roleBadgeVariant } from "@/components/admin/StatusBadge";
import { getApiErrorMessage } from "@/services/apiClient";
import { fetchUsers } from "@/services/adminService";
import type { PaginationMeta, UserListItem } from "@/types/admin";
import { formatDateTime } from "@/utils";

export default function UsersPanel() {
  const [users, setUsers] = useState<UserListItem[]>([]);
  const [pagination, setPagination] = useState<PaginationMeta | null>(null);
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState("");
  const [roleFilter, setRoleFilter] = useState("");
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadUsers = useCallback(async () => {
    setIsLoading(true);
    setError(null);

    try {
      const response = await fetchUsers({
        page,
        page_size: 10,
        search: search || undefined,
        role: roleFilter || undefined,
      });

      setUsers(response.items);
      setPagination(response.pagination);
    } catch (loadError) {
      setError(getApiErrorMessage(loadError, "Failed to load users"));
    } finally {
      setIsLoading(false);
    }
  }, [page, roleFilter, search]);

  useEffect(() => {
    loadUsers();
  }, [loadUsers]);

  const columns: Column<UserListItem>[] = [
    {
      key: "username",
      header: "User",
      render: (user) => (
        <div>
          <p className="font-medium text-white">{user.username}</p>
          <p className="text-xs text-slate-500">{user.email}</p>
        </div>
      ),
    },
    {
      key: "full_name",
      header: "Full Name",
      render: (user) => user.full_name,
    },
    {
      key: "role",
      header: "Role",
      render: (user) => (
        <StatusBadge label={user.role} variant={roleBadgeVariant(user.role)} />
      ),
    },
    {
      key: "status",
      header: "Status",
      render: (user) => (
        <StatusBadge
          label={user.is_active ? "Active" : "Inactive"}
          variant={user.is_active ? "success" : "muted"}
        />
      ),
    },
    {
      key: "last_login",
      header: "Last Login",
      render: (user) =>
        user.last_login_at ? formatDateTime(user.last_login_at) : "Never",
    },
    {
      key: "created_at",
      header: "Created",
      render: (user) => formatDateTime(user.created_at),
    },
  ];

  return (
    <div className="space-y-4">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h3 className="text-lg font-semibold text-white">User Management</h3>
          <p className="text-sm text-slate-400">View and manage platform users and roles</p>
        </div>

        <div className="flex flex-wrap gap-2">
          <input
            type="search"
            value={search}
            onChange={(event) => {
              setSearch(event.target.value);
              setPage(1);
            }}
            placeholder="Search users..."
            className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200 placeholder:text-slate-500 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
          />
          <select
            value={roleFilter}
            onChange={(event) => {
              setRoleFilter(event.target.value);
              setPage(1);
            }}
            className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
          >
            <option value="">All roles</option>
            <option value="admin">Admin</option>
            <option value="analyst">Analyst</option>
            <option value="viewer">Viewer</option>
          </select>
          <button
            type="button"
            onClick={loadUsers}
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

      <DataTable
        columns={columns}
        data={users}
        rowKey={(user) => user.id}
        isLoading={isLoading}
        emptyMessage="No users found."
      />

      {pagination ? (
        <Pagination pagination={pagination} onPageChange={setPage} />
      ) : null}
    </div>
  );
}
