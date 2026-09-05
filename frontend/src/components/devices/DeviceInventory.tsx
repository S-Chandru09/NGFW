import { useCallback, useEffect, useMemo, useState } from "react";
import DataTable, { type Column } from "@/components/admin/DataTable";
import Pagination from "@/components/admin/Pagination";
import StatusBadge from "@/components/admin/StatusBadge";
import DeviceFormModal from "@/components/devices/DeviceFormModal";
import { useAuth } from "@/hooks/useAuth";
import { fetchUsers } from "@/services/adminService";
import { ApiError, getApiErrorMessage } from "@/services/apiClient";
import { createDevice, deleteDevice, fetchDevices, updateDevice } from "@/services/deviceService";
import type { PaginationMeta, UserListItem } from "@/types/admin";
import type {
  Device,
  DeviceFormData,
  DeviceSortField,
  DeviceSortOrder,
  DeviceType,
} from "@/types/device";
import {
  DEVICE_SORT_FIELDS,
  DEVICE_TYPES,
  EMPTY_DEVICE_FORM,
  buildDeviceCreatePayload,
  buildDeviceUpdatePayload,
  deviceToFormData,
} from "@/types/device";
import { formatDateTime } from "@/utils";
import { isValidOptionalIpAddress } from "@/utils/ipAddress";

function formatPermissionError(error: unknown, fallback: string): string {
  if (error instanceof ApiError && error.code === "UNAUTHORIZED") {
    return "Your session expired. Please sign in again.";
  }

  if (error instanceof ApiError && error.code === "FORBIDDEN") {
    return "You do not have permission to perform this action.";
  }

  return getApiErrorMessage(error, fallback);
}

export default function DeviceInventory() {
  const { user } = useAuth();
  const canWrite = user?.role === "admin";

  const [devices, setDevices] = useState<Device[]>([]);
  const [users, setUsers] = useState<UserListItem[]>([]);
  const [pagination, setPagination] = useState<PaginationMeta | null>(null);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const [deviceTypeFilter, setDeviceTypeFilter] = useState<DeviceType | "">("");
  const [userFilter, setUserFilter] = useState("");
  const [ipDraft, setIpDraft] = useState("");
  const [ipFilter, setIpFilter] = useState("");
  const [sortBy, setSortBy] = useState<DeviceSortField>("created_at");
  const [sortOrder, setSortOrder] = useState<DeviceSortOrder>("desc");
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionMessage, setActionMessage] = useState<string | null>(null);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [modalMode, setModalMode] = useState<"create" | "edit">("create");
  const [editingDevice, setEditingDevice] = useState<Device | null>(null);
  const [form, setForm] = useState<DeviceFormData>(EMPTY_DEVICE_FORM);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  const usersById = useMemo(() => {
    return new Map(users.map((item) => [item.id, item]));
  }, [users]);

  const loadUsers = useCallback(async () => {
    try {
      const response = await fetchUsers({ page: 1, page_size: 100 });
      setUsers(response.items);
    } catch {
      setUsers([]);
    }
  }, []);

  const loadDevices = useCallback(async () => {
    setIsLoading(true);
    setError(null);

    try {
      const response = await fetchDevices({
        page,
        page_size: pageSize,
        user_id: userFilter || undefined,
        device_type: deviceTypeFilter || undefined,
        ip_address: ipFilter || undefined,
        sort_by: sortBy,
        sort_order: sortOrder,
      });

      setDevices(response.items);
      setPagination(response.pagination);
    } catch (loadError) {
      setDevices([]);
      setPagination(null);
      setError(formatPermissionError(loadError, "Failed to load devices"));
    } finally {
      setIsLoading(false);
    }
  }, [deviceTypeFilter, ipFilter, page, pageSize, sortBy, sortOrder, userFilter]);

  useEffect(() => {
    loadUsers();
  }, [loadUsers]);

  useEffect(() => {
    loadDevices();
  }, [loadDevices]);

  const applyIpFilter = () => {
    const nextIp = ipDraft.trim();
    if (!isValidOptionalIpAddress(nextIp)) {
      setError("Enter a valid IPv4 or IPv6 address to filter, or leave IP blank.");
      return;
    }

    setError(null);
    setPage(1);
    setIpFilter(nextIp);
  };

  const openCreateModal = () => {
    if (!canWrite) {
      return;
    }

    setModalMode("create");
    setEditingDevice(null);
    setForm(EMPTY_DEVICE_FORM);
    setFormError(null);
    setIsModalOpen(true);
  };

  const openEditModal = (device: Device) => {
    if (!canWrite) {
      return;
    }

    setModalMode("edit");
    setEditingDevice(device);
    setForm(deviceToFormData(device));
    setFormError(null);
    setIsModalOpen(true);
  };

  const closeModal = () => {
    setIsModalOpen(false);
    setEditingDevice(null);
    setFormError(null);
  };

  const handleSubmit = async () => {
    if (!canWrite) {
      setFormError("You do not have permission to perform this action.");
      return;
    }

    if (form.device_name.trim().length < 2) {
      setFormError("Device name must be at least 2 characters.");
      return;
    }

    if (!isValidOptionalIpAddress(form.ip_address)) {
      setFormError("Enter a valid IPv4 or IPv6 address, or leave IP blank.");
      return;
    }

    setIsSubmitting(true);
    setFormError(null);

    try {
      if (modalMode === "create") {
        const response = await createDevice(buildDeviceCreatePayload(form));
        setActionMessage(response.message || `Device "${form.device_name}" created.`);
      } else if (editingDevice) {
        const response = await updateDevice(
          editingDevice.device_id,
          buildDeviceUpdatePayload(form),
        );
        setActionMessage(response.message || `Device "${form.device_name}" updated.`);
      }

      closeModal();
      await loadDevices();
    } catch (submitError) {
      setFormError(formatPermissionError(submitError, "Failed to save device"));
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleDelete = async (device: Device) => {
    if (!canWrite) {
      return;
    }

    const confirmed = window.confirm(
      `Delete device "${device.device_name}"?\n\nThis removes the device inventory record only. Network flows, threat alerts, and trust scores are not deleted.`,
    );

    if (!confirmed) {
      return;
    }

    setActionMessage(null);

    try {
      const response = await deleteDevice(device.device_id);
      setActionMessage(response.message || `Device "${device.device_name}" deleted.`);
      await loadDevices();
    } catch (deleteError) {
      setError(formatPermissionError(deleteError, "Failed to delete device"));
    }
  };

  const columns: Column<Device>[] = [
    {
      key: "device_name",
      header: "Device",
      render: (device) => (
        <div>
          <p className="font-medium text-white">{device.device_name}</p>
          <p className="text-xs text-slate-500">{device.device_id}</p>
        </div>
      ),
    },
    {
      key: "device_type",
      header: "Type",
      render: (device) => <span className="capitalize">{device.device_type}</span>,
    },
    {
      key: "os_type",
      header: "OS",
      render: (device) => device.os_type || "—",
    },
    {
      key: "ip_address",
      header: "IP address",
      render: (device) => device.ip_address || "—",
    },
    {
      key: "user_id",
      header: "Linked user",
      render: (device) => {
        if (!device.user_id) {
          return <span className="text-slate-500">Unassigned</span>;
        }

        const linkedUser = usersById.get(device.user_id);
        if (!linkedUser) {
          return <span className="text-xs text-slate-500">{device.user_id}</span>;
        }

        return (
          <div>
            <p className="text-sm text-slate-200">{linkedUser.username}</p>
            <p className="text-xs text-slate-500">{linkedUser.email}</p>
          </div>
        );
      },
    },
    {
      key: "trust_score",
      header: "Trust score",
      render: (device) => device.trust_score.toFixed(2),
    },
    {
      key: "is_trusted",
      header: "Trusted",
      render: (device) => (
        <StatusBadge
          label={device.is_trusted ? "Trusted" : "Untrusted"}
          variant={device.is_trusted ? "success" : "warning"}
        />
      ),
    },
    {
      key: "is_compliant",
      header: "Compliance",
      render: (device) => (
        <StatusBadge
          label={device.is_compliant ? "Compliant" : "Non-compliant"}
          variant={device.is_compliant ? "success" : "danger"}
        />
      ),
    },
    {
      key: "last_seen_at",
      header: "Last seen",
      render: (device) => (device.last_seen_at ? formatDateTime(device.last_seen_at) : "Never"),
    },
    {
      key: "created_at",
      header: "Created",
      render: (device) => formatDateTime(device.created_at),
    },
  ];

  if (canWrite) {
    columns.push({
      key: "actions",
      header: "Actions",
      className: "whitespace-normal",
      render: (device) => (
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            onClick={() => openEditModal(device)}
            className="rounded-md border border-slate-700 px-2 py-1 text-xs text-slate-200 transition hover:bg-slate-800"
          >
            Edit
          </button>
          <button
            type="button"
            onClick={() => handleDelete(device)}
            className="rounded-md border border-red-500/30 px-2 py-1 text-xs text-red-300 transition hover:bg-red-500/10"
          >
            Delete
          </button>
        </div>
      ),
    });
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h2 className="text-xl font-semibold text-white">Device Inventory</h2>
          <p className="mt-1 text-sm text-slate-400">
            Registered endpoints used for Zero Trust identity and firewall attribution
          </p>
        </div>

        <div className="flex flex-wrap gap-2">
          {canWrite ? (
            <button
              type="button"
              onClick={openCreateModal}
              className="rounded-lg bg-primary-500 px-4 py-2 text-sm font-medium text-white transition hover:bg-primary-600"
            >
              Add device
            </button>
          ) : null}
          <button
            type="button"
            onClick={loadDevices}
            className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200 transition hover:bg-slate-800"
          >
            Refresh
          </button>
        </div>
      </div>

      <div className="flex flex-wrap gap-2">
        <select
          value={deviceTypeFilter}
          onChange={(event) => {
            setDeviceTypeFilter(event.target.value as DeviceType | "");
            setPage(1);
          }}
          className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
        >
          <option value="">All types</option>
          {DEVICE_TYPES.map((type) => (
            <option key={type} value={type}>
              {type}
            </option>
          ))}
        </select>

        <select
          value={userFilter}
          onChange={(event) => {
            setUserFilter(event.target.value);
            setPage(1);
          }}
          className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
        >
          <option value="">All users</option>
          {users.map((item) => (
            <option key={item.id} value={item.id}>
              {item.username} ({item.email})
            </option>
          ))}
        </select>

        <input
          type="search"
          value={ipDraft}
          onChange={(event) => setIpDraft(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === "Enter") {
              event.preventDefault();
              applyIpFilter();
            }
          }}
          placeholder="Filter by IP address"
          className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200 placeholder:text-slate-500 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
        />
        <button
          type="button"
          onClick={applyIpFilter}
          className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200 transition hover:bg-slate-800"
        >
          Apply IP
        </button>

        <select
          value={sortBy}
          onChange={(event) => {
            setSortBy(event.target.value as DeviceSortField);
            setPage(1);
          }}
          className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
        >
          {DEVICE_SORT_FIELDS.map((field) => (
            <option key={field} value={field}>
              Sort: {field.replace(/_/g, " ")}
            </option>
          ))}
        </select>

        <select
          value={sortOrder}
          onChange={(event) => {
            setSortOrder(event.target.value as DeviceSortOrder);
            setPage(1);
          }}
          className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
        >
          <option value="desc">Descending</option>
          <option value="asc">Ascending</option>
        </select>

        <select
          value={pageSize}
          onChange={(event) => {
            setPageSize(Number(event.target.value));
            setPage(1);
          }}
          className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
        >
          <option value={10}>10 / page</option>
          <option value={20}>20 / page</option>
          <option value={50}>50 / page</option>
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
        data={devices}
        rowKey={(device) => device.device_id}
        isLoading={isLoading}
        emptyMessage="No devices found."
      />

      {pagination ? <Pagination pagination={pagination} onPageChange={setPage} /> : null}

      {canWrite ? (
        <DeviceFormModal
          isOpen={isModalOpen}
          mode={modalMode}
          form={form}
          users={users}
          isSubmitting={isSubmitting}
          error={formError}
          onChange={setForm}
          onClose={closeModal}
          onSubmit={handleSubmit}
        />
      ) : null}
    </div>
  );
}
