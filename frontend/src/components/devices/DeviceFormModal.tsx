import type { UserListItem } from "@/types/admin";
import type { DeviceFormData, DeviceType } from "@/types/device";
import { DEVICE_TYPES } from "@/types/device";
import { cn } from "@/utils";

interface DeviceFormModalProps {
  isOpen: boolean;
  mode: "create" | "edit";
  form: DeviceFormData;
  users: UserListItem[];
  isSubmitting: boolean;
  error: string | null;
  onChange: (form: DeviceFormData) => void;
  onClose: () => void;
  onSubmit: () => void;
}

const inputClassName =
  "w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200 placeholder:text-slate-500 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500";

export default function DeviceFormModal({
  isOpen,
  mode,
  form,
  users,
  isSubmitting,
  error,
  onChange,
  onClose,
  onSubmit,
}: DeviceFormModalProps) {
  if (!isOpen) {
    return null;
  }

  const updateField = <K extends keyof DeviceFormData>(field: K, value: DeviceFormData[K]) => {
    onChange({ ...form, [field]: value });
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 p-4">
      <div className="max-h-[90vh] w-full max-w-xl overflow-y-auto rounded-2xl border border-slate-800 bg-slate-900 p-6 shadow-2xl">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h3 className="text-lg font-semibold text-white">
              {mode === "create" ? "Add Device" : "Edit Device"}
            </h3>
            <p className="mt-1 text-sm text-slate-400">
              {mode === "create"
                ? "Register a device in inventory. Trust score and trusted status are assigned by the backend."
                : "Update inventory fields. Trust score and trusted status cannot be changed here."}
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg border border-slate-700 px-3 py-1.5 text-sm text-slate-300 transition hover:bg-slate-800"
          >
            Close
          </button>
        </div>

        {error ? (
          <div className="mt-4 rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-200">
            {error}
          </div>
        ) : null}

        <form
          className="mt-6 grid gap-4 sm:grid-cols-2"
          onSubmit={(event) => {
            event.preventDefault();
            onSubmit();
          }}
        >
          <div className="sm:col-span-2">
            <label className="mb-1 block text-xs font-medium text-slate-400">Device name</label>
            <input
              type="text"
              value={form.device_name}
              onChange={(event) => updateField("device_name", event.target.value)}
              className={inputClassName}
              required
              minLength={2}
              maxLength={100}
            />
          </div>

          <div>
            <label className="mb-1 block text-xs font-medium text-slate-400">Device type</label>
            <select
              value={form.device_type}
              onChange={(event) => updateField("device_type", event.target.value as DeviceType)}
              className={inputClassName}
            >
              {DEVICE_TYPES.map((type) => (
                <option key={type} value={type}>
                  {type}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="mb-1 block text-xs font-medium text-slate-400">OS</label>
            <input
              type="text"
              value={form.os_type}
              onChange={(event) => updateField("os_type", event.target.value)}
              className={inputClassName}
              maxLength={50}
              placeholder="e.g. Windows"
            />
          </div>

          <div>
            <label className="mb-1 block text-xs font-medium text-slate-400">IP address</label>
            <input
              type="text"
              value={form.ip_address}
              onChange={(event) => updateField("ip_address", event.target.value)}
              className={inputClassName}
              maxLength={45}
              placeholder="IPv4 or IPv6"
            />
          </div>

          <div>
            <label className="mb-1 block text-xs font-medium text-slate-400">Linked user</label>
            <select
              value={form.user_id}
              onChange={(event) => updateField("user_id", event.target.value)}
              className={inputClassName}
            >
              <option value="">Unassigned</option>
              {users.map((user) => (
                <option key={user.id} value={user.id}>
                  {user.username} ({user.email})
                </option>
              ))}
            </select>
          </div>

          {mode === "edit" ? (
            <div className="sm:col-span-2">
              <label className="flex items-center gap-2 text-sm text-slate-300">
                <input
                  type="checkbox"
                  checked={form.is_compliant}
                  onChange={(event) => updateField("is_compliant", event.target.checked)}
                  className="h-4 w-4 rounded border-slate-600 bg-slate-950 text-primary-500"
                />
                Device is compliant
              </label>
            </div>
          ) : null}

          <div className="sm:col-span-2 flex justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-300 transition hover:bg-slate-800"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isSubmitting}
              className={cn(
                "rounded-lg bg-primary-500 px-4 py-2 text-sm font-medium text-white transition hover:bg-primary-600",
                isSubmitting && "cursor-not-allowed opacity-60",
              )}
            >
              {isSubmitting ? "Saving..." : mode === "create" ? "Add device" : "Save changes"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
