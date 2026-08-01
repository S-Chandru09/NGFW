import type { FirewallRuleFormData } from "@/types/firewall";
import { cn } from "@/utils";

interface FirewallRuleFormModalProps {
  isOpen: boolean;
  mode: "create" | "edit";
  form: FirewallRuleFormData;
  isSubmitting: boolean;
  error: string | null;
  onChange: (form: FirewallRuleFormData) => void;
  onClose: () => void;
  onSubmit: () => void;
}

const inputClassName =
  "w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200 placeholder:text-slate-500 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500";

export default function FirewallRuleFormModal({
  isOpen,
  mode,
  form,
  isSubmitting,
  error,
  onChange,
  onClose,
  onSubmit,
}: FirewallRuleFormModalProps) {
  if (!isOpen) {
    return null;
  }

  const updateField = <K extends keyof FirewallRuleFormData>(
    field: K,
    value: FirewallRuleFormData[K],
  ) => {
    onChange({ ...form, [field]: value });
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 p-4">
      <div className="max-h-[90vh] w-full max-w-2xl overflow-y-auto rounded-2xl border border-slate-800 bg-slate-900 p-6 shadow-2xl">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h3 className="text-lg font-semibold text-white">
              {mode === "create" ? "Create Firewall Rule" : "Edit Firewall Rule"}
            </h3>
            <p className="mt-1 text-sm text-slate-400">
              Configure traffic matching criteria and enforcement action
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
            <label className="mb-1 block text-xs font-medium text-slate-400">Rule Name</label>
            <input
              type="text"
              value={form.name}
              onChange={(event) => updateField("name", event.target.value)}
              className={inputClassName}
              required
              minLength={3}
              maxLength={100}
            />
          </div>

          <div className="sm:col-span-2">
            <label className="mb-1 block text-xs font-medium text-slate-400">Description</label>
            <textarea
              value={form.description}
              onChange={(event) => updateField("description", event.target.value)}
              className={cn(inputClassName, "min-h-[80px]")}
              maxLength={500}
            />
          </div>

          <div>
            <label className="mb-1 block text-xs font-medium text-slate-400">Action</label>
            <select
              value={form.action}
              onChange={(event) =>
                updateField("action", event.target.value as FirewallRuleFormData["action"])
              }
              className={inputClassName}
            >
              <option value="allow">Allow</option>
              <option value="block">Block</option>
              <option value="whitelist">Whitelist</option>
              <option value="blacklist">Blacklist</option>
              <option value="temporary_block">Temporary Block</option>
            </select>
          </div>

          <div>
            <label className="mb-1 block text-xs font-medium text-slate-400">Protocol</label>
            <select
              value={form.protocol}
              onChange={(event) =>
                updateField("protocol", event.target.value as FirewallRuleFormData["protocol"])
              }
              className={inputClassName}
            >
              <option value="any">Any</option>
              <option value="tcp">TCP</option>
              <option value="udp">UDP</option>
              <option value="icmp">ICMP</option>
            </select>
          </div>

          <div>
            <label className="mb-1 block text-xs font-medium text-slate-400">Source IP / CIDR</label>
            <input
              type="text"
              value={form.source_ip}
              onChange={(event) => updateField("source_ip", event.target.value)}
              placeholder="Any"
              className={inputClassName}
            />
          </div>

          <div>
            <label className="mb-1 block text-xs font-medium text-slate-400">Destination IP / CIDR</label>
            <input
              type="text"
              value={form.destination_ip}
              onChange={(event) => updateField("destination_ip", event.target.value)}
              placeholder="Any"
              className={inputClassName}
            />
          </div>

          <div>
            <label className="mb-1 block text-xs font-medium text-slate-400">Source Port</label>
            <input
              type="number"
              value={form.source_port}
              onChange={(event) => updateField("source_port", event.target.value)}
              min={1}
              max={65535}
              className={inputClassName}
            />
          </div>

          <div>
            <label className="mb-1 block text-xs font-medium text-slate-400">Destination Port</label>
            <input
              type="number"
              value={form.destination_port}
              onChange={(event) => updateField("destination_port", event.target.value)}
              min={1}
              max={65535}
              className={inputClassName}
            />
          </div>

          <div>
            <label className="mb-1 block text-xs font-medium text-slate-400">Source Country</label>
            <input
              type="text"
              value={form.source_country}
              onChange={(event) => updateField("source_country", event.target.value.toUpperCase())}
              placeholder="e.g. US"
              maxLength={2}
              className={inputClassName}
            />
          </div>

          <div>
            <label className="mb-1 block text-xs font-medium text-slate-400">Destination Country</label>
            <input
              type="text"
              value={form.destination_country}
              onChange={(event) => updateField("destination_country", event.target.value.toUpperCase())}
              placeholder="e.g. IN"
              maxLength={2}
              className={inputClassName}
            />
          </div>

          <div>
            <label className="mb-1 block text-xs font-medium text-slate-400">Priority</label>
            <input
              type="number"
              value={form.priority}
              onChange={(event) => updateField("priority", Number(event.target.value))}
              min={1}
              max={1000}
              className={inputClassName}
              required
            />
          </div>

          {form.action === "temporary_block" ? (
            <div>
              <label className="mb-1 block text-xs font-medium text-slate-400">Expires At</label>
              <input
                type="datetime-local"
                value={form.expires_at}
                onChange={(event) => updateField("expires_at", event.target.value)}
                className={inputClassName}
                required
              />
            </div>
          ) : null}

          <div className="flex items-center gap-3 sm:col-span-2">
            <input
              id="rule-enabled"
              type="checkbox"
              checked={form.is_enabled}
              onChange={(event) => updateField("is_enabled", event.target.checked)}
              className="h-4 w-4 rounded border-slate-600 bg-slate-950 text-primary-500 focus:ring-primary-500"
            />
            <label htmlFor="rule-enabled" className="text-sm text-slate-300">
              Enable rule immediately
            </label>
          </div>

          <div className="flex justify-end gap-3 sm:col-span-2">
            <button
              type="button"
              onClick={onClose}
              className="rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-200 transition hover:bg-slate-800"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isSubmitting}
              className="rounded-lg bg-primary-500 px-4 py-2 text-sm font-medium text-white transition hover:bg-primary-600 disabled:cursor-not-allowed disabled:opacity-60"
            >
              {isSubmitting ? "Saving..." : mode === "create" ? "Create Rule" : "Save Changes"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
