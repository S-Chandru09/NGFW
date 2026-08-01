import type { IncidentFormData } from "@/types/incident";

interface IncidentFormModalProps {
  isOpen: boolean;
  form: IncidentFormData;
  isSubmitting: boolean;
  error: string | null;
  onChange: (form: IncidentFormData) => void;
  onClose: () => void;
  onSubmit: () => void;
}

const inputClassName =
  "w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200 placeholder:text-slate-500 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500";

export default function IncidentFormModal({
  isOpen,
  form,
  isSubmitting,
  error,
  onChange,
  onClose,
  onSubmit,
}: IncidentFormModalProps) {
  if (!isOpen) {
    return null;
  }

  const updateField = <K extends keyof IncidentFormData>(field: K, value: IncidentFormData[K]) => {
    onChange({ ...form, [field]: value });
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 p-4">
      <div className="w-full max-w-lg rounded-2xl border border-slate-800 bg-slate-900 p-6 shadow-2xl">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h3 className="text-lg font-semibold text-white">Create Incident</h3>
            <p className="mt-1 text-sm text-slate-400">Open a new security incident for investigation</p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg border border-slate-700 px-3 py-1.5 text-sm text-slate-300 transition hover:bg-slate-800"
          >
            Close
          </button>
        </div>

        <div className="mt-5 space-y-4">
          <div>
            <label className="mb-1.5 block text-xs font-medium text-slate-400">Title</label>
            <input
              type="text"
              value={form.title}
              onChange={(event) => updateField("title", event.target.value)}
              placeholder="e.g. Brute force attack detected"
              className={inputClassName}
            />
          </div>

          <div>
            <label className="mb-1.5 block text-xs font-medium text-slate-400">Description</label>
            <textarea
              value={form.description}
              onChange={(event) => updateField("description", event.target.value)}
              rows={4}
              placeholder="Describe the incident..."
              className={inputClassName}
            />
          </div>

          <div className="grid gap-4 sm:grid-cols-2">
            <div>
              <label className="mb-1.5 block text-xs font-medium text-slate-400">Severity</label>
              <select
                value={form.severity}
                onChange={(event) =>
                  updateField("severity", event.target.value as IncidentFormData["severity"])
                }
                className={inputClassName}
              >
                <option value="info">Info</option>
                <option value="warning">Warning</option>
                <option value="error">Error</option>
                <option value="critical">Critical</option>
              </select>
            </div>
            <div>
              <label className="mb-1.5 block text-xs font-medium text-slate-400">Threat Type</label>
              <input
                type="text"
                value={form.threat_type}
                onChange={(event) => updateField("threat_type", event.target.value)}
                placeholder="e.g. brute_force"
                className={inputClassName}
              />
            </div>
          </div>

          <div className="grid gap-4 sm:grid-cols-2">
            <div>
              <label className="mb-1.5 block text-xs font-medium text-slate-400">Source IP</label>
              <input
                type="text"
                value={form.source_ip}
                onChange={(event) => updateField("source_ip", event.target.value)}
                placeholder="203.0.113.50"
                className={inputClassName}
              />
            </div>
            <div>
              <label className="mb-1.5 block text-xs font-medium text-slate-400">Destination IP</label>
              <input
                type="text"
                value={form.destination_ip}
                onChange={(event) => updateField("destination_ip", event.target.value)}
                placeholder="10.0.0.1"
                className={inputClassName}
              />
            </div>
          </div>
        </div>

        {error ? (
          <p className="mt-4 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-200">
            {error}
          </p>
        ) : null}

        <div className="mt-6 flex justify-end gap-3">
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-300 transition hover:bg-slate-800"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={onSubmit}
            disabled={isSubmitting}
            className="rounded-lg bg-primary-500 px-4 py-2 text-sm font-medium text-white transition hover:bg-primary-400 disabled:opacity-50"
          >
            {isSubmitting ? "Creating..." : "Create Incident"}
          </button>
        </div>
      </div>
    </div>
  );
}
