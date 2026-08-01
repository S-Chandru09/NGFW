import type { IOCFormData, IOCDatabaseTab } from "@/types/ioc";
import { cn } from "@/utils";

interface IOCFormModalProps {
  isOpen: boolean;
  type: IOCDatabaseTab;
  form: IOCFormData;
  isSubmitting: boolean;
  error: string | null;
  onChange: (form: IOCFormData) => void;
  onClose: () => void;
  onSubmit: () => void;
}

const inputClassName =
  "w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200 placeholder:text-slate-500 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500";

const typeLabels: Record<IOCDatabaseTab, string> = {
  ip: "IP Address",
  domain: "Domain",
  hash: "File Hash",
};

const typePlaceholders: Record<IOCDatabaseTab, string> = {
  ip: "e.g. 192.168.1.100",
  domain: "e.g. malicious.example.com",
  hash: "MD5, SHA1, or SHA256 hash",
};

export default function IOCFormModal({
  isOpen,
  type,
  form,
  isSubmitting,
  error,
  onChange,
  onClose,
  onSubmit,
}: IOCFormModalProps) {
  if (!isOpen) {
    return null;
  }

  const updateField = <K extends keyof IOCFormData>(field: K, value: IOCFormData[K]) => {
    onChange({ ...form, [field]: value });
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 p-4">
      <div className="w-full max-w-lg rounded-2xl border border-slate-800 bg-slate-900 p-6 shadow-2xl">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h3 className="text-lg font-semibold text-white">Add {typeLabels[type]} IOC</h3>
            <p className="mt-1 text-sm text-slate-400">Store indicator in MongoDB IOC database</p>
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
          className="mt-6 space-y-4"
          onSubmit={(event) => {
            event.preventDefault();
            onSubmit();
          }}
        >
          <div>
            <label className="mb-1 block text-xs font-medium text-slate-400">{typeLabels[type]}</label>
            <input
              type="text"
              value={form.value}
              onChange={(event) => updateField("value", event.target.value)}
              placeholder={typePlaceholders[type]}
              className={inputClassName}
              required
            />
          </div>

          <div className="grid gap-4 sm:grid-cols-2">
            <div>
              <label className="mb-1 block text-xs font-medium text-slate-400">Reputation Score</label>
              <input
                type="number"
                min={0}
                max={100}
                value={form.reputation_score}
                onChange={(event) => updateField("reputation_score", Number(event.target.value))}
                className={inputClassName}
                required
              />
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium text-slate-400">Source</label>
              <input
                type="text"
                value={form.source}
                onChange={(event) => updateField("source", event.target.value)}
                className={inputClassName}
                required
              />
            </div>
          </div>

          {type === "ip" ? (
            <div>
              <label className="mb-1 block text-xs font-medium text-slate-400">Country</label>
              <input
                type="text"
                value={form.country}
                onChange={(event) => updateField("country", event.target.value)}
                placeholder="e.g. US"
                className={inputClassName}
              />
            </div>
          ) : null}

          <div>
            <label className="mb-1 block text-xs font-medium text-slate-400">Description</label>
            <textarea
              value={form.description}
              onChange={(event) => updateField("description", event.target.value)}
              className={cn(inputClassName, "min-h-[80px]")}
            />
          </div>

          <div>
            <label className="mb-1 block text-xs font-medium text-slate-400">Tags (comma-separated)</label>
            <input
              type="text"
              value={form.tags}
              onChange={(event) => updateField("tags", event.target.value)}
              placeholder="malware, c2, phishing"
              className={inputClassName}
            />
          </div>

          <div className="flex flex-wrap gap-4">
            <label className="flex items-center gap-2 text-sm text-slate-300">
              <input
                type="checkbox"
                checked={form.is_malicious}
                onChange={(event) => updateField("is_malicious", event.target.checked)}
                className="h-4 w-4 rounded border-slate-600 bg-slate-950 text-primary-500"
              />
              Malicious
            </label>
            <label className="flex items-center gap-2 text-sm text-slate-300">
              <input
                type="checkbox"
                checked={form.is_active}
                onChange={(event) => updateField("is_active", event.target.checked)}
                className="h-4 w-4 rounded border-slate-600 bg-slate-950 text-primary-500"
              />
              Active
            </label>
          </div>

          <div className="flex justify-end gap-3">
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
              className="rounded-lg bg-primary-500 px-4 py-2 text-sm font-medium text-white transition hover:bg-primary-600 disabled:opacity-60"
            >
              {isSubmitting ? "Saving..." : "Add IOC"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
