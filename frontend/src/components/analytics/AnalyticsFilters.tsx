import type { AnalyticsFiltersState } from "@/types/analytics";
import { cn } from "@/utils";

interface AnalyticsFiltersProps {
  filters: AnalyticsFiltersState;
  onChange: (filters: AnalyticsFiltersState) => void;
  onApply: () => void;
  isLoading?: boolean;
}

const inputClassName =
  "rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500";

export default function AnalyticsFilters({
  filters,
  onChange,
  onApply,
  isLoading,
}: AnalyticsFiltersProps) {
  const update = <K extends keyof AnalyticsFiltersState>(
    key: K,
    value: AnalyticsFiltersState[K],
  ) => {
    onChange({ ...filters, [key]: value });
  };

  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/40 p-5">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <h3 className="text-sm font-semibold text-white">Filters</h3>
          <p className="mt-1 text-xs text-slate-500">
            Adjust time ranges for daily, monthly, protocol, and country analytics
          </p>
        </div>

        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <div>
            <label className="mb-1.5 block text-xs font-medium text-slate-400">Daily range</label>
            <select
              value={filters.days}
              onChange={(event) => update("days", Number(event.target.value))}
              className={inputClassName}
            >
              <option value={7}>Last 7 days</option>
              <option value={14}>Last 14 days</option>
              <option value={30}>Last 30 days</option>
              <option value={60}>Last 60 days</option>
              <option value={90}>Last 90 days</option>
            </select>
          </div>

          <div>
            <label className="mb-1.5 block text-xs font-medium text-slate-400">Monthly range</label>
            <select
              value={filters.months}
              onChange={(event) => update("months", Number(event.target.value))}
              className={inputClassName}
            >
              <option value={3}>Last 3 months</option>
              <option value={6}>Last 6 months</option>
              <option value={12}>Last 12 months</option>
              <option value={18}>Last 18 months</option>
              <option value={24}>Last 24 months</option>
            </select>
          </div>

          <div>
            <label className="mb-1.5 block text-xs font-medium text-slate-400">
              Protocol / country window
            </label>
            <select
              value={filters.periodHours}
              onChange={(event) => update("periodHours", Number(event.target.value))}
              className={inputClassName}
            >
              <option value={24}>Last 24 hours</option>
              <option value={48}>Last 48 hours</option>
              <option value={72}>Last 72 hours</option>
              <option value={168}>Last 7 days</option>
            </select>
          </div>

          <div className="flex items-end">
            <button
              type="button"
              onClick={onApply}
              disabled={isLoading}
              className={cn(
                "w-full rounded-lg bg-primary-500 px-4 py-2 text-sm font-medium text-white transition hover:bg-primary-400",
                "disabled:cursor-not-allowed disabled:opacity-60",
              )}
            >
              {isLoading ? "Applying..." : "Apply Filters"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
