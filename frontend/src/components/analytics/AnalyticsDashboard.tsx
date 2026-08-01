import { useCallback, useEffect, useState } from "react";
import AnalyticsCharts from "@/components/analytics/AnalyticsCharts";
import AnalyticsFilters from "@/components/analytics/AnalyticsFilters";
import AnalyticsStatsCards from "@/components/analytics/AnalyticsStatsCards";
import AnalyticsTables from "@/components/analytics/AnalyticsTables";
import { getApiErrorMessage } from "@/services/apiClient";
import { fetchAnalyticsOverview } from "@/services/analyticsService";
import type {
  AnalyticsDashboardTab,
  AnalyticsFiltersState,
  AnalyticsOverview,
} from "@/types/analytics";
import { DEFAULT_ANALYTICS_FILTERS } from "@/types/analytics";
import { cn, formatDateTime } from "@/utils";

const tabs: Array<{ id: AnalyticsDashboardTab; label: string }> = [
  { id: "charts", label: "Charts" },
  { id: "tables", label: "Tables" },
];

export default function AnalyticsDashboard() {
  const [activeTab, setActiveTab] = useState<AnalyticsDashboardTab>("charts");
  const [filters, setFilters] = useState<AnalyticsFiltersState>(DEFAULT_ANALYTICS_FILTERS);
  const [appliedFilters, setAppliedFilters] = useState<AnalyticsFiltersState>(DEFAULT_ANALYTICS_FILTERS);
  const [data, setData] = useState<AnalyticsOverview | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadData = useCallback(async () => {
    setIsLoading(true);
    setError(null);

    try {
      const response = await fetchAnalyticsOverview({
        days: appliedFilters.days,
        months: appliedFilters.months,
        period_hours: appliedFilters.periodHours,
      });
      setData(response);
    } catch (loadError) {
      setError(getApiErrorMessage(loadError, "Failed to load analytics dashboard"));
    } finally {
      setIsLoading(false);
    }
  }, [appliedFilters]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleApplyFilters = () => {
    setAppliedFilters(filters);
  };

  if (isLoading && !data) {
    return (
      <div className="flex min-h-[320px] items-center justify-center rounded-2xl border border-slate-800 bg-slate-900/40">
        <div className="h-10 w-10 animate-spin rounded-full border-2 border-primary-500 border-t-transparent" />
      </div>
    );
  }

  if (error && !data) {
    return (
      <div className="rounded-2xl border border-red-500/30 bg-red-500/10 p-6">
        <h3 className="text-lg font-semibold text-red-300">Unable to load analytics dashboard</h3>
        <p className="mt-2 text-sm text-red-200/80">{error}</p>
        <button
          type="button"
          onClick={loadData}
          className="mt-4 rounded-lg bg-red-500/20 px-4 py-2 text-sm font-medium text-red-200 transition hover:bg-red-500/30"
        >
          Retry
        </button>
      </div>
    );
  }

  if (!data) {
    return null;
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h2 className="text-xl font-semibold text-white">Analytics Dashboard</h2>
          <p className="mt-1 text-sm text-slate-400">
            Daily, monthly, protocol, and country traffic analytics
          </p>
        </div>

        <div className="flex items-center gap-3">
          <p className="text-xs text-slate-500">Updated {formatDateTime(data.generated_at)}</p>
          <button
            type="button"
            onClick={loadData}
            disabled={isLoading}
            className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200 transition hover:bg-slate-800 disabled:opacity-50"
          >
            {isLoading ? "Refreshing..." : "Refresh"}
          </button>
        </div>
      </div>

      {error ? (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-200">
          {error}
        </div>
      ) : null}

      <AnalyticsFilters
        filters={filters}
        onChange={setFilters}
        onApply={handleApplyFilters}
        isLoading={isLoading}
      />

      <AnalyticsStatsCards data={data} />

      <div className="flex flex-wrap gap-2 border-b border-slate-800 pb-1">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            type="button"
            onClick={() => setActiveTab(tab.id)}
            className={cn(
              "rounded-t-lg px-4 py-2 text-sm font-medium transition",
              activeTab === tab.id
                ? "bg-slate-900 text-primary-300 ring-1 ring-inset ring-primary-500/30"
                : "text-slate-400 hover:text-slate-200",
            )}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {activeTab === "charts" ? <AnalyticsCharts data={data} /> : null}

      {activeTab === "tables" ? (
        <AnalyticsTables
          dailyPoints={data.daily.data_points}
          monthlyPoints={data.monthly.data_points}
          protocols={data.protocols.protocols}
          countries={data.countries.countries}
        />
      ) : null}
    </div>
  );
}
