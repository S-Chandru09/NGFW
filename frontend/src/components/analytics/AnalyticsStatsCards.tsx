import StatCard from "@/components/dashboard/StatCard";
import type { AnalyticsOverview } from "@/types/analytics";
import { formatBytes } from "@/utils";

interface AnalyticsStatsCardsProps {
  data: AnalyticsOverview;
}

export default function AnalyticsStatsCards({ data }: AnalyticsStatsCardsProps) {
  const { daily, protocols, countries } = data;

  return (
    <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
      <StatCard label="Total Flows" value={daily.totals.flow_count} accent="blue" />
      <StatCard
        label="Total Traffic"
        value={formatBytes(daily.totals.total_bytes)}
        accent="green"
      />
      <StatCard label="Threats Detected" value={daily.totals.threat_count} accent="red" />
      <StatCard label="Blocked Flows" value={daily.totals.blocked_count} accent="amber" />
      <StatCard label="Protocols" value={protocols.protocols.length} accent="slate" />
      <StatCard label="Countries" value={countries.countries.length} accent="blue" />
      <StatCard label="Allowed Flows" value={daily.totals.allowed_count} accent="green" />
      <StatCard
        label="Unknown Geo Flows"
        value={countries.unknown_flow_count}
        accent="amber"
      />
    </div>
  );
}
