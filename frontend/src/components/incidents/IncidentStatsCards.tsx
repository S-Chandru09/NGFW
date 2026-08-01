import StatCard from "@/components/dashboard/StatCard";
import type { IncidentStats } from "@/types/incident";

interface IncidentStatsCardsProps {
  stats: IncidentStats;
}

export default function IncidentStatsCards({ stats }: IncidentStatsCardsProps) {
  return (
    <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
      <StatCard label="Total Incidents" value={stats.total_incidents} accent="blue" />
      <StatCard label="Open" value={stats.open_incidents} accent="amber" />
      <StatCard label="Critical" value={stats.critical_incidents} accent="red" />
      <StatCard label="Contained" value={stats.contained_incidents} accent="green" />
    </div>
  );
}
