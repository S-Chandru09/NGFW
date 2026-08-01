import StatCard from "@/components/dashboard/StatCard";
import type { IOCStatsResponse } from "@/types/ioc";

interface IOCStatsCardsProps {
  stats: IOCStatsResponse;
}

export default function IOCStatsCards({ stats }: IOCStatsCardsProps) {
  return (
    <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
      <StatCard label="Total IOCs" value={stats.total_iocs} accent="blue" />
      <StatCard label="IP Indicators" value={stats.ip_count} accent="green" />
      <StatCard label="Domain Indicators" value={stats.domain_count} accent="amber" />
      <StatCard label="Hash Indicators" value={stats.hash_count} accent="red" />
    </div>
  );
}
