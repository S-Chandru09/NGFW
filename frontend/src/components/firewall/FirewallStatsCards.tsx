import StatCard from "@/components/dashboard/StatCard";
import type { FirewallRuleStatsResponse } from "@/types/firewall";

interface FirewallStatsCardsProps {
  stats: FirewallRuleStatsResponse;
}

export default function FirewallStatsCards({ stats }: FirewallStatsCardsProps) {
  return (
    <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
      <StatCard label="Total Rules" value={stats.total_rules} accent="blue" />
      <StatCard label="Enabled" value={stats.enabled_rules} accent="green" />
      <StatCard label="Disabled" value={stats.disabled_rules} accent="slate" />
      <StatCard label="Expired" value={stats.expired_rules} accent="amber" />
    </div>
  );
}
