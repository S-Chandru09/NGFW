import ThreatAnalytics from "@/components/threats/ThreatAnalytics";

export default function ThreatAnalyticsPage() {
  return <ThreatAnalytics periodHours={24} topLimit={10} refreshIntervalMs={60000} />;
}
