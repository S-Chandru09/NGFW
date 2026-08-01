import LiveTraffic from "@/components/dashboard/LiveTraffic";

export default function DashboardHomePage() {
  return <LiveTraffic periodHours={24} refreshIntervalMs={30000} />;
}
