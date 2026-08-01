import NetworkGraph from "@/components/network/NetworkGraph";

export default function NetworkGraphPage() {
  return <NetworkGraph periodHours={24} maxNodes={40} refreshIntervalMs={60000} />;
}
