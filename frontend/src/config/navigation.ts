export interface NavItem {
  label: string;
  path: string;
  icon: "dashboard" | "firewall" | "threats" | "network" | "logs" | "packets" | "settings" | "admin" | "zeroTrust" | "devices" | "ioc" | "stixTaxii" | "incidents" | "analytics";
}

export const navigationItems: NavItem[] = [
  { label: "Dashboard", path: "/", icon: "dashboard" },
  { label: "Zero Trust", path: "/zero-trust", icon: "zeroTrust" },
  { label: "Device Inventory", path: "/devices", icon: "devices" },
  { label: "Network Graph", path: "/network", icon: "network" },
  { label: "Threat Analytics", path: "/threats", icon: "threats" },
  { label: "Analytics", path: "/analytics", icon: "analytics" },
  { label: "IOC Database", path: "/ioc-database", icon: "ioc" },
  { label: "STIX / TAXII", path: "/stix-taxii", icon: "stixTaxii" },
  { label: "Incidents", path: "/incidents", icon: "incidents" },
  { label: "Admin Panel", path: "/admin", icon: "admin" },
  { label: "Firewall Rules", path: "/firewall", icon: "firewall" },
  { label: "Audit Logs", path: "/logs", icon: "logs" },
  { label: "Packet Upload", path: "/packets", icon: "packets" },
  { label: "Settings", path: "/settings", icon: "settings" },
];
