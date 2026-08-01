import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import StatusBadge, { severityBadgeVariant } from "@/components/admin/StatusBadge";
import type { IncidentStats } from "@/types/incident";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#f87171",
  error: "#fb923c",
  warning: "#fbbf24",
  info: "#38bdf8",
};

const STATUS_COLORS: Record<string, string> = {
  open: "#f87171",
  investigating: "#fbbf24",
  contained: "#38bdf8",
  resolved: "#34d399",
  closed: "#94a3b8",
};

interface IncidentSeverityPanelProps {
  stats: IncidentStats;
}

function formatLabel(value: string) {
  return value.replace(/_/g, " ").replace(/\b\w/g, (char) => char.toUpperCase());
}

export default function IncidentSeverityPanel({ stats }: IncidentSeverityPanelProps) {
  const severityData = Object.entries(stats.severity_distribution)
    .filter(([, count]) => count > 0)
    .map(([name, value]) => ({ name: formatLabel(name), key: name, value }));

  const statusData = Object.entries(stats.status_distribution)
    .filter(([, count]) => count > 0)
    .map(([name, value]) => ({ name: formatLabel(name), key: name, value }));

  const responseData = [
    { name: "IPs Blocked", value: stats.blocked_ips_total },
    { name: "Sessions Killed", value: stats.sessions_killed_total },
    { name: "Reports Generated", value: stats.reports_generated_total },
  ].filter((item) => item.value > 0);

  return (
    <div className="space-y-6">
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {(["critical", "error", "warning", "info"] as const).map((severity) => (
          <div
            key={severity}
            className="rounded-xl border border-slate-800 bg-slate-900/60 p-4"
          >
            <div className="flex items-center justify-between gap-3">
              <StatusBadge label={formatLabel(severity)} variant={severityBadgeVariant(severity)} />
              <span className="text-2xl font-semibold text-white">
                {stats.severity_distribution[severity] ?? 0}
              </span>
            </div>
          </div>
        ))}
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <div className="rounded-2xl border border-slate-800 bg-slate-900/40 p-5">
          <h3 className="text-sm font-semibold text-white">Severity Distribution</h3>
          <p className="mt-1 text-xs text-slate-500">Incidents grouped by severity level</p>
          <div className="mt-4 h-64">
            {severityData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={severityData}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    innerRadius={55}
                    outerRadius={90}
                    paddingAngle={3}
                  >
                    {severityData.map((entry) => (
                      <Cell key={entry.key} fill={SEVERITY_COLORS[entry.key] ?? "#64748b"} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "#0f172a",
                      border: "1px solid #1e293b",
                      borderRadius: "8px",
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex h-full items-center justify-center text-sm text-slate-500">
                No incidents recorded yet
              </div>
            )}
          </div>
        </div>

        <div className="rounded-2xl border border-slate-800 bg-slate-900/40 p-5">
          <h3 className="text-sm font-semibold text-white">Status Distribution</h3>
          <p className="mt-1 text-xs text-slate-500">Current incident lifecycle states</p>
          <div className="mt-4 h-64">
            {statusData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={statusData} margin={{ top: 10, right: 10, left: 0, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis dataKey="name" stroke="#64748b" fontSize={11} />
                  <YAxis stroke="#64748b" fontSize={12} allowDecimals={false} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "#0f172a",
                      border: "1px solid #1e293b",
                      borderRadius: "8px",
                    }}
                  />
                  <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                    {statusData.map((entry) => (
                      <Cell key={entry.key} fill={STATUS_COLORS[entry.key] ?? "#64748b"} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex h-full items-center justify-center text-sm text-slate-500">
                No status data available
              </div>
            )}
          </div>
        </div>
      </div>

      {responseData.length > 0 ? (
        <div className="rounded-2xl border border-slate-800 bg-slate-900/40 p-5">
          <h3 className="text-sm font-semibold text-white">Response Actions Summary</h3>
          <p className="mt-1 text-xs text-slate-500">Containment actions taken across all incidents</p>
          <div className="mt-4 grid gap-3 sm:grid-cols-3">
            {responseData.map((item) => (
              <div
                key={item.name}
                className="rounded-xl border border-slate-800 bg-slate-950/60 px-4 py-3"
              >
                <p className="text-xs text-slate-500">{item.name}</p>
                <p className="mt-1 text-xl font-semibold text-white">{item.value}</p>
              </div>
            ))}
          </div>
        </div>
      ) : null}
    </div>
  );
}
