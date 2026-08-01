import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { AnalyticsOverview } from "@/types/analytics";

const CHART_COLORS = ["#38bdf8", "#34d399", "#fbbf24", "#f87171", "#a78bfa", "#fb923c", "#22d3ee"];

const tooltipStyle = {
  backgroundColor: "#0f172a",
  border: "1px solid #1e293b",
  borderRadius: "8px",
};

interface AnalyticsChartsProps {
  data: AnalyticsOverview;
}

function formatDayLabel(period: string) {
  const date = new Date(period);
  return date.toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

export default function AnalyticsCharts({ data }: AnalyticsChartsProps) {
  const dailyData = data.daily.data_points.map((point) => ({
    ...point,
    label: formatDayLabel(point.period),
  }));

  const monthlyData = data.monthly.data_points.map((point) => ({
    ...point,
    label: point.period,
  }));

  const protocolData = data.protocols.protocols.map((item) => ({
    name: item.protocol,
    value: item.flow_count,
    bytes: item.total_bytes,
    percentage: item.percentage,
  }));

  const countryData = data.countries.countries.slice(0, 10).map((item) => ({
    name: item.country_code,
    fullName: item.country_name,
    flow_count: item.flow_count,
    total_bytes: item.total_bytes,
    threat_count: item.threat_count,
    percentage: item.percentage,
  }));

  return (
    <div className="space-y-6">
      <div className="grid gap-6 xl:grid-cols-2">
        <div className="rounded-2xl border border-slate-800 bg-slate-900/40 p-5">
          <h3 className="text-sm font-semibold text-white">Daily Traffic & Threats</h3>
          <p className="mt-1 text-xs text-slate-500">
            Flow volume and threat detections over {data.daily.days} days
          </p>
          <div className="mt-4 h-80">
            {dailyData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={dailyData} margin={{ top: 10, right: 10, left: 0, bottom: 0 }}>
                  <defs>
                    <linearGradient id="flowGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#38bdf8" stopOpacity={0.35} />
                      <stop offset="95%" stopColor="#38bdf8" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis dataKey="label" stroke="#64748b" fontSize={11} tickLine={false} />
                  <YAxis stroke="#64748b" fontSize={12} tickLine={false} axisLine={false} />
                  <Tooltip contentStyle={tooltipStyle} />
                  <Legend />
                  <Area
                    type="monotone"
                    dataKey="flow_count"
                    name="Flows"
                    stroke="#38bdf8"
                    fill="url(#flowGradient)"
                  />
                  <Line
                    type="monotone"
                    dataKey="threat_count"
                    name="Threats"
                    stroke="#f87171"
                    strokeWidth={2}
                    dot={false}
                  />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex h-full items-center justify-center text-sm text-slate-500">
                No daily data available
              </div>
            )}
          </div>
        </div>

        <div className="rounded-2xl border border-slate-800 bg-slate-900/40 p-5">
          <h3 className="text-sm font-semibold text-white">Monthly Trends</h3>
          <p className="mt-1 text-xs text-slate-500">
            Monthly flow and blocked traffic over {data.monthly.months} months
          </p>
          <div className="mt-4 h-80">
            {monthlyData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={monthlyData} margin={{ top: 10, right: 10, left: 0, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis dataKey="label" stroke="#64748b" fontSize={11} tickLine={false} />
                  <YAxis stroke="#64748b" fontSize={12} tickLine={false} axisLine={false} />
                  <Tooltip contentStyle={tooltipStyle} />
                  <Legend />
                  <Bar dataKey="flow_count" name="Flows" fill="#38bdf8" radius={[4, 4, 0, 0]} />
                  <Bar dataKey="blocked_count" name="Blocked" fill="#f87171" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex h-full items-center justify-center text-sm text-slate-500">
                No monthly data available
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="grid gap-6 xl:grid-cols-2">
        <div className="rounded-2xl border border-slate-800 bg-slate-900/40 p-5">
          <h3 className="text-sm font-semibold text-white">Protocol Distribution</h3>
          <p className="mt-1 text-xs text-slate-500">
            Traffic share by protocol (last {data.protocols.period_hours}h)
          </p>
          <div className="mt-4 h-72">
            {protocolData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={protocolData}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    innerRadius={55}
                    outerRadius={95}
                    paddingAngle={2}
                  >
                    {protocolData.map((entry, index) => (
                      <Cell key={entry.name} fill={CHART_COLORS[index % CHART_COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={tooltipStyle} />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex h-full items-center justify-center text-sm text-slate-500">
                No protocol data available
              </div>
            )}
          </div>
        </div>

        <div className="rounded-2xl border border-slate-800 bg-slate-900/40 p-5">
          <h3 className="text-sm font-semibold text-white">Top Countries by Flows</h3>
          <p className="mt-1 text-xs text-slate-500">
            Source country traffic (last {data.countries.period_hours}h)
          </p>
          <div className="mt-4 h-72">
            {countryData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={countryData} layout="vertical" margin={{ left: 10, right: 20 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis type="number" stroke="#64748b" fontSize={12} />
                  <YAxis
                    type="category"
                    dataKey="name"
                    stroke="#64748b"
                    fontSize={12}
                    width={40}
                  />
                  <Tooltip
                    contentStyle={tooltipStyle}
                    formatter={(value, _name, item) => [
                      value,
                      (item?.payload as { fullName?: string })?.fullName ?? "Flows",
                    ]}
                  />
                  <Bar dataKey="flow_count" name="Flows" radius={[0, 4, 4, 0]}>
                    {countryData.map((entry, index) => (
                      <Cell key={entry.name} fill={CHART_COLORS[index % CHART_COLORS.length]} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex h-full items-center justify-center text-sm text-slate-500">
                No country data available
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="rounded-2xl border border-slate-800 bg-slate-900/40 p-5">
        <h3 className="text-sm font-semibold text-white">Threat vs Blocked (Daily)</h3>
        <p className="mt-1 text-xs text-slate-500">Comparative daily threat and blocked flow counts</p>
        <div className="mt-4 h-72">
          {dailyData.length > 0 ? (
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={dailyData} margin={{ top: 10, right: 10, left: 0, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="label" stroke="#64748b" fontSize={11} tickLine={false} />
                <YAxis stroke="#64748b" fontSize={12} tickLine={false} axisLine={false} />
                <Tooltip contentStyle={tooltipStyle} />
                <Legend />
                <Line
                  type="monotone"
                  dataKey="threat_count"
                  name="Threats"
                  stroke="#f87171"
                  strokeWidth={2}
                  dot={false}
                />
                <Line
                  type="monotone"
                  dataKey="blocked_count"
                  name="Blocked"
                  stroke="#fbbf24"
                  strokeWidth={2}
                  dot={false}
                />
              </LineChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex h-full items-center justify-center text-sm text-slate-500">
              No trend data available
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
