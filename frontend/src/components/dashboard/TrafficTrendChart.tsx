import {
  Area,
  AreaChart,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { HourlyTrafficPoint } from "@/types/dashboard";

interface TrafficTrendChartProps {
  data: HourlyTrafficPoint[];
}

function formatHourLabel(value: string) {
  const date = new Date(value);
  return date.toLocaleTimeString(undefined, {
    hour: "2-digit",
    minute: "2-digit",
  });
}

export default function TrafficTrendChart({ data }: TrafficTrendChartProps) {
  const chartData = data.map((point) => ({
    ...point,
    label: formatHourLabel(point.hour),
  }));

  return (
    <div className="h-80 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={chartData} margin={{ top: 10, right: 10, left: 0, bottom: 0 }}>
          <defs>
            <linearGradient id="flowGradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.35} />
              <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
            </linearGradient>
            <linearGradient id="threatGradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#ef4444" stopOpacity={0.35} />
              <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
          <XAxis
            dataKey="label"
            stroke="#64748b"
            tick={{ fill: "#94a3b8", fontSize: 12 }}
            tickLine={false}
          />
          <YAxis
            stroke="#64748b"
            tick={{ fill: "#94a3b8", fontSize: 12 }}
            tickLine={false}
            axisLine={false}
          />
          <Tooltip
            contentStyle={{
              backgroundColor: "#0f172a",
              border: "1px solid #1e293b",
              borderRadius: "0.75rem",
              color: "#f8fafc",
            }}
          />
          <Legend />
          <Area
            type="monotone"
            dataKey="flow_count"
            name="Flows"
            stroke="#3b82f6"
            fill="url(#flowGradient)"
            strokeWidth={2}
          />
          <Area
            type="monotone"
            dataKey="threat_count"
            name="Threats"
            stroke="#ef4444"
            fill="url(#threatGradient)"
            strokeWidth={2}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
