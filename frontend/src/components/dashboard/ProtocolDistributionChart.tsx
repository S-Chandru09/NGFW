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
import type { ProtocolTraffic } from "@/types/dashboard";
import { formatBytes } from "@/utils";

interface ProtocolDistributionChartProps {
  data: ProtocolTraffic[];
}

const COLORS = ["#3b82f6", "#22c55e", "#f59e0b", "#ef4444", "#8b5cf6", "#06b6d4", "#94a3b8"];

export default function ProtocolDistributionChart({
  data,
}: ProtocolDistributionChartProps) {
  const chartData = data.slice(0, 6).map((item) => ({
    name: item.protocol.toUpperCase(),
    flows: item.flow_count,
    bytes: item.total_bytes,
    percentage: item.percentage,
  }));

  if (chartData.length === 0) {
    return (
      <div className="flex h-80 items-center justify-center text-sm text-slate-500">
        No protocol traffic data available
      </div>
    );
  }

  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <div className="h-72">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={chartData}
              dataKey="flows"
              nameKey="name"
              cx="50%"
              cy="50%"
              innerRadius={55}
              outerRadius={90}
              paddingAngle={3}
            >
              {chartData.map((entry, index) => (
                <Cell key={entry.name} fill={COLORS[index % COLORS.length]} />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{
                backgroundColor: "#0f172a",
                border: "1px solid #1e293b",
                borderRadius: "0.75rem",
                color: "#f8fafc",
              }}
            />
          </PieChart>
        </ResponsiveContainer>
      </div>

      <div className="h-72">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={chartData} layout="vertical" margin={{ left: 10, right: 20 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={false} />
            <XAxis type="number" stroke="#64748b" tick={{ fill: "#94a3b8", fontSize: 12 }} />
            <YAxis
              type="category"
              dataKey="name"
              width={60}
              stroke="#64748b"
              tick={{ fill: "#94a3b8", fontSize: 12 }}
            />
            <Tooltip
              formatter={(value: number, name: string, item) => {
                if (name === "bytes") {
                  return [formatBytes(item.payload.bytes), "Bytes"];
                }
                return [value, "Flows"];
              }}
              contentStyle={{
                backgroundColor: "#0f172a",
                border: "1px solid #1e293b",
                borderRadius: "0.75rem",
                color: "#f8fafc",
              }}
            />
            <Bar dataKey="flows" name="flows" radius={[0, 4, 4, 0]}>
              {chartData.map((entry, index) => (
                <Cell key={entry.name} fill={COLORS[index % COLORS.length]} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
