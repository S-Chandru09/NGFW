import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { AttackTypeItem } from "@/types/dashboard";

interface AttackTypesBarChartProps {
  data: AttackTypeItem[];
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#f59e0b",
  low: "#22c55e",
  unknown: "#64748b",
};

function formatThreatType(value: string) {
  return value
    .replace(/_/g, " ")
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

export default function AttackTypesBarChart({ data }: AttackTypesBarChartProps) {
  const chartData = data.slice(0, 8).map((item) => ({
    name: formatThreatType(item.threat_type),
    count: item.count,
    percentage: item.percentage,
    severity: item.severity.toLowerCase(),
  }));

  if (chartData.length === 0) {
    return (
      <div className="flex h-80 items-center justify-center text-sm text-slate-500">
        No attack type data available
      </div>
    );
  }

  return (
    <div className="h-80 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={chartData} layout="vertical" margin={{ left: 20, right: 20 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={false} />
          <XAxis type="number" stroke="#64748b" tick={{ fill: "#94a3b8", fontSize: 12 }} />
          <YAxis
            type="category"
            dataKey="name"
            width={120}
            stroke="#64748b"
            tick={{ fill: "#94a3b8", fontSize: 12 }}
          />
          <Tooltip
            formatter={(value: number, _name, item) => [
              `${value} attacks (${item.payload.percentage}%)`,
              "Count",
            ]}
            contentStyle={{
              backgroundColor: "#0f172a",
              border: "1px solid #1e293b",
              borderRadius: "0.75rem",
              color: "#f8fafc",
            }}
          />
          <Bar dataKey="count" name="Attacks" radius={[0, 4, 4, 0]}>
            {chartData.map((entry) => (
              <Cell
                key={entry.name}
                fill={SEVERITY_COLORS[entry.severity] || SEVERITY_COLORS.unknown}
              />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
