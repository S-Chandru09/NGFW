import { Cell, Legend, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";

interface TrustLevelPieChartProps {
  distribution: Record<string, number>;
}

const LEVEL_COLORS: Record<string, string> = {
  critical: "#ef4444",
  low: "#f97316",
  medium: "#f59e0b",
  high: "#38bdf8",
  verified: "#22c55e",
};

const LEVEL_LABELS: Record<string, string> = {
  critical: "Critical",
  low: "Low",
  medium: "Medium",
  high: "High",
  verified: "Verified",
};

export default function TrustLevelPieChart({ distribution }: TrustLevelPieChartProps) {
  const chartData = Object.entries(distribution)
    .filter(([, value]) => value > 0)
    .map(([key, value]) => ({
      name: LEVEL_LABELS[key] ?? key,
      value,
      color: LEVEL_COLORS[key] ?? "#64748b",
    }));

  if (chartData.length === 0) {
    return (
      <div className="flex h-80 items-center justify-center text-sm text-slate-500">
        No trust level distribution data available
      </div>
    );
  }

  return (
    <div className="h-80 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={chartData}
            dataKey="value"
            nameKey="name"
            cx="50%"
            cy="50%"
            innerRadius={70}
            outerRadius={110}
            paddingAngle={3}
            label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
          >
            {chartData.map((entry) => (
              <Cell key={entry.name} fill={entry.color} />
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
          <Legend />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}
