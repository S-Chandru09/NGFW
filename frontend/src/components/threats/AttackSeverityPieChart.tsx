import { Cell, Legend, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";
import type { AttackCountBreakdown } from "@/types/dashboard";

interface AttackSeverityPieChartProps {
  attacks: AttackCountBreakdown;
}

const SEVERITY_COLORS: Record<string, string> = {
  Critical: "#ef4444",
  High: "#f97316",
  Medium: "#f59e0b",
  Low: "#22c55e",
};

export default function AttackSeverityPieChart({ attacks }: AttackSeverityPieChartProps) {
  const chartData = [
    { name: "Critical", value: attacks.critical_attacks },
    { name: "High", value: attacks.high_attacks },
    { name: "Medium", value: attacks.medium_attacks },
    { name: "Low", value: attacks.low_attacks },
  ].filter((item) => item.value > 0);

  if (chartData.length === 0) {
    return (
      <div className="flex h-80 items-center justify-center text-sm text-slate-500">
        No severity distribution data available
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
              <Cell key={entry.name} fill={SEVERITY_COLORS[entry.name]} />
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
