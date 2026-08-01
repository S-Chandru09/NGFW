import { Cell, Legend, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";

interface AccessDecisionPieChartProps {
  allowed: number;
  denied: number;
}

export default function AccessDecisionPieChart({ allowed, denied }: AccessDecisionPieChartProps) {
  const chartData = [
    { name: "Allowed", value: allowed, color: "#22c55e" },
    { name: "Denied", value: denied, color: "#ef4444" },
  ].filter((item) => item.value > 0);

  if (chartData.length === 0) {
    return (
      <div className="flex h-80 items-center justify-center text-sm text-slate-500">
        No access decision data available
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
            paddingAngle={4}
            label={({ name, value }) => `${name}: ${value}`}
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
