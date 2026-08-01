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
import type { AttackCountBreakdown } from "@/types/dashboard";

interface AttackVolumeBarChartProps {
  attacks: AttackCountBreakdown;
}

const PERIOD_COLORS = ["#3b82f6", "#8b5cf6", "#06b6d4"];

export default function AttackVolumeBarChart({ attacks }: AttackVolumeBarChartProps) {
  const chartData = [
    { period: "Today", attacks: attacks.attacks_today },
    { period: "This Week", attacks: attacks.attacks_this_week },
    { period: "This Month", attacks: attacks.attacks_this_month },
  ];

  return (
    <div className="h-80 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={chartData} margin={{ top: 10, right: 10, left: 0, bottom: 0 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
          <XAxis
            dataKey="period"
            stroke="#64748b"
            tick={{ fill: "#94a3b8", fontSize: 12 }}
            tickLine={false}
          />
          <YAxis
            stroke="#64748b"
            tick={{ fill: "#94a3b8", fontSize: 12 }}
            tickLine={false}
            axisLine={false}
            allowDecimals={false}
          />
          <Tooltip
            contentStyle={{
              backgroundColor: "#0f172a",
              border: "1px solid #1e293b",
              borderRadius: "0.75rem",
              color: "#f8fafc",
            }}
          />
          <Bar dataKey="attacks" name="Attacks" radius={[6, 6, 0, 0]}>
            {chartData.map((entry, index) => (
              <Cell key={entry.period} fill={PERIOD_COLORS[index % PERIOD_COLORS.length]} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
