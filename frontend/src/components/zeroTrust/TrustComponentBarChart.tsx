import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { TrustScoreStatsResponse } from "@/types/trustScore";

interface TrustComponentBarChartProps {
  stats: TrustScoreStatsResponse;
}

export default function TrustComponentBarChart({ stats }: TrustComponentBarChartProps) {
  const chartData = [
    {
      name: "Device",
      average: stats.device_score_summary.average_score,
      min: stats.device_score_summary.min_score,
      max: stats.device_score_summary.max_score,
    },
    {
      name: "User",
      average: stats.user_score_summary.average_score,
      min: stats.user_score_summary.min_score,
      max: stats.user_score_summary.max_score,
    },
    {
      name: "Behaviour",
      average: stats.behaviour_score_summary.average_score,
      min: stats.behaviour_score_summary.min_score,
      max: stats.behaviour_score_summary.max_score,
    },
  ];

  return (
    <div className="h-80 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={chartData} margin={{ top: 10, right: 10, left: 0, bottom: 0 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
          <XAxis dataKey="name" stroke="#64748b" fontSize={12} />
          <YAxis domain={[0, 100]} stroke="#64748b" fontSize={12} />
          <Tooltip
            contentStyle={{
              backgroundColor: "#0f172a",
              border: "1px solid #1e293b",
              borderRadius: "0.75rem",
              color: "#f8fafc",
            }}
          />
          <Legend />
          <Bar dataKey="average" name="Average" fill="#38bdf8" radius={[6, 6, 0, 0]} />
          <Bar dataKey="min" name="Minimum" fill="#f59e0b" radius={[6, 6, 0, 0]} />
          <Bar dataKey="max" name="Maximum" fill="#22c55e" radius={[6, 6, 0, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
