import {
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { TrustScore } from "@/types/trustScore";
import { formatDateTime } from "@/utils";

interface TrustScoreTrendChartProps {
  scores: TrustScore[];
}

export default function TrustScoreTrendChart({ scores }: TrustScoreTrendChartProps) {
  const chartData = [...scores]
    .sort(
      (left, right) =>
        new Date(left.calculated_at).getTime() - new Date(right.calculated_at).getTime(),
    )
    .map((score) => ({
      label: formatDateTime(score.calculated_at),
      composite: score.composite_score,
      device: score.device_score,
      user: score.user_score,
      behaviour: score.behaviour_score,
      risk: Math.round(100 - score.composite_score),
    }));

  if (chartData.length === 0) {
    return (
      <div className="flex h-80 items-center justify-center text-sm text-slate-500">
        No trust score trend data available
      </div>
    );
  }

  return (
    <div className="h-80 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={chartData} margin={{ top: 10, right: 10, left: 0, bottom: 0 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
          <XAxis dataKey="label" stroke="#64748b" fontSize={11} interval="preserveStartEnd" />
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
          <Line type="monotone" dataKey="composite" name="Trust" stroke="#38bdf8" strokeWidth={2} dot={false} />
          <Line type="monotone" dataKey="risk" name="Risk" stroke="#ef4444" strokeWidth={2} dot={false} />
          <Line type="monotone" dataKey="device" name="Device" stroke="#22c55e" strokeWidth={1.5} dot={false} />
          <Line type="monotone" dataKey="user" name="User" stroke="#a78bfa" strokeWidth={1.5} dot={false} />
          <Line type="monotone" dataKey="behaviour" name="Behaviour" stroke="#f59e0b" strokeWidth={1.5} dot={false} />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
