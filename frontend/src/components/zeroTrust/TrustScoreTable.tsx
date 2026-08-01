import StatusBadge, { threatLevelBadgeVariant } from "@/components/admin/StatusBadge";
import type { TrustScore } from "@/types/trustScore";
import { formatDateTime } from "@/utils";

interface TrustScoreTableProps {
  scores: TrustScore[];
}

export default function TrustScoreTable({ scores }: TrustScoreTableProps) {
  if (scores.length === 0) {
    return (
      <div className="flex min-h-[200px] items-center justify-center rounded-xl border border-slate-800 bg-slate-900/40 text-sm text-slate-500">
        No trust scores recorded yet
      </div>
    );
  }

  return (
    <div className="overflow-hidden rounded-xl border border-slate-800 bg-slate-900/40">
      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-slate-800">
          <thead className="bg-slate-900/80">
            <tr>
              {["Entity", "Device", "User", "Behaviour", "Trust", "Risk", "Level", "Access", "Updated"].map(
                (header) => (
                  <th
                    key={header}
                    className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide text-slate-400"
                  >
                    {header}
                  </th>
                ),
              )}
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/80">
            {scores.map((score) => (
              <tr key={score.score_id} className="hover:bg-slate-800/30">
                <td className="px-4 py-3 text-sm text-white">
                  {score.username ?? score.user_id.slice(0, 8)}
                </td>
                <td className="px-4 py-3 text-sm text-slate-300">{score.device_score.toFixed(1)}</td>
                <td className="px-4 py-3 text-sm text-slate-300">{score.user_score.toFixed(1)}</td>
                <td className="px-4 py-3 text-sm text-slate-300">{score.behaviour_score.toFixed(1)}</td>
                <td className="px-4 py-3 text-sm font-medium text-sky-300">
                  {score.composite_score.toFixed(1)}
                </td>
                <td className="px-4 py-3 text-sm font-medium text-red-300">
                  {(100 - score.composite_score).toFixed(1)}
                </td>
                <td className="px-4 py-3">
                  <StatusBadge
                    label={score.trust_level}
                    variant={threatLevelBadgeVariant(score.trust_level)}
                  />
                </td>
                <td className="px-4 py-3">
                  <StatusBadge
                    label={score.is_access_allowed ? "Allow" : "Deny"}
                    variant={score.is_access_allowed ? "success" : "danger"}
                  />
                </td>
                <td className="px-4 py-3 text-sm text-slate-400">
                  {formatDateTime(score.calculated_at)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
