import LogsPanel from "@/components/admin/LogsPanel";

export default function LogsPage() {
  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-semibold text-white">Audit Logs</h2>
        <p className="mt-1 text-sm text-slate-400">
          Search and review security audit events across the platform
        </p>
      </div>
      <LogsPanel />
    </div>
  );
}
