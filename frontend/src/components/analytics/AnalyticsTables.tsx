import DataTable, { type Column } from "@/components/admin/DataTable";
import type {
  AnalyticsTimePoint,
  CountryAnalyticsItem,
  ProtocolAnalyticsItem,
} from "@/types/analytics";
import { formatBytes, formatCompactNumber } from "@/utils";

interface AnalyticsTablesProps {
  dailyPoints: AnalyticsTimePoint[];
  monthlyPoints: AnalyticsTimePoint[];
  protocols: ProtocolAnalyticsItem[];
  countries: CountryAnalyticsItem[];
}

const dailyColumns: Column<AnalyticsTimePoint>[] = [
  {
    key: "period",
    header: "Date",
    render: (row) => <span className="text-slate-300">{row.period}</span>,
  },
  {
    key: "flow_count",
    header: "Flows",
    render: (row) => <span>{formatCompactNumber(row.flow_count)}</span>,
  },
  {
    key: "total_bytes",
    header: "Traffic",
    render: (row) => <span>{formatBytes(row.total_bytes)}</span>,
  },
  {
    key: "threat_count",
    header: "Threats",
    render: (row) => <span className="text-red-300">{row.threat_count}</span>,
  },
  {
    key: "blocked_count",
    header: "Blocked",
    render: (row) => <span className="text-amber-300">{row.blocked_count}</span>,
  },
  {
    key: "allowed_count",
    header: "Allowed",
    render: (row) => <span className="text-emerald-300">{row.allowed_count}</span>,
  },
];

const monthlyColumns: Column<AnalyticsTimePoint>[] = [
  {
    key: "period",
    header: "Month",
    render: (row) => <span className="text-slate-300">{row.period}</span>,
  },
  {
    key: "flow_count",
    header: "Flows",
    render: (row) => <span>{formatCompactNumber(row.flow_count)}</span>,
  },
  {
    key: "total_bytes",
    header: "Traffic",
    render: (row) => <span>{formatBytes(row.total_bytes)}</span>,
  },
  {
    key: "threat_count",
    header: "Threats",
    render: (row) => <span className="text-red-300">{row.threat_count}</span>,
  },
  {
    key: "blocked_count",
    header: "Blocked",
    render: (row) => <span className="text-amber-300">{row.blocked_count}</span>,
  },
];

const protocolColumns: Column<ProtocolAnalyticsItem>[] = [
  {
    key: "protocol",
    header: "Protocol",
    render: (row) => <span className="font-medium text-white">{row.protocol}</span>,
  },
  {
    key: "flow_count",
    header: "Flows",
    render: (row) => <span>{formatCompactNumber(row.flow_count)}</span>,
  },
  {
    key: "total_bytes",
    header: "Traffic",
    render: (row) => <span>{formatBytes(row.total_bytes)}</span>,
  },
  {
    key: "threat_count",
    header: "Threats",
    render: (row) => <span className="text-red-300">{row.threat_count}</span>,
  },
  {
    key: "blocked_count",
    header: "Blocked",
    render: (row) => <span className="text-amber-300">{row.blocked_count}</span>,
  },
  {
    key: "percentage",
    header: "Share",
    render: (row) => <span className="text-primary-300">{row.percentage.toFixed(1)}%</span>,
  },
];

const countryColumns: Column<CountryAnalyticsItem>[] = [
  {
    key: "country",
    header: "Country",
    render: (row) => (
      <div>
        <p className="font-medium text-white">{row.country_name}</p>
        <p className="text-xs text-slate-500">{row.country_code}</p>
      </div>
    ),
  },
  {
    key: "flow_count",
    header: "Flows",
    render: (row) => <span>{formatCompactNumber(row.flow_count)}</span>,
  },
  {
    key: "total_bytes",
    header: "Traffic",
    render: (row) => <span>{formatBytes(row.total_bytes)}</span>,
  },
  {
    key: "threat_count",
    header: "Threats",
    render: (row) => <span className="text-red-300">{row.threat_count}</span>,
  },
  {
    key: "blocked_count",
    header: "Blocked",
    render: (row) => <span className="text-amber-300">{row.blocked_count}</span>,
  },
  {
    key: "percentage",
    header: "Share",
    render: (row) => <span className="text-primary-300">{row.percentage.toFixed(1)}%</span>,
  },
  {
    key: "top_source_ips",
    header: "Top IPs",
    render: (row) => (
      <span className="font-mono text-xs text-slate-400">
        {row.top_source_ips.length > 0 ? row.top_source_ips.join(", ") : "—"}
      </span>
    ),
  },
];

export default function AnalyticsTables({
  dailyPoints,
  monthlyPoints,
  protocols,
  countries,
}: AnalyticsTablesProps) {
  return (
    <div className="space-y-6">
      <div className="rounded-2xl border border-slate-800 bg-slate-900/40 p-5">
        <h3 className="text-sm font-semibold text-white">Daily Analytics</h3>
        <p className="mt-1 text-xs text-slate-500">Day-by-day traffic and threat metrics</p>
        <div className="mt-4">
          <DataTable
            columns={dailyColumns}
            data={dailyPoints}
            rowKey={(row) => row.period}
            emptyMessage="No daily analytics data available"
          />
        </div>
      </div>

      <div className="rounded-2xl border border-slate-800 bg-slate-900/40 p-5">
        <h3 className="text-sm font-semibold text-white">Monthly Analytics</h3>
        <p className="mt-1 text-xs text-slate-500">Month-by-month aggregated metrics</p>
        <div className="mt-4">
          <DataTable
            columns={monthlyColumns}
            data={monthlyPoints}
            rowKey={(row) => row.period}
            emptyMessage="No monthly analytics data available"
          />
        </div>
      </div>

      <div className="grid gap-6 xl:grid-cols-2">
        <div className="rounded-2xl border border-slate-800 bg-slate-900/40 p-5">
          <h3 className="text-sm font-semibold text-white">Protocols</h3>
          <p className="mt-1 text-xs text-slate-500">Traffic breakdown by network protocol</p>
          <div className="mt-4">
            <DataTable
              columns={protocolColumns}
              data={protocols}
              rowKey={(row) => row.protocol}
              emptyMessage="No protocol data available"
            />
          </div>
        </div>

        <div className="rounded-2xl border border-slate-800 bg-slate-900/40 p-5">
          <h3 className="text-sm font-semibold text-white">Countries</h3>
          <p className="mt-1 text-xs text-slate-500">Traffic breakdown by source country</p>
          <div className="mt-4">
            <DataTable
              columns={countryColumns}
              data={countries}
              rowKey={(row) => row.country_code}
              emptyMessage="No country data available"
            />
          </div>
        </div>
      </div>
    </div>
  );
}
