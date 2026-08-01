import type { TaxiiCollection } from "@/types/stixTaxii";
import { formatDateTime } from "@/utils";

interface TaxiiCollectionsTableProps {
  collections: TaxiiCollection[];
}

export default function TaxiiCollectionsTable({ collections }: TaxiiCollectionsTableProps) {
  if (collections.length === 0) {
    return (
      <p className="py-8 text-center text-sm text-slate-500">
        No TAXII collections configured.
      </p>
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="min-w-full divide-y divide-slate-800">
        <thead>
          <tr className="text-left text-xs font-medium uppercase tracking-wide text-slate-500">
            <th className="px-4 py-3">Collection</th>
            <th className="px-4 py-3">ID</th>
            <th className="px-4 py-3">Objects</th>
            <th className="px-4 py-3">Last Synced</th>
            <th className="px-4 py-3">Access</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-800/80">
          {collections.map((collection) => (
            <tr key={collection.id} className="text-sm text-slate-300">
              <td className="px-4 py-3">
                <p className="font-medium text-white">{collection.title}</p>
                <p className="mt-0.5 text-xs text-slate-500">{collection.description}</p>
              </td>
              <td className="px-4 py-3 font-mono text-xs text-primary-300">{collection.id}</td>
              <td className="px-4 py-3">{collection.object_count}</td>
              <td className="px-4 py-3 text-xs text-slate-400">
                {collection.last_synced_at ? formatDateTime(collection.last_synced_at) : "Never"}
              </td>
              <td className="px-4 py-3">
                <span className="inline-flex rounded-full bg-emerald-500/15 px-2 py-0.5 text-xs text-emerald-300">
                  {collection.can_read ? "Read" : "No access"}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
