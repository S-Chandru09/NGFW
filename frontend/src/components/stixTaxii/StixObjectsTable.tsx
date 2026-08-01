import DataTable, { type Column } from "@/components/admin/DataTable";
import Pagination from "@/components/admin/Pagination";
import type { PaginationMeta } from "@/types/admin";
import type { StixObject } from "@/types/stixTaxii";
import { formatDateTime } from "@/utils";

interface StixObjectsTableProps {
  objects: StixObject[];
  pagination: PaginationMeta | null;
  onPageChange: (page: number) => void;
  isLoading?: boolean;
}

const columns: Column<StixObject>[] = [
  {
    key: "name",
    header: "Name",
    render: (row) => (
      <div>
        <p className="font-medium text-white">{row.name}</p>
        <p className="mt-0.5 font-mono text-xs text-slate-500">{row.stix_id}</p>
      </div>
    ),
  },
  {
    key: "object_type",
    header: "Type",
    render: (row) => (
      <span className="inline-flex rounded-full bg-slate-800 px-2 py-0.5 text-xs capitalize text-slate-300">
        {row.object_type}
      </span>
    ),
  },
  {
    key: "collection_id",
    header: "Collection",
    render: (row) => (
      <span className="font-mono text-xs text-primary-300">{row.collection_id}</span>
    ),
  },
  {
    key: "modified",
    header: "Modified",
    render: (row) => (
      <span className="text-xs text-slate-400">{formatDateTime(row.modified)}</span>
    ),
  },
];

export default function StixObjectsTable({
  objects,
  pagination,
  onPageChange,
  isLoading,
}: StixObjectsTableProps) {
  return (
    <div className="space-y-4">
      <DataTable
        columns={columns}
        data={objects}
        rowKey={(row) => row.stix_id}
        isLoading={isLoading}
        emptyMessage="No STIX objects found. Sync from IOC database to populate."
      />

      {pagination && pagination.total_pages > 1 ? (
        <Pagination pagination={pagination} onPageChange={onPageChange} />
      ) : null}
    </div>
  );
}
