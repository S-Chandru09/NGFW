import type { ReactNode } from "react";
import { cn } from "@/utils";

export interface Column<T> {
  key: string;
  header: string;
  className?: string;
  render: (row: T) => ReactNode;
}

interface DataTableProps<T> {
  columns: Column<T>[];
  data: T[];
  rowKey: (row: T) => string;
  isLoading?: boolean;
  emptyMessage?: string;
}

export default function DataTable<T>({
  columns,
  data,
  rowKey,
  isLoading = false,
  emptyMessage = "No records found.",
}: DataTableProps<T>) {
  if (isLoading) {
    return (
      <div className="flex min-h-[240px] items-center justify-center rounded-xl border border-slate-800 bg-slate-900/40">
        <div className="h-8 w-8 animate-spin rounded-full border-2 border-primary-500 border-t-transparent" />
      </div>
    );
  }

  if (data.length === 0) {
    return (
      <div className="flex min-h-[240px] items-center justify-center rounded-xl border border-slate-800 bg-slate-900/40">
        <p className="text-sm text-slate-500">{emptyMessage}</p>
      </div>
    );
  }

  return (
    <div className="overflow-hidden rounded-xl border border-slate-800 bg-slate-900/40">
      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-slate-800">
          <thead className="bg-slate-900/80">
            <tr>
              {columns.map((column) => (
                <th
                  key={column.key}
                  scope="col"
                  className={cn(
                    "px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide text-slate-400",
                    column.className,
                  )}
                >
                  {column.header}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/80">
            {data.map((row) => (
              <tr key={rowKey(row)} className="transition hover:bg-slate-800/30">
                {columns.map((column) => (
                  <td
                    key={column.key}
                    className={cn("whitespace-nowrap px-4 py-3 text-sm text-slate-200", column.className)}
                  >
                    {column.render(row)}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
