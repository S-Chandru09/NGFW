import type { PaginationMeta } from "@/types/admin";
import { cn } from "@/utils";

interface PaginationProps {
  pagination: PaginationMeta;
  onPageChange: (page: number) => void;
  className?: string;
}

export default function Pagination({ pagination, onPageChange, className }: PaginationProps) {
  const { page, total_pages: totalPages, total_items: totalItems, has_previous: hasPrevious, has_next: hasNext } =
    pagination;

  if (totalPages <= 1) {
    return (
      <p className={cn("text-xs text-slate-500", className)}>
        Showing {totalItems} {totalItems === 1 ? "record" : "records"}
      </p>
    );
  }

  return (
    <div className={cn("flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between", className)}>
      <p className="text-xs text-slate-500">
        Page {page} of {totalPages} · {totalItems} total
      </p>

      <div className="flex items-center gap-2">
        <button
          type="button"
          onClick={() => onPageChange(page - 1)}
          disabled={!hasPrevious}
          className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs text-slate-200 transition hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-40"
        >
          Previous
        </button>
        <button
          type="button"
          onClick={() => onPageChange(page + 1)}
          disabled={!hasNext}
          className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs text-slate-200 transition hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-40"
        >
          Next
        </button>
      </div>
    </div>
  );
}
