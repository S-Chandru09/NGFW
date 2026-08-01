import { useCallback, useEffect, useState } from "react";
import DataTable, { type Column } from "@/components/admin/DataTable";
import Pagination from "@/components/admin/Pagination";
import StatusBadge from "@/components/admin/StatusBadge";
import PacketAnalysisModal from "@/components/packets/PacketAnalysisModal";
import { getApiErrorMessage } from "@/services/apiClient";
import { fetchPacketUploads, fetchPacketUploadStatus, uploadPcapFile } from "@/services/packetService";
import type { PaginationMeta } from "@/types/admin";
import type { PacketAnalysisResponse, PacketUpload } from "@/types/packetUpload";
import { formatBytes, formatDateTime } from "@/utils";

function getThreatCount(upload: PacketUpload): number | null {
  const response = upload.ai_engine_response as PacketAnalysisResponse | null | undefined;
  if (!response) {
    return null;
  }

  if (typeof response.threats_detected === "number") {
    return response.threats_detected;
  }

  return response.summary?.malicious_flows ?? null;
}

export default function PacketUploadPanel() {
  const [uploads, setUploads] = useState<PacketUpload[]>([]);
  const [pagination, setPagination] = useState<PaginationMeta | null>(null);
  const [page, setPage] = useState(1);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isUploading, setIsUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [selectedUpload, setSelectedUpload] = useState<PacketUpload | null>(null);

  const loadUploads = useCallback(async (silent = false) => {
    if (!silent) {
      setIsLoading(true);
    }
    setError(null);

    try {
      const response = await fetchPacketUploads({ page, page_size: 10 });
      setUploads(response.items);
      setPagination(response.pagination);
    } catch (loadError) {
      setError(getApiErrorMessage(loadError, "Failed to load packet uploads"));
    } finally {
      if (!silent) {
        setIsLoading(false);
      }
    }
  }, [page]);

  useEffect(() => {
    loadUploads();
  }, [loadUploads]);

  useEffect(() => {
    const pendingUploads = uploads.filter(
      (upload) =>
        upload.status === "processing" ||
        upload.ai_engine_status === "processing" ||
        upload.ai_engine_status === "queued",
    );

    if (pendingUploads.length === 0) {
      return;
    }

    const pendingIds = pendingUploads.map((upload) => upload.upload_id);

    const intervalId = window.setInterval(async () => {
      await Promise.all(
        pendingIds.map(async (uploadId) => {
          try {
            const statusResponse = await fetchPacketUploadStatus(uploadId);
            setUploads((currentUploads) =>
              currentUploads.map((currentUpload) =>
                currentUpload.upload_id === uploadId
                  ? {
                      ...currentUpload,
                      status: statusResponse.status,
                      ai_engine_status: statusResponse.ai_engine_status,
                      ai_engine_response: statusResponse.ai_engine_response ?? currentUpload.ai_engine_response,
                      ai_engine_error: statusResponse.ai_engine_error,
                    }
                  : currentUpload,
              ),
            );
          } catch {
            // Keep polling on transient failures.
          }
        }),
      );
    }, 3000);

    return () => window.clearInterval(intervalId);
  }, [
    uploads
      .map((upload) => `${upload.upload_id}:${upload.status}:${upload.ai_engine_status}`)
      .join("|"),
  ]);

  const handleUpload = async () => {
    if (!selectedFile) {
      setError("Select a PCAP or PCAPNG file to upload");
      return;
    }

    setIsUploading(true);
    setError(null);
    setMessage(null);

    try {
      const response = await uploadPcapFile(selectedFile);
      setMessage(response.message || "PCAP uploaded successfully");
      setSelectedFile(null);
      await loadUploads();
    } catch (uploadError) {
      setError(getApiErrorMessage(uploadError, "Failed to upload PCAP file"));
    } finally {
      setIsUploading(false);
    }
  };

  const columns: Column<PacketUpload>[] = [
    { key: "original_filename", header: "Filename", render: (row) => row.original_filename },
    {
      key: "file_size",
      header: "Size",
      render: (row) => formatBytes(row.file_size),
    },
    {
      key: "packet_count",
      header: "Packets",
      render: (row) => row.packet_count.toLocaleString(),
    },
    {
      key: "status",
      header: "Status",
      render: (row) => <StatusBadge label={row.status} variant="info" />,
    },
    {
      key: "ai_engine_status",
      header: "AI Engine",
      render: (row) => <StatusBadge label={row.ai_engine_status} variant="muted" />,
    },
    {
      key: "threats",
      header: "Threats",
      render: (row) => {
        const threatCount = getThreatCount(row);
        if (threatCount === null) {
          return <span className="text-slate-500">—</span>;
        }

        return (
          <StatusBadge
            label={threatCount.toLocaleString()}
            variant={threatCount > 0 ? "danger" : "success"}
          />
        );
      },
    },
    {
      key: "created_at",
      header: "Uploaded",
      render: (row) => formatDateTime(row.created_at),
    },
    {
      key: "actions",
      header: "",
      render: (row) =>
        row.ai_engine_response ? (
          <button
            type="button"
            onClick={() => setSelectedUpload(row)}
            className="rounded-lg border border-slate-700 px-3 py-1.5 text-xs font-medium text-slate-200 transition hover:bg-slate-800"
          >
            View results
          </button>
        ) : (
          <span className="text-xs text-slate-500">—</span>
        ),
    },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-semibold text-white">Packet Upload</h2>
        <p className="mt-1 text-sm text-slate-400">
          Upload PCAP files for validation, storage, and AI engine analysis
        </p>
      </div>

      <div className="rounded-2xl border border-slate-800 bg-slate-950/60 p-5 sm:p-6">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-end">
          <div className="flex-1">
            <label htmlFor="pcap-file" className="mb-2 block text-sm font-medium text-slate-300">
              PCAP / PCAPNG file
            </label>
            <input
              id="pcap-file"
              type="file"
              accept=".pcap,.pcapng,.cap"
              onChange={(event) => setSelectedFile(event.target.files?.[0] ?? null)}
              className="block w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200 file:mr-4 file:rounded-md file:border-0 file:bg-primary-500/20 file:px-3 file:py-1.5 file:text-primary-200"
            />
          </div>
          <button
            type="button"
            onClick={handleUpload}
            disabled={isUploading || !selectedFile}
            className="rounded-lg bg-primary-500 px-4 py-2 text-sm font-medium text-white transition hover:bg-primary-400 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {isUploading ? "Uploading..." : "Upload PCAP"}
          </button>
        </div>
      </div>

      {message ? (
        <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-200">
          {message}
        </div>
      ) : null}

      {error ? (
        <div className="rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-200">
          {error}
        </div>
      ) : null}

      <div className="rounded-2xl border border-slate-800 bg-slate-950/60 p-5 sm:p-6">
        {isLoading ? (
          <div className="flex min-h-[240px] items-center justify-center">
            <div className="h-10 w-10 animate-spin rounded-full border-2 border-primary-500 border-t-transparent" />
          </div>
        ) : (
          <>
            <DataTable
              columns={columns}
              data={uploads}
              rowKey={(row) => row.upload_id}
              emptyMessage="No PCAP uploads yet"
            />
            {pagination ? (
              <div className="mt-4">
                <Pagination pagination={pagination} onPageChange={setPage} />
              </div>
            ) : null}
          </>
        )}
      </div>

      <PacketAnalysisModal upload={selectedUpload} onClose={() => setSelectedUpload(null)} />
    </div>
  );
}
