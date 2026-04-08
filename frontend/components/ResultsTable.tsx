"use client";

import { useJobStore } from "@/store/useJobStore";
import { useRouter } from "next/navigation";

function stripHtml(val: unknown): string {
  if (val === null || val === undefined) return "—";
  return String(val).replace(/<[^>]*>/g, "").trim() || "—";
}
export default function ResultsTable() {
  const results     = useJobStore((s) => s.results);
  const isDone       = useJobStore((s) => s.isDone);
  const isConnected  = useJobStore((s) => s.isConnected);
  const filename     = useJobStore((s) => s.filename);
  const jobId        = useJobStore((s) => s.jobId);
  const reset        = useJobStore((s) => s.reset);
  const total_rows   = results[0]?.total_rows ?? null;
  const router = useRouter();

  const progress = total_rows ? Math.round((results.length / total_rows) * 100) : 0;

  const handleNewUpload = () => {
    reset();
    router.push("/");
  };

  if (!jobId) {
    return (
      <div className="flex flex-col items-center justify-center min-h-screen bg-[#0a0a0f]">
        <p className="text-zinc-400 mb-4">No active job found.</p>
        <button onClick={handleNewUpload} className="px-5 py-2 bg-[#00ff9d] text-black font-semibold rounded-lg">
          Upload a file
        </button>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#0a0a0f] px-6 py-10" style={{ fontFamily: "'Syne', sans-serif" }}>
      {/* Header */}
      <div className="max-w-6xl mx-auto mb-8">
        <div className="flex items-center justify-between flex-wrap gap-4">
          <div>
            <h1 className="text-3xl font-bold text-white">
              Excel<span className="text-[#00ff9d]">Flow</span>
            </h1>
            <p className="text-zinc-500 text-sm mt-1">{filename}</p>
          </div>

          {/* Status badge */}
          <div className="flex items-center gap-3">
            {!isDone && (
              <span className="flex items-center gap-2 text-sm text-[#00ff9d] bg-[#00ff9d15] px-3 py-1.5 rounded-full">
                <span className={`w-2 h-2 rounded-full ${isConnected ? "bg-[#00ff9d] animate-pulse" : "bg-zinc-500"}`} />
                {isConnected ? "Processing live..." : "Connecting..."}
              </span>
            )}
            {isDone && (
              <span className="flex items-center gap-2 text-sm text-white bg-zinc-800 px-3 py-1.5 rounded-full">
                ✅ Complete — {results.length} rows processed
              </span>
            )}
            <button
              onClick={handleNewUpload}
              className="px-4 py-2 text-sm bg-zinc-800 hover:bg-zinc-700 text-white rounded-lg transition-colors"
            >
              New Upload
            </button>
          </div>
        </div>

        {/* Progress bar */}
        {!isDone && total_rows && (
          <div className="mt-6">
            <div className="flex justify-between text-xs text-zinc-500 mb-2">
              <span>{results.length} / {total_rows} rows</span>
              <span>{progress}%</span>
            </div>
            <div className="w-full h-1.5 bg-zinc-800 rounded-full overflow-hidden">
              <div
                className="h-full bg-[#00ff9d] rounded-full transition-all duration-500"
                style={{ width: `${progress}%` }}
              />
            </div>
          </div>
        )}
      </div>

      {/* Table */}
      <div className="max-w-6xl mx-auto">
        {results.length === 0 ? (
          <div className="text-center py-24 text-zinc-600">
            <div className="text-4xl mb-3">⏳</div>
            <p>Waiting for first row result...</p>
          </div>
        ) : (
          <div className="rounded-xl border border-zinc-800 overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="bg-zinc-900 border-b border-zinc-800">
                    <th className="text-left px-4 py-3 text-zinc-400 font-medium">#</th>
                    {Object.keys(results[0].row_data).map((col) => (
                      <th key={col} className="text-left px-4 py-3 text-zinc-400 font-medium">
                        {col}
                      </th>
                    ))}
                    <th className="text-left px-4 py-3 text-zinc-400 font-medium">Result</th>
                  </tr>
                </thead>
                <tbody>
                  {results.map((row, i) => (
                    <tr
                      key={row.row_index}
                      className={`border-b border-zinc-800/50 transition-colors
                        ${i === results.length - 1 ? "bg-[#00ff9d08]" : "hover:bg-zinc-900/50"}
                      `}
                    >
                      <td className="px-4 py-3 text-zinc-500">{row.row_index + 1}</td>
                      {Object.values(row.row_data).map((val, j) => (
                        <td key={j} className="px-4 py-3 text-zinc-300">
                          {stripHtml(val)}
                        </td>
                      ))}
                      <td className="px-4 py-3">
                        <span className="text-[#00ff9d] text-xs bg-[#00ff9d10] px-2 py-1 rounded">
                          {JSON.stringify(row.result)}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
