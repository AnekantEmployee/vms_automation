"use client";

import { useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { useJobStore } from "@/store/useJobStore";
import { uploadExcel } from "@/lib/api";

export default function FileUpload() {
  const router = useRouter();
  const inputRef = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const setJob = useJobStore((s) => s.setJob);

  const handleFile = async (file: File) => {
    if (!file.name.endsWith(".xlsx") && !file.name.endsWith(".xls")) {
      setError("Please upload a valid Excel file (.xlsx or .xls)");
      return;
    }
    setError(null);
    setLoading(true);
    try {
      const { job_id, filename } = await uploadExcel(file);
      setJob(job_id, filename);
      router.push("/results");
    } catch {
      setError("Upload failed. Is the backend running?");
    } finally {
      setLoading(false);
    }
  };

  const onDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files[0];
    if (file) handleFile(file);
  };

  return (
    <div className="flex flex-col items-center justify-center min-h-screen bg-[#0a0a0f] px-4">
      {/* Title */}
      <div className="mb-12 text-center">
        <h1 className="text-5xl font-bold text-white tracking-tight mb-3" style={{ fontFamily: "'Syne', sans-serif" }}>
          Excel<span className="text-[#00ff9d]">Flow</span>
        </h1>
        <p className="text-zinc-400 text-lg">Upload your Excel file and watch rows process live</p>
      </div>

      {/* Drop zone */}
      <div
        onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
        onClick={() => inputRef.current?.click()}
        className={`
          relative w-full max-w-xl border-2 border-dashed rounded-2xl p-16
          flex flex-col items-center justify-center cursor-pointer
          transition-all duration-300
          ${dragging
            ? "border-[#00ff9d] bg-[#00ff9d10] scale-[1.02]"
            : "border-zinc-700 bg-zinc-900/50 hover:border-zinc-500 hover:bg-zinc-900"
          }
        `}
      >
        <input
          ref={inputRef}
          type="file"
          accept=".xlsx,.xls"
          className="hidden"
          onChange={(e) => e.target.files?.[0] && handleFile(e.target.files[0])}
        />

        {/* Icon */}
        <div className={`mb-6 p-5 rounded-2xl transition-colors ${dragging ? "bg-[#00ff9d20]" : "bg-zinc-800"}`}>
          <svg className={`w-10 h-10 ${dragging ? "text-[#00ff9d]" : "text-zinc-400"}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5}
              d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
          </svg>
        </div>

        <p className="text-white font-semibold text-lg mb-1">
          {dragging ? "Drop it!" : "Drop your Excel file here"}
        </p>
        <p className="text-zinc-500 text-sm">or click to browse — .xlsx, .xls supported</p>

        {loading && (
          <div className="mt-6 flex items-center gap-2 text-[#00ff9d] text-sm">
            <svg className="animate-spin w-4 h-4" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
            </svg>
            Uploading & starting processing...
          </div>
        )}
      </div>

      {error && (
        <p className="mt-4 text-red-400 text-sm bg-red-400/10 px-4 py-2 rounded-lg">
          {error}
        </p>
      )}
    </div>
  );
}
