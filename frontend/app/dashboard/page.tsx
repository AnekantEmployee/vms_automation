"use client";

import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { useAssetStore } from "@/store/useAssetStore";
import { formatSecs } from "@/lib/api";

const TH: React.CSSProperties = { fontSize: "11px", color: "#52525b", textTransform: "uppercase", letterSpacing: "0.06em", fontWeight: 600, padding: "12px 20px", textAlign: "left", whiteSpace: "nowrap" };
const TD: React.CSSProperties = { fontSize: "13px", color: "#d4d4d8", padding: "14px 20px", whiteSpace: "nowrap" };

function Badge({ status }: { status: string }) {
  const map: Record<string, [string, string, string]> = {
    done:       ["rgba(16,185,129,0.1)", "#34d399", "rgba(16,185,129,0.2)"],
    processing: ["rgba(245,158,11,0.1)", "#fbbf24", "rgba(245,158,11,0.2)"],
    error:      ["rgba(239,68,68,0.1)",  "#f87171", "rgba(239,68,68,0.2)"],
  };
  const [bg, color, border] = map[status] ?? map.processing;
  return <span style={{ fontSize: "11px", padding: "3px 10px", borderRadius: "999px", background: bg, color, border: `1px solid ${border}`, fontWeight: 600 }}>{status}</span>;
}

export default function DashboardPage() {
  const router = useRouter();
  const inputRef = useRef<HTMLInputElement>(null);
  const { scans, loading, fetchScans, upload } = useAssetStore();
  const [hovered, setHovered]   = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);

  useEffect(() => { fetchScans(); }, []);

  useEffect(() => {
    if (!scans.some((s) => s.status === "processing")) return;
    const t = setInterval(fetchScans, 5000);
    return () => clearInterval(t);
  }, [scans]);

  const handleFile = async (file: File) => {
    setUploadError(null); setUploading(true);
    try { await upload(file, file.name); }
    catch { setUploadError("Upload failed. Check the file format and backend."); }
    finally { setUploading(false); }
  };

  const totalAssets   = scans.reduce((a, s) => a + (s.total_assets ?? 0), 0);
  const completed     = scans.filter((s) => s.status === "done").length;
  const processing    = scans.filter((s) => s.status === "processing").length;

  return (
    <div style={{ padding: "36px 40px", width: "100%", boxSizing: "border-box" }}>

      {/* Header */}
      <div style={{ marginBottom: "32px" }}>
        <h1 style={{ fontSize: "22px", fontWeight: 700, color: "white", margin: 0 }}>Dashboard</h1>
        <p style={{ fontSize: "13px", color: "#71717a", marginTop: "4px", marginBottom: 0 }}>Overview of your vulnerability management activity</p>
      </div>

      {/* Stats */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "16px", marginBottom: "28px" }}>
        {[
          { label: "Total Scans",    value: scans.length,  color: "white" },
          { label: "Completed",      value: completed,     color: "#34d399" },
          { label: "Processing",     value: processing,    color: "#fbbf24" },
          { label: "Total Assets",   value: totalAssets,   color: "white" },
        ].map((s) => (
          <div key={s.label} style={{ background: "#0d0d14", border: "1px solid #1f1f2e", borderRadius: "12px", padding: "20px 24px" }}>
            <div style={{ fontSize: "11px", color: "#71717a", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: "8px" }}>{s.label}</div>
            <div style={{ fontSize: "28px", fontWeight: 700, color: s.color }}>{s.value}</div>
          </div>
        ))}
      </div>

      {/* Upload */}
      <div style={{ background: "#0d0d14", border: "1px solid #1f1f2e", borderRadius: "12px", padding: "20px 24px", marginBottom: "28px" }}>
        <div style={{ fontSize: "11px", color: "#71717a", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: "12px" }}>Quick Scan Upload</div>
        <div
          onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
          onDragLeave={() => setDragging(false)}
          onDrop={(e) => { e.preventDefault(); setDragging(false); const f = e.dataTransfer.files[0]; if (f) handleFile(f); }}
          onClick={() => inputRef.current?.click()}
          style={{ border: `2px dashed ${dragging ? "#00ff9d" : "#2a2a3a"}`, borderRadius: "12px", padding: "28px 24px", display: "flex", flexDirection: "column", alignItems: "center", cursor: "pointer", background: dragging ? "rgba(0,255,157,0.04)" : "transparent", transition: "all 0.2s" }}
        >
          <input ref={inputRef} type="file" accept=".xlsx,.xls,.csv" style={{ display: "none" }} onChange={(e) => e.target.files?.[0] && handleFile(e.target.files[0])} />
          <svg width="28" height="28" fill="none" stroke={dragging ? "#00ff9d" : "#52525b"} viewBox="0 0 24 24" style={{ marginBottom: "10px" }}>
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12" />
          </svg>
          <p style={{ fontSize: "13px", color: dragging ? "#00ff9d" : "#a1a1aa", fontWeight: 500, margin: 0 }}>
            {uploading ? "Uploading..." : dragging ? "Drop it!" : "Drop file or click to browse"}
          </p>
          <p style={{ fontSize: "11px", color: "#52525b", marginTop: "4px", marginBottom: 0 }}>.xlsx, .xls, .csv</p>
        </div>
        {uploadError && (
          <div style={{ marginTop: "12px", padding: "10px 14px", background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.2)", borderRadius: "8px", fontSize: "12px", color: "#f87171" }}>
            {uploadError}
          </div>
        )}
      </div>

      {/* Scan History */}
      <div style={{ background: "#0d0d14", border: "1px solid #1f1f2e", borderRadius: "12px", overflow: "hidden" }}>
        <div style={{ padding: "16px 20px", borderBottom: "1px solid #1f1f2e" }}>
          <span style={{ fontSize: "13px", fontWeight: 600, color: "white" }}>Scan History</span>
        </div>
        {loading ? (
          <div style={{ padding: "64px 24px", textAlign: "center", color: "#52525b", fontSize: "13px" }}>Loading...</div>
        ) : scans.length === 0 ? (
          <div style={{ padding: "64px 24px", textAlign: "center", color: "#52525b", fontSize: "13px" }}>
            No scans yet. Upload a file above to get started.
          </div>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", minWidth: "700px" }}>
              <thead>
                <tr style={{ borderBottom: "1px solid #1f1f2e" }}>
                  {["Name", "File", "Assets", "Duration", "Status", "Started"].map((h) => (
                    <th key={h} style={TH}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {scans.map((scan) => (
                  <tr key={scan.id}
                    onClick={() => router.push(`/dashboard/${scan.id}`)}
                    onMouseEnter={() => setHovered(scan.id)}
                    onMouseLeave={() => setHovered(null)}
                    style={{ borderBottom: "1px solid #18181f", cursor: "pointer", background: hovered === scan.id ? "#111118" : "transparent", transition: "background 0.15s" }}>
                    <td style={{ ...TD, color: "white", fontWeight: 600 }}>{scan.scan_name || scan.filename || "—"}</td>
                    <td style={{ ...TD, color: "#71717a", fontSize: "12px" }}>{scan.filename || "—"}</td>
                    <td style={TD}>{scan.total_assets}</td>
                    <td style={{ ...TD, fontFamily: "monospace", color: "#71717a" }}>{formatSecs(scan.total_asset_secs)}</td>
                    <td style={TD}><Badge status={scan.status} /></td>
                    <td style={{ ...TD, color: "#71717a" }}>{new Date(scan.created_at).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
