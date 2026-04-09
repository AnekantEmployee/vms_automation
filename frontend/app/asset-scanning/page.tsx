"use client";

import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { listScans, uploadExcel, type ScanSession } from "@/lib/api";

const S = {
  page:        { padding: "40px 48px", maxWidth: "1200px" } as React.CSSProperties,
  header:      { display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "32px" } as React.CSSProperties,
  h1:          { fontSize: "24px", fontWeight: 700, color: "white", margin: 0 } as React.CSSProperties,
  sub:         { fontSize: "13px", color: "#71717a", marginTop: "4px" } as React.CSSProperties,
  btn:         { display: "flex", alignItems: "center", gap: "8px", padding: "10px 18px", background: "#00ff9d", color: "#000", fontSize: "13px", fontWeight: 700, borderRadius: "8px", border: "none", cursor: "pointer" } as React.CSSProperties,
  statsGrid:   { display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "16px", marginBottom: "32px" } as React.CSSProperties,
  card:        { background: "#0d0d14", border: "1px solid #1f1f2e", borderRadius: "12px", padding: "20px 24px" } as React.CSSProperties,
  cardLabel:   { fontSize: "11px", color: "#71717a", textTransform: "uppercase" as const, letterSpacing: "0.05em", marginBottom: "8px" } as React.CSSProperties,
  cardValue:   { fontSize: "28px", fontWeight: 700, color: "white" } as React.CSSProperties,
  table:       { background: "#0d0d14", border: "1px solid #1f1f2e", borderRadius: "12px", overflow: "hidden" } as React.CSSProperties,
  tableHead:   { padding: "14px 24px", borderBottom: "1px solid #1f1f2e", display: "flex", alignItems: "center", justifyContent: "space-between" } as React.CSSProperties,
  th:          { fontSize: "11px", color: "#52525b", textTransform: "uppercase" as const, letterSpacing: "0.06em", fontWeight: 600 } as React.CSSProperties,
  tr:          { display: "grid", gridTemplateColumns: "2fr 80px 100px 160px 40px", alignItems: "center", padding: "0 24px", borderBottom: "1px solid #18181f", cursor: "pointer", transition: "background 0.15s" } as React.CSSProperties,
  td:          { padding: "14px 0", fontSize: "13px", color: "#d4d4d8" } as React.CSSProperties,
  empty:       { padding: "64px 24px", textAlign: "center" as const, color: "#52525b", fontSize: "13px" } as React.CSSProperties,
};

function badge(status: string) {
  const map: Record<string, { bg: string; color: string; border: string }> = {
    done:       { bg: "rgba(16,185,129,0.1)", color: "#34d399", border: "rgba(16,185,129,0.2)" },
    processing: { bg: "rgba(245,158,11,0.1)", color: "#fbbf24", border: "rgba(245,158,11,0.2)" },
    error:      { bg: "rgba(239,68,68,0.1)",  color: "#f87171", border: "rgba(239,68,68,0.2)" },
  };
  const c = map[status] ?? map.processing;
  return (
    <span style={{ fontSize: "11px", padding: "3px 10px", borderRadius: "999px", background: c.bg, color: c.color, border: `1px solid ${c.border}`, fontWeight: 600 }}>
      {status}
    </span>
  );
}

function NewScanModal({ onClose, onSuccess }: { onClose: () => void; onSuccess: () => void }) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);

  const handleFile = async (file: File) => {
    setError(null);
    setLoading(true);
    try {
      await uploadExcel(file);
      onSuccess();
      onClose();
    } catch {
      setError("Upload failed. Check the file format and backend.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ position: "fixed", inset: 0, zIndex: 50, display: "flex", alignItems: "center", justifyContent: "center", background: "rgba(0,0,0,0.7)", backdropFilter: "blur(4px)" }}>
      <div style={{ background: "#0d0d14", border: "1px solid #1f1f2e", borderRadius: "16px", padding: "32px", width: "100%", maxWidth: "460px", boxShadow: "0 25px 60px rgba(0,0,0,0.5)" }}>
        {/* Header */}
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "20px" }}>
          <span style={{ fontSize: "16px", fontWeight: 700, color: "white" }}>New Asset Scan</span>
          <button onClick={onClose} style={{ background: "none", border: "none", color: "#71717a", cursor: "pointer", padding: "4px" }}>
            <svg width="18" height="18" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <p style={{ fontSize: "12px", color: "#71717a", marginBottom: "20px", lineHeight: 1.6 }}>
          Upload an Excel file with columns:<br />
          <code style={{ color: "#00ff9d", fontSize: "11px" }}>asset_ip, asset_role, data_classification, environment, owner_email</code>
        </p>

        {/* Drop zone */}
        <div
          onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
          onDragLeave={() => setDragging(false)}
          onDrop={(e) => { e.preventDefault(); setDragging(false); const f = e.dataTransfer.files[0]; if (f) handleFile(f); }}
          onClick={() => inputRef.current?.click()}
          style={{
            border: `2px dashed ${dragging ? "#00ff9d" : "#2a2a3a"}`,
            borderRadius: "12px",
            padding: "40px 24px",
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            cursor: "pointer",
            background: dragging ? "rgba(0,255,157,0.04)" : "transparent",
            transition: "all 0.2s",
          }}
        >
          <input ref={inputRef} type="file" accept=".xlsx,.xls,.csv" style={{ display: "none" }}
            onChange={(e) => e.target.files?.[0] && handleFile(e.target.files[0])} />
          <svg width="32" height="32" fill="none" stroke={dragging ? "#00ff9d" : "#52525b"} viewBox="0 0 24 24" style={{ marginBottom: "12px" }}>
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12" />
          </svg>
          <p style={{ fontSize: "13px", color: dragging ? "#00ff9d" : "#a1a1aa", fontWeight: 500 }}>
            {dragging ? "Drop it!" : "Drop file or click to browse"}
          </p>
          <p style={{ fontSize: "11px", color: "#52525b", marginTop: "4px" }}>.xlsx, .xls, .csv</p>
          {loading && <p style={{ fontSize: "12px", color: "#00ff9d", marginTop: "12px" }}>Uploading...</p>}
        </div>

        {error && (
          <div style={{ marginTop: "12px", padding: "10px 14px", background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.2)", borderRadius: "8px", fontSize: "12px", color: "#f87171" }}>
            {error}
          </div>
        )}
      </div>
    </div>
  );
}

export default function AssetScanningPage() {
  const router = useRouter();
  const [scans, setScans]         = useState<ScanSession[]>([]);
  const [loading, setLoading]     = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [hovered, setHovered]     = useState<string | null>(null);

  const fetchScans = async () => {
    try { setScans(await listScans()); } finally { setLoading(false); }
  };

  useEffect(() => { fetchScans(); }, []);

  useEffect(() => {
    if (!scans.some((s) => s.status === "processing")) return;
    const t = setInterval(fetchScans, 5000);
    return () => clearInterval(t);
  }, [scans]);

  return (
    <div style={S.page}>
      {showModal && <NewScanModal onClose={() => setShowModal(false)} onSuccess={fetchScans} />}

      {/* Header */}
      <div style={S.header}>
        <div>
          <h1 style={S.h1}>Asset Scanning</h1>
          <p style={S.sub}>Upload and analyse asset lists</p>
        </div>
        <button style={S.btn} onClick={() => setShowModal(true)}>
          <svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M12 4v16m8-8H4" />
          </svg>
          New Scan
        </button>
      </div>

      {/* Stats */}
      <div style={S.statsGrid}>
        {[
          { label: "Total Scans",  value: scans.length },
          { label: "Completed",    value: scans.filter((s) => s.status === "done").length },
          { label: "Total Assets", value: scans.reduce((a, s) => a + (s.total_assets ?? 0), 0) },
        ].map((stat) => (
          <div key={stat.label} style={S.card}>
            <div style={S.cardLabel}>{stat.label}</div>
            <div style={S.cardValue}>{stat.value}</div>
          </div>
        ))}
      </div>

      {/* Table */}
      <div style={S.table}>
        <div style={S.tableHead}>
          <span style={{ fontSize: "13px", fontWeight: 600, color: "white" }}>Scan History</span>
        </div>

        {loading ? (
          <div style={S.empty}>Loading...</div>
        ) : scans.length === 0 ? (
          <div style={S.empty}>No scans yet. Click <span style={{ color: "#00ff9d" }}>New Scan</span> to get started.</div>
        ) : (
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr style={{ borderBottom: "1px solid #1f1f2e" }}>
                {["Filename", "Assets", "Status", "Date", ""].map((h) => (
                  <th key={h} style={{ ...S.th, padding: "12px 24px", textAlign: "left" as const }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {scans.map((scan) => (
                <tr
                  key={scan.id}
                  onClick={() => router.push(`/asset-scanning/${scan.id}`)}
                  onMouseEnter={() => setHovered(scan.id)}
                  onMouseLeave={() => setHovered(null)}
                  style={{ borderBottom: "1px solid #18181f", cursor: "pointer", background: hovered === scan.id ? "#111118" : "transparent", transition: "background 0.15s" }}
                >
                  <td style={{ ...S.td, padding: "14px 24px", color: "white", fontWeight: 500 }}>{scan.filename || "—"}</td>
                  <td style={{ ...S.td, padding: "14px 24px" }}>{scan.total_assets}</td>
                  <td style={{ ...S.td, padding: "14px 24px" }}>{badge(scan.status)}</td>
                  <td style={{ ...S.td, padding: "14px 24px", color: "#71717a" }}>{new Date(scan.created_at).toLocaleString()}</td>
                  <td style={{ padding: "14px 24px", textAlign: "right" as const }}>
                    <svg width="14" height="14" fill="none" stroke="#52525b" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                    </svg>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
