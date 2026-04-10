"use client";

import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { useQualysStore } from "@/store/useQualysStore";
import { useAssetStore } from "@/store/useAssetStore";
import { formatSecs, searchByIp, type QualysScanSession, type AssetRow } from "@/lib/api";

const TH: React.CSSProperties = { fontSize: "11px", color: "#52525b", textTransform: "uppercase", letterSpacing: "0.06em", fontWeight: 600, padding: "12px 20px", textAlign: "left", whiteSpace: "nowrap" };
const TD: React.CSSProperties = { fontSize: "13px", color: "#d4d4d8", padding: "14px 20px", whiteSpace: "nowrap" };
const INPUT: React.CSSProperties = { width: "100%", background: "#111118", border: "1px solid #2a2a3a", borderRadius: "8px", padding: "9px 12px", fontSize: "13px", color: "white", outline: "none", boxSizing: "border-box" };

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, [string, string, string]> = {
    done:       ["rgba(16,185,129,0.1)", "#34d399", "rgba(16,185,129,0.2)"],
    processing: ["rgba(245,158,11,0.1)", "#fbbf24", "rgba(245,158,11,0.2)"],
    error:      ["rgba(239,68,68,0.1)",  "#f87171", "rgba(239,68,68,0.2)"],
  };
  const [bg, color, border] = map[status] ?? map.processing;
  return <span style={{ fontSize: "11px", padding: "3px 10px", borderRadius: "999px", background: bg, color, border: `1px solid ${border}`, fontWeight: 600 }}>{status}</span>;
}

// ── 2-step upload modal ───────────────────────────────────────────────────────

function UploadModal({ onClose, onSuccess }: { onClose: () => void; onSuccess: () => void }) {
  const inputRef = useRef<HTMLInputElement>(null);
  const { scans: assetScans, fetchScans: fetchAssetScans } = useAssetStore();
  const { upload } = useQualysStore();

  const [step, setStep]                   = useState<1 | 2>(1);
  const [selectedScanId, setSelectedScanId] = useState("");
  const [dragging, setDragging]           = useState(false);
  const [uploading, setUploading]         = useState(false);
  const [error, setError]                 = useState<string | null>(null);

  useEffect(() => { fetchAssetScans(); }, []);

  const selectedScan = assetScans.find((s) => s.id === selectedScanId);

  const handleFile = async (file: File) => {
    setError(null); setUploading(true);
    try {
      await upload(file, selectedScan?.scan_name || file.name);
      onSuccess(); onClose();
    } catch { setError("Upload failed. Check the file format and backend."); }
    finally { setUploading(false); }
  };

  return (
    <div style={{ position: "fixed", inset: 0, zIndex: 50, display: "flex", alignItems: "center", justifyContent: "center", background: "rgba(0,0,0,0.75)", backdropFilter: "blur(4px)" }}>
      <div style={{ background: "#0d0d14", border: "1px solid #1f1f2e", borderRadius: "16px", padding: "28px", width: "calc(100% - 48px)", maxWidth: "480px", boxSizing: "border-box" }}>

        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "20px" }}>
          <div>
            <span style={{ fontSize: "16px", fontWeight: 700, color: "white" }}>Upload Qualys Report</span>
            <div style={{ fontSize: "11px", color: "#52525b", marginTop: "3px" }}>Step {step} of 2</div>
          </div>
          <button onClick={onClose} style={{ background: "none", border: "none", color: "#71717a", cursor: "pointer", padding: "4px", lineHeight: 0 }}>
            <svg width="18" height="18" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
          </button>
        </div>

        {/* Progress bar */}
        <div style={{ display: "flex", gap: "8px", marginBottom: "24px" }}>
          {[1, 2].map((n) => (
            <div key={n} style={{ flex: 1, height: "3px", borderRadius: "2px", background: step >= n ? "#818cf8" : "#1f1f2e", transition: "background 0.2s" }} />
          ))}
        </div>

        {step === 1 ? (
          <>
            <p style={{ fontSize: "13px", color: "#a1a1aa", marginBottom: "16px", lineHeight: 1.6, marginTop: 0 }}>
              Select the <span style={{ color: "white", fontWeight: 600 }}>Asset Scan</span> this Qualys report belongs to. This links vulnerabilities to your scanned assets.
            </p>
            <label style={{ fontSize: "11px", color: "#71717a", textTransform: "uppercase", letterSpacing: "0.06em", display: "block", marginBottom: "6px" }}>Asset Scan</label>
            {assetScans.length === 0 ? (
              <div style={{ padding: "14px", background: "rgba(245,158,11,0.08)", border: "1px solid rgba(245,158,11,0.2)", borderRadius: "8px", fontSize: "12px", color: "#fbbf24" }}>
                No asset scans found. Create one in <strong>Asset Scanning</strong> first.
              </div>
            ) : (
              <select style={{ ...INPUT, cursor: "pointer" }} value={selectedScanId} onChange={(e) => setSelectedScanId(e.target.value)}>
                <option value="">— Choose an asset scan —</option>
                {assetScans.map((s) => (
                  <option key={s.id} value={s.id}>{s.scan_name || s.filename} ({s.total_assets} assets)</option>
                ))}
              </select>
            )}
            <button
              onClick={() => { if (!selectedScanId) { setError("Please select an asset scan."); return; } setError(null); setStep(2); }}
              disabled={assetScans.length === 0}
              style={{ marginTop: "20px", width: "100%", padding: "10px", background: assetScans.length === 0 ? "#1f1f2e" : "#818cf8", color: assetScans.length === 0 ? "#52525b" : "white", fontWeight: 700, fontSize: "13px", border: "none", borderRadius: "8px", cursor: assetScans.length === 0 ? "default" : "pointer" }}>
              Continue →
            </button>
          </>
        ) : (
          <>
            <div style={{ fontSize: "12px", color: "#71717a", marginBottom: "16px" }}>
              Uploading for: <span style={{ color: "#818cf8", fontWeight: 600 }}>{selectedScan?.scan_name || "—"}</span>
              <button onClick={() => setStep(1)} style={{ marginLeft: "10px", background: "none", border: "none", color: "#52525b", fontSize: "11px", cursor: "pointer", textDecoration: "underline" }}>change</button>
            </div>
            <div
              onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
              onDragLeave={() => setDragging(false)}
              onDrop={(e) => { e.preventDefault(); setDragging(false); const f = e.dataTransfer.files[0]; if (f) handleFile(f); }}
              onClick={() => inputRef.current?.click()}
              style={{ border: `2px dashed ${dragging ? "#818cf8" : "#2a2a3a"}`, borderRadius: "12px", padding: "32px 24px", display: "flex", flexDirection: "column", alignItems: "center", cursor: "pointer", background: dragging ? "rgba(129,140,248,0.04)" : "transparent", transition: "all 0.2s" }}
            >
              <input ref={inputRef} type="file" accept=".xlsx,.xls,.csv" style={{ display: "none" }} onChange={(e) => e.target.files?.[0] && handleFile(e.target.files[0])} />
              <svg width="28" height="28" fill="none" stroke={dragging ? "#818cf8" : "#52525b"} viewBox="0 0 24 24" style={{ marginBottom: "10px" }}>
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12" />
              </svg>
              <p style={{ fontSize: "13px", color: dragging ? "#818cf8" : "#a1a1aa", fontWeight: 500, margin: 0 }}>
                {uploading ? "Uploading..." : dragging ? "Drop it!" : "Drop Qualys report or click to browse"}
              </p>
              <p style={{ fontSize: "11px", color: "#52525b", marginTop: "4px", marginBottom: 0 }}>.xlsx, .xls, .csv</p>
            </div>
          </>
        )}

        {error && (
          <div style={{ marginTop: "12px", padding: "10px 14px", background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.2)", borderRadius: "8px", fontSize: "12px", color: "#f87171" }}>
            {error}
          </div>
        )}
      </div>
    </div>
  );
}

// ── Asset scan badge — looks up asset rows by IP ──────────────────────────────

export function AssetScanBadge({ ip }: { ip: string }) {
  const router = useRouter();
  const [rows, setRows] = useState<AssetRow[] | null>(null);

  useEffect(() => {
    if (!ip) { setRows([]); return; }
    searchByIp(ip).then(setRows).catch(() => setRows([]));
  }, [ip]);

  if (rows === null) return <span style={{ color: "#52525b", fontSize: "11px" }}>…</span>;
  if (rows.length === 0) return <span style={{ color: "#3f3f46", fontSize: "11px" }}>—</span>;

  const unique = Array.from(new Map(rows.map((r) => [r.scan_id, r])).values());
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
      {unique.map((r) => (
        <button key={r.scan_id}
          onClick={(e) => { e.stopPropagation(); router.push(`/asset-scanning/${r.scan_id}/${r.id}`); }}
          style={{ display: "flex", alignItems: "center", gap: "6px", background: "rgba(129,140,248,0.1)", border: "1px solid rgba(129,140,248,0.25)", borderRadius: "6px", padding: "3px 8px", fontSize: "11px", color: "#818cf8", cursor: "pointer", fontWeight: 600, whiteSpace: "nowrap" }}>
          <span style={{ color: "#a78bfa", fontFamily: "monospace" }}>{r.ip}</span>
          <span style={{ color: "#3f3f46" }}>·</span>
          <span style={{ color: "#6366f1", fontSize: "10px" }}>{r.scan_id.slice(0, 8)}…</span>
        </button>
      ))}
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function DashboardPage() {
  const router = useRouter();
  const { scans, loading, fetchScans, remove } = useQualysStore();
  const [showModal, setShowModal] = useState(false);
  const [hovered, setHovered]    = useState<string | null>(null);
  const [deleting, setDeleting]  = useState<string | null>(null);

  const handleDelete = async (e: React.MouseEvent, id: string) => {
    e.stopPropagation();
    if (!confirm("Delete this report and all its vulnerabilities?")) return;
    setDeleting(id);
    try { await remove(id); } finally { setDeleting(null); }
  };

  useEffect(() => { fetchScans(); }, []);

  useEffect(() => {
    if (!scans.some((s) => s.status === "processing")) return;
    const t = setInterval(fetchScans, 5000);
    return () => clearInterval(t);
  }, [scans]);

  const completed  = scans.filter((s) => s.status === "done").length;
  const processing = scans.filter((s) => s.status === "processing").length;
  const totalRows  = scans.reduce((a, s) => a + (s.total_rows ?? 0), 0);

  return (
    <div style={{ padding: "36px 40px", width: "100%", boxSizing: "border-box" }}>
      {showModal && <UploadModal onClose={() => setShowModal(false)} onSuccess={fetchScans} />}

      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "32px" }}>
        <div>
          <h1 style={{ fontSize: "22px", fontWeight: 700, color: "white", margin: 0 }}>Dashboard</h1>
          <p style={{ fontSize: "13px", color: "#71717a", marginTop: "4px", marginBottom: 0 }}>Overview of your vulnerability management activity</p>
        </div>
        <button onClick={() => setShowModal(true)}
          style={{ display: "flex", alignItems: "center", gap: "8px", padding: "10px 18px", background: "#818cf8", color: "white", fontSize: "13px", fontWeight: 700, borderRadius: "8px", border: "none", cursor: "pointer", flexShrink: 0 }}>
          <svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12" /></svg>
          Upload Report
        </button>
      </div>

      {/* Stats */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "16px", marginBottom: "28px" }}>
        {[
          { label: "Total Reports", value: scans.length, color: "white" },
          { label: "Completed",     value: completed,    color: "#34d399" },
          { label: "Processing",    value: processing,   color: "#fbbf24" },
          { label: "Total Vulns",   value: totalRows,    color: "white" },
        ].map((s) => (
          <div key={s.label} style={{ background: "#0d0d14", border: "1px solid #1f1f2e", borderRadius: "12px", padding: "20px 24px" }}>
            <div style={{ fontSize: "11px", color: "#71717a", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: "8px" }}>{s.label}</div>
            <div style={{ fontSize: "28px", fontWeight: 700, color: s.color }}>{s.value}</div>
          </div>
        ))}
      </div>

      {/* Report History */}
      <div style={{ background: "#0d0d14", border: "1px solid #1f1f2e", borderRadius: "12px", overflow: "hidden" }}>
        <div style={{ padding: "16px 20px", borderBottom: "1px solid #1f1f2e" }}>
          <span style={{ fontSize: "13px", fontWeight: 600, color: "white" }}>Report History</span>
        </div>
        {loading ? (
          <div style={{ padding: "64px 24px", textAlign: "center", color: "#52525b", fontSize: "13px" }}>Loading...</div>
        ) : scans.length === 0 ? (
          <div style={{ padding: "64px 24px", textAlign: "center", color: "#52525b", fontSize: "13px" }}>
            No reports yet.{" "}
            <span style={{ color: "#818cf8", cursor: "pointer" }} onClick={() => setShowModal(true)}>Upload a report</span> to get started.
          </div>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", minWidth: "800px" }}>
              <thead>
                <tr style={{ borderBottom: "1px solid #1f1f2e" }}>
                  {["Name", "File", "Vulnerabilities", "Asset Scan", "Duration", "Status", "Started", ""].map((h) => (
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
                    <td style={TD}>{scan.total_rows}</td>
                    <td style={{ ...TD }}>
                      <button onClick={(e) => { e.stopPropagation(); router.push(`/dashboard/${scan.id}`); }}
                        style={{ background: "rgba(129,140,248,0.1)", border: "1px solid rgba(129,140,248,0.25)", borderRadius: "6px", padding: "3px 10px", fontSize: "11px", color: "#818cf8", cursor: "pointer", fontWeight: 600 }}>
                        View IPs →
                      </button>
                    </td>
                    <td style={{ ...TD, fontFamily: "monospace", color: "#71717a" }}>{formatSecs(scan.total_asset_secs)}</td>
                    <td style={TD}><StatusBadge status={scan.status} /></td>
                    <td style={{ ...TD, color: "#71717a" }}>{new Date(scan.created_at).toLocaleString()}</td>
                    <td style={{ padding: "14px 20px" }} onClick={(e) => e.stopPropagation()}>
                      <button onClick={(e) => handleDelete(e, scan.id)} disabled={deleting === scan.id} title="Delete report"
                        style={{ background: "none", border: "none", cursor: deleting === scan.id ? "default" : "pointer", color: deleting === scan.id ? "#3f3f46" : "#52525b", padding: "4px", lineHeight: 0 }}>
                        <svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                        </svg>
                      </button>
                    </td>
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
