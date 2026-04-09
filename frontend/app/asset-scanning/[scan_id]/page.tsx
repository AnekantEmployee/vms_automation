"use client";

import { useEffect, useRef, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { getScan, deleteAsset, addManualAssets, addExcelAssets, duration, type ScanDetail, type ManualAsset } from "@/lib/api";

function Badge({ status }: { status: string }) {
  const map: Record<string, [string, string, string]> = {
    done:       ["rgba(16,185,129,0.1)", "#34d399", "rgba(16,185,129,0.2)"],
    pending:    ["rgba(245,158,11,0.1)", "#fbbf24", "rgba(245,158,11,0.2)"],
    processing: ["rgba(245,158,11,0.1)", "#fbbf24", "rgba(245,158,11,0.2)"],
    error:      ["rgba(239,68,68,0.1)",  "#f87171", "rgba(239,68,68,0.2)"],
  };
  const [bg, color, border] = map[status] ?? map.pending;
  return <span style={{ fontSize: "11px", padding: "3px 10px", borderRadius: "999px", background: bg, color, border: `1px solid ${border}`, fontWeight: 600, whiteSpace: "nowrap" }}>{status}</span>;
}

function ScoreBar({ score }: { score: number }) {
  const color = score >= 7 ? "#ef4444" : score >= 4 ? "#f59e0b" : "#00ff9d";
  return (
    <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
      <div style={{ width: "64px", height: "4px", background: "#1f1f2e", borderRadius: "4px", overflow: "hidden", flexShrink: 0 }}>
        <div style={{ height: "100%", width: `${(score / 10) * 100}%`, background: color, borderRadius: "4px" }} />
      </div>
      <span style={{ fontSize: "12px", color: "#d4d4d8", whiteSpace: "nowrap" }}>{score}/10</span>
    </div>
  );
}

function Scanning() {
  return (
    <span style={{ color: "#fbbf24", display: "flex", alignItems: "center", gap: "5px", fontSize: "11px", whiteSpace: "nowrap" }}>
      <span style={{ width: "6px", height: "6px", borderRadius: "50%", background: "#fbbf24", display: "inline-block", animation: "pulse 1.5s infinite", flexShrink: 0 }} />
      Scanning...
    </span>
  );
}

const TH: React.CSSProperties = { fontSize: "11px", color: "#52525b", textTransform: "uppercase", letterSpacing: "0.06em", fontWeight: 600, padding: "12px 16px", textAlign: "left", whiteSpace: "nowrap" };
const TD: React.CSSProperties = { padding: "13px 16px", fontSize: "13px", color: "#d4d4d8", whiteSpace: "nowrap" };
const INPUT: React.CSSProperties = { width: "100%", background: "#111118", border: "1px solid #2a2a3a", borderRadius: "8px", padding: "9px 12px", fontSize: "13px", color: "white", outline: "none", boxSizing: "border-box" };

function AddAssetsModal({ scanId, onClose, onSuccess }: { scanId: string; onClose: () => void; onSuccess: () => void }) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [tab, setTab]         = useState<"excel" | "manual">("excel");
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);
  const [ip, setIp]     = useState("");
  const [role, setRole] = useState("");
  const [dc, setDc]     = useState("internal");
  const [env, setEnv]   = useState("production");
  const [owner, setOwner] = useState("");

  const handleFile = async (file: File) => {
    setError(null); setLoading(true);
    try { await addExcelAssets(scanId, file); onSuccess(); onClose(); }
    catch { setError("Upload failed."); }
    finally { setLoading(false); }
  };

  const handleManual = async () => {
    if (!ip.trim()) { setError("IP address is required."); return; }
    setError(null); setLoading(true);
    try {
      const asset: ManualAsset = { ip, declared_role: role, data_classification: dc, environment: env, owner };
      await addManualAssets(scanId, [asset]);
      onSuccess(); onClose();
    } catch { setError("Failed to add asset."); }
    finally { setLoading(false); }
  };

  const tabStyle = (active: boolean): React.CSSProperties => ({
    flex: 1, padding: "8px", fontSize: "12px", fontWeight: 600, border: "none", cursor: "pointer", borderRadius: "6px",
    background: active ? "#1f1f2e" : "transparent", color: active ? "white" : "#71717a", transition: "all 0.15s",
  });

  return (
    <div style={{ position: "fixed", inset: 0, zIndex: 50, display: "flex", alignItems: "center", justifyContent: "center", background: "rgba(0,0,0,0.75)", backdropFilter: "blur(4px)" }}>
      <div style={{ background: "#0d0d14", border: "1px solid #1f1f2e", borderRadius: "16px", padding: "28px", width: "calc(100% - 48px)", maxWidth: "460px", boxSizing: "border-box" }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "20px" }}>
          <span style={{ fontSize: "16px", fontWeight: 700, color: "white" }}>Add Assets</span>
          <button onClick={onClose} style={{ background: "none", border: "none", color: "#71717a", cursor: "pointer", padding: "4px", lineHeight: 0 }}>
            <svg width="18" height="18" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
          </button>
        </div>
        <div style={{ display: "flex", gap: "4px", background: "#111118", borderRadius: "8px", padding: "4px", marginBottom: "20px" }}>
          <button style={tabStyle(tab === "excel")}  onClick={() => setTab("excel")}>📄 Upload Excel</button>
          <button style={tabStyle(tab === "manual")} onClick={() => setTab("manual")}>✏️ Manual Entry</button>
        </div>
        {tab === "excel" ? (
          <div
            onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
            onDragLeave={() => setDragging(false)}
            onDrop={(e) => { e.preventDefault(); setDragging(false); const f = e.dataTransfer.files[0]; if (f) handleFile(f); }}
            onClick={() => inputRef.current?.click()}
            style={{ border: `2px dashed ${dragging ? "#00ff9d" : "#2a2a3a"}`, borderRadius: "12px", padding: "32px 24px", display: "flex", flexDirection: "column", alignItems: "center", cursor: "pointer", background: dragging ? "rgba(0,255,157,0.04)" : "transparent" }}
          >
            <input ref={inputRef} type="file" accept=".xlsx,.xls,.csv" style={{ display: "none" }} onChange={(e) => e.target.files?.[0] && handleFile(e.target.files[0])} />
            <svg width="28" height="28" fill="none" stroke={dragging ? "#00ff9d" : "#52525b"} viewBox="0 0 24 24" style={{ marginBottom: "10px" }}>
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12" />
            </svg>
            <p style={{ fontSize: "13px", color: dragging ? "#00ff9d" : "#a1a1aa", fontWeight: 500, margin: 0 }}>{dragging ? "Drop it!" : "Drop file or click to browse"}</p>
            <p style={{ fontSize: "11px", color: "#52525b", marginTop: "4px", marginBottom: 0 }}>.xlsx, .xls, .csv</p>
            {loading && <p style={{ fontSize: "12px", color: "#00ff9d", marginTop: "10px", marginBottom: 0 }}>Uploading...</p>}
          </div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
            {[
              { label: "IP Address *", value: ip, set: setIp, placeholder: "e.g. 192.168.1.1" },
              { label: "Role", value: role, set: setRole, placeholder: "e.g. Web Server (optional)" },
              { label: "Owner Email", value: owner, set: setOwner, placeholder: "team@example.com (optional)" },
            ].map(({ label, value, set, placeholder }) => (
              <div key={label}>
                <label style={{ fontSize: "11px", color: "#71717a", textTransform: "uppercase", letterSpacing: "0.06em", display: "block", marginBottom: "5px" }}>{label}</label>
                <input style={INPUT} placeholder={placeholder} value={value} onChange={(e) => set(e.target.value)} />
              </div>
            ))}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px" }}>
              <div>
                <label style={{ fontSize: "11px", color: "#71717a", textTransform: "uppercase", letterSpacing: "0.06em", display: "block", marginBottom: "5px" }}>Classification</label>
                <select style={{ ...INPUT, cursor: "pointer" }} value={dc} onChange={(e) => setDc(e.target.value)}>
                  {["public", "internal", "confidential", "restricted"].map((v) => <option key={v} value={v}>{v}</option>)}
                </select>
              </div>
              <div>
                <label style={{ fontSize: "11px", color: "#71717a", textTransform: "uppercase", letterSpacing: "0.06em", display: "block", marginBottom: "5px" }}>Environment</label>
                <select style={{ ...INPUT, cursor: "pointer" }} value={env} onChange={(e) => setEnv(e.target.value)}>
                  {["production", "staging", "development", "dr"].map((v) => <option key={v} value={v}>{v}</option>)}
                </select>
              </div>
            </div>
            <button onClick={handleManual} disabled={loading}
              style={{ marginTop: "4px", padding: "10px", background: loading ? "#1f1f2e" : "#00ff9d", color: "#000", fontWeight: 700, fontSize: "13px", border: "none", borderRadius: "8px", cursor: loading ? "default" : "pointer" }}>
              {loading ? "Adding..." : "Add Asset"}
            </button>
          </div>
        )}
        {error && <div style={{ marginTop: "12px", padding: "10px 14px", background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.2)", borderRadius: "8px", fontSize: "12px", color: "#f87171" }}>{error}</div>}
      </div>
    </div>
  );
}

export default function ScanDetailPage() {
  const { scan_id } = useParams<{ scan_id: string }>();
  const router = useRouter();
  const [scan, setScan]         = useState<ScanDetail | null>(null);
  const [loading, setLoading]   = useState(true);
  const [hovered, setHovered]     = useState<string | null>(null);
  const [deleting, setDeleting]   = useState<string | null>(null);
  const [showAdd, setShowAdd]     = useState(false);

  const fetchScan = async () => {
    try { setScan(await getScan(scan_id)); } finally { setLoading(false); }
  };

  const handleDelete = async (e: React.MouseEvent, rowId: string) => {
    e.stopPropagation();
    if (!confirm("Delete this asset?")) return;
    setDeleting(rowId);
    try { await deleteAsset(scan_id, rowId); await fetchScan(); } finally { setDeleting(null); }
  };

  useEffect(() => { fetchScan(); }, [scan_id]);

  useEffect(() => {
    if (!scan?.assets.some((a) => a.status === "pending")) return;
    const t = setInterval(fetchScan, 5000);
    return () => clearInterval(t);
  }, [scan]);

  if (loading) return <div style={{ padding: "48px", color: "#71717a" }}>Loading...</div>;
  if (!scan)   return <div style={{ padding: "48px", color: "#f87171" }}>Scan not found.</div>;

  const done     = scan.assets.filter((a) => a.status === "done").length;
  const pending  = scan.assets.filter((a) => a.status === "pending").length;
  const errors   = scan.assets.filter((a) => a.status === "error").length;
  const progress = scan.total_assets ? Math.round((done / scan.total_assets) * 100) : 0;

  return (
    <div style={{ padding: "36px 40px", width: "100%", boxSizing: "border-box" }}>
      {showAdd && <AddAssetsModal scanId={scan_id} onClose={() => setShowAdd(false)} onSuccess={fetchScan} />}
      {/* Back */}
      <button onClick={() => router.push("/asset-scanning")}
        style={{ display: "flex", alignItems: "center", gap: "6px", background: "none", border: "none", color: "#71717a", cursor: "pointer", fontSize: "13px", marginBottom: "24px", padding: 0 }}>
        <svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
        </svg>
        Back to scans
      </button>

      {/* Header */}
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", marginBottom: "28px", gap: "16px" }}>
        <div style={{ minWidth: 0 }}>
          <h1 style={{ fontSize: "22px", fontWeight: 700, color: "white", margin: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{scan.filename || "Scan"}</h1>
          <p style={{ fontSize: "12px", color: "#71717a", marginTop: "4px", marginBottom: 0 }}>
            {new Date(scan.created_at).toLocaleString()}
          </p>
        </div>
        <Badge status={scan.status} />
        <button onClick={() => setShowAdd(true)}
          style={{ display: "flex", alignItems: "center", gap: "6px", padding: "8px 14px", background: "transparent", border: "1px solid #2a2a3a", color: "#a1a1aa", fontSize: "12px", fontWeight: 600, borderRadius: "8px", cursor: "pointer" }}>
          <svg width="12" height="12" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M12 4v16m8-8H4" /></svg>
          Add Assets
        </button>
      </div>

      {/* Stats */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "14px", marginBottom: "24px" }}>
        {[
          { label: "Total",     value: scan.total_assets, color: "white" },
          { label: "Completed", value: done,    color: "#34d399" },
          { label: "Pending",   value: pending, color: "#fbbf24" },
          { label: "Errors",    value: errors,  color: "#f87171" },
        ].map((s) => (
          <div key={s.label} style={{ background: "#0d0d14", border: "1px solid #1f1f2e", borderRadius: "12px", padding: "18px 20px" }}>
            <div style={{ fontSize: "11px", color: "#71717a", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: "6px" }}>{s.label}</div>
            <div style={{ fontSize: "24px", fontWeight: 700, color: s.color }}>{s.value}</div>
          </div>
        ))}
      </div>

      {/* Progress */}
      {scan.status !== "done" && (
        <div style={{ background: "#0d0d14", border: "1px solid #1f1f2e", borderRadius: "12px", padding: "18px 20px", marginBottom: "24px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", fontSize: "12px", color: "#71717a", marginBottom: "10px" }}>
            <span>Processing assets...</span>
            <span>{progress}%</span>
          </div>
          <div style={{ height: "4px", background: "#1f1f2e", borderRadius: "4px", overflow: "hidden" }}>
            <div style={{ height: "100%", width: `${progress}%`, background: "#00ff9d", borderRadius: "4px", transition: "width 0.5s" }} />
          </div>
        </div>
      )}

      {/* Assets Table */}
      <div style={{ background: "#0d0d14", border: "1px solid #1f1f2e", borderRadius: "12px", overflow: "hidden" }}>
        <div style={{ padding: "14px 20px", borderBottom: "1px solid #1f1f2e" }}>
          <span style={{ fontSize: "13px", fontWeight: 600, color: "white" }}>Assets ({scan.assets.length})</span>
        </div>
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", minWidth: "780px" }}>
            <thead>
              <tr style={{ borderBottom: "1px solid #1f1f2e" }}>
                {["#", "IP Address", "Role", "Environment", "Time Taken", "Risk Score", "Status", ""].map((h) => (
                  <th key={h} style={TH}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {scan.assets.map((asset) => {
                const score     = asset.result?.score as number | undefined;
                const clickable = asset.status === "done";
                return (
                  <tr
                    key={asset.id}
                    onClick={() => clickable && router.push(`/asset-scanning/${scan_id}/${asset.id}`)}
                    onMouseEnter={() => clickable && setHovered(asset.id)}
                    onMouseLeave={() => setHovered(null)}
                    style={{ borderBottom: "1px solid #18181f", cursor: clickable ? "pointer" : "default", background: hovered === asset.id ? "#111118" : "transparent", opacity: asset.status === "pending" ? 0.6 : 1, transition: "background 0.15s" }}
                  >
                    <td style={{ ...TD, color: "#52525b", fontSize: "12px" }}>{asset.row_index + 1}</td>
                    <td style={{ ...TD, color: "white", fontFamily: "monospace", fontWeight: 500 }}>{asset.ip}</td>
                    <td style={{ ...TD, color: "#a1a1aa", maxWidth: "160px", overflow: "hidden", textOverflow: "ellipsis" }}>{asset.declared_role || "—"}</td>
                    <td style={{ ...TD, color: "#71717a" }}>{asset.environment}</td>
                    <td style={{ ...TD, fontFamily: "monospace", color: "#71717a", fontSize: "12px" }}>
                      {asset.status === "done" ? duration(asset.started_at, asset.scanned_at) : asset.status === "pending" ? <Scanning /> : "—"}
                    </td>
                    <td style={TD}>
                      {score !== undefined ? <ScoreBar score={score} /> : asset.status === "pending" ? <Scanning /> : <span style={{ color: "#3f3f46" }}>—</span>}
                    </td>
                    <td style={TD}><Badge status={asset.status} /></td>
                    <td style={{ padding: "13px 16px", whiteSpace: "nowrap" }}>
                      <div style={{ display: "flex", alignItems: "center", justifyContent: "flex-end", gap: "10px" }}>
                        <button
                          onClick={(e) => handleDelete(e, asset.id)}
                          disabled={deleting === asset.id}
                          title="Delete asset"
                          style={{ background: "none", border: "none", cursor: "pointer", color: deleting === asset.id ? "#3f3f46" : "#52525b", padding: "4px", lineHeight: 0 }}
                        >
                          <svg width="13" height="13" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                          </svg>
                        </button>
                        {clickable && (
                          <svg width="13" height="13" fill="none" stroke="#52525b" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                          </svg>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
