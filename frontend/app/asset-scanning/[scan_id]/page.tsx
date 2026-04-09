"use client";

import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { getScan, deleteAsset, duration, type ScanDetail } from "@/lib/api";

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

export default function ScanDetailPage() {
  const { scan_id } = useParams<{ scan_id: string }>();
  const router = useRouter();
  const [scan, setScan]         = useState<ScanDetail | null>(null);
  const [loading, setLoading]   = useState(true);
  const [hovered, setHovered]   = useState<string | null>(null);
  const [deleting, setDeleting] = useState<string | null>(null);

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
            {scan.completed_at && (
              <span style={{ marginLeft: "12px", color: "#52525b" }}>
                · Duration: <span style={{ fontFamily: "monospace", color: "#a1a1aa" }}>{duration(scan.created_at, scan.completed_at)}</span>
              </span>
            )}
          </p>
        </div>
        <Badge status={scan.status} />
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
                {["#", "IP Address", "Role", "Environment", "Duration", "Risk Score", "Status", ""].map((h) => (
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
