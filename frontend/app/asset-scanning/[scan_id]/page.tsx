"use client";

import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { getScan, type ScanDetail } from "@/lib/api";

function badge(status: string) {
  const map: Record<string, { bg: string; color: string; border: string }> = {
    done:       { bg: "rgba(16,185,129,0.1)", color: "#34d399", border: "rgba(16,185,129,0.2)" },
    pending:    { bg: "rgba(245,158,11,0.1)", color: "#fbbf24", border: "rgba(245,158,11,0.2)" },
    processing: { bg: "rgba(245,158,11,0.1)", color: "#fbbf24", border: "rgba(245,158,11,0.2)" },
    error:      { bg: "rgba(239,68,68,0.1)",  color: "#f87171", border: "rgba(239,68,68,0.2)" },
  };
  const c = map[status] ?? map.pending;
  return (
    <span style={{ fontSize: "11px", padding: "3px 10px", borderRadius: "999px", background: c.bg, color: c.color, border: `1px solid ${c.border}`, fontWeight: 600 }}>
      {status}
    </span>
  );
}

function ScoreBar({ score }: { score: number }) {
  const color = score >= 7 ? "#ef4444" : score >= 4 ? "#f59e0b" : "#00ff9d";
  return (
    <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
      <div style={{ width: "72px", height: "4px", background: "#1f1f2e", borderRadius: "4px", overflow: "hidden" }}>
        <div style={{ height: "100%", width: `${(score / 10) * 100}%`, background: color, borderRadius: "4px" }} />
      </div>
      <span style={{ fontSize: "12px", color: "#d4d4d8" }}>{score}/10</span>
    </div>
  );
}

export default function ScanDetailPage() {
  const { scan_id } = useParams<{ scan_id: string }>();
  const router = useRouter();
  const [scan, setScan]       = useState<ScanDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [hovered, setHovered] = useState<string | null>(null);

  const fetchScan = async () => {
    try { setScan(await getScan(scan_id)); } finally { setLoading(false); }
  };

  useEffect(() => { fetchScan(); }, [scan_id]);

  useEffect(() => {
    if (!scan?.assets.some((a) => a.status === "pending")) return;
    const t = setInterval(fetchScan, 5000);
    return () => clearInterval(t);
  }, [scan]);

  if (loading) return <div style={{ padding: "48px", color: "#71717a" }}>Loading...</div>;
  if (!scan)   return <div style={{ padding: "48px", color: "#f87171" }}>Scan not found.</div>;

  const done    = scan.assets.filter((a) => a.status === "done").length;
  const pending = scan.assets.filter((a) => a.status === "pending").length;
  const errors  = scan.assets.filter((a) => a.status === "error").length;
  const progress = scan.total_assets ? Math.round((done / scan.total_assets) * 100) : 0;

  return (
    <div style={{ padding: "40px 48px", maxWidth: "1200px" }}>
      {/* Back */}
      <button
        onClick={() => router.push("/asset-scanning")}
        style={{ display: "flex", alignItems: "center", gap: "6px", background: "none", border: "none", color: "#71717a", cursor: "pointer", fontSize: "13px", marginBottom: "28px", padding: 0 }}
      >
        <svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
        </svg>
        Back to scans
      </button>

      {/* Header */}
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", marginBottom: "32px" }}>
        <div>
          <h1 style={{ fontSize: "22px", fontWeight: 700, color: "white", margin: 0 }}>{scan.filename || "Scan"}</h1>
          <p style={{ fontSize: "12px", color: "#71717a", marginTop: "4px" }}>{new Date(scan.created_at).toLocaleString()}</p>
        </div>
        {badge(scan.status)}
      </div>

      {/* Stats */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "16px", marginBottom: "28px" }}>
        {[
          { label: "Total",     value: scan.total_assets, color: "white" },
          { label: "Completed", value: done,    color: "#34d399" },
          { label: "Pending",   value: pending, color: "#fbbf24" },
          { label: "Errors",    value: errors,  color: "#f87171" },
        ].map((s) => (
          <div key={s.label} style={{ background: "#0d0d14", border: "1px solid #1f1f2e", borderRadius: "12px", padding: "20px 24px" }}>
            <div style={{ fontSize: "11px", color: "#71717a", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: "8px" }}>{s.label}</div>
            <div style={{ fontSize: "26px", fontWeight: 700, color: s.color }}>{s.value}</div>
          </div>
        ))}
      </div>

      {/* Progress bar */}
      {scan.status !== "done" && (
        <div style={{ background: "#0d0d14", border: "1px solid #1f1f2e", borderRadius: "12px", padding: "20px 24px", marginBottom: "28px" }}>
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
        <div style={{ padding: "16px 24px", borderBottom: "1px solid #1f1f2e" }}>
          <span style={{ fontSize: "13px", fontWeight: 600, color: "white" }}>Assets ({scan.assets.length})</span>
        </div>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr style={{ borderBottom: "1px solid #1f1f2e" }}>
              {["#", "IP Address", "Role", "Environment", "Risk Score", "Status", ""].map((h) => (
                <th key={h} style={{ fontSize: "11px", color: "#52525b", textTransform: "uppercase", letterSpacing: "0.06em", fontWeight: 600, padding: "12px 20px", textAlign: "left" }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {scan.assets.map((asset) => {
              const score = asset.result?.score as number | undefined;
              const clickable = asset.status === "done";
              return (
                <tr
                  key={asset.id}
                  onClick={() => clickable && router.push(`/asset-scanning/${scan_id}/${asset.id}`)}
                  onMouseEnter={() => clickable && setHovered(asset.id)}
                  onMouseLeave={() => setHovered(null)}
                  style={{
                    borderBottom: "1px solid #18181f",
                    cursor: clickable ? "pointer" : "default",
                    background: hovered === asset.id ? "#111118" : "transparent",
                    opacity: asset.status === "pending" ? 0.5 : 1,
                    transition: "background 0.15s",
                  }}
                >
                  <td style={{ padding: "14px 20px", fontSize: "12px", color: "#52525b" }}>{asset.row_index + 1}</td>
                  <td style={{ padding: "14px 20px", fontSize: "13px", color: "white", fontFamily: "monospace", fontWeight: 500 }}>{asset.ip}</td>
                  <td style={{ padding: "14px 20px", fontSize: "13px", color: "#a1a1aa" }}>{asset.declared_role || "—"}</td>
                  <td style={{ padding: "14px 20px", fontSize: "13px", color: "#71717a" }}>{asset.environment}</td>
                  <td style={{ padding: "14px 20px" }}>
                    {score !== undefined ? <ScoreBar score={score} /> : <span style={{ color: "#3f3f46", fontSize: "12px" }}>—</span>}
                  </td>
                  <td style={{ padding: "14px 20px" }}>{badge(asset.status)}</td>
                  <td style={{ padding: "14px 20px", textAlign: "right" }}>
                    {clickable && <svg width="14" height="14" fill="none" stroke="#52525b" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" /></svg>}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
