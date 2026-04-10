"use client";

import { use, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { getQualysScan, deleteQualysRow, duration, type QualysScanDetail } from "@/lib/api";
import { AssetScanBadge } from "../page";

const TH: React.CSSProperties = { fontSize: "11px", color: "#52525b", textTransform: "uppercase", letterSpacing: "0.06em", fontWeight: 600, padding: "12px 20px", textAlign: "left", whiteSpace: "nowrap" };
const TD: React.CSSProperties = { fontSize: "13px", color: "#d4d4d8", padding: "14px 20px", whiteSpace: "nowrap" };

function SeverityBadge({ level }: { level: string }) {
  const map: Record<string, [string, string]> = {
    "5": ["rgba(239,68,68,0.1)",  "#f87171"],
    "4": ["rgba(239,68,68,0.1)",  "#f87171"],
    "3": ["rgba(245,158,11,0.1)", "#fbbf24"],
    "2": ["rgba(99,102,241,0.1)", "#818cf8"],
    "1": ["rgba(16,185,129,0.1)", "#34d399"],
  };
  const label: Record<string, string> = { "5": "Critical", "4": "High", "3": "Medium", "2": "Low", "1": "Info" };
  const [bg, color] = map[level] ?? ["rgba(113,113,122,0.1)", "#71717a"];
  return <span style={{ fontSize: "11px", padding: "3px 10px", borderRadius: "999px", background: bg, color, border: `1px solid ${color}44`, fontWeight: 600 }}>{label[level] ?? level}</span>;
}

function CvssChip({ score }: { score: string }) {
  if (!score) return <span style={{ color: "#52525b" }}>—</span>;
  const n = parseFloat(score);
  const color = n >= 9 ? "#f87171" : n >= 7 ? "#fbbf24" : n >= 4 ? "#818cf8" : "#34d399";
  return <span style={{ fontFamily: "monospace", color, fontWeight: 600 }}>{score}</span>;
}

export default function QualysScanDetailPage({ params }: { params: Promise<{ scan_id: string }> }) {
  const { scan_id } = use(params);
  const router = useRouter();
  const [scan, setScan] = useState<QualysScanDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [hovered, setHovered] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<string | null>(null);

  const handleDeleteRow = async (e: React.MouseEvent, rowId: string) => {
    e.stopPropagation();
    if (!confirm("Delete this vulnerability row?")) return;
    setDeleting(rowId);
    try {
      await deleteQualysRow(scan_id, rowId);
      setScan((prev) => prev ? { ...prev, rows: prev.rows.filter((r) => r.id !== rowId) } : prev);
    } finally { setDeleting(null); }
  };

  useEffect(() => {
    getQualysScan(scan_id).then(setScan).finally(() => setLoading(false));
  }, [scan_id]);

  if (loading) return <div style={{ padding: "36px 40px", color: "#52525b", fontSize: "13px" }}>Loading...</div>;
  if (!scan)   return <div style={{ padding: "36px 40px", color: "#f87171", fontSize: "13px" }}>Scan not found.</div>;

  const rows = scan.rows ?? [];
  const severityCounts = rows.reduce((acc, r) => {
    const s = r.result?.severity ?? "";
    acc[s] = (acc[s] ?? 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  return (
    <div style={{ padding: "36px 40px", width: "100%", boxSizing: "border-box" }}>

      {/* Back + Header */}
      <div style={{ marginBottom: "32px" }}>
        <button onClick={() => router.back()}
          style={{ display: "inline-flex", alignItems: "center", gap: "6px", background: "none", border: "none", color: "#71717a", fontSize: "12px", cursor: "pointer", padding: 0, marginBottom: "16px" }}>
          <svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
          </svg>
          Back to Dashboard
        </button>
        <h1 style={{ fontSize: "22px", fontWeight: 700, color: "white", margin: 0 }}>{scan.scan_name || scan.filename}</h1>
        <p style={{ fontSize: "12px", color: "#71717a", marginTop: "4px", marginBottom: 0, fontFamily: "monospace" }}>
          {scan.id} · {duration(scan.created_at, scan.completed_at)}
        </p>
      </div>

      {/* Stats */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "16px", marginBottom: "28px" }}>
        {[
          { label: "Total Vulns",   value: rows.length,                                                          color: "white" },
          { label: "Critical/High", value: (severityCounts["5"] ?? 0) + (severityCounts["4"] ?? 0),             color: "#f87171" },
          { label: "Medium",        value: severityCounts["3"] ?? 0,                                             color: "#fbbf24" },
          { label: "Low/Info",      value: (severityCounts["2"] ?? 0) + (severityCounts["1"] ?? 0),             color: "#34d399" },
        ].map((s) => (
          <div key={s.label} style={{ background: "#0d0d14", border: "1px solid #1f1f2e", borderRadius: "12px", padding: "20px 24px" }}>
            <div style={{ fontSize: "11px", color: "#71717a", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: "8px" }}>{s.label}</div>
            <div style={{ fontSize: "28px", fontWeight: 700, color: s.color }}>{s.value}</div>
          </div>
        ))}
      </div>

      {/* Vulnerabilities Table */}
      <div style={{ background: "#0d0d14", border: "1px solid #1f1f2e", borderRadius: "12px", overflow: "hidden" }}>
        <div style={{ padding: "16px 20px", borderBottom: "1px solid #1f1f2e" }}>
          <span style={{ fontSize: "13px", fontWeight: 600, color: "white" }}>Vulnerabilities</span>
        </div>
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", minWidth: "900px" }}>
            <thead>
              <tr style={{ borderBottom: "1px solid #1f1f2e" }}>
                {["CVE", "Title", "Asset IP", "Asset Scan", "Severity", "CVSSv3", "CVSSv2", "Status", "Last Detected", ""].map((h) => (
                  <th key={h} style={TH}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => {
                const r = row.result;
                return (
                  <tr key={row.id}
                    onClick={() => router.push(`/dashboard/${scan_id}/${row.id}`)}
                    onMouseEnter={() => setHovered(row.id)}
                    onMouseLeave={() => setHovered(null)}
                    style={{ borderBottom: "1px solid #18181f", cursor: "pointer", background: hovered === row.id ? "#111118" : "transparent", transition: "background 0.15s" }}>
                    <td style={{ ...TD, color: "#a78bfa", fontFamily: "monospace", fontWeight: 600 }}>{r?.cve || "—"}</td>
                    <td style={{ ...TD, maxWidth: "260px", overflow: "hidden", textOverflow: "ellipsis" }}>{r?.title || "—"}</td>
                    <td style={{ ...TD, fontFamily: "monospace", color: "#71717a" }}>{r?.asset_ipv4 || "—"}</td>
                    <td style={TD}><AssetScanBadge ip={r?.asset_ipv4 ?? ""} /></td>
                    <td style={TD}><SeverityBadge level={r?.severity ?? ""} /></td>
                    <td style={TD}><CvssChip score={r?.cvss_v3 ?? ""} /></td>
                    <td style={TD}><CvssChip score={r?.cvss_v2 ?? ""} /></td>
                    <td style={{ ...TD, color: "#71717a" }}>{r?.vuln_status || "—"}</td>
                    <td style={{ ...TD, color: "#71717a", fontSize: "12px" }}>{r?.last_detected || "—"}</td>
                    <td style={{ padding: "14px 20px" }} onClick={(e) => e.stopPropagation()}>
                      <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                        <button onClick={(e) => handleDeleteRow(e, row.id)} disabled={deleting === row.id} title="Delete row"
                          style={{ background: "none", border: "none", cursor: deleting === row.id ? "default" : "pointer", color: deleting === row.id ? "#3f3f46" : "#52525b", padding: "4px", lineHeight: 0 }}>
                          <svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                          </svg>
                        </button>
                        <svg width="13" height="13" fill="none" stroke="#3f3f46" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                        </svg>
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
