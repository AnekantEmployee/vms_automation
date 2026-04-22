"use client";

import { use, useEffect, useState, useMemo } from "react";
import { useRouter } from "next/navigation";
import { getQualysScan, deleteQualysRow, retryRisk, duration, searchByIp, type QualysScanDetail, type AssetRow } from "@/lib/api";

const _ipCache = new Map<string, Promise<AssetRow[]>>();

function AssetIpLink({ ip }: { ip: string }) {
  const router = useRouter();
  const [target, setTarget] = useState<AssetRow | null>(null);
  useEffect(() => {
    if (!ip) return;
    if (!_ipCache.has(ip)) _ipCache.set(ip, searchByIp(ip).catch(() => []));
    _ipCache.get(ip)!.then((rows) => { if (rows.length > 0) setTarget(rows[0]); });
  }, [ip]);
  if (!ip) return <span style={{ color: "#3f3f46" }}>—</span>;
  if (!target) return <span style={{ color: "#71717a" }}>{ip}</span>;
  return (
    <span onClick={(e) => { e.stopPropagation(); router.push(`/asset-scanning/${target.scan_id}/${target.id}`); }}
      style={{ color: "#818cf8", cursor: "pointer", textDecoration: "underline", textDecorationColor: "#818cf844" }}>
      {ip}
    </span>
  );
}

const TH: React.CSSProperties = { fontSize: "11px", color: "#52525b", textTransform: "uppercase", letterSpacing: "0.06em", fontWeight: 600, padding: "12px 20px", textAlign: "left", whiteSpace: "nowrap" };
const TD: React.CSSProperties = { fontSize: "13px", color: "#d4d4d8", padding: "14px 20px", whiteSpace: "nowrap" };
const SEL: React.CSSProperties = { background: "#111118", border: "1px solid #2a2a3a", borderRadius: "7px", padding: "6px 10px", fontSize: "12px", color: "#a1a1aa", cursor: "pointer", outline: "none" };

function SeverityBadge({ level }: { level: string }) {
  const map: Record<string, [string, string]> = {
    "5": ["rgba(239,68,68,0.1)", "#f87171"], "4": ["rgba(239,68,68,0.1)", "#f87171"],
    "3": ["rgba(245,158,11,0.1)", "#fbbf24"], "2": ["rgba(99,102,241,0.1)", "#818cf8"],
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

type SortKey = "severity" | "cvss" | "risk_score" | "last_detected" | "title";
type SortDir = "asc" | "desc";

export default function QualysScanDetailPage({ params }: { params: Promise<{ scan_id: string }> }) {
  const { scan_id } = use(params);
  const router = useRouter();
  const [scan, setScan] = useState<QualysScanDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [hovered, setHovered] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<string | null>(null);
  const [retrying, setRetrying] = useState<string | null>(null);

  // filters & sort
  const [search, setSearch] = useState("");
  const [filterSeverity, setFilterSeverity] = useState("all");
  const [filterRisk, setFilterRisk] = useState("all");
  const [filterIp, setFilterIp] = useState("all");
  const [sortKey, setSortKey] = useState<SortKey>("severity");
  const [sortDir, setSortDir] = useState<SortDir>("desc");

  const handleRetryRisk = async (e: React.MouseEvent, rowId: string) => {
    e.stopPropagation();
    setRetrying(rowId);
    try {
      await retryRisk(scan_id, rowId);
      const poll = setInterval(async () => {
        const updated = await getQualysScan(scan_id);
        const row = updated.rows.find((r) => r.id === rowId);
        if (row?.result?.risk && !(row.result.risk as Record<string, unknown>).error) {
          setScan(updated); setRetrying(null); clearInterval(poll);
        }
      }, 3000);
      setTimeout(() => { clearInterval(poll); setRetrying(null); }, 300000);
    } catch { setRetrying(null); }
  };

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

  const rows = scan?.rows ?? [];

  const uniqueIps = useMemo(() => Array.from(new Set(rows.map(r => r.result?.asset_ipv4).filter(Boolean))), [rows]);

  const severityOrder: Record<string, number> = { "5": 5, "4": 4, "3": 3, "2": 2, "1": 1 };
  const riskOrder: Record<string, number> = { Critical: 4, High: 3, Medium: 2, Low: 1 };

  const processedRows = useMemo(() => {
    let r = [...rows];

    // search
    if (search.trim()) {
      const q = search.toLowerCase();
      r = r.filter(row =>
        row.result?.cve?.toLowerCase().includes(q) ||
        row.result?.title?.toLowerCase().includes(q) ||
        row.result?.asset_ipv4?.toLowerCase().includes(q)
      );
    }

    // severity filter
    if (filterSeverity !== "all") r = r.filter(row => row.result?.severity === filterSeverity);

    // risk label filter
    if (filterRisk !== "all") {
      r = r.filter(row => {
        const risk = row.result?.risk as { risk_label?: string } | undefined;
        return risk?.risk_label === filterRisk;
      });
    }

    // ip filter
    if (filterIp !== "all") r = r.filter(row => row.result?.asset_ipv4 === filterIp);

    // sort
    r.sort((a, b) => {
      let av = 0, bv = 0;
      if (sortKey === "severity") {
        av = severityOrder[a.result?.severity ?? ""] ?? 0;
        bv = severityOrder[b.result?.severity ?? ""] ?? 0;
      } else if (sortKey === "cvss") {
        av = parseFloat(a.result?.cvss_v3 ?? "0") || 0;
        bv = parseFloat(b.result?.cvss_v3 ?? "0") || 0;
      } else if (sortKey === "risk_score") {
        const ra = a.result?.risk as { risk_score?: number; risk_label?: string } | undefined;
        const rb = b.result?.risk as { risk_score?: number; risk_label?: string } | undefined;
        av = ra?.risk_score ?? riskOrder[ra?.risk_label ?? ""] ?? 0;
        bv = rb?.risk_score ?? riskOrder[rb?.risk_label ?? ""] ?? 0;
      } else if (sortKey === "last_detected") {
        av = new Date(a.result?.last_detected ?? 0).getTime();
        bv = new Date(b.result?.last_detected ?? 0).getTime();
      } else if (sortKey === "title") {
        return sortDir === "asc"
          ? (a.result?.title ?? "").localeCompare(b.result?.title ?? "")
          : (b.result?.title ?? "").localeCompare(a.result?.title ?? "");
      }
      return sortDir === "asc" ? av - bv : bv - av;
    });

    return r;
  }, [rows, search, filterSeverity, filterRisk, filterIp, sortKey, sortDir]);

  const severityCounts = rows.reduce((acc, r) => {
    const s = r.result?.severity ?? "";
    acc[s] = (acc[s] ?? 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  if (loading) return <div style={{ padding: "36px 40px", color: "#52525b", fontSize: "13px" }}>Loading...</div>;
  if (!scan)   return <div style={{ padding: "36px 40px", color: "#f87171", fontSize: "13px" }}>Scan not found.</div>;

  const toggleSort = (key: SortKey) => {
    if (sortKey === key) setSortDir(d => d === "asc" ? "desc" : "asc");
    else { setSortKey(key); setSortDir("desc"); }
  };

  const SortIcon = ({ k }: { k: SortKey }) => (
    <span style={{ marginLeft: "4px", opacity: sortKey === k ? 1 : 0.3, fontSize: "10px" }}>
      {sortKey === k ? (sortDir === "asc" ? "↑" : "↓") : "↕"}
    </span>
  );

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
          { label: "Total Vulns",   value: rows.length,                                                      color: "white" },
          { label: "Critical/High", value: (severityCounts["5"] ?? 0) + (severityCounts["4"] ?? 0),         color: "#f87171" },
          { label: "Medium",        value: severityCounts["3"] ?? 0,                                         color: "#fbbf24" },
          { label: "Low/Info",      value: (severityCounts["2"] ?? 0) + (severityCounts["1"] ?? 0),         color: "#34d399" },
        ].map((s) => (
          <div key={s.label} style={{ background: "#0d0d14", border: "1px solid #1f1f2e", borderRadius: "12px", padding: "20px 24px" }}>
            <div style={{ fontSize: "11px", color: "#71717a", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: "8px" }}>{s.label}</div>
            <div style={{ fontSize: "28px", fontWeight: 700, color: s.color }}>{s.value}</div>
          </div>
        ))}
      </div>

      {/* Vulnerabilities Table */}
      <div style={{ background: "#0d0d14", border: "1px solid #1f1f2e", borderRadius: "12px", overflow: "hidden", display: "flex", flexDirection: "column", minHeight: 0 }}>

        {/* Table header bar with search + filters */}
        <div style={{ padding: "14px 20px", borderBottom: "1px solid #1f1f2e", display: "flex", alignItems: "center", justifyContent: "space-between", gap: "12px", flexWrap: "wrap" }}>
          <span style={{ fontSize: "13px", fontWeight: 600, color: "white", flexShrink: 0 }}>
            Vulnerabilities <span style={{ color: "#52525b", fontWeight: 400, fontSize: "12px" }}>({processedRows.length}/{rows.length})</span>
          </span>
          <div style={{ display: "flex", alignItems: "center", gap: "8px", flexWrap: "wrap" }}>
            {/* Search */}
            <div style={{ position: "relative" }}>
              <svg width="13" height="13" fill="none" stroke="#52525b" viewBox="0 0 24 24" style={{ position: "absolute", left: "9px", top: "50%", transform: "translateY(-50%)", pointerEvents: "none" }}>
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-4.35-4.35M17 11A6 6 0 1 1 5 11a6 6 0 0 1 12 0z" />
              </svg>
              <input
                value={search} onChange={e => setSearch(e.target.value)}
                placeholder="Search CVE, title, IP…"
                style={{ ...SEL, paddingLeft: "28px", width: "200px" }}
              />
            </div>
            {/* Severity filter */}
            <select value={filterSeverity} onChange={e => setFilterSeverity(e.target.value)} style={SEL}>
              <option value="all">All Severities</option>
              <option value="5">Critical</option>
              <option value="4">High</option>
              <option value="3">Medium</option>
              <option value="2">Low</option>
              <option value="1">Info</option>
            </select>
            {/* Risk filter */}
            <select value={filterRisk} onChange={e => setFilterRisk(e.target.value)} style={SEL}>
              <option value="all">All Risk</option>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
            </select>
            {/* IP filter */}
            {uniqueIps.length > 1 && (
              <select value={filterIp} onChange={e => setFilterIp(e.target.value)} style={SEL}>
                <option value="all">All IPs</option>
                {uniqueIps.map(ip => <option key={ip} value={ip!}>{ip}</option>)}
              </select>
            )}
            {/* Sort */}
            <select value={sortKey} onChange={e => { setSortKey(e.target.value as SortKey); setSortDir("desc"); }} style={SEL}>
              <option value="severity">Sort: Severity</option>
              <option value="cvss">Sort: CVSSv3</option>
              <option value="risk_score">Sort: Risk Score</option>
              <option value="last_detected">Sort: Last Detected</option>
              <option value="title">Sort: Title</option>
            </select>
            <button onClick={() => setSortDir(d => d === "asc" ? "desc" : "asc")}
              style={{ ...SEL, padding: "6px 10px", fontFamily: "monospace", fontSize: "13px" }}>
              {sortDir === "desc" ? "↓" : "↑"}
            </button>
            {/* Reset */}
            {(search || filterSeverity !== "all" || filterRisk !== "all" || filterIp !== "all") && (
              <button onClick={() => { setSearch(""); setFilterSeverity("all"); setFilterRisk("all"); setFilterIp("all"); }}
                style={{ ...SEL, color: "#f87171", borderColor: "rgba(248,113,113,0.2)" }}>
                Clear
              </button>
            )}
          </div>
        </div>

        <div style={{ overflowX: "auto", overflowY: "auto", maxHeight: "calc(100vh - 420px)" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", minWidth: "900px" }}>
            <thead style={{ position: "sticky", top: 0, zIndex: 1, background: "#0d0d14" }}>
              <tr style={{ borderBottom: "1px solid #1f1f2e" }}>
                <th style={TH}>CVE</th>
                <th style={{ ...TH, cursor: "pointer" }} onClick={() => toggleSort("title")}>Title <SortIcon k="title" /></th>
                <th style={TH}>Asset IP</th>
                <th style={{ ...TH, textAlign: "center", cursor: "pointer" }} onClick={() => toggleSort("severity")}>Severity <SortIcon k="severity" /></th>
                <th style={{ ...TH, textAlign: "center", cursor: "pointer" }} onClick={() => toggleSort("cvss")}>CVSSv3 <SortIcon k="cvss" /></th>
                <th style={{ ...TH, textAlign: "center", cursor: "pointer" }} onClick={() => toggleSort("risk_score")}>Risk <SortIcon k="risk_score" /></th>
                <th style={{ ...TH, cursor: "pointer" }} onClick={() => toggleSort("last_detected")}>Last Detected <SortIcon k="last_detected" /></th>
                <th style={TH}></th>
              </tr>
            </thead>
            <tbody>
              {processedRows.length === 0 ? (
                <tr><td colSpan={8} style={{ padding: "40px", textAlign: "center", color: "#52525b", fontSize: "13px" }}>No results match your filters.</td></tr>
              ) : processedRows.map((row) => {
                const r = row.result;
                return (
                  <tr key={row.id}
                    onClick={() => router.push(`/dashboard/${scan_id}/${row.id}`)}
                    onMouseEnter={() => setHovered(row.id)}
                    onMouseLeave={() => setHovered(null)}
                    style={{ borderBottom: "1px solid #18181f", cursor: "pointer", background: hovered === row.id ? "#111118" : "transparent", transition: "background 0.15s" }}>
                    <td style={{ ...TD, color: "#a78bfa", fontFamily: "monospace", fontWeight: 600 }}>{r?.cve || "—"}</td>
                    <td style={{ ...TD, maxWidth: "260px", overflow: "hidden", textOverflow: "ellipsis" }}>{r?.title || "—"}</td>
                    <td style={{ ...TD, fontFamily: "monospace" }}><AssetIpLink ip={r?.asset_ipv4 ?? ""} /></td>
                    <td style={{ ...TD, textAlign: "center" }}><SeverityBadge level={r?.severity ?? ""} /></td>
                    <td style={{ ...TD, textAlign: "center" }}><CvssChip score={r?.cvss_v3 ?? ""} /></td>
                    <td style={{ ...TD, textAlign: "center" }}>{(() => {
                      const risk = r?.risk as { risk_label?: string; risk_score?: number; error?: string } | undefined;
                      const hasRisk = risk?.risk_label && !risk?.error;
                      if (!hasRisk) return (
                        <button onClick={(e) => handleRetryRisk(e, row.id)} disabled={retrying === row.id}
                          style={{ background: "none", border: "1px solid #2a2a3a", borderRadius: "6px", padding: "3px 10px", fontSize: "11px", color: retrying === row.id ? "#52525b" : "#71717a", cursor: retrying === row.id ? "default" : "pointer", display: "inline-flex", alignItems: "center", gap: "5px" }}>
                          {retrying === row.id ? "Analysing..." : "↺ Retry"}
                        </button>
                      );
                      const lc: Record<string, string> = { Critical: "#f87171", High: "#fbbf24", Medium: "#818cf8", Low: "#34d399" };
                      const c = lc[risk.risk_label!] ?? "#71717a";
                      return (
                        <div style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: "10px" }}>
                          <div style={{ width: "36px", height: "36px", borderRadius: "50%", border: `2px solid ${c}66`, background: `${c}12`, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
                            <span style={{ fontFamily: "monospace", fontSize: "11px", fontWeight: 700, color: c }}>{risk.risk_score ?? "—"}</span>
                          </div>
                          <span style={{ fontSize: "11px", fontWeight: 700, color: c }}>{risk.risk_label}</span>
                        </div>
                      );
                    })()}</td>
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

