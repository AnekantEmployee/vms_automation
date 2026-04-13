"use client";

import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { formatSecs, startRecon, getReconJob, importRecon, type ReconJob, type ReconAsset } from "@/lib/api";
import { useAssetStore } from "@/store/useAssetStore";

const TH: React.CSSProperties = { fontSize: "11px", color: "#52525b", textTransform: "uppercase", letterSpacing: "0.06em", fontWeight: 600, padding: "12px 20px", textAlign: "left", whiteSpace: "nowrap" };
const TD: React.CSSProperties = { fontSize: "13px", color: "#d4d4d8", padding: "14px 20px", whiteSpace: "nowrap" };
const INPUT: React.CSSProperties = { width: "100%", background: "#111118", border: "1px solid #2a2a3a", borderRadius: "8px", padding: "9px 12px", fontSize: "13px", color: "white", outline: "none", boxSizing: "border-box" };

function Badge({ status }: { status: string }) {
  const map: Record<string, [string, string, string]> = {
    done:       ["rgba(16,185,129,0.1)", "#34d399", "rgba(16,185,129,0.2)"],
    processing: ["rgba(245,158,11,0.1)", "#fbbf24", "rgba(245,158,11,0.2)"],
    error:      ["rgba(239,68,68,0.1)",  "#f87171", "rgba(239,68,68,0.2)"],
  };
  const [bg, color, border] = map[status] ?? map.processing;
  return <span style={{ fontSize: "11px", padding: "3px 10px", borderRadius: "999px", background: bg, color, border: `1px solid ${border}`, fontWeight: 600, whiteSpace: "nowrap" }}>{status}</span>;
}

function ClassBadge({ val }: { val: string }) {
  const map: Record<string, string> = { public: "#34d399", internal: "#fbbf24", confidential: "#818cf8", restricted: "#f87171", Unknown: "#52525b" };
  const color = map[val] ?? "#52525b";
  return <span style={{ fontSize: "11px", padding: "3px 8px", borderRadius: "999px", background: `${color}18`, color, border: `1px solid ${color}44`, fontWeight: 600 }}>{val}</span>;
}

// ── Modal ──────────────────────────────────────────────────────────────────────

function NewScanModal({ onClose, onSuccess }: { onClose: () => void; onSuccess: (scanId?: string) => void }) {
  const router    = useRouter();
  const inputRef  = useRef<HTMLInputElement>(null);
  const pollRef   = useRef<ReturnType<typeof setInterval> | null>(null);
  const { upload } = useAssetStore();

  const [tab, setTab]           = useState<"domain" | "excel" | "manual">("domain");
  const [scanName, setScanName] = useState("");
  const [loading, setLoading]   = useState(false);
  const [error, setError]       = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);

  // Excel / Manual fields
  const [ip, setIp]       = useState("");
  const [role, setRole]   = useState("");
  const [dc, setDc]       = useState("internal");
  const [env, setEnv]     = useState("production");
  const [owner, setOwner] = useState("");

  // Domain recon state
  const [domain, setDomain]       = useState("");
  const [job, setJob]             = useState<ReconJob | null>(null);
  const [reconRunning, setReconRunning] = useState(false);
  const [importing, setImporting] = useState(false);
  const [hoveredIp, setHoveredIp] = useState<string | null>(null);

  const stopPoll = () => { if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; } };
  useEffect(() => () => stopPoll(), []);

  // ── Domain handlers ──────────────────────────────────────────────────────────

  const handleStartRecon = async () => {
    if (!domain.trim()) { setError("Enter a domain."); return; }
    setError(null); setReconRunning(true); setJob(null);
    try {
      const res = await startRecon(domain.trim());
      setJob({ id: res.job_id, domain: res.domain, status: "processing", total_assets: null, assets: null, error: null, created_at: new Date().toISOString(), completed_at: null });
      pollRef.current = setInterval(async () => {
        const updated = await getReconJob(res.job_id);
        setJob(updated);
        if (updated.status !== "processing") stopPoll();
      }, 3000);
    } catch { setError("Failed to start recon. Check backend."); }
    finally { setReconRunning(false); }
  };

  const handleImportRecon = async () => {
    if (!job || job.status !== "done") return;
    setImporting(true); setError(null);
    try {
      const res = await importRecon(job.id, scanName || `Recon: ${job.domain}`);
      onSuccess(res.scan_id);
      onClose();
      router.push(`/asset-scanning/${res.scan_id}`);
    } catch { setError("Import failed."); }
    finally { setImporting(false); }
  };

  // ── Excel / Manual handlers ──────────────────────────────────────────────────

  const handleFile = async (file: File) => {
    setError(null); setLoading(true);
    try { await upload(file, scanName || file.name); onSuccess(); onClose(); }
    catch { setError("Upload failed. Check the file format and backend."); }
    finally { setLoading(false); }
  };

  const handleManual = async () => {
    if (!ip.trim()) { setError("IP address is required."); return; }
    setError(null); setLoading(true);
    try {
      const csv = `asset_ip,asset_role,data_classification,environment,owner_email\n${ip},${role},${dc},${env},${owner}`;
      const file = new File([new Blob([csv], { type: "text/csv" })], "manual.csv", { type: "text/csv" });
      await upload(file, scanName || ip);
      onSuccess(); onClose();
    } catch { setError("Failed to create scan."); }
    finally { setLoading(false); }
  };

  const tabStyle = (active: boolean): React.CSSProperties => ({
    flex: 1, padding: "8px", fontSize: "12px", fontWeight: 600, border: "none", cursor: "pointer", borderRadius: "6px",
    background: active ? "#1f1f2e" : "transparent", color: active ? "white" : "#71717a", transition: "all 0.15s",
  });

  const assets: ReconAsset[] = job?.assets ?? [];

  // Modal is wider when recon results are showing
  const wide = tab === "domain" && assets.length > 0;

  return (
    <div style={{ position: "fixed", inset: 0, zIndex: 50, display: "flex", alignItems: "center", justifyContent: "center", background: "rgba(0,0,0,0.75)", backdropFilter: "blur(4px)", padding: "24px" }}>
      <div style={{ background: "#0d0d14", border: "1px solid #1f1f2e", borderRadius: "16px", padding: "28px", width: "100%", maxWidth: wide ? "900px" : "480px", boxSizing: "border-box", maxHeight: "90vh", overflowY: "auto", transition: "max-width 0.3s" }}>

        {/* Header */}
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "20px" }}>
          <span style={{ fontSize: "16px", fontWeight: 700, color: "white" }}>New Asset Scan</span>
          <button onClick={onClose} style={{ background: "none", border: "none", color: "#71717a", cursor: "pointer", padding: "4px", lineHeight: 0 }}>
            <svg width="18" height="18" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
          </button>
        </div>

        {/* Scan name */}
        <div style={{ marginBottom: "16px" }}>
          <label style={{ fontSize: "11px", color: "#71717a", textTransform: "uppercase", letterSpacing: "0.06em", display: "block", marginBottom: "6px" }}>Scan Name</label>
          <input style={INPUT} placeholder="e.g. Q2 Production Audit" value={scanName} onChange={(e) => setScanName(e.target.value)} />
        </div>

        {/* Tabs */}
        <div style={{ display: "flex", gap: "4px", background: "#111118", borderRadius: "8px", padding: "4px", marginBottom: "20px" }}>
          <button style={tabStyle(tab === "domain")} onClick={() => { setTab("domain"); setError(null); }}>🌐 Domain Scan</button>
          <button style={tabStyle(tab === "excel")}  onClick={() => { setTab("excel");  setError(null); }}>📄 Upload Excel</button>
          <button style={tabStyle(tab === "manual")} onClick={() => { setTab("manual"); setError(null); }}>✏️ Manual Entry</button>
        </div>

        {/* ── Domain Scan ── */}
        {tab === "domain" && (
          <div>
            <div style={{ display: "flex", gap: "10px", marginBottom: "16px" }}>
              <input
                style={{ ...INPUT, flex: 1 }}
                placeholder="e.g. example.com"
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleStartRecon()}
              />
              <button
                onClick={handleStartRecon}
                disabled={reconRunning || job?.status === "processing"}
                style={{ padding: "9px 18px", background: reconRunning || job?.status === "processing" ? "#1f1f2e" : "#00ff9d", color: "#000", fontWeight: 700, fontSize: "13px", border: "none", borderRadius: "8px", cursor: reconRunning || job?.status === "processing" ? "default" : "pointer", whiteSpace: "nowrap" }}
              >
                {reconRunning ? "Starting..." : job?.status === "processing" ? "Scanning..." : "Start Recon"}
              </button>
            </div>

            {/* Status bar */}
            {job && (
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "12px", padding: "12px 16px", background: "#111118", borderRadius: "8px", marginBottom: "16px" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                  <Badge status={job.status} />
                  <span style={{ fontSize: "12px", color: "#a1a1aa", fontFamily: "monospace" }}>{job.domain}</span>
                  {job.status === "processing" && <span style={{ fontSize: "12px", color: "#fbbf24" }}>Running passive recon…</span>}
                  {job.total_assets != null && <span style={{ fontSize: "12px", color: "#71717a" }}>{job.total_assets} assets found</span>}
                  {job.error && <span style={{ fontSize: "12px", color: "#f87171" }}>{job.error}</span>}
                </div>
                {job.status === "done" && assets.length > 0 && (
                  <button
                    onClick={handleImportRecon}
                    disabled={importing}
                    style={{ padding: "7px 16px", background: importing ? "#1f1f2e" : "#818cf8", color: "white", fontWeight: 700, fontSize: "12px", border: "none", borderRadius: "8px", cursor: importing ? "default" : "pointer", whiteSpace: "nowrap" }}
                  >
                    {importing ? "Importing..." : `Import & Scan (${assets.length})`}
                  </button>
                )}
              </div>
            )}

            {/* Discovered assets table */}
            {assets.length > 0 && (
              <div style={{ border: "1px solid #1f1f2e", borderRadius: "10px", overflow: "hidden" }}>
                <div style={{ padding: "10px 16px", borderBottom: "1px solid #1f1f2e", fontSize: "11px", color: "#71717a", textTransform: "uppercase", letterSpacing: "0.06em" }}>
                  Discovered Assets — {assets.length}
                </div>
                <div style={{ overflowX: "auto", maxHeight: "320px", overflowY: "auto" }}>
                  <table style={{ width: "100%", borderCollapse: "collapse", minWidth: "700px" }}>
                    <thead>
                      <tr style={{ borderBottom: "1px solid #1f1f2e" }}>
                        {["IP", "Hostnames", "Role", "Classification", "Environment", "Org"].map((h) => (
                          <th key={h} style={{ ...TH, padding: "10px 14px" }}>{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {assets.map((a) => (
                        <tr key={a.ip}
                          onMouseEnter={() => setHoveredIp(a.ip)}
                          onMouseLeave={() => setHoveredIp(null)}
                          style={{ borderBottom: "1px solid #18181f", background: hoveredIp === a.ip ? "#111118" : "transparent" }}>
                          <td style={{ ...TD, padding: "10px 14px", color: "#a78bfa", fontFamily: "monospace", fontWeight: 600 }}>{a.ip}</td>
                          <td style={{ ...TD, padding: "10px 14px", color: "#71717a", fontSize: "12px", maxWidth: "180px", overflow: "hidden", textOverflow: "ellipsis" }}>
                            {a.hostnames.slice(0, 2).join(", ")}{a.hostnames.length > 2 ? ` +${a.hostnames.length - 2}` : ""}
                          </td>
                          <td style={{ ...TD, padding: "10px 14px", color: "#a1a1aa", fontSize: "12px" }}>{a.asset_role || "—"}</td>
                          <td style={{ ...TD, padding: "10px 14px" }}><ClassBadge val={a.data_classification || "Unknown"} /></td>
                          <td style={{ ...TD, padding: "10px 14px", color: "#71717a" }}>{a.environment || "—"}</td>
                          <td style={{ ...TD, padding: "10px 14px", color: "#71717a", fontSize: "12px", maxWidth: "160px", overflow: "hidden", textOverflow: "ellipsis" }}>{a.org || "—"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        )}

        {/* ── Upload Excel ── */}
        {tab === "excel" && (
          <>
            <p style={{ fontSize: "11px", color: "#52525b", marginBottom: "14px", lineHeight: 1.6 }}>
              Columns: <code style={{ color: "#00ff9d" }}>asset_ip, asset_role, data_classification, environment, owner_email</code>
            </p>
            <div
              onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
              onDragLeave={() => setDragging(false)}
              onDrop={(e) => { e.preventDefault(); setDragging(false); const f = e.dataTransfer.files[0]; if (f) handleFile(f); }}
              onClick={() => inputRef.current?.click()}
              style={{ border: `2px dashed ${dragging ? "#00ff9d" : "#2a2a3a"}`, borderRadius: "12px", padding: "32px 24px", display: "flex", flexDirection: "column", alignItems: "center", cursor: "pointer", background: dragging ? "rgba(0,255,157,0.04)" : "transparent", transition: "all 0.2s" }}
            >
              <input ref={inputRef} type="file" accept=".xlsx,.xls,.csv" style={{ display: "none" }} onChange={(e) => e.target.files?.[0] && handleFile(e.target.files[0])} />
              <svg width="28" height="28" fill="none" stroke={dragging ? "#00ff9d" : "#52525b"} viewBox="0 0 24 24" style={{ marginBottom: "10px" }}>
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12" />
              </svg>
              <p style={{ fontSize: "13px", color: dragging ? "#00ff9d" : "#a1a1aa", fontWeight: 500, margin: 0 }}>{dragging ? "Drop it!" : "Drop file or click to browse"}</p>
              <p style={{ fontSize: "11px", color: "#52525b", marginTop: "4px", marginBottom: 0 }}>.xlsx, .xls, .csv</p>
              {loading && <p style={{ fontSize: "12px", color: "#00ff9d", marginTop: "10px", marginBottom: 0 }}>Uploading...</p>}
            </div>
          </>
        )}

        {/* ── Manual Entry ── */}
        {tab === "manual" && (
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
              {loading ? "Creating..." : "Start Scan"}
            </button>
          </div>
        )}

        {error && <div style={{ marginTop: "12px", padding: "10px 14px", background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.2)", borderRadius: "8px", fontSize: "12px", color: "#f87171" }}>{error}</div>}
      </div>
    </div>
  );
}

// ── Page ───────────────────────────────────────────────────────────────────────

export default function AssetScanningPage() {
  const router = useRouter();
  const { scans, loading, deleting, fetchScans, remove } = useAssetStore();
  const [showModal, setShowModal] = useState(false);
  const [hovered, setHovered]     = useState<string | null>(null);

  useEffect(() => { fetchScans(); }, []);
  useEffect(() => {
    if (!scans.some((s) => s.status === "processing")) return;
    const t = setInterval(fetchScans, 5000);
    return () => clearInterval(t);
  }, [scans]);

  const handleDelete = async (e: React.MouseEvent, id: string) => {
    e.stopPropagation();
    if (!confirm("Delete this scan and all its assets?")) return;
    await remove(id);
  };

  return (
    <div style={{ padding: "36px 40px", width: "100%", boxSizing: "border-box" }}>
      {showModal && <NewScanModal onClose={() => setShowModal(false)} onSuccess={fetchScans} />}

      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "32px", gap: "16px" }}>
        <div>
          <h1 style={{ fontSize: "22px", fontWeight: 700, color: "white", margin: 0 }}>Asset Scanning</h1>
          <p style={{ fontSize: "13px", color: "#71717a", marginTop: "4px", marginBottom: 0 }}>Discover and analyse assets</p>
        </div>
        <button onClick={() => setShowModal(true)}
          style={{ display: "flex", alignItems: "center", gap: "8px", padding: "10px 18px", background: "#00ff9d", color: "#000", fontSize: "13px", fontWeight: 700, borderRadius: "8px", border: "none", cursor: "pointer", flexShrink: 0 }}>
          <svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M12 4v16m8-8H4" /></svg>
          New Scan
        </button>
      </div>

      {/* Stats */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "16px", marginBottom: "32px" }}>
        {[
          { label: "Total Scans",  value: scans.length },
          { label: "Completed",    value: scans.filter((s) => s.status === "done").length },
          { label: "Total Assets", value: scans.reduce((a, s) => a + (s.total_assets ?? 0), 0) },
        ].map((stat) => (
          <div key={stat.label} style={{ background: "#0d0d14", border: "1px solid #1f1f2e", borderRadius: "12px", padding: "20px 24px" }}>
            <div style={{ fontSize: "11px", color: "#71717a", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: "8px" }}>{stat.label}</div>
            <div style={{ fontSize: "28px", fontWeight: 700, color: "white" }}>{stat.value}</div>
          </div>
        ))}
      </div>

      {/* Table */}
      <div style={{ background: "#0d0d14", border: "1px solid #1f1f2e", borderRadius: "12px", overflow: "hidden" }}>
        <div style={{ padding: "16px 20px", borderBottom: "1px solid #1f1f2e" }}>
          <span style={{ fontSize: "13px", fontWeight: 600, color: "white" }}>Scan History</span>
        </div>
        {loading ? (
          <div style={{ padding: "64px 24px", textAlign: "center", color: "#52525b", fontSize: "13px" }}>Loading...</div>
        ) : scans.length === 0 ? (
          <div style={{ padding: "64px 24px", textAlign: "center", color: "#52525b", fontSize: "13px" }}>
            No scans yet. Click <span style={{ color: "#00ff9d" }}>New Scan</span> to get started.
          </div>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", minWidth: "700px" }}>
              <thead>
                <tr style={{ borderBottom: "1px solid #1f1f2e" }}>
                  {["Name", "File", "Assets", "Duration", "Status", "Started", ""].map((h) => (
                    <th key={h} style={TH}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {scans.map((scan) => (
                  <tr key={scan.id} onClick={() => router.push(`/asset-scanning/${scan.id}`)}
                    onMouseEnter={() => setHovered(scan.id)} onMouseLeave={() => setHovered(null)}
                    style={{ borderBottom: "1px solid #18181f", cursor: "pointer", background: hovered === scan.id ? "#111118" : "transparent", transition: "background 0.15s" }}>
                    <td style={{ ...TD, color: "white", fontWeight: 600 }}>{scan.scan_name || scan.filename || "—"}</td>
                    <td style={{ ...TD, color: "#71717a", fontSize: "12px" }}>{scan.filename || "—"}</td>
                    <td style={TD}>{scan.total_assets}</td>
                    <td style={{ ...TD, fontFamily: "monospace", color: "#71717a" }}>{formatSecs(scan.total_asset_secs)}</td>
                    <td style={TD}><Badge status={scan.status} /></td>
                    <td style={{ ...TD, color: "#71717a" }}>{new Date(scan.created_at).toLocaleString()}</td>
                    <td style={{ padding: "14px 20px", whiteSpace: "nowrap" }}>
                      <div style={{ display: "flex", alignItems: "center", justifyContent: "flex-end", gap: "12px" }}>
                        <button onClick={(e) => handleDelete(e, scan.id)} disabled={deleting === scan.id} title="Delete scan"
                          style={{ background: "none", border: "none", cursor: "pointer", color: deleting === scan.id ? "#3f3f46" : "#52525b", padding: "4px", lineHeight: 0 }}>
                          <svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                          </svg>
                        </button>
                        <svg width="14" height="14" fill="none" stroke="#52525b" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                        </svg>
                      </div>
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
