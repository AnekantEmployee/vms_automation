"use client";

import { useRouter } from "next/navigation";

const TD: React.CSSProperties = { fontSize: "13px", color: "#d4d4d8", padding: "14px 20px", whiteSpace: "nowrap" };
const TH: React.CSSProperties = { fontSize: "11px", color: "#52525b", textTransform: "uppercase", letterSpacing: "0.06em", fontWeight: 600, padding: "12px 20px", textAlign: "left", whiteSpace: "nowrap" };

const DUMMY_ASSETS = [
  { ip: "192.168.1.10", role: "Web Server",    env: "production",  classification: "confidential", owner: "ops@company.com",     risk: "High",   cves: 4, status: "done" },
  { ip: "192.168.1.11", role: "Database",      env: "production",  classification: "restricted",   owner: "dba@company.com",     risk: "Critical", cves: 7, status: "done" },
  { ip: "192.168.1.20", role: "Load Balancer", env: "production",  classification: "internal",     owner: "infra@company.com",   risk: "Low",    cves: 1, status: "done" },
  { ip: "10.0.0.5",     role: "API Gateway",   env: "staging",     classification: "internal",     owner: "dev@company.com",     risk: "Medium", cves: 3, status: "done" },
  { ip: "10.0.0.6",     role: "Auth Service",  env: "staging",     classification: "confidential", owner: "security@company.com",risk: "High",   cves: 5, status: "done" },
  { ip: "172.16.0.1",   role: "Monitoring",    env: "development", classification: "public",       owner: "devops@company.com",  risk: "Low",    cves: 0, status: "done" },
];

function RiskBadge({ risk }: { risk: string }) {
  const map: Record<string, [string, string]> = {
    Critical: ["rgba(239,68,68,0.1)",   "#f87171"],
    High:     ["rgba(245,158,11,0.1)",  "#fbbf24"],
    Medium:   ["rgba(99,102,241,0.1)",  "#818cf8"],
    Low:      ["rgba(16,185,129,0.1)",  "#34d399"],
  };
  const [bg, color] = map[risk] ?? map.Low;
  return <span style={{ fontSize: "11px", padding: "3px 10px", borderRadius: "999px", background: bg, color, border: `1px solid ${color}44`, fontWeight: 600 }}>{risk}</span>;
}

export default function DashboardScanDetail({ params }: { params: { scan_id: string } }) {
  const router = useRouter();

  const riskCounts = DUMMY_ASSETS.reduce((acc, a) => {
    acc[a.risk] = (acc[a.risk] ?? 0) + 1;
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
        <h1 style={{ fontSize: "22px", fontWeight: 700, color: "white", margin: 0 }}>Scan Detail</h1>
        <p style={{ fontSize: "13px", color: "#71717a", marginTop: "4px", marginBottom: 0, fontFamily: "monospace" }}>{params.scan_id}</p>
      </div>

      {/* Stats */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "16px", marginBottom: "28px" }}>
        {[
          { label: "Total Assets", value: DUMMY_ASSETS.length, color: "white" },
          { label: "Critical",     value: riskCounts.Critical ?? 0, color: "#f87171" },
          { label: "High",         value: riskCounts.High ?? 0,     color: "#fbbf24" },
          { label: "Total CVEs",   value: DUMMY_ASSETS.reduce((a, r) => a + r.cves, 0), color: "#818cf8" },
        ].map((s) => (
          <div key={s.label} style={{ background: "#0d0d14", border: "1px solid #1f1f2e", borderRadius: "12px", padding: "20px 24px" }}>
            <div style={{ fontSize: "11px", color: "#71717a", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: "8px" }}>{s.label}</div>
            <div style={{ fontSize: "28px", fontWeight: 700, color: s.color }}>{s.value}</div>
          </div>
        ))}
      </div>

      {/* Assets Table */}
      <div style={{ background: "#0d0d14", border: "1px solid #1f1f2e", borderRadius: "12px", overflow: "hidden" }}>
        <div style={{ padding: "16px 20px", borderBottom: "1px solid #1f1f2e", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          <span style={{ fontSize: "13px", fontWeight: 600, color: "white" }}>Assets</span>
          <span style={{ fontSize: "11px", color: "#52525b" }}>Dummy data — real data coming soon</span>
        </div>
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", minWidth: "800px" }}>
            <thead>
              <tr style={{ borderBottom: "1px solid #1f1f2e" }}>
                {["IP Address", "Role", "Environment", "Classification", "Owner", "Risk", "CVEs"].map((h) => (
                  <th key={h} style={TH}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {DUMMY_ASSETS.map((a) => (
                <tr key={a.ip} style={{ borderBottom: "1px solid #18181f" }}>
                  <td style={{ ...TD, color: "#a78bfa", fontFamily: "monospace", fontWeight: 600 }}>{a.ip}</td>
                  <td style={TD}>{a.role}</td>
                  <td style={{ ...TD, color: "#71717a" }}>{a.env}</td>
                  <td style={{ ...TD, color: "#71717a" }}>{a.classification}</td>
                  <td style={{ ...TD, color: "#71717a", fontSize: "12px" }}>{a.owner}</td>
                  <td style={TD}><RiskBadge risk={a.risk} /></td>
                  <td style={{ ...TD, color: a.cves > 0 ? "#f87171" : "#52525b", fontFamily: "monospace" }}>{a.cves}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
