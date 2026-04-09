"use client";

import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { getAssetDetail, type AssetRow } from "@/lib/api";

function Row({ label, value }: { label: string; value: unknown }) {
  if (value === null || value === undefined || value === "") return null;
  const display = Array.isArray(value)
    ? (value as unknown[]).join(", ")
    : typeof value === "object"
    ? JSON.stringify(value, null, 2)
    : String(value);
  return (
    <div style={{ padding: "12px 0", borderBottom: "1px solid #18181f" }}>
      <div style={{ fontSize: "11px", color: "#52525b", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: "4px" }}>{label}</div>
      <div style={{ fontSize: "13px", color: "#d4d4d8", whiteSpace: "pre-wrap", wordBreak: "break-word" }}>{display}</div>
    </div>
  );
}

function ScoreGauge({ score }: { score: number }) {
  const color = score >= 7 ? "#ef4444" : score >= 4 ? "#f59e0b" : "#00ff9d";
  const label = score >= 7 ? "High Risk" : score >= 4 ? "Medium Risk" : "Low Risk";
  const r = 40, circ = 2 * Math.PI * r;
  const dash = (score / 10) * circ;
  return (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", padding: "28px 24px", background: "#0d0d14", border: "1px solid #1f1f2e", borderRadius: "12px" }}>
      <div style={{ position: "relative", width: "120px", height: "120px", marginBottom: "12px" }}>
        <svg viewBox="0 0 100 100" style={{ width: "100%", height: "100%", transform: "rotate(-90deg)" }}>
          <circle cx="50" cy="50" r={r} fill="none" stroke="#1f1f2e" strokeWidth="10" />
          <circle cx="50" cy="50" r={r} fill="none" stroke={color} strokeWidth="10"
            strokeDasharray={`${dash} ${circ}`} strokeLinecap="round" />
        </svg>
        <div style={{ position: "absolute", inset: 0, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center" }}>
          <span style={{ fontSize: "28px", fontWeight: 700, color: "white", lineHeight: 1 }}>{score}</span>
          <span style={{ fontSize: "11px", color: "#71717a" }}>/10</span>
        </div>
      </div>
      <span style={{ fontSize: "13px", fontWeight: 600, color }}>{label}</span>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div style={{ background: "#0d0d14", border: "1px solid #1f1f2e", borderRadius: "12px", padding: "20px 24px", marginBottom: "16px" }}>
      <div style={{ fontSize: "12px", fontWeight: 600, color: "white", marginBottom: "4px", textTransform: "uppercase", letterSpacing: "0.06em" }}>{title}</div>
      {children}
    </div>
  );
}

export default function AssetDetailPage() {
  const { scan_id, row_id } = useParams<{ scan_id: string; row_id: string }>();
  const router = useRouter();
  const [asset, setAsset]   = useState<AssetRow | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getAssetDetail(scan_id, row_id).then(setAsset).finally(() => setLoading(false));
  }, [scan_id, row_id]);

  if (loading) return <div style={{ padding: "48px", color: "#71717a" }}>Loading...</div>;
  if (!asset)  return <div style={{ padding: "48px", color: "#f87171" }}>Asset not found.</div>;

  const r = asset.result ?? {};
  const score       = r.score as number | undefined;
  const mitigations = r.mitigations as string[] | undefined;
  const cves        = r.cves as unknown[] | undefined;
  const services    = r.services as string[] | undefined;
  const openPorts   = r.open_ports as number[] | undefined;

  return (
    <div style={{ padding: "40px 48px", maxWidth: "1100px" }}>
      {/* Back */}
      <button
        onClick={() => router.push(`/asset-scanning/${scan_id}`)}
        style={{ display: "flex", alignItems: "center", gap: "6px", background: "none", border: "none", color: "#71717a", cursor: "pointer", fontSize: "13px", marginBottom: "28px", padding: 0 }}
      >
        <svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
        </svg>
        Back to scan
      </button>

      {/* Header */}
      <div style={{ marginBottom: "32px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "12px", marginBottom: "6px" }}>
          <h1 style={{ fontSize: "22px", fontWeight: 700, color: "white", fontFamily: "monospace", margin: 0 }}>{asset.ip}</h1>
          <span style={{ fontSize: "11px", padding: "3px 10px", borderRadius: "999px", background: "rgba(16,185,129,0.1)", color: "#34d399", border: "1px solid rgba(16,185,129,0.2)", fontWeight: 600 }}>
            {asset.status}
          </span>
        </div>
        <p style={{ fontSize: "13px", color: "#71717a" }}>{asset.declared_role || "Role unknown"} · {asset.environment} · {asset.data_classification}</p>
      </div>

      {/* Two-column layout */}
      <div style={{ display: "grid", gridTemplateColumns: "220px 1fr", gap: "24px", alignItems: "start" }}>
        {/* Left — score + meta */}
        <div>
          {score !== undefined && <ScoreGauge score={score} />}
          <div style={{ background: "#0d0d14", border: "1px solid #1f1f2e", borderRadius: "12px", padding: "4px 24px", marginTop: "16px" }}>
            <Row label="Tier"           value={r.tier} />
            <Row label="Tier Label"     value={r.tier_label} />
            <Row label="Confirmed Role" value={r.confirmed_role} />
            <Row label="Owner"          value={asset.owner} />
            <Row label="Scanned At"     value={asset.scanned_at ? new Date(asset.scanned_at).toLocaleString() : null} />
          </div>
        </div>

        {/* Right — details */}
        <div>
          <Section title="Network & System">
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0 32px" }}>
              <Row label="OS"          value={r.os} />
              <Row label="Hostname"    value={r.hostname} />
              <Row label="Open Ports"  value={openPorts?.join(", ")} />
              <Row label="Services"    value={services?.join(", ")} />
              <Row label="ASN"         value={r.asn} />
              <Row label="ISP"         value={r.isp} />
              <Row label="Country"     value={r.country} />
              <Row label="Abuse Score" value={r.abuse_score} />
            </div>
          </Section>

          {r.risk_summary && (
            <Section title="Risk Summary">
              <p style={{ fontSize: "13px", color: "#a1a1aa", lineHeight: 1.7, marginTop: "8px" }}>{String(r.risk_summary)}</p>
            </Section>
          )}

          {mitigations && mitigations.length > 0 && (
            <Section title="Mitigations">
              <ul style={{ listStyle: "none", padding: 0, marginTop: "8px" }}>
                {mitigations.map((m, i) => (
                  <li key={i} style={{ display: "flex", gap: "8px", fontSize: "13px", color: "#a1a1aa", padding: "6px 0", borderBottom: i < mitigations.length - 1 ? "1px solid #18181f" : "none" }}>
                    <span style={{ color: "#00ff9d", flexShrink: 0 }}>•</span>
                    {m}
                  </li>
                ))}
              </ul>
            </Section>
          )}

          {cves && cves.length > 0 && (
            <Section title={`CVEs (${cves.length})`}>
              <div style={{ display: "flex", flexWrap: "wrap", gap: "8px", marginTop: "10px", maxHeight: "200px", overflowY: "auto" }}>
                {cves.map((cve, i) => (
                  <span key={i} style={{ fontSize: "11px", padding: "4px 10px", background: "#111118", border: "1px solid #2a2a3a", borderRadius: "6px", color: "#a1a1aa", fontFamily: "monospace" }}>
                    {typeof cve === "string" ? cve : JSON.stringify(cve)}
                  </span>
                ))}
              </div>
            </Section>
          )}

          {!score && (
            <Section title="Raw Result">
              <pre style={{ fontSize: "11px", color: "#71717a", overflowX: "auto", maxHeight: "400px", marginTop: "8px" }}>
                {JSON.stringify(r, null, 2)}
              </pre>
            </Section>
          )}
        </div>
      </div>
    </div>
  );
}
