"use client";

import { use, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { getQualysScan, type QualysRow } from "@/lib/api";
import { AssetScanBadge } from "../../page";

const TH: React.CSSProperties = { fontSize: "10px", color: "#52525b", textTransform: "uppercase", letterSpacing: "0.06em", fontWeight: 600, marginBottom: "3px" };
const VAL: React.CSSProperties = { fontSize: "13px", color: "#a1a1aa" };

function Section({ title, color = "#52525b", children }: { title: string; color?: string; children: React.ReactNode }) {
  return (
    <div style={{ background: "#0d0d14", border: "1px solid #1f1f2e", borderRadius: "12px", padding: "20px 24px" }}>
      <div style={{ fontSize: "11px", color, textTransform: "uppercase", letterSpacing: "0.08em", fontWeight: 700, marginBottom: "16px" }}>{title}</div>
      {children}
    </div>
  );
}

function Grid({ items }: { items: [string, string | undefined | null][] }) {
  const filtered = items.filter(([, v]) => v);
  if (!filtered.length) return null;
  return (
    <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "14px" }}>
      {filtered.map(([label, val]) => (
        <div key={label}>
          <div style={TH}>{label}</div>
          <div style={VAL}>{val}</div>
        </div>
      ))}
    </div>
  );
}

function Chips({ items, color, bg, border }: { items: string[]; color: string; bg: string; border: string }) {
  if (!items?.length) return null;
  return (
    <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
      {items.map((s) => (
        <span key={s} style={{ fontSize: "11px", padding: "2px 8px", borderRadius: "6px", background: bg, color, border: `1px solid ${border}`, fontFamily: "monospace" }}>{s}</span>
      ))}
    </div>
  );
}

function TextBlock({ label, content }: { label: string; content: string }) {
  if (!content) return null;
  return (
    <div style={{ marginTop: "14px" }}>
      <div style={{ ...TH, marginBottom: "6px" }}>{label}</div>
      <div style={{ fontSize: "13px", color: "#a1a1aa", lineHeight: 1.7 }}>{content}</div>
    </div>
  );
}

function SeverityBadge({ level }: { level: string }) {
  const map: Record<string, [string, string]> = {
    "5": ["rgba(239,68,68,0.1)", "#f87171"],
    "4": ["rgba(239,68,68,0.1)", "#f87171"],
    "3": ["rgba(245,158,11,0.1)", "#fbbf24"],
    "2": ["rgba(99,102,241,0.1)", "#818cf8"],
    "1": ["rgba(16,185,129,0.1)", "#34d399"],
  };
  const label: Record<string, string> = { "5": "Critical", "4": "High", "3": "Medium", "2": "Low", "1": "Info" };
  const [bg, color] = map[level] ?? ["rgba(113,113,122,0.1)", "#71717a"];
  return <span style={{ fontSize: "12px", padding: "4px 12px", borderRadius: "999px", background: bg, color, border: `1px solid ${color}44`, fontWeight: 600 }}>{label[level] ?? level}</span>;
}

export default function QualysRowDetailPage({ params }: { params: Promise<{ scan_id: string; row_id: string }> }) {
  const { scan_id, row_id } = use(params);
  const router = useRouter();
  const [row, setRow] = useState<QualysRow | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getQualysScan(scan_id)
      .then((scan) => setRow(scan.rows.find((r) => r.id === row_id) ?? null))
      .finally(() => setLoading(false));
  }, [scan_id, row_id]);

  if (loading) return <div style={{ padding: "48px", color: "#52525b", fontSize: "13px" }}>Loading...</div>;
  if (!row?.result) return <div style={{ padding: "48px", color: "#f87171", fontSize: "13px" }}>Row not found.</div>;

  const r = row.result;
  const kb = r.kb;

  return (
    <div style={{ padding: "36px 40px", width: "100%", boxSizing: "border-box" }}>

      {/* Back */}
      <button onClick={() => router.push(`/dashboard/${scan_id}`)}
        style={{ display: "inline-flex", alignItems: "center", gap: "6px", background: "none", border: "none", color: "#71717a", fontSize: "12px", cursor: "pointer", padding: 0, marginBottom: "24px" }}>
        <svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
        </svg>
        Back to scan
      </button>

      {/* Header */}
      <div style={{ marginBottom: "28px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "12px", flexWrap: "wrap", marginBottom: "6px" }}>
          <h1 style={{ fontSize: "20px", fontWeight: 700, color: "white", margin: 0 }}>{r.title || "—"}</h1>
          <SeverityBadge level={r.severity ?? ""} />
        </div>
        <div style={{ display: "flex", gap: "16px", flexWrap: "wrap", alignItems: "center" }}>
          {r.cve && <span style={{ fontFamily: "monospace", fontSize: "13px", color: "#a78bfa" }}>{r.cve}</span>}
          {r.qid && <span style={{ fontFamily: "monospace", fontSize: "12px", color: "#52525b" }}>QID {r.qid}</span>}
          {r.asset_ipv4 && (
            <span style={{ display: "flex", alignItems: "center", gap: "6px" }}>
              <span style={{ fontFamily: "monospace", fontSize: "12px", color: "#71717a" }}>{r.asset_ipv4}</span>
              <AssetScanBadge ip={r.asset_ipv4} />
            </span>
          )}
        </div>
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>

        {/* Detection Info */}
        <Section title="Detection">
          <Grid items={[
            ["Asset Name",     r.asset_name],
            ["Asset IPv4",     r.asset_ipv4],
            ["Asset IPv6",     r.asset_ipv6],
            ["Protocol / Port", r.protocol && r.port ? `${r.protocol} / ${r.port}` : undefined],
            ["OS",             r.operating_system],
            ["Status",         r.vuln_status],
            ["First Detected", r.first_detected],
            ["Last Detected",  r.last_detected],
            ["Last Fixed",     r.last_fixed],
            ["Last Reopened",  r.last_reopened],
            ["Times Detected", r.times_detected],
            ["Detection Age",  r.detection_age ? `${r.detection_age} days` : undefined],
            ["Asset Tags",     r.asset_tags],
            ["Asset ID",       r.asset_id],
          ]} />
          {r.results && (
            <div style={{ marginTop: "14px" }}>
              <div style={TH}>Detection Output</div>
              <pre style={{ fontSize: "12px", color: "#71717a", background: "#080810", padding: "12px 14px", borderRadius: "8px", margin: "6px 0 0", whiteSpace: "pre-wrap", lineHeight: 1.6 }}>{r.results}</pre>
            </div>
          )}
        </Section>

        {/* Scoring */}
        <Section title="Scoring">
          <Grid items={[
            ["CVSSv3",              r.cvss_v3],
            ["CVSSv2",              r.cvss_v2],
            ["CVSS Rating",         r.cvss_rating_label],
            ["QVS Score",           r.qvs_score],
            ["TruRisk Score",       r.trurisk_score],
            ["Asset Critical Score",r.asset_critical_score],
            ["KB Severity",         r.kb_severity],
            ["RTI",                 r.rti],
          ]} />
        </Section>

        {/* Vulnerability Info */}
        <Section title="Vulnerability">
          <Grid items={[
            ["Category",       r.category],
            ["Type Detected",  r.type_detected],
            ["Patchable",      r.vuln_patchable],
            ["Published Date", r.published_date],
            ["Patch Released", r.patch_released],
            ["Disabled",       r.disabled],
            ["Ignored",        r.ignored],
          ]} />
          {r.cve_description && <TextBlock label="CVE Description" content={r.cve_description} />}
          {r.threat && (
            <div style={{ marginTop: "14px" }}>
              <div style={TH}>Threat</div>
              <div style={{ fontSize: "13px", color: "#a1a1aa", lineHeight: 1.7, marginTop: "6px" }} dangerouslySetInnerHTML={{ __html: r.threat }} />
            </div>
          )}
          <TextBlock label="Solution" content={r.solution} />
        </Section>

        {/* KB Enrichment */}
        {kb && (
          <Section title="Qualys KB Enrichment" color="#818cf8">
            <Grid items={[
              ["Vuln Type",       kb.vuln_type],
              ["Patchable",       kb.patchable === "1" ? "Yes" : kb.patchable === "0" ? "No" : kb.patchable],
              ["Patch Published", kb.patch_published],
              ["CVSS v2 Base",    kb.cvss_base],
              ["CVSS v2 Temporal",kb.cvss_temporal],
              ["CVSS v2 Vector",  kb.cvss_vector],
              ["CVSS v3 Base",    kb.cvss3_base],
              ["CVSS v3 Temporal",kb.cvss3_temporal],
              ["CVSS v3 Vector",  kb.cvss3_vector],
              ["Attack Vector",   kb.cvss3_attack_vector],
              ["Published",       kb.published],
              ["Last Modified",   kb.last_modified],
              ["Discovery",       kb.discovery_remote === "1" ? "Remote" : kb.discovery_remote === "0" ? "Local" : undefined],
              ["Auth Required",   kb.discovery_auth],
              ["Threat Intel",    kb.threat_intel],
              ["Exploitability",  kb.exploitability],
              ["Malware",         kb.associated_malware],
            ]} />

            {kb.cve_ids?.length > 0 && (
              <div style={{ marginTop: "14px" }}>
                <div style={TH}>CVE IDs (KB)</div>
                <div style={{ marginTop: "6px" }}>
                  <Chips items={kb.cve_ids} color="#a78bfa" bg="rgba(167,139,250,0.1)" border="rgba(167,139,250,0.2)" />
                </div>
              </div>
            )}

            {kb.affected_software?.length > 0 && (
              <div style={{ marginTop: "14px" }}>
                <div style={TH}>Affected Software</div>
                <div style={{ marginTop: "6px" }}>
                  <Chips items={kb.affected_software} color="#fbbf24" bg="rgba(251,191,36,0.08)" border="rgba(251,191,36,0.15)" />
                </div>
              </div>
            )}

            <TextBlock label="Diagnosis" content={kb.diagnosis} />
            <TextBlock label="Consequence" content={kb.consequence} />
            <TextBlock label="KB Solution" content={kb.solution} />
            {kb.affected_products && <TextBlock label="Affected Products" content={kb.affected_products} />}

            {kb.compliance?.length > 0 && (
              <div style={{ marginTop: "14px" }}>
                <div style={TH}>Compliance</div>
                <div style={{ display: "flex", flexDirection: "column", gap: "6px", marginTop: "6px" }}>
                  {kb.compliance.map((c, i) => (
                    <div key={i} style={{ fontSize: "12px", color: "#71717a", padding: "8px 12px", background: "#111118", borderRadius: "6px" }}>
                      <span style={{ color: "#a1a1aa", fontWeight: 600 }}>{c.type}</span>
                      {c.section ? <span style={{ color: "#52525b" }}> · {c.section}</span> : ""}
                      {c.description ? <span> — {c.description}</span> : ""}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </Section>
        )}

      </div>
    </div>
  );
}
