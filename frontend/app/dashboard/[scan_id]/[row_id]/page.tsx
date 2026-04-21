"use client";

import { use, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { getQualysScan, getExploit, analyseExploit, searchByIp, getAssetDetail, type QualysRow, type ExploitResult, type AssetRow } from "@/lib/api";
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
  const [exploit, setExploit] = useState<ExploitResult | null>(null);
  const [exploitLoading, setExploitLoading] = useState(false);
  const [assetRow, setAssetRow] = useState<AssetRow | null>(null);

  useEffect(() => {
    getQualysScan(scan_id)
      .then((scan) => {
        const found = scan.rows.find((r) => r.id === row_id) ?? null;
        setRow(found);
        // Use embedded exploit if already processed during upload
        if (found?.result?.exploit) {
          setExploit(found.result.exploit as ExploitResult);
        } else {
          const cve = found?.result?.cve;
          if (cve) getExploit(cve).then((rec) => setExploit(rec.result)).catch(() => {});
        }
        // Fetch linked asset criticality via IP
        const ip = found?.result?.asset_ipv4;
        if (ip) {
          searchByIp(ip)
            .then((rows) => {
              if (rows.length > 0) {
                getAssetDetail(rows[0].scan_id, rows[0].id)
                  .then(setAssetRow)
                  .catch(() => {});
              }
            })
            .catch(() => {});
        }
      })
      .finally(() => setLoading(false));
  }, [scan_id, row_id]);

  const handleAnalyseExploit = async (cve: string) => {
    setExploitLoading(true);
    try {
      const result = await analyseExploit(cve, false);
      setExploit(result);
    } catch {}
    finally { setExploitLoading(false); }
  };

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

        {/* Asset Criticality */}
        {assetRow?.result && (() => {
          const a = assetRow.result as Record<string, unknown>;
          const tierColor: Record<string, string> = { "1": "#f87171", "2": "#fbbf24", "3": "#818cf8", "4": "#34d399" };
          const tc = tierColor[a.tier as string] ?? "#71717a";
          const score = a.score as number;
          return (
            <Section title="Asset Criticality" color="#00ff9d">
              {/* Score bar */}
              <div style={{ display: "flex", alignItems: "center", gap: "16px", marginBottom: "16px", flexWrap: "wrap" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                  <div style={{ width: "120px", height: "6px", background: "#1f1f2e", borderRadius: "4px", overflow: "hidden" }}>
                    <div style={{ height: "100%", width: `${(score / 10) * 100}%`, background: tc, borderRadius: "4px" }} />
                  </div>
                  <span style={{ fontSize: "13px", color: tc, fontWeight: 700 }}>{score}/10</span>
                </div>
                {a.tier_label && <span style={{ fontSize: "11px", padding: "3px 10px", borderRadius: "999px", background: `${tc}18`, color: tc, border: `1px solid ${tc}44`, fontWeight: 600 }}>{a.tier_label as string}</span>}
              </div>

              <Grid items={[
                ["Confirmed Role",     a.confirmed_role as string],
                ["Baseline Criticality",a.baseline_criticality as string],
                ["Environment",        a.environment as string],
                ["Data Classification",a.data_classification as string],
                ["OS",                 a.os as string],
                ["Hostname",           a.hostname as string],
                ["Internet Facing",    a.internet_facing !== undefined ? (a.internet_facing ? "Yes" : "No") : undefined],
                ["Open Ports",         a.open_ports_count !== undefined ? String(a.open_ports_count) : undefined],
                ["AbuseIPDB Score",    a.abuse_confidence !== undefined && (a.abuse_confidence as number) >= 0 ? `${a.abuse_confidence}%` : undefined],
                ["GreyNoise",          a.greynoise_classification as string],
                ["ASN",                a.asn as string],
                ["Hosting Provider",   a.hosting_provider as string],
                ["Total CVEs",         a.total_cves !== undefined ? String(a.total_cves) : undefined],
                ["Critical CVEs",      a.critical_cves !== undefined ? String(a.critical_cves) : undefined],
                ["Max CVSS",           a.max_cvss !== undefined ? String(a.max_cvss) : undefined],
              ]} />

              {a.summary && <TextBlock label="Risk Summary" content={a.summary as string} />}
              {a.role_reasoning && <TextBlock label="Role Reasoning" content={a.role_reasoning as string} />}

              {(a.risk_factors as string[])?.length > 0 && (
                <div style={{ marginTop: "14px" }}>
                  <div style={{ ...TH, marginBottom: "6px" }}>Risk Factors</div>
                  <ul style={{ margin: 0, paddingLeft: "18px", display: "flex", flexDirection: "column", gap: "4px" }}>
                    {(a.risk_factors as string[]).map((f, i) => <li key={i} style={{ fontSize: "12px", color: "#a1a1aa" }}>{f}</li>)}
                  </ul>
                </div>
              )}

              {(a.remediation as string[])?.length > 0 && (
                <div style={{ marginTop: "14px" }}>
                  <div style={{ ...TH, marginBottom: "6px" }}>Remediation Actions</div>
                  <ul style={{ margin: 0, paddingLeft: "18px", display: "flex", flexDirection: "column", gap: "4px" }}>
                    {(a.remediation as string[]).map((r, i) => <li key={i} style={{ fontSize: "12px", color: "#a1a1aa" }}>{r}</li>)}
                  </ul>
                </div>
              )}

              {(a.services as string[])?.length > 0 && (
                <div style={{ marginTop: "14px" }}>
                  <div style={TH}>Services</div>
                  <div style={{ marginTop: "6px" }}>
                    <Chips items={a.services as string[]} color="#34d399" bg="rgba(52,211,153,0.08)" border="rgba(52,211,153,0.2)" />
                  </div>
                </div>
              )}
            </Section>
          );
        })()}

        {/* CVE Exploitability */}
        {exploit ? (() => {
          const ex = exploit;
          const tierColor: Record<string, string> = {
            critical: "#f87171", high: "#fbbf24", medium: "#818cf8", low: "#34d399",
          };
          const tc = tierColor[ex.exploitability_tier?.toLowerCase() ?? ""] ?? "#71717a";
          return (
            <Section title="CVE Exploitability" color="#f87171">
              {/* Summary bar */}
              <div style={{ display: "flex", alignItems: "center", gap: "16px", marginBottom: "16px", flexWrap: "wrap" }}>
                {ex.exploitability_score !== undefined && (
                  <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                    <div style={{ width: "120px", height: "6px", background: "#1f1f2e", borderRadius: "4px", overflow: "hidden" }}>
                      <div style={{ height: "100%", width: `${(ex.exploitability_score / 10) * 100}%`, background: tc, borderRadius: "4px" }} />
                    </div>
                    <span style={{ fontSize: "13px", color: tc, fontWeight: 700 }}>{ex.exploitability_score}/10</span>
                  </div>
                )}
                {ex.tier_label && <span style={{ fontSize: "11px", padding: "3px 10px", borderRadius: "999px", background: `${tc}18`, color: tc, border: `1px solid ${tc}44`, fontWeight: 600 }}>{ex.tier_label}</span>}
                {ex.patch_priority && <span style={{ fontSize: "11px", color: "#71717a" }}>Patch Priority: <span style={{ color: "#a1a1aa" }}>{ex.patch_priority}</span></span>}
              </div>

              <Grid items={[
                ["Exploit Count",    ex.exploit_count !== undefined ? String(ex.exploit_count) : undefined],
                ["Raw Exploit Count",String(ex.raw_exploit_count)],
                ["EPSS Estimate",    ex.epss_estimate !== undefined ? `${(ex.epss_estimate * 100).toFixed(2)}%` : undefined],
                ["Has Metasploit",   ex.has_metasploit !== undefined ? (ex.has_metasploit ? "Yes" : "No") : undefined],
                ["Has Full Exploit", ex.has_full_exploit !== undefined ? (ex.has_full_exploit ? "Yes" : "No") : undefined],
                ["In The Wild",      ex.in_the_wild !== undefined ? (ex.in_the_wild ? "Yes" : "No") : undefined],
                ["Exploit Maturity", ex.exploit_maturity],
                ["Attack Complexity",ex.attack_complexity],
                ["Attacker Profile", ex.attacker_profile],
                ["Analysed At",      ex.analysed_at ? new Date(ex.analysed_at as string).toLocaleString() : undefined],
              ]} />

              {ex.executive_summary && <TextBlock label="Executive Summary" content={ex.executive_summary as string} />}
              {ex.analysis_notes    && <TextBlock label="Analysis Notes"    content={ex.analysis_notes as string} />}
              {ex.most_dangerous_url && (
                <div style={{ marginTop: "14px" }}>
                  <div style={TH}>Most Dangerous Exploit</div>
                  <a href={ex.most_dangerous_url as string} target="_blank" rel="noreferrer"
                    style={{ fontSize: "12px", color: "#818cf8", wordBreak: "break-all", display: "block", marginTop: "4px" }}>
                    {ex.most_dangerous_url as string}
                  </a>
                  {ex.most_dangerous_notes && <div style={{ fontSize: "12px", color: "#71717a", marginTop: "4px" }}>{ex.most_dangerous_notes as string}</div>}
                </div>
              )}

              {ex.unique_exploits && ex.unique_exploits.length > 0 && (
                <div style={{ marginTop: "14px" }}>
                  <div style={{ ...TH, marginBottom: "8px" }}>Known Exploits ({ex.unique_exploits.length})</div>
                  <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                    {ex.unique_exploits.map((ue, i) => (
                      <div key={i} style={{ background: "#111118", border: "1px solid #1f1f2e", borderRadius: "8px", padding: "12px 14px" }}>
                        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "8px", flexWrap: "wrap", marginBottom: "6px" }}>
                          <span style={{ fontSize: "12px", color: "white", fontWeight: 600 }}>{ue.name || ue.source}</span>
                          <div style={{ display: "flex", gap: "6px" }}>
                            <span style={{ fontSize: "10px", padding: "2px 7px", borderRadius: "4px", background: "rgba(129,140,248,0.1)", color: "#818cf8", border: "1px solid rgba(129,140,248,0.2)" }}>{ue.source}</span>
                            <span style={{ fontSize: "10px", padding: "2px 7px", borderRadius: "4px", background: "rgba(251,191,36,0.08)", color: "#fbbf24", border: "1px solid rgba(251,191,36,0.15)" }}>{ue.exploit_type}</span>
                          </div>
                        </div>
                        <div style={{ display: "flex", gap: "16px", fontSize: "11px", color: "#52525b", marginBottom: ue.url ? "6px" : 0 }}>
                          <span>Reliability: <span style={{ color: "#a1a1aa" }}>{ue.reliability}</span></span>
                          <span>Weaponization: <span style={{ color: "#a1a1aa" }}>{ue.weaponization}</span></span>
                          <span>Skill Required: <span style={{ color: "#a1a1aa" }}>{ue.skill_required}</span></span>
                        </div>
                        {ue.url && <a href={ue.url} target="_blank" rel="noreferrer" style={{ fontSize: "11px", color: "#818cf8", wordBreak: "break-all" }}>{ue.url}</a>}
                        {ue.notes && <div style={{ fontSize: "11px", color: "#71717a", marginTop: "4px" }}>{ue.notes}</div>}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {ex.mitigations && ex.mitigations.length > 0 && (
                <div style={{ marginTop: "14px" }}>
                  <div style={{ ...TH, marginBottom: "6px" }}>Mitigations</div>
                  <ul style={{ margin: 0, paddingLeft: "18px", display: "flex", flexDirection: "column", gap: "4px" }}>
                    {ex.mitigations.map((m, i) => <li key={i} style={{ fontSize: "12px", color: "#a1a1aa" }}>{m}</li>)}
                  </ul>
                </div>
              )}
            </Section>
          );
        })() : r.cve ? (
          <Section title="CVE Exploitability" color="#f87171">
            <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
              <span style={{ fontSize: "13px", color: "#52525b" }}>No exploit analysis yet for {r.cve}.</span>
              <button
                onClick={() => handleAnalyseExploit(r.cve!)}
                disabled={exploitLoading}
                style={{ padding: "6px 14px", background: exploitLoading ? "#1f1f2e" : "rgba(239,68,68,0.15)", color: exploitLoading ? "#52525b" : "#f87171", border: "1px solid rgba(239,68,68,0.25)", borderRadius: "6px", fontSize: "12px", fontWeight: 600, cursor: exploitLoading ? "default" : "pointer" }}
              >
                {exploitLoading ? "Analysing..." : "Analyse Now"}
              </button>
            </div>
          </Section>
        ) : null}

      </div>
    </div>
  );
}
