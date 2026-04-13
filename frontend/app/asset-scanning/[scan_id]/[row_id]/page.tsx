"use client";

import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { getAssetDetail, type AssetRow } from "@/lib/api";

// ── helpers ───────────────────────────────────────────────────────────────────

function clean(val: unknown): string {
  if (val === null || val === undefined || val === "" || val === "nan") return "—";
  return String(val);
}

function scoreColor(s: number) {
  return s >= 7 ? "#ef4444" : s >= 4 ? "#f59e0b" : "#00ff9d";
}

// ── small components ──────────────────────────────────────────────────────────

function KV({ label, value, mono = false }: { label: string; value: unknown; mono?: boolean }) {
  const v = clean(value);
  if (v === "—" && value !== 0) return null;
  return (
    <div style={{ padding: "10px 0", borderBottom: "1px solid #18181f" }}>
      <div style={{ fontSize: "10px", color: "#52525b", textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: "3px" }}>{label}</div>
      <div style={{ fontSize: "13px", color: "#d4d4d8", fontFamily: mono ? "monospace" : "inherit" }}>{v}</div>
    </div>
  );
}

function Section({ title, children, accent }: { title: string; children: React.ReactNode; accent?: string }) {
  return (
    <div style={{ background: "#0d0d14", border: `1px solid ${accent ?? "#1f1f2e"}`, borderRadius: "12px", padding: "20px 24px", marginBottom: "16px" }}>
      <div style={{ fontSize: "11px", fontWeight: 700, color: accent ?? "#71717a", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: "12px" }}>{title}</div>
      {children}
    </div>
  );
}

function Tag({ children, color = "#a1a1aa", bg = "#1a1a24" }: { children: React.ReactNode; color?: string; bg?: string }) {
  return (
    <span style={{ fontSize: "11px", padding: "3px 10px", borderRadius: "6px", background: bg, color, fontFamily: "monospace", display: "inline-block", margin: "2px" }}>
      {children}
    </span>
  );
}

function CvssBar({ score, label }: { score: number; label: string }) {
  const color = score >= 9 ? "#ef4444" : score >= 7 ? "#f59e0b" : score >= 4 ? "#facc15" : "#00ff9d";
  return (
    <div style={{ display: "flex", alignItems: "center", gap: "10px", padding: "8px 0", borderBottom: "1px solid #18181f" }}>
      <div style={{ width: "80px", fontSize: "11px", color: "#71717a", flexShrink: 0 }}>{label}</div>
      <div style={{ flex: 1, height: "4px", background: "#1f1f2e", borderRadius: "4px", overflow: "hidden" }}>
        <div style={{ height: "100%", width: `${(score / 10) * 100}%`, background: color, borderRadius: "4px" }} />
      </div>
      <div style={{ fontSize: "12px", color, fontWeight: 600, width: "32px", textAlign: "right" }}>{score}</div>
    </div>
  );
}

function ScoreGauge({ score }: { score: number }) {
  const color = scoreColor(score);
  const label = score >= 7 ? "High Risk" : score >= 4 ? "Medium Risk" : "Low Risk";
  const r = 40, circ = 2 * Math.PI * r;
  return (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", padding: "28px 20px", background: "#0d0d14", border: `1px solid ${color}33`, borderRadius: "12px" }}>
      <div style={{ position: "relative", width: "120px", height: "120px", marginBottom: "10px" }}>
        <svg viewBox="0 0 100 100" style={{ width: "100%", height: "100%", transform: "rotate(-90deg)" }}>
          <circle cx="50" cy="50" r={r} fill="none" stroke="#1f1f2e" strokeWidth="10" />
          <circle cx="50" cy="50" r={r} fill="none" stroke={color} strokeWidth="10"
            strokeDasharray={`${(score / 10) * circ} ${circ}`} strokeLinecap="round" />
        </svg>
        <div style={{ position: "absolute", inset: 0, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center" }}>
          <span style={{ fontSize: "30px", fontWeight: 800, color: "white", lineHeight: 1 }}>{score}</span>
          <span style={{ fontSize: "11px", color: "#71717a" }}>/10</span>
        </div>
      </div>
      <span style={{ fontSize: "13px", fontWeight: 700, color }}>{label}</span>
      <span style={{ fontSize: "11px", color: "#52525b", marginTop: "2px" }}>Risk Score</span>
    </div>
  );
}

// ── main page ─────────────────────────────────────────────────────────────────

export default function AssetDetailPage() {
  const { scan_id, row_id } = useParams<{ scan_id: string; row_id: string }>();
  const router = useRouter();
  const [asset, setAsset]     = useState<AssetRow | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getAssetDetail(scan_id, row_id).then(setAsset).finally(() => setLoading(false));
  }, [scan_id, row_id]);

  if (loading) return <div style={{ padding: "48px", color: "#71717a" }}>Loading...</div>;
  if (!asset)  return <div style={{ padding: "48px", color: "#f87171" }}>Asset not found.</div>;

  const r = asset.result ?? {};

  // If risk_scoring JSON was truncated, the raw partial JSON may be stored in summary.
  // Try to parse it and merge the real fields.
  let riskResult = r;
  const rawSummary = r.summary as string;
  if (rawSummary && rawSummary.trim().startsWith("{")) {
    try {
      const parsed = JSON.parse(rawSummary);
      riskResult = { ...r, ...parsed };
    } catch {
      // leave as-is
    }
  }
  const score          = (riskResult.score as number) || 0;
  const tier           = (riskResult.tier as string) || "—";
  const tierLabel      = (riskResult.tier_label as string) || "Unknown";
  const riskFactors    = (riskResult.risk_factors as string[]) ?? [];
  const remediation    = (riskResult.remediation as string[]) ?? [];
  const summary        = rawSummary?.trim().startsWith("{") ? ((riskResult.summary as string) || "") : (rawSummary || "");
  const confirmedRole  = r.confirmed_role as string;
  const detectedRoles  = r.detected_roles as string[] ?? [];
  const roleConfidence = r.role_confidence as string;
  const roleMismatch   = r.role_mismatch as boolean;
  const mismatchNote   = r.mismatch_note as string;
  const roleReasoning  = r.role_reasoning as string;
  const baseline       = r.baseline_criticality as string;

  const openPorts      = r.open_ports as number[] ?? [];
  const services       = r.services as string[] ?? [];
  const serviceDetails = r.service_details as { port: number; name: string; product: string; version: string; state: string }[] ?? [];
  const hostname       = r.hostname as string;
  const os             = r.os as string;
  const internetFacing = r.internet_facing as boolean;
  const asn            = r.asn as string;
  const org            = r.org as string;
  const country        = r.country as string;
  const hostingProvider = r.hosting_provider as string;

  const abuseConfidence = r.abuse_confidence as number;
  const abuseReports    = r.abuse_reports as number;
  const isKnownScanner  = r.is_known_scanner as boolean;
  const greyNoise       = r.greynoise_classification as string;
  const threatSummary   = r.threat_intel_summary as string;
  const shodanPorts     = r.shodan_ports as number[] ?? [];
  const shodanVulns     = r.shodan_vulns as string[] ?? [];

  const totalCves    = r.total_cves as number;
  const criticalCves = r.critical_cves as number;
  const highCves     = r.high_cves as number;
  const mediumCves   = r.medium_cves as number;
  const lowCves      = r.low_cves as number;
  const maxCvss      = r.max_cvss as number;
  const topCves      = r.top_cves as { id: string; cvss: number; description: string }[] ?? [];

  const col2: React.CSSProperties = { display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0 32px" };

  return (
    <div style={{ padding: "40px 48px", maxWidth: "1200px" }}>
      {/* Back */}
      <button onClick={() => router.push(`/asset-scanning/${scan_id}`)}
        style={{ display: "flex", alignItems: "center", gap: "6px", background: "none", border: "none", color: "#71717a", cursor: "pointer", fontSize: "13px", marginBottom: "28px", padding: 0 }}>
        <svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
        </svg>
        Back to scan
      </button>

      {/* Header */}
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", marginBottom: "32px" }}>
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: "12px", marginBottom: "6px" }}>
            <h1 style={{ fontSize: "24px", fontWeight: 800, color: "white", fontFamily: "monospace", margin: 0 }}>{asset.ip}</h1>
            {internetFacing && (
              <span style={{ fontSize: "10px", padding: "3px 8px", borderRadius: "4px", background: "rgba(239,68,68,0.1)", color: "#f87171", border: "1px solid rgba(239,68,68,0.2)", fontWeight: 600 }}>
                INTERNET FACING
              </span>
            )}
          </div>
          <p style={{ fontSize: "13px", color: "#71717a", margin: 0 }}>
            {clean(confirmedRole)} · {asset.environment} · {asset.data_classification} · {asset.owner}
          </p>
          {hostname && <p style={{ fontSize: "12px", color: "#52525b", marginTop: "2px", fontFamily: "monospace" }}>{hostname}</p>}
        </div>
        <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: "6px" }}>
          <span style={{ fontSize: "11px", padding: "3px 10px", borderRadius: "999px", background: "rgba(16,185,129,0.1)", color: "#34d399", border: "1px solid rgba(16,185,129,0.2)", fontWeight: 600 }}>
            {asset.status}
          </span>
          {asset.scanned_at && <span style={{ fontSize: "11px", color: "#52525b" }}>{new Date(asset.scanned_at).toLocaleString()}</span>}
        </div>
      </div>

      {/* Top grid: score + tier + summary */}
      <div style={{ display: "grid", gridTemplateColumns: "200px 1fr", gap: "16px", marginBottom: "16px", alignItems: "start" }}>
        <ScoreGauge score={score} />
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: "12px" }}>
          {[
            { label: "Tier",             value: `Tier ${tier} — ${tierLabel}`, color: score >= 7 ? "#ef4444" : score >= 4 ? "#f59e0b" : "#00ff9d" },
            { label: "Baseline",         value: baseline,   color: "#a1a1aa" },
            { label: "Role Confidence",  value: roleConfidence, color: "#a1a1aa" },
            { label: "Total CVEs",       value: totalCves,  color: "#f87171" },
            { label: "Critical CVEs",    value: criticalCves, color: "#ef4444" },
            { label: "Max CVSS",         value: maxCvss,    color: maxCvss >= 9 ? "#ef4444" : "#f59e0b" },
          ].map((s) => (
            <div key={s.label} style={{ background: "#0d0d14", border: "1px solid #1f1f2e", borderRadius: "10px", padding: "14px 16px" }}>
              <div style={{ fontSize: "10px", color: "#52525b", textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: "6px" }}>{s.label}</div>
              <div style={{ fontSize: "16px", fontWeight: 700, color: s.color }}>{s.value}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Executive Summary */}
      {summary && (
        <Section title="Executive Summary" accent="#6366f1">
          <p style={{ fontSize: "13px", color: "#a1a1aa", lineHeight: 1.8, margin: 0 }}>{summary}</p>
        </Section>
      )}

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px" }}>
        {/* Left column */}
        <div>
          {/* Network */}
          <Section title="Network & System">
            <div style={col2}>
              <KV label="IP"              value={asset.ip} mono />
              <KV label="Hostname"        value={hostname} mono />
              <KV label="OS"              value={os} />
              <KV label="Country"         value={country} />
              <KV label="ASN"             value={asn} mono />
              <KV label="Organisation"    value={org} />
              <KV label="Hosting"         value={hostingProvider} />
              <KV label="Internet Facing" value={internetFacing ? "Yes" : "No"} />
            </div>
            {openPorts.length > 0 && (
              <div style={{ marginTop: "12px" }}>
                <div style={{ fontSize: "10px", color: "#52525b", textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: "8px" }}>Open Ports</div>
                <div>{openPorts.map((p) => <Tag key={p} color="#00ff9d" bg="rgba(0,255,157,0.07)">{p}</Tag>)}</div>
              </div>
            )}
            {serviceDetails.length > 0 && (
              <div style={{ marginTop: "14px" }}>
                <div style={{ fontSize: "10px", color: "#52525b", textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: "8px" }}>Service Details</div>
                <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "12px" }}>
                  <thead>
                    <tr>
                      {["Port", "Service", "Product", "Version"].map((h) => (
                        <th key={h} style={{ textAlign: "left", padding: "6px 8px", color: "#52525b", fontSize: "10px", textTransform: "uppercase", borderBottom: "1px solid #1f1f2e" }}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {serviceDetails.map((s) => (
                      <tr key={s.port} style={{ borderBottom: "1px solid #18181f" }}>
                        <td style={{ padding: "7px 8px", color: "#00ff9d", fontFamily: "monospace" }}>{s.port}</td>
                        <td style={{ padding: "7px 8px", color: "#d4d4d8" }}>{s.name}</td>
                        <td style={{ padding: "7px 8px", color: "#a1a1aa" }}>{s.product || "—"}</td>
                        <td style={{ padding: "7px 8px", color: "#71717a" }}>{s.version || "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Section>

          {/* Threat Intel */}
          <Section title="Threat Intelligence">
            <div style={col2}>
              <KV label="Abuse Confidence" value={`${abuseConfidence}%`} />
              <KV label="Abuse Reports"    value={abuseReports} />
              <KV label="Known Scanner"    value={isKnownScanner ? "Yes" : "No"} />
              <KV label="GreyNoise"        value={greyNoise} />
            </div>
            {shodanPorts.length > 0 && (
              <div style={{ marginTop: "10px" }}>
                <div style={{ fontSize: "10px", color: "#52525b", textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: "6px" }}>Shodan Ports</div>
                <div>{shodanPorts.map((p) => <Tag key={p}>{p}</Tag>)}</div>
              </div>
            )}
            {shodanVulns.length > 0 && (
              <div style={{ marginTop: "10px" }}>
                <div style={{ fontSize: "10px", color: "#52525b", textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: "6px" }}>Shodan Vulns</div>
                <div>{shodanVulns.map((v) => <Tag key={v} color="#f87171" bg="rgba(239,68,68,0.07)">{v}</Tag>)}</div>
              </div>
            )}
            {threatSummary && <p style={{ fontSize: "12px", color: "#71717a", marginTop: "12px", lineHeight: 1.7 }}>{threatSummary}</p>}
          </Section>

          {/* Role */}
          <Section title="Role Analysis">
            <KV label="Confirmed Role"   value={confirmedRole} />
            <KV label="Declared Role"    value={asset.declared_role} />
            <KV label="Role Confidence"  value={roleConfidence} />
            <KV label="Baseline"         value={baseline} />
            {roleMismatch && <KV label="Mismatch Note" value={mismatchNote} />}
            {detectedRoles.length > 0 && (
              <div style={{ padding: "10px 0" }}>
                <div style={{ fontSize: "10px", color: "#52525b", textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: "6px" }}>Detected Roles</div>
                <div>{detectedRoles.map((r) => <Tag key={r} color="#a78bfa" bg="rgba(167,139,250,0.07)">{r}</Tag>)}</div>
              </div>
            )}
            {roleReasoning && <p style={{ fontSize: "12px", color: "#71717a", marginTop: "10px", lineHeight: 1.7, borderTop: "1px solid #18181f", paddingTop: "10px" }}>{roleReasoning}</p>}
          </Section>
        </div>

        {/* Right column */}
        <div>
          {/* CVE breakdown */}
          <Section title="CVE Breakdown" accent="#ef4444">
            <CvssBar score={criticalCves} label="Critical" />
            <CvssBar score={highCves}     label="High" />
            <CvssBar score={mediumCves}   label="Medium" />
            <CvssBar score={lowCves}      label="Low" />
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px", marginTop: "14px" }}>
              <div style={{ background: "#111118", borderRadius: "8px", padding: "12px 16px" }}>
                <div style={{ fontSize: "10px", color: "#52525b", textTransform: "uppercase", marginBottom: "4px" }}>Total CVEs</div>
                <div style={{ fontSize: "22px", fontWeight: 700, color: "#f87171" }}>{totalCves}</div>
              </div>
              <div style={{ background: "#111118", borderRadius: "8px", padding: "12px 16px" }}>
                <div style={{ fontSize: "10px", color: "#52525b", textTransform: "uppercase", marginBottom: "4px" }}>Max CVSS</div>
                <div style={{ fontSize: "22px", fontWeight: 700, color: "#ef4444" }}>{maxCvss}</div>
              </div>
            </div>
          </Section>

          {/* Top CVEs */}
          {topCves.length > 0 && (
            <Section title="Top CVEs">
              {topCves.map((cve) => {
                const c = cve.cvss >= 9 ? "#ef4444" : cve.cvss >= 7 ? "#f59e0b" : "#facc15";
                return (
                  <div key={cve.id} style={{ padding: "10px 0", borderBottom: "1px solid #18181f" }}>
                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "4px" }}>
                      <span style={{ fontSize: "12px", fontFamily: "monospace", color: "#a78bfa", fontWeight: 600 }}>{cve.id}</span>
                      <span style={{ fontSize: "11px", fontWeight: 700, color: c, background: `${c}15`, padding: "2px 8px", borderRadius: "4px" }}>CVSS {cve.cvss}</span>
                    </div>
                    <p style={{ fontSize: "11px", color: "#71717a", margin: 0, lineHeight: 1.6 }}>{cve.description}</p>
                  </div>
                );
              })}
            </Section>
          )}

          {/* Risk Factors */}
          {riskFactors.length > 0 && (
            <Section title="Risk Factors" accent="#f59e0b">
              {riskFactors.map((f, i) => (
                <div key={i} style={{ display: "flex", gap: "10px", padding: "8px 0", borderBottom: i < riskFactors.length - 1 ? "1px solid #18181f" : "none" }}>
                  <span style={{ color: "#f59e0b", flexShrink: 0, marginTop: "1px" }}>⚠</span>
                  <span style={{ fontSize: "13px", color: "#a1a1aa", lineHeight: 1.6 }}>{f}</span>
                </div>
              ))}
            </Section>
          )}

          {/* Remediation */}
          {remediation.length > 0 && (
            <Section title="Remediation Steps" accent="#00ff9d">
              {remediation.map((step, i) => (
                <div key={i} style={{ display: "flex", gap: "10px", padding: "8px 0", borderBottom: i < remediation.length - 1 ? "1px solid #18181f" : "none" }}>
                  <span style={{ color: "#00ff9d", flexShrink: 0, fontWeight: 700, fontSize: "12px", marginTop: "1px" }}>{i + 1}.</span>
                  <span style={{ fontSize: "13px", color: "#a1a1aa", lineHeight: 1.6 }}>{step}</span>
                </div>
              ))}
            </Section>
          )}
        </div>
      </div>
    </div>
  );
}
