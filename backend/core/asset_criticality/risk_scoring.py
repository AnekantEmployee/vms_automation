import json
import re

TIER_LABELS = {
    "1": "Critical",
    "2": "High",
    "3": "Medium",
    "4": "Low",
}

TIER_THRESHOLDS = [
    (8.5, "1"),
    (6.5, "2"),
    (4.0, "3"),
    (0.0, "4"),
]


def _score_to_tier(score: float) -> str:
    for threshold, tier in TIER_THRESHOLDS:
        if score >= threshold:
            return tier
    return "4"


def run_risk_scoring(llm, asset: dict) -> dict:
    """
    llm   : any object with a .call(prompt: str) -> str method
    asset : fully enriched dict (nmap + ip_intel + role_inference + cve data)
    """

    top_cves_str = json.dumps(asset.get("top_cves", [])[:3], indent=2)

    prompt = f"""You are a senior cybersecurity risk analyst producing an asset risk assessment.

=== ORG-PROVIDED CONTEXT ===
Declared Role        : {asset.get("declared_role", "unknown")}
Data Classification  : {asset.get("data_classification", "unknown")}
Environment          : {asset.get("environment", "unknown")}
Owner                : {asset.get("owner", "unknown")}

=== CONFIRMED ASSET PROFILE (from recon + role inference) ===
IP                   : {asset.get("ip")}
Hostname             : {asset.get("hostname", "none")}
OS                   : {asset.get("os", "unknown")}
Confirmed Role       : {asset.get("confirmed_role", "unknown")}
Detected Roles       : {asset.get("detected_roles", [])}
Baseline Criticality : {asset.get("baseline_criticality", "unknown")}
Role Reasoning       : {asset.get("role_reasoning", "")}
Role Mismatch        : {asset.get("role_mismatch", False)} — {asset.get("mismatch_note", "")}

=== NETWORK EXPOSURE ===
Internet Facing      : {asset.get("internet_facing", False)}
Open Port Count      : {asset.get("open_ports_count", 0)}
Open Ports           : {asset.get("open_ports", [])}
Services             : {asset.get("services", [])}
ASN / Hosting        : {asset.get("asn", "")} / {asset.get("hosting_provider", "")}

=== THREAT INTELLIGENCE ===
{asset.get("threat_intel_summary", "none")}
AbuseIPDB Score      : {asset.get("abuse_confidence", -1)}%
Known Scanner        : {asset.get("is_known_scanner", False)}
GreyNoise Class.     : {asset.get("greynoise_classification", "unknown")}
Shodan Vulns         : {asset.get("shodan_vulns", [])}

=== VULNERABILITY DATA (last 12 months, NVD) ===
Total CVEs           : {asset.get("total_cves", 0)}
Critical (>=9.0)     : {asset.get("critical_cves", 0)}
High (7.0-8.9)       : {asset.get("high_cves", 0)}
Medium (4.0-6.9)     : {asset.get("medium_cves", 0)}
Max CVSS             : {asset.get("max_cvss", 0)}
Top CVEs:
{top_cves_str}

=== SCORING RUBRIC ===
Produce a composite risk score from 0 to 10 based on these weighted dimensions:
  1. Asset Role Criticality  (weight 25%) — based on confirmed role + baseline_criticality
  2. Vulnerability Exposure  (weight 25%) — max CVSS, critical CVE count
  3. Network Attack Surface  (weight 20%) — internet-facing, open port count
  4. Threat Intelligence     (weight 15%) — AbuseIPDB, GreyNoise, shodan vulns
  5. Data & Env Sensitivity  (weight 15%) — data_classification + environment

Tier mapping:
  Tier 1 (Critical) → score >= 8.5
  Tier 2 (High)     → score >= 6.5
  Tier 3 (Medium)   → score >= 4.0
  Tier 4 (Low)      → score <  4.0

=== OUTPUT FORMAT ===
Respond ONLY with valid JSON, no markdown, no explanation:
{{
  "score":        <float 0.0–10.0, one decimal place>,
  "tier":         "<1|2|3|4>",
  "tier_label":   "<Critical|High|Medium|Low>",
  "risk_factors": [
    "<specific risk factor 1 with concrete data point>",
    "<specific risk factor 2>",
    "<specific risk factor 3>"
  ],
  "remediation": [
    "<prioritised action 1 — most urgent>",
    "<prioritised action 2>",
    "<prioritised action 3>"
  ],
  "summary": "<3-sentence executive summary of risk posture for a non-technical audience>"
}}"""

    raw = llm(prompt)
    try:
        clean = re.sub(r"```(?:json)?|```", "", raw).strip()
        # If truncated, try to close the JSON and parse what we have
        if not clean.endswith("}"):
            # Find last complete field before truncation
            clean = clean.rsplit(",", 1)[0] + "\n}}"
        result = json.loads(clean)

        # Validate + normalise
        score = float(result.get("score", 0))
        score = round(max(0.0, min(10.0, score)), 1)
        result["score"]      = score
        result["tier"]       = str(result.get("tier", _score_to_tier(score)))
        result["tier_label"] = TIER_LABELS.get(result["tier"], "Unknown")

        return result

    except (json.JSONDecodeError, KeyError, ValueError) as e:
        print(f"[risk_scoring] JSON parse failed: {e}\nRaw: {raw[:300]}")
        return {
            "score":        0.0,
            "tier":         "unknown",
            "tier_label":   "Unknown",
            "risk_factors": [],
            "remediation":  [],
            "summary":      raw[:500],
        }