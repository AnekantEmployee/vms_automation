"""
role_inference.py — LLM Step 1: Confirm or refine the declared asset role.

Even though the user declares a role, the LLM cross-validates it against
real evidence (ports, services, hostname, OS) and may:
  - Confirm the declared role
  - Detect additional roles (e.g. "Web Server + Database" combo)
  - Flag a mismatch (e.g. "declared File Server but LDAP/Kerberos ports suggest AD")

This gives a richer, evidence-backed role description that Step 2 uses to
assign a correct baseline criticality weight.

Returns:
{
    "confirmed_role":       "Active Directory / Domain Controller",
    "detected_roles":       ["Active Directory / Domain Controller"],
    "role_confidence":      "high",        # high | medium | low
    "role_mismatch":        False,
    "mismatch_note":        "",
    "baseline_criticality": "critical",    # critical | high | medium | low
    "role_reasoning":       "Port 389 (LDAP)...",
}
"""

import json
import re


# Map plain LLM text to a canonical baseline weight.
# The LLM is free to reason, but must pick one of these labels.
BASELINE_WEIGHTS = {
    "critical": 10,
    "high":      7,
    "medium":    5,
    "low":       2,
}


def run_role_inference(llm, asset: dict) -> dict:
    """
    llm   : any object with a .call(prompt: str) -> str method
    asset : dict containing nmap + ip_intel data (pre-merged by the agent)
    """
    declared_role = asset.get("declared_role", "Unknown")

    prompt = f"""You are a senior infrastructure security architect.

Your job is to analyse network evidence and confirm or refine the declared role of an asset.

=== ORG-PROVIDED CONTEXT ===
Declared Role        : {declared_role}
Data Classification  : {asset.get("data_classification", "unknown")}
Environment          : {asset.get("environment", "unknown")}
Owner                : {asset.get("owner", "unknown")}

=== DISCOVERED EVIDENCE ===
IP Address           : {asset.get("ip")}
Reverse Hostname     : {asset.get("hostname", "none")}
Operating System     : {asset.get("os", "unknown")}
Open Ports           : {asset.get("open_ports", [])}
Services             : {asset.get("services", [])}
Service Details      : {json.dumps(asset.get("service_details", []), indent=2)}
Internet Facing      : {asset.get("internet_facing", False)}
ASN / Org            : {asset.get("asn", "")} / {asset.get("org", "")}
Hosting Provider     : {asset.get("hosting_provider", "")}
Threat Intel Summary : {asset.get("threat_intel_summary", "none")}

=== ROLE EVIDENCE GUIDE (use as reference, not hardcoded rules) ===
- Ports 88, 389, 636, 3268, 3269 → Active Directory / Domain Controller
- Ports 445, 139 → File sharing / SMB (could be File Server or AD)
- Ports 1433, 3306, 5432, 1521, 27017 → Database Server
- Ports 25, 465, 587, 993, 143 → Email Server
- Ports 80, 443, 8080, 8443 + web services → Web / App Server
- Ports 22 only or RDP 3389 → Endpoint / Jump host
- Ports 161, 162, 179, 520 → Network Device
- Port 9200, 5601 → SIEM / Logging
- Hostname keywords: dc, ad, ldap, fs, file, sql, db, web, mail, smtp, backup, bak

=== TASK ===
1. Cross-validate the declared role against the evidence.
2. List all roles you can detect (an asset may serve multiple roles).
3. Assess baseline_criticality — how critical is this type of asset BY NATURE (independent of CVEs):
   - critical : AD/DC, PKI, DNS, core network, production database with PII
   - high     : Email, ERP, finance systems, production web app
   - medium   : File servers, developer servers, internal web apps
   - low      : Endpoints, dev/staging non-critical, backup servers

Respond ONLY with valid JSON, no markdown, no explanation:
{{
  "confirmed_role":       "<best single role label>",
  "detected_roles":       ["<role1>", "<role2>"],
  "role_confidence":      "<high|medium|low>",
  "role_mismatch":        <true|false>,
  "mismatch_note":        "<empty string if no mismatch>",
  "baseline_criticality": "<critical|high|medium|low>",
  "role_reasoning":       "<2-3 sentences citing specific ports/services/hostname>"
}}"""

    raw = llm.call(prompt)
    try:
        # Strip any accidental markdown fences
        clean = re.sub(r"```(?:json)?|```", "", raw).strip()
        result = json.loads(clean)
        # Validate baseline_criticality is one of our known weights
        if result.get("baseline_criticality") not in BASELINE_WEIGHTS:
            result["baseline_criticality"] = "medium"
        return result
    except (json.JSONDecodeError, KeyError) as e:
        print(f"[role_inference] JSON parse failed: {e}\nRaw: {raw[:300]}")
        return {
            "confirmed_role":       declared_role,
            "detected_roles":       [declared_role],
            "role_confidence":      "low",
            "role_mismatch":        False,
            "mismatch_note":        "",
            "baseline_criticality": "medium",
            "role_reasoning":       raw[:300],
        }