"""
inspect_row.py
--------------
Scans the DB, auto-picks the first available 'done' Qualys row,
then calls every API endpoint and saves each section to its own JSON file.

No arguments needed — just run:
    python inspect_row.py

Optional overrides:
    python inspect_row.py --scan-id <uuid> --row-id <uuid>
    python inspect_row.py --base-url http://localhost:8001

Output saved to:
    output/inspect_row/<scan_id>/<row_id>/
        01_qualys_row.json
        02_kb_enrichment.json
        03_exploit.json
        03_exploit_all_cves.json     (if QID maps to multiple CVEs)
        04_asset_criticality.json
        04_asset_all_scans.json      (if IP appears in multiple scans)
        05_nvd_meta.json
        06_summary.json
"""

import argparse
import json
import os
import sys
from pathlib import Path

import requests
from dotenv import load_dotenv
from supabase import create_client

load_dotenv(dotenv_path=Path(__file__).parent / ".env")

# ── Args ───────────────────────────────────────────────────────────────────────

parser = argparse.ArgumentParser()
parser.add_argument("--scan-id",  default=None, help="Qualys scan UUID (auto-detected if omitted)")
parser.add_argument("--row-id",   default=None, help="Qualys row UUID (auto-detected if omitted)")
parser.add_argument("--base-url", default="http://localhost:8001")
args = parser.parse_args()

BASE = args.base_url.rstrip("/")

# ── DB connection ──────────────────────────────────────────────────────────────

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    print("ERROR: SUPABASE_URL and SUPABASE_KEY must be set in .env")
    sys.exit(1)

db = create_client(SUPABASE_URL, SUPABASE_KEY)

# ── Auto-detect scan_id and row_id from DB ────────────────────────────────────

def hr(title: str):
    print(f"\n{'─'*60}\n  {title}\n{'─'*60}")

hr("DB Scan — auto-detecting row")

if args.scan_id and args.row_id:
    SCAN_ID = args.scan_id
    ROW_ID  = args.row_id
    print(f"  Using provided scan_id : {SCAN_ID}")
    print(f"  Using provided row_id  : {ROW_ID}")
else:
    # Get the most recent qualys scan that is done
    scans_res = db.table("qualys_scans").select("id, scan_name, filename, status, created_at") \
        .eq("status", "done").order("created_at", desc=True).limit(5).execute()

    if not scans_res.data:
        print("  No 'done' Qualys scans found in DB.")
        # Try any status
        scans_res = db.table("qualys_scans").select("id, scan_name, filename, status, created_at") \
            .order("created_at", desc=True).limit(5).execute()
        if not scans_res.data:
            print("  No Qualys scans found at all. Upload a report first.")
            sys.exit(1)

    print(f"\n  Available Qualys scans ({len(scans_res.data)} found):")
    for s in scans_res.data:
        print(f"    [{s['status']}] {s['id']}  {s.get('scan_name') or s.get('filename')}  ({s['created_at'][:10]})")

    chosen_scan = scans_res.data[0]
    SCAN_ID = chosen_scan["id"]
    print(f"\n  Auto-selected scan : {SCAN_ID}  ({chosen_scan.get('scan_name') or chosen_scan.get('filename')})")

    # Get the first done row with a CVE and an IP from that scan
    rows_res = db.table("qualys_scan_rows").select("id, row_index, status, result") \
        .eq("scan_id", SCAN_ID).eq("status", "done").order("row_index").limit(50).execute()

    if not rows_res.data:
        print(f"  No 'done' rows in scan {SCAN_ID}.")
        sys.exit(1)

    # Prefer a row that has both a CVE and an asset IP
    chosen_row = None
    for r in rows_res.data:
        res = r.get("result") or {}
        if res.get("cve") and res.get("asset_ipv4"):
            chosen_row = r
            break

    # Fall back to any done row
    if not chosen_row:
        chosen_row = rows_res.data[0]

    ROW_ID = chosen_row["id"]
    res_preview = chosen_row.get("result") or {}
    print(f"  Auto-selected row  : {ROW_ID}  (index {chosen_row['row_index']})")
    print(f"    CVE   : {res_preview.get('cve', '—')}")
    print(f"    QID   : {res_preview.get('qid', '—')}")
    print(f"    IP    : {res_preview.get('asset_ipv4', '—')}")
    print(f"    Title : {res_preview.get('title', '—')}")

OUT_DIR = Path("output") / "inspect_row" / SCAN_ID / ROW_ID
OUT_DIR.mkdir(parents=True, exist_ok=True)

# ── Helpers ────────────────────────────────────────────────────────────────────

def get(path: str, params: dict = None):
    r = requests.get(f"{BASE}{path}", params=params, timeout=300)
    r.raise_for_status()
    return r.json()

def save(name: str, data) -> None:
    p = OUT_DIR / name
    p.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    print(f"  saved → {p}")

# ── 1. Qualys row ──────────────────────────────────────────────────────────────

hr("1 / 6  Qualys row")
try:
    row = get(f"/api/qualys/scans/{SCAN_ID}/{ROW_ID}")
except requests.HTTPError as e:
    print(f"  ERROR: {e}")
    sys.exit(1)

save("01_qualys_row.json", row)

result   = row.get("result") or {}
cve_id   = result.get("cve", "")
qid      = result.get("qid", "")
asset_ip = result.get("asset_ipv4", "")

print(f"  CVE   : {cve_id or '—'}")
print(f"  QID   : {qid or '—'}")
print(f"  IP    : {asset_ip or '—'}")
print(f"  Title : {result.get('title', '—')}")

# ── 2. KB enrichment ──────────────────────────────────────────────────────────

hr("2 / 6  KB enrichment")
kb = result.get("kb")

if kb:
    print("  Using embedded kb from row result.")
    save("02_kb_enrichment.json", kb)
elif qid:
    print(f"  Fetching live for QID {qid} ...")
    try:
        kb_list = get("/api/qualys/kb", params={"qids": int(qid)})
        save("02_kb_enrichment.json", kb_list)
        kb = kb_list[0] if isinstance(kb_list, list) and kb_list else None
    except Exception as e:
        print(f"  WARN: {e}")
        save("02_kb_enrichment.json", {"error": str(e)})
else:
    # Try to find KB data from DB directly via qualys_scan_rows for same QID
    print("  No QID in row — checking DB for same QID in other rows ...")
    save("02_kb_enrichment.json", {"skipped": "no QID"})

# ── 3. CVE exploitability ─────────────────────────────────────────────────────

hr("3 / 6  CVE exploitability")

kb_cve_ids = (kb.get("cve_ids") or []) if isinstance(kb, dict) else []
cve_to_use = kb_cve_ids[0] if kb_cve_ids else cve_id

exploit_result = {}

if cve_to_use:
    print(f"  Primary CVE: {cve_to_use}")

    # Check DB directly first
    db_exploit = db.table("cve_exploitability").select("*") \
        .eq("cve_id", cve_to_use.upper()).execute()

    if db_exploit.data:
        exploit_result = db_exploit.data[0].get("result", {})
        print("  Found in DB (cve_exploitability table).")
        save("03_exploit.json", db_exploit.data[0])
    else:
        print("  Not in DB — calling analyse endpoint (may take ~30s) ...")
        try:
            exploit_result = get("/api/exploit", params={"cve_id": cve_to_use, "force_refresh": "false"})
            save("03_exploit.json", exploit_result)
        except Exception as e:
            print(f"  WARN: {e}")
            exploit_result = {"error": str(e)}
            save("03_exploit.json", exploit_result)

    # If KB has multiple CVEs, fetch all from DB or API
    if len(kb_cve_ids) > 1:
        all_exploits = {}
        for cid in kb_cve_ids:
            db_rec = db.table("cve_exploitability").select("*").eq("cve_id", cid.upper()).execute()
            if db_rec.data:
                all_exploits[cid] = db_rec.data[0]
            else:
                try:
                    all_exploits[cid] = get("/api/exploit", params={"cve_id": cid, "force_refresh": "false"})
                except Exception as e:
                    all_exploits[cid] = {"error": str(e)}
        save("03_exploit_all_cves.json", all_exploits)
        print(f"  Also saved all {len(kb_cve_ids)} KB CVEs → 03_exploit_all_cves.json")
else:
    print("  No CVE ID — skipped.")
    save("03_exploit.json", {"skipped": "no CVE ID"})

# ── 4. Asset criticality ──────────────────────────────────────────────────────

hr("4 / 6  Asset criticality")
asset_result = {}

if asset_ip:
    print(f"  Searching DB for asset rows with IP {asset_ip} ...")
    db_asset_rows = db.table("asset_scan_rows").select("*") \
        .ilike("ip", f"%{asset_ip}%").execute()

    if db_asset_rows.data:
        # Prefer rows with a result
        rows_with_result = [r for r in db_asset_rows.data if r.get("result")]
        chosen = rows_with_result[0] if rows_with_result else db_asset_rows.data[0]
        asset_result = chosen.get("result") or {}
        save("04_asset_criticality.json", chosen)
        print(f"  Found {len(db_asset_rows.data)} asset row(s). Saved first with result.")

        if len(db_asset_rows.data) > 1:
            save("04_asset_all_scans.json", db_asset_rows.data)
            print(f"  Also saved all {len(db_asset_rows.data)} rows → 04_asset_all_scans.json")
    else:
        print(f"  No asset rows found for IP {asset_ip}.")
        save("04_asset_criticality.json", {"skipped": f"no asset rows for {asset_ip}"})
else:
    print("  No asset_ipv4 — skipped.")
    save("04_asset_criticality.json", {"skipped": "no asset_ipv4"})

# ── 5. NVD metadata ───────────────────────────────────────────────────────────

hr("5 / 6  NVD metadata")
NVD_FIELDS = [
    "cve_id", "description", "cvss_v3_score", "cvss_v3_vector",
    "cvss_v2_score", "severity", "cwe", "affected_products",
    "references", "published", "analysed_at",
]
nvd = {k: exploit_result[k] for k in NVD_FIELDS if exploit_result.get(k) is not None}
save("05_nvd_meta.json", nvd if nvd else {"skipped": "no NVD data"})
print(f"  CVSS v3 : {nvd.get('cvss_v3_score', '—')}  severity: {nvd.get('severity', '—')}")

# ── 6. Summary ────────────────────────────────────────────────────────────────

hr("6 / 6  Summary")
ac = asset_result if isinstance(asset_result, dict) else {}

summary = {
    # Identity
    "scan_id":           SCAN_ID,
    "row_id":            ROW_ID,
    "cve":               cve_id,
    "qid":               qid,
    "title":             result.get("title"),
    "severity":          result.get("severity"),
    "asset_ipv4":        asset_ip,
    "asset_ipv6":        result.get("asset_ipv6"),
    "asset_name":        result.get("asset_name"),
    "asset_id":          result.get("asset_id"),
    "asset_tags":        result.get("asset_tags"),
    "operating_system":  result.get("operating_system"),
    # Detection
    "vuln_status":       result.get("vuln_status"),
    "first_detected":    result.get("first_detected"),
    "last_detected":     result.get("last_detected"),
    "last_fixed":        result.get("last_fixed"),
    "last_reopened":     result.get("last_reopened"),
    "times_detected":    result.get("times_detected"),
    "detection_age":     result.get("detection_age"),
    "protocol":          result.get("protocol"),
    "port":              result.get("port"),
    "type_detected":     result.get("type_detected"),
    "results_output":    result.get("results"),
    # Scoring
    "cvss_v2":               result.get("cvss_v2"),
    "cvss_v3":               result.get("cvss_v3"),
    "cvss_rating_label":     result.get("cvss_rating_label"),
    "qvs_score":             result.get("qvs_score"),
    "trurisk_score":         result.get("trurisk_score"),
    "asset_critical_score":  result.get("asset_critical_score"),
    "kb_severity":           result.get("kb_severity"),
    "rti":                   result.get("rti"),
    # Vulnerability
    "category":           result.get("category"),
    "vuln_patchable":     result.get("vuln_patchable"),
    "published_date":     result.get("published_date"),
    "patch_released":     result.get("patch_released"),
    "disabled":           result.get("disabled"),
    "ignored":            result.get("ignored"),
    "cve_description":    result.get("cve_description"),
    "threat":             result.get("threat"),
    "solution":           result.get("solution"),
    "vulnerability_tags": result.get("vulnerability_tags"),
    # KB
    "kb_cve_ids":            (kb or {}).get("cve_ids"),
    "kb_cvss_v2_base":       (kb or {}).get("cvss_base"),
    "kb_cvss_v3_base":       (kb or {}).get("cvss3_base"),
    "kb_cvss_v3_vector":     (kb or {}).get("cvss3_vector"),
    "kb_patchable":          (kb or {}).get("patchable"),
    "kb_patch_published":    (kb or {}).get("patch_published"),
    "kb_threat_intel":       (kb or {}).get("threat_intel"),
    "kb_exploitability":     (kb or {}).get("exploitability"),
    "kb_associated_malware": (kb or {}).get("associated_malware"),
    "kb_affected_software":  (kb or {}).get("affected_software"),
    "kb_diagnosis":          (kb or {}).get("diagnosis"),
    "kb_consequence":        (kb or {}).get("consequence"),
    "kb_solution":           (kb or {}).get("solution"),
    "kb_discovery_remote":   (kb or {}).get("discovery_remote"),
    "kb_discovery_auth":     (kb or {}).get("discovery_auth"),
    "kb_compliance":         (kb or {}).get("compliance"),
    "kb_vuln_type":          (kb or {}).get("vuln_type"),
    "kb_affected_products":  (kb or {}).get("affected_products"),
    # NVD
    "nvd_cvss_v3_score":     nvd.get("cvss_v3_score"),
    "nvd_cvss_v3_vector":    nvd.get("cvss_v3_vector"),
    "nvd_cvss_v2_score":     nvd.get("cvss_v2_score"),
    "nvd_severity":          nvd.get("severity"),
    "nvd_cwe":               nvd.get("cwe"),
    "nvd_affected_products": nvd.get("affected_products"),
    "nvd_description":       nvd.get("description"),
    "nvd_published":         nvd.get("published"),
    "nvd_references":        nvd.get("references"),
    # Exploit
    "exploit_score":          exploit_result.get("exploitability_score"),
    "exploit_tier":           exploit_result.get("exploitability_tier"),
    "exploit_tier_label":     exploit_result.get("tier_label"),
    "exploit_maturity":       exploit_result.get("exploit_maturity"),
    "exploit_count":          exploit_result.get("exploit_count"),
    "raw_exploit_count":      exploit_result.get("raw_exploit_count"),
    "has_metasploit":         exploit_result.get("has_metasploit"),
    "has_full_exploit":       exploit_result.get("has_full_exploit"),
    "in_the_wild":            exploit_result.get("in_the_wild"),
    "epss_estimate":          exploit_result.get("epss_estimate"),
    "attack_complexity":      exploit_result.get("attack_complexity"),
    "attacker_profile":       exploit_result.get("attacker_profile"),
    "patch_priority":         exploit_result.get("patch_priority"),
    "mitigations":            exploit_result.get("mitigations"),
    "executive_summary":      exploit_result.get("executive_summary"),
    "analysis_notes":         exploit_result.get("analysis_notes"),
    "most_dangerous_url":     exploit_result.get("most_dangerous_url"),
    "most_dangerous_notes":   exploit_result.get("most_dangerous_notes"),
    "unique_exploits":        exploit_result.get("unique_exploits"),
    "sources_searched":       exploit_result.get("sources_searched"),
    "raw_exploits_by_source": exploit_result.get("raw_exploits_by_source"),
    # Asset criticality
    "asset_risk_score":           ac.get("score"),
    "asset_risk_tier":            ac.get("tier"),
    "asset_risk_tier_label":      ac.get("tier_label"),
    "asset_confirmed_role":       ac.get("confirmed_role"),
    "asset_detected_roles":       ac.get("detected_roles"),
    "asset_role_confidence":      ac.get("role_confidence"),
    "asset_role_mismatch":        ac.get("role_mismatch"),
    "asset_mismatch_note":        ac.get("mismatch_note"),
    "asset_baseline_criticality": ac.get("baseline_criticality"),
    "asset_role_reasoning":       ac.get("role_reasoning"),
    "asset_risk_factors":         ac.get("risk_factors"),
    "asset_remediation":          ac.get("remediation"),
    "asset_risk_summary":         ac.get("summary"),
    "asset_internet_facing":      ac.get("internet_facing"),
    "asset_open_ports":           ac.get("open_ports"),
    "asset_open_ports_count":     ac.get("open_ports_count"),
    "asset_services":             ac.get("services"),
    "asset_service_details":      ac.get("service_details"),
    "asset_os":                   ac.get("os"),
    "asset_hostname":             ac.get("hostname"),
    "asset_asn":                  ac.get("asn"),
    "asset_org":                  ac.get("org"),
    "asset_country":              ac.get("country"),
    "asset_hosting_provider":     ac.get("hosting_provider"),
    "asset_abuse_confidence":     ac.get("abuse_confidence"),
    "asset_abuse_reports":        ac.get("abuse_reports"),
    "asset_is_known_scanner":     ac.get("is_known_scanner"),
    "asset_greynoise_class":      ac.get("greynoise_classification"),
    "asset_shodan_ports":         ac.get("shodan_ports"),
    "asset_shodan_vulns":         ac.get("shodan_vulns"),
    "asset_threat_intel_summary": ac.get("threat_intel_summary"),
    "asset_total_cves":           ac.get("total_cves"),
    "asset_critical_cves":        ac.get("critical_cves"),
    "asset_high_cves":            ac.get("high_cves"),
    "asset_medium_cves":          ac.get("medium_cves"),
    "asset_low_cves":             ac.get("low_cves"),
    "asset_max_cvss":             ac.get("max_cvss"),
    "asset_top_cves":             ac.get("top_cves"),
    "asset_declared_role":        ac.get("declared_role"),
    "asset_data_classification":  ac.get("data_classification"),
    "asset_environment":          ac.get("environment"),
    "asset_owner":                ac.get("owner"),
    "asset_scanned_at":           ac.get("scanned_at"),
}

summary = {k: v for k, v in summary.items() if v is not None}
save("06_summary.json", summary)

# ── Done ───────────────────────────────────────────────────────────────────────

print(f"\n{'═'*60}")
print(f"  Output : {OUT_DIR.resolve()}")
print(f"{'═'*60}")
print("  01_qualys_row.json        raw row from DB")
print("  02_kb_enrichment.json     Qualys KB data")
print("  03_exploit.json           CVE exploitability")
print("  04_asset_criticality.json asset agent result")
print("  05_nvd_meta.json          NVD metadata")
print("  06_summary.json           all fields combined")
print(f"{'═'*60}\n")
