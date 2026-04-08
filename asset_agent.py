import sys
import json
from pathlib import Path
from dotenv import load_dotenv
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

load_dotenv()
sys.path.insert(0, str(Path(__file__).parent))

from asset_criticality.nmap_scan      import run_nmap
from asset_criticality.ip_intel       import run_ip_intel
from asset_criticality.cve_lookup     import run_cve_lookup
from asset_criticality.role_inference import run_role_inference
from asset_criticality.risk_scoring   import run_risk_scoring
from main_config.llm_manager          import get_master_llm


def run_agent(
    ip: str,
    declared_role: str,
    data_classification: str,
    environment: str,
    owner: str,
) -> dict:
    """
    Run the full asset criticality & risk pipeline.

    Parameters
    ----------
    ip                  : IPv4 address of the asset
    declared_role       : Role provided by the org (e.g. "Active Directory / Domain Controller")
    data_classification : "public" | "internal" | "confidential" | "restricted"
    environment         : "production" | "staging" | "development" | "dr"
    owner               : Email or team name of the asset owner

    Returns
    -------
    Fully enriched asset dict ready for reporting / storage.
    """

    print("\n" + "="*60)
    print(f"  Asset Criticality Agent  |  {ip}")
    print("="*60)

    # --- Base asset dict (org-provided inputs) ---
    asset: dict = {
        "ip":                  ip,
        "declared_role":       declared_role,
        "data_classification": data_classification,
        "environment":         environment,
        "owner":               owner,
    }

    # ── Step 1: Parallel asset_criticality (nmap + ip_intel) ──────────────────────
    print("\n[Step 1/4] Running nmap + IP threat intel in parallel...")
    with ThreadPoolExecutor(max_workers=2) as ex:
        f_nmap   = ex.submit(run_nmap, ip)
        f_intel  = ex.submit(run_ip_intel, ip)
        nmap_data  = f_nmap.result()
        intel_data = f_intel.result()

    asset.update(nmap_data)
    asset.update(intel_data)

    # ── Step 2: CVE lookup (depends on nmap services) ─────────────────
    print(f"\n[Step 2/4] Looking up CVEs for services: {asset.get('services', [])}...")
    cve_data = run_cve_lookup(
        services=asset.get("services", []),
        os_name=asset.get("os", ""),
    )
    asset.update(cve_data)

    # ── Step 3: LLM role inference ────────────────────────────────────
    print("\n[Step 3/4] LLM: Role inference & baseline criticality...")
    llm, _ = get_master_llm(probe=False)
    role_data = run_role_inference(llm, asset)
    asset.update(role_data)
    print(f"           Confirmed role : {asset.get('confirmed_role')}")
    print(f"           Baseline       : {asset.get('baseline_criticality')}")
    if asset.get("role_mismatch"):
        print(f"           ⚠ Mismatch  : {asset.get('mismatch_note')}")

    # ── Step 4: LLM risk scoring ──────────────────────────────────────
    print("\n[Step 4/4] LLM: Composite risk score + tier + remediation...")
    score_data = run_risk_scoring(llm, asset)
    asset.update(score_data)
    print(f"           Score : {asset.get('score')}/10")
    print(f"           Tier  : Tier {asset.get('tier')} — {asset.get('tier_label')}")

    # ── Finalise ──────────────────────────────────────────────────────
    asset["scanned_at"] = datetime.now(timezone.utc).isoformat()

    print("\n" + "="*60)
    print("  DONE")
    print("="*60 + "\n")
    return asset


# ── Interactive entry point ───────────────────────────────────────────
if __name__ == "__main__":
    print("\n=== Asset Criticality & Risk Agent ===")

    ip                  = input("Target IP address                                            : ").strip()
    declared_role       = input("Asset role          [Enter to let AI infer]                  : ").strip() or "Unknown / Let AI infer"
    data_classification = input("Data classification [public/internal/confidential/restricted] : ").strip() or "internal"
    environment         = input("Environment         [production/staging/development/dr]       : ").strip() or "production"
    owner               = input("Owner email / team                                            : ").strip() or "unknown"

    result = run_agent(
        ip=ip,
        declared_role=declared_role,
        data_classification=data_classification,
        environment=environment,
        owner=owner,
    )

    print(json.dumps(result, indent=2, default=str))

    out = Path("results") / f"{ip.replace('.', '_')}.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(result, indent=2, default=str))
    print(f"\nResult saved to: {out}")