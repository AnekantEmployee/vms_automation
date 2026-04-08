from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor

from backend.core.asset_criticality.nmap_scan      import run_nmap
from backend.core.asset_criticality.ip_intel       import run_ip_intel
from backend.core.asset_criticality.cve_lookup     import run_cve_lookup
from backend.core.asset_criticality.role_inference import run_role_inference
from backend.core.asset_criticality.risk_scoring   import run_risk_scoring
from main_config.llm_manager          import get_master_llm


def run_asset_agent(
    ip: str,
    declared_role: str,
    data_classification: str,
    environment: str,
    owner: str,
) -> dict:
    asset: dict = {
        "ip":                  ip,
        "declared_role":       declared_role,
        "data_classification": data_classification,
        "environment":         environment,
        "owner":               owner,
    }

    with ThreadPoolExecutor(max_workers=2) as ex:
        f_nmap  = ex.submit(run_nmap, ip)
        f_intel = ex.submit(run_ip_intel, ip)
        asset.update(f_nmap.result())
        asset.update(f_intel.result())

    cve_data = run_cve_lookup(
        services=asset.get("services", []),
        os_name=asset.get("os", ""),
    )
    asset.update(cve_data)

    llm, _ = get_master_llm()
    asset.update(run_role_inference(llm, asset))
    asset.update(run_risk_scoring(llm, asset))

    asset["scanned_at"] = datetime.now(timezone.utc).isoformat()
    return asset
