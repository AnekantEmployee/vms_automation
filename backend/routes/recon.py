import asyncio
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel
from backend.db.queries import (
    create_recon_job, update_recon_job, get_recon_job, get_all_recon_jobs,
    create_scan_session, create_scan_rows,
    update_scan_row_result, update_scan_row_error, update_scan_session_status,
)

router = APIRouter(tags=["Recon"])


# ── Passive recon background task ──────────────────────────────────────────────

def _run_recon(job_id: str, domain: str):
    import sys, os, time
    # Ensure project root is on path so passive_recon.py can be found
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    if root not in sys.path:
        sys.path.insert(0, root)
    try:
        from passive_recon import (
            collect_hostnames, resolve_ips, enrich_ip,
            mx_ips, ns_ips, infer_role, infer_classification, infer_environment,
        )

        hostnames = collect_hostnames(domain)
        ip_map = resolve_ips(hostnames)
        for ip, host in mx_ips(domain).items():
            ip_map.setdefault(ip, []).append(f"MX:{host}")
        for ip, host in ns_ips(domain).items():
            ip_map.setdefault(ip, []).append(f"NS:{host}")

        assets = []
        for ip, hosts in ip_map.items():
            org_info = enrich_ip(ip)
            time.sleep(0.4)
            hosts = sorted(set(h for h in hosts if h))
            role           = infer_role(hosts, org_info)
            classification = infer_classification(hosts, role)
            environment    = infer_environment(hosts, role)
            assets.append({
                "ip":                  ip,
                "hostnames":           hosts,
                "asn":                 org_info["asn"],
                "org":                 org_info["org"],
                "country":             org_info["country"],
                "region":              org_info["region"],
                "city":                org_info["city"],
                "anycast":             org_info["anycast"],
                "asset_role":          role,
                "data_classification": classification,
                "environment":         environment,
            })

        update_recon_job(job_id, "done", assets=assets)

    except Exception as e:
        update_recon_job(job_id, "error", error=str(e))


# ── Asset scan background task (after import) ──────────────────────────────────

async def _run_asset_scan(scan_id: str, rows_payload: list[dict], row_id_map: dict[int, str]):
    from backend.services.asset_service import run_asset_agent

    async def _one(rp: dict):
        row_id = row_id_map[rp["row_index"]]
        try:
            result = await asyncio.to_thread(
                run_asset_agent,
                rp["ip"], rp["declared_role"],
                rp["data_classification"], rp["environment"], rp["owner"],
            )
            update_scan_row_result(row_id, result)
        except Exception as e:
            update_scan_row_error(row_id, str(e))

    await asyncio.gather(*[_one(r) for r in rows_payload])
    update_scan_session_status(scan_id, "done")


# ── Routes ─────────────────────────────────────────────────────────────────────

class StartReconRequest(BaseModel):
    domain: str


@router.post("/recon/start")
def start_recon(body: StartReconRequest, background_tasks: BackgroundTasks):
    domain = (
        body.domain.lower().strip()
        .removeprefix("http://").removeprefix("https://")
        .split("/")[0]
    )
    job = create_recon_job(domain)
    background_tasks.add_task(_run_recon, job["id"], domain)
    return {"job_id": job["id"], "domain": domain, "status": "processing"}


@router.get("/recon/jobs")
def list_recon_jobs():
    return get_all_recon_jobs()


@router.get("/recon/{job_id}")
def get_recon(job_id: str):
    job = get_recon_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Recon job not found")
    return job


class ImportReconRequest(BaseModel):
    scan_name: str = ""


@router.post("/recon/{job_id}/import")
async def import_recon(job_id: str, body: ImportReconRequest, background_tasks: BackgroundTasks):
    job = get_recon_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Recon job not found")
    if job["status"] != "done":
        raise HTTPException(status_code=400, detail="Recon job is not complete yet")

    assets = job.get("assets") or []
    if not assets:
        raise HTTPException(status_code=400, detail="No assets found in recon job")

    scan_name = body.scan_name or f"Recon: {job['domain']}"
    session = create_scan_session(
        filename=f"{job['domain']}_recon.json",
        total_assets=len(assets),
        scan_name=scan_name,
    )
    scan_id = session["id"]

    rows_payload = [
        {
            "row_index":           i,
            "ip":                  a["ip"],
            "declared_role":       a.get("asset_role") or "Unknown / Let AI infer",
            "data_classification": a.get("data_classification") or "internal",
            "environment":         a.get("environment") or "production",
            "owner":               "unknown",
        }
        for i, a in enumerate(assets)
    ]

    db_rows = create_scan_rows(scan_id, rows_payload)
    row_id_map = {r["row_index"]: r["id"] for r in db_rows}

    background_tasks.add_task(
        asyncio.run,
        _run_asset_scan(scan_id, rows_payload, row_id_map),
    )

    return {"scan_id": scan_id, "total_assets": len(assets), "message": "Import started"}
