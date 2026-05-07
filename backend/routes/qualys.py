from fastapi import APIRouter, HTTPException, Query, UploadFile, File, Form, BackgroundTasks
from asyncio import to_thread
from typing import Optional
import uuid
from backend.services.qualys_service import query_by_qids, debug_raw_xml, _kb_request
from backend.services.qualys_processor import process_qualys_excel
from backend.db.queries import (
    get_all_qualys_scans, get_qualys_scan, get_qualys_scan_rows,
    get_qualys_scan_rows_with_summary, get_qualys_scan_row,
    delete_qualys_scan, delete_qualys_scan_row, get_qualys_rows_by_ip,
)

router = APIRouter(tags=["Qualys"])


@router.get("/qualys/kb")
async def qualys_kb(qids: list[int] = Query(...)):
    try:
        result = await to_thread(query_by_qids, qids)
        return result
    except RuntimeError as e:
        raise HTTPException(status_code=502, detail=str(e))


@router.get("/qualys/kb/debug")
async def qualys_kb_debug(qids: list[int] = Query(...)):
    """Returns raw XML of first VULN — use to identify missing tag names."""
    try:
        root = await to_thread(_kb_request, {"ids": ",".join(str(q) for q in qids), "details": "All"})
        return {"raw_xml": debug_raw_xml(root)}
    except RuntimeError as e:
        raise HTTPException(status_code=502, detail=str(e))


@router.post("/qualys/upload")
async def upload_qualys(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    scan_name: Optional[str] = Form(None),
):
    file_bytes = await file.read()
    job_id = str(uuid.uuid4())
    background_tasks.add_task(process_qualys_excel, job_id, file_bytes, file.filename, scan_name or "")
    return {"job_id": job_id, "message": "Processing started", "filename": file.filename}


@router.get("/qualys/scans")
def list_qualys_scans():
    from datetime import datetime, timezone
    sessions = get_all_qualys_scans()
    for session in sessions:
        total_secs = 0
        try:
            if session.get("created_at") and session.get("completed_at"):
                start = datetime.fromisoformat(session["created_at"])
                end   = datetime.fromisoformat(session["completed_at"])
                if start.tzinfo is None: start = start.replace(tzinfo=timezone.utc)
                if end.tzinfo is None:   end   = end.replace(tzinfo=timezone.utc)
                total_secs = max(0, int((end - start).total_seconds()))
        except Exception:
            pass
        session["total_asset_secs"] = total_secs
    return sessions


@router.get("/qualys/scans/{scan_id}")
def get_qualys_scan_detail(scan_id: str):
    session = get_qualys_scan(scan_id)
    if not session:
        raise HTTPException(status_code=404, detail="Qualys scan not found")
    return {**session, "rows": get_qualys_scan_rows_with_summary(scan_id)}


@router.get("/qualys/scans/{scan_id}/{row_id}")
def get_qualys_row_detail(scan_id: str, row_id: str):
    row = get_qualys_scan_row(row_id)
    if not row or row.get("scan_id") != scan_id:
        raise HTTPException(status_code=404, detail="Row not found")
    return row


@router.post("/qualys/scans/{scan_id}/{row_id}/retry-risk")
async def retry_risk(scan_id: str, row_id: str, background_tasks: BackgroundTasks):
    from backend.services.qualys_processor import run_risk_agent
    from backend.db.queries import get_qualys_scan_row, get_asset_criticality_by_ip, get_cve_exploitability
    from backend.db.queries import upsert_cve_exploitability
    from backend.services.exploit_service import run_exploit_agent
    import asyncio

    row = get_qualys_scan_row(row_id)
    if not row or row.get("scan_id") != scan_id:
        raise HTTPException(status_code=404, detail="Row not found")

    async def _retry():
        from backend.db.client import get_db
        from datetime import datetime, timezone
        result = dict(row.get("result") or {})
        # re-attach exploit if missing and CVE exists
        cve = result.get("cve", "")
        if cve and cve.upper().startswith("CVE-") and not result.get("exploit"):
            try:
                cached = get_cve_exploitability(cve)
                result["exploit"] = cached["result"] if cached else await asyncio.to_thread(run_exploit_agent, cve)
            except Exception:
                pass
        # re-attach asset criticality if missing
        ip = result.get("asset_ipv4", "")
        if ip and not result.get("asset_criticality"):
            try:
                rec = await asyncio.to_thread(get_asset_criticality_by_ip, ip)
                if rec:
                    result["asset_criticality"] = rec
            except Exception:
                pass
        # always run risk agent regardless of CVE presence
        try:
            result["risk"] = await asyncio.to_thread(run_risk_agent, result)
        except Exception as e:
            result["risk"] = {"error": str(e)}
        db = get_db()
        db.table("qualys_scan_rows").update({
            "status": "done",
            "result": result,
            "scanned_at": datetime.now(timezone.utc).isoformat(),
        }).eq("id", row_id).execute()

    background_tasks.add_task(_retry)
    return {"status": "retrying", "row_id": row_id}


@router.delete("/qualys/scans/{scan_id}/{row_id}")
def remove_qualys_row(scan_id: str, row_id: str):
    row = get_qualys_scan_row(row_id)
    if not row or row.get("scan_id") != scan_id:
        raise HTTPException(status_code=404, detail="Row not found")
    delete_qualys_scan_row(row_id)
    return {"deleted": row_id}


@router.post("/qualys/attack-chain")
async def generate_attack_chain(body: dict, background_tasks: BackgroundTasks):
    from backend.services.attack_chain_service import run_attack_chain_agent
    from backend.db.client import get_db
    from datetime import datetime, timezone

    ip = (body.get("ip") or "").strip()
    if not ip:
        raise HTTPException(status_code=422, detail="ip is required")

    rows = get_qualys_rows_by_ip(ip)
    if not rows:
        raise HTTPException(status_code=404, detail=f"No done qualys rows found for IP {ip}")

    # Check if a fresh chain already exists (< 1 hour old)
    db = get_db()
    existing = (
        db.table("attack_chains")
        .select("*")
        .eq("ip", ip)
        .order("created_at", desc=True)
        .limit(1)
        .execute()
    )
    if existing.data and not body.get("force_refresh"):
        rec = existing.data[0]
        age_secs = (datetime.now(timezone.utc) - datetime.fromisoformat(rec["created_at"].replace("Z", "+00:00"))).total_seconds()
        if age_secs < 3600:
            return rec

    # Run synchronously — attack chain is a single LLM call, not per-row
    try:
        result = await to_thread(run_attack_chain_agent, ip, rows)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    saved = db.table("attack_chains").insert({
        "ip":         ip,
        "total_vulns": len(rows),
        "result":     result,
    }).execute()

    return saved.data[0]


@router.get("/qualys/attack-chain/{ip:path}")
def get_attack_chain(ip: str):
    db = get_db()
    res = (
        db.table("attack_chains")
        .select("*")
        .eq("ip", ip)
        .order("created_at", desc=True)
        .limit(1)
        .execute()
    )
    if not res.data:
        raise HTTPException(status_code=404, detail="No attack chain found for this IP")
    return res.data[0]


@router.delete("/qualys/scans/{scan_id}")
def remove_qualys_scan(scan_id: str):
    if not get_qualys_scan(scan_id):
        raise HTTPException(status_code=404, detail="Qualys scan not found")
    delete_qualys_scan(scan_id)
    return {"deleted": scan_id}
