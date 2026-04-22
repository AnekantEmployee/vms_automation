from fastapi import APIRouter, HTTPException, Query, UploadFile, File, Form, BackgroundTasks
from asyncio import to_thread
from typing import Optional
import uuid
from backend.services.qualys_service import query_by_qids, debug_raw_xml, _kb_request
from backend.services.qualys_processor import process_qualys_excel
from backend.db.queries import (
    get_all_qualys_scans, get_qualys_scan, get_qualys_scan_rows,
    get_qualys_scan_rows_with_summary, get_qualys_scan_row,
    delete_qualys_scan, delete_qualys_scan_row,
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


@router.delete("/qualys/scans/{scan_id}/{row_id}")
def remove_qualys_row(scan_id: str, row_id: str):
    row = get_qualys_scan_row(row_id)
    if not row or row.get("scan_id") != scan_id:
        raise HTTPException(status_code=404, detail="Row not found")
    delete_qualys_scan_row(row_id)
    return {"deleted": row_id}


@router.delete("/qualys/scans/{scan_id}")
def remove_qualys_scan(scan_id: str):
    if not get_qualys_scan(scan_id):
        raise HTTPException(status_code=404, detail="Qualys scan not found")
    delete_qualys_scan(scan_id)
    return {"deleted": scan_id}
