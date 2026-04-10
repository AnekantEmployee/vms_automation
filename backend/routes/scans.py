from fastapi import APIRouter, HTTPException, UploadFile, File, Form, BackgroundTasks
from pydantic import BaseModel
from typing import Optional
from fastapi import Query
from backend.db.queries import (
    get_all_scan_sessions, get_scan_session, get_scan_rows, get_scan_row,
    delete_scan_session, delete_scan_row, add_assets_to_scan,
    search_scan_rows_by_ip,
)
from backend.services.asset_service import run_asset_agent
from backend.services.excel_processor import _read_df, _clean
import asyncio

router = APIRouter(tags=["Scans"])


# ── Read ───────────────────────────────────────────────────────────────────────

@router.get("/scans")
def list_scans():
    sessions = get_all_scan_sessions()
    # Compute total asset duration (sum of started_at -> scanned_at for each row)
    for session in sessions:
        rows = get_scan_rows(session["id"])
        total_secs = 0
        for r in rows:
            if r.get("started_at") and r.get("scanned_at"):
                try:
                    from datetime import datetime, timezone
                    start = datetime.fromisoformat(r["started_at"])
                    end   = datetime.fromisoformat(r["scanned_at"])
                    if start.tzinfo is None: start = start.replace(tzinfo=timezone.utc)
                    if end.tzinfo is None:   end   = end.replace(tzinfo=timezone.utc)
                    total_secs += max(0, int((end - start).total_seconds()))
                except Exception:
                    pass
        session["total_asset_secs"] = total_secs
    return sessions


@router.get("/scans/search")
def search_by_ip(ip: str = Query(..., description="IP address to search for")):
    rows = search_scan_rows_by_ip(ip)
    if not rows:
        raise HTTPException(status_code=404, detail="No assets found for the given IP")
    return rows


@router.get("/scans/{scan_id}")
def get_scan(scan_id: str):
    session = get_scan_session(scan_id)
    if not session:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {**session, "assets": get_scan_rows(scan_id)}


@router.get("/scans/{scan_id}/{row_id}")
def get_asset_detail(scan_id: str, row_id: str):
    row = get_scan_row(row_id)
    if not row or row.get("scan_id") != scan_id:
        raise HTTPException(status_code=404, detail="Asset not found")
    return row


# ── Delete ─────────────────────────────────────────────────────────────────────

@router.delete("/scans/{scan_id}")
def remove_scan(scan_id: str):
    if not get_scan_session(scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")
    delete_scan_session(scan_id)
    return {"deleted": scan_id}


@router.delete("/scans/{scan_id}/{row_id}")
def remove_asset(scan_id: str, row_id: str):
    row = get_scan_row(row_id)
    if not row or row.get("scan_id") != scan_id:
        raise HTTPException(status_code=404, detail="Asset not found")
    delete_scan_row(row_id)
    return {"deleted": row_id}


# ── Add assets ─────────────────────────────────────────────────────────────────

class ManualAsset(BaseModel):
    ip: str
    declared_role: Optional[str] = "Unknown / Let AI infer"
    data_classification: Optional[str] = "internal"
    environment: Optional[str] = "production"
    owner: Optional[str] = "unknown"


async def _process_new_rows(scan_id: str, db_rows: list[dict]):
    """Run asset agent for newly added rows in background."""
    from backend.db.queries import update_scan_row_result, update_scan_row_error, update_scan_session_status
    from backend.db.queries import get_scan_rows

    async def _one(row: dict):
        try:
            result = await asyncio.to_thread(
                run_asset_agent,
                row["ip"], row["declared_role"],
                row["data_classification"], row["environment"], row["owner"],
            )
            update_scan_row_result(row["id"], result)
        except Exception as e:
            update_scan_row_error(row["id"], str(e))

    await asyncio.gather(*[_one(r) for r in db_rows])

    # Check if all rows in scan are done
    all_rows = get_scan_rows(scan_id)
    if all(r["status"] in ("done", "error") for r in all_rows):
        update_scan_session_status(scan_id, "done")


@router.post("/scans/{scan_id}/add/manual")
async def add_manual_assets(scan_id: str, background_tasks: BackgroundTasks, assets: list[ManualAsset]):
    if not get_scan_session(scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")
    rows = [a.model_dump() for a in assets]
    db_rows = add_assets_to_scan(scan_id, rows)
    background_tasks.add_task(_process_new_rows, scan_id, db_rows)
    return {"added": len(db_rows), "scan_id": scan_id}


@router.post("/scans/{scan_id}/add/excel")
async def add_excel_assets(scan_id: str, background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    if not get_scan_session(scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")
    file_bytes = await file.read()
    df = _read_df(file_bytes, file.filename or "")
    rows = [
        {
            "ip":                  _clean(row.get("ip"), ""),
            "declared_role":       _clean(row.get("declared_role"), "Unknown / Let AI infer"),
            "data_classification": _clean(row.get("data_classification"), "internal"),
            "environment":         _clean(row.get("environment"), "production"),
            "owner":               _clean(row.get("owner"), "unknown"),
        }
        for _, row in df.iterrows()
        if _clean(row.get("ip"), "")
    ]
    if not rows:
        raise HTTPException(status_code=400, detail="No valid rows found in file")
    db_rows = add_assets_to_scan(scan_id, rows)
    background_tasks.add_task(_process_new_rows, scan_id, db_rows)
    return {"added": len(db_rows), "scan_id": scan_id}
