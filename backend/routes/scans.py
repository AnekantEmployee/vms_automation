from fastapi import APIRouter, HTTPException
from backend.db.queries import (
    get_all_scan_sessions, get_scan_session, get_scan_rows, get_scan_row,
    delete_scan_session, delete_scan_row,
)

router = APIRouter()


@router.get("/scans")
def list_scans():
    return get_all_scan_sessions()


@router.get("/scans/{scan_id}")
def get_scan(scan_id: str):
    session = get_scan_session(scan_id)
    if not session:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {**session, "assets": get_scan_rows(scan_id)}


@router.delete("/scans/{scan_id}")
def remove_scan(scan_id: str):
    if not get_scan_session(scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")
    delete_scan_session(scan_id)
    return {"deleted": scan_id}


@router.get("/scans/{scan_id}/{row_id}")
def get_asset_detail(scan_id: str, row_id: str):
    row = get_scan_row(row_id)
    if not row or row.get("scan_id") != scan_id:
        raise HTTPException(status_code=404, detail="Asset not found")
    return row


@router.delete("/scans/{scan_id}/{row_id}")
def remove_asset(scan_id: str, row_id: str):
    row = get_scan_row(row_id)
    if not row or row.get("scan_id") != scan_id:
        raise HTTPException(status_code=404, detail="Asset not found")
    delete_scan_row(row_id)
    return {"deleted": row_id}
