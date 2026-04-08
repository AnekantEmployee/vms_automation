from fastapi import APIRouter, HTTPException
from backend.db.queries import (
    get_all_scan_sessions,
    get_scan_session,
    get_scan_rows,
    get_scan_row,
)

router = APIRouter()


@router.get("/scans")
def list_scans():
    """List all scan sessions (history)."""
    return get_all_scan_sessions()


@router.get("/scans/{scan_id}")
def get_scan(scan_id: str):
    """Get scan session + all its asset rows."""
    session = get_scan_session(scan_id)
    if not session:
        raise HTTPException(status_code=404, detail="Scan not found")
    rows = get_scan_rows(scan_id)
    return {**session, "assets": rows}


@router.get("/scans/{scan_id}/{row_id}")
def get_asset_detail(scan_id: str, row_id: str):
    """Get full detail for a single asset row."""
    row = get_scan_row(row_id)
    if not row or row.get("scan_id") != scan_id:
        raise HTTPException(status_code=404, detail="Asset not found")
    return row
