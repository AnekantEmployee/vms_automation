from datetime import datetime, timezone
from backend.db.client import get_db


# ── asset_scanning (scan session) ─────────────────────────────────────────────

def create_scan_session(filename: str, total_assets: int) -> dict:
    db = get_db()
    res = db.table("asset_scanning").insert({
        "filename":     filename,
        "total_assets": total_assets,
        "status":       "processing",
    }).execute()
    return res.data[0]


def update_scan_session_status(scan_id: str, status: str) -> None:
    db = get_db()
    db.table("asset_scanning").update({"status": status}).eq("id", scan_id).execute()


def get_all_scan_sessions() -> list[dict]:
    db = get_db()
    res = db.table("asset_scanning").select("*").order("created_at", desc=True).execute()
    return res.data


def get_scan_session(scan_id: str) -> dict | None:
    db = get_db()
    res = db.table("asset_scanning").select("*").eq("id", scan_id).execute()
    return res.data[0] if res.data else None


# ── asset_scan_rows (individual assets) ───────────────────────────────────────

def create_scan_rows(scan_id: str, rows: list[dict]) -> list[dict]:
    """Insert all asset rows for a scan session at once."""
    db = get_db()
    payload = [
        {
            "scan_id":             scan_id,
            "row_index":           r["row_index"],
            "ip":                  r["ip"],
            "declared_role":       r.get("declared_role", ""),
            "data_classification": r.get("data_classification", "internal"),
            "environment":         r.get("environment", "production"),
            "owner":               r.get("owner", "unknown"),
            "status":              "pending",
        }
        for r in rows
    ]
    res = db.table("asset_scan_rows").insert(payload).execute()
    return res.data


def update_scan_row_result(row_id: str, result: dict) -> None:
    db = get_db()
    db.table("asset_scan_rows").update({
        "status":     "done",
        "result":     result,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }).eq("id", row_id).execute()


def update_scan_row_error(row_id: str, error: str) -> None:
    db = get_db()
    db.table("asset_scan_rows").update({
        "status": "error",
        "result": {"error": error},
    }).eq("id", row_id).execute()


def get_scan_rows(scan_id: str) -> list[dict]:
    db = get_db()
    res = (
        db.table("asset_scan_rows")
        .select("*")
        .eq("scan_id", scan_id)
        .order("row_index")
        .execute()
    )
    return res.data


def get_scan_row(row_id: str) -> dict | None:
    db = get_db()
    res = db.table("asset_scan_rows").select("*").eq("id", row_id).execute()
    return res.data[0] if res.data else None
