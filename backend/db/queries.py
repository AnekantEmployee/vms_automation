from datetime import datetime, timezone
from backend.db.client import get_db
import json


# ── asset_scanning ─────────────────────────────────────────────────────────────

def create_scan_session(filename: str, total_assets: int, scan_name: str = "") -> dict:
    db = get_db()
    res = db.table("asset_scanning").insert({
        "filename":     filename,
        "total_assets": total_assets,
        "scan_name":    scan_name or filename,
        "status":       "processing",
    }).execute()
    return res.data[0]


def update_scan_session_status(scan_id: str, status: str) -> None:
    db = get_db()
    update: dict = {"status": status}
    if status == "done":
        update["completed_at"] = datetime.now(timezone.utc).isoformat()
    db.table("asset_scanning").update(update).eq("id", scan_id).execute()


def delete_scan_session(scan_id: str) -> None:
    db = get_db()
    db.table("asset_scan_rows").delete().eq("scan_id", scan_id).execute()
    db.table("asset_scanning").delete().eq("id", scan_id).execute()


def get_all_scan_sessions() -> list[dict]:
    db = get_db()
    res = db.table("asset_scanning").select("*").order("created_at", desc=True).execute()
    return res.data


def get_scan_session(scan_id: str) -> dict | None:
    db = get_db()
    res = db.table("asset_scanning").select("*").eq("id", scan_id).execute()
    return res.data[0] if res.data else None


# ── asset_scan_rows ────────────────────────────────────────────────────────────

def _row_payload(scan_id: str, r: dict, row_index: int) -> dict:
    return {
        "scan_id":             scan_id,
        "row_index":           row_index,
        "ip":                  r["ip"],
        "declared_role":       r.get("declared_role", ""),
        "data_classification": r.get("data_classification", "internal"),
        "environment":         r.get("environment", "production"),
        "owner":               r.get("owner", "unknown"),
        "status":              "pending",
        "started_at":          datetime.now(timezone.utc).isoformat(),
    }


def create_scan_rows(scan_id: str, rows: list[dict]) -> list[dict]:
    db = get_db()
    payload = [_row_payload(scan_id, r, r["row_index"]) for r in rows]
    res = db.table("asset_scan_rows").insert(payload).execute()
    return res.data


def add_assets_to_scan(scan_id: str, new_rows: list[dict]) -> list[dict]:
    """Append new asset rows to an existing scan and bump total_assets count."""
    db = get_db()
    existing = db.table("asset_scan_rows").select("row_index").eq("scan_id", scan_id).execute()
    max_idx = max((r["row_index"] for r in existing.data), default=-1)
    payload = [_row_payload(scan_id, r, max_idx + 1 + i) for i, r in enumerate(new_rows)]
    res = db.table("asset_scan_rows").insert(payload).execute()
    total = len(existing.data) + len(new_rows)
    db.table("asset_scanning").update({
        "total_assets": total,
        "status":       "processing",
        "completed_at": None,
    }).eq("id", scan_id).execute()
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
        "status":     "error",
        "result":     {"error": error},
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }).eq("id", row_id).execute()


def delete_scan_row(row_id: str) -> None:
    db = get_db()
    db.table("asset_scan_rows").delete().eq("id", row_id).execute()


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


# ── cve_exploitability ─────────────────────────────────────────────────────────

def upsert_cve_exploitability(cve_id: str, result: dict) -> dict:
    db = get_db()
    payload = {
        "cve_id":      cve_id.upper(),
        "result":      result,
        "analysed_at": datetime.now(timezone.utc).isoformat(),
    }
    res = (
        db.table("cve_exploitability")
        .upsert(payload, on_conflict="cve_id")
        .execute()
    )
    return res.data[0]


def get_cve_exploitability(cve_id: str) -> dict | None:
    db = get_db()
    res = db.table("cve_exploitability").select("*").eq("cve_id", cve_id.upper()).execute()
    return res.data[0] if res.data else None


def list_cve_exploitability() -> list[dict]:
    db = get_db()
    res = (
        db.table("cve_exploitability")
        .select("id, cve_id, analysed_at, result")
        .order("analysed_at", desc=True)
        .execute()
    )
    return res.data


def delete_cve_exploitability(cve_id: str) -> None:
    db = get_db()
    db.table("cve_exploitability").delete().eq("cve_id", cve_id.upper()).execute()
