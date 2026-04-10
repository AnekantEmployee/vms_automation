import io
import asyncio
import pandas as pd
from datetime import datetime, timezone
from backend.db.client import get_db
from backend.services.qualys_service import query_by_qids


# ── Column map: Excel header → internal key ────────────────────────────────────

_COL_MAP = {
    "cve":                   "cve",
    "cve-description":       "cve_description",
    "cvssv2_base_(nvd)":     "cvss_v2",
    "cvssv3.1_base_(nvd)":   "cvss_v3",
    "qid":                   "qid",
    "title":                 "title",
    "severity":              "severity",
    "kb_severity":           "kb_severity",
    "type_detected":         "type_detected",
    "last_detected":         "last_detected",
    "first_detected":        "first_detected",
    "protocol":              "protocol",
    "port":                  "port",
    "status":                "vuln_status",
    "asset_id":              "asset_id",
    "asset_name":            "asset_name",
    "asset_ipv4":            "asset_ipv4",
    "asset_ipv6":            "asset_ipv6",
    "solution":              "solution",
    "asset_tags":            "asset_tags",
    "disabled":              "disabled",
    "ignored":               "ignored",
    "qvs_score":             "qvs_score",
    "detection_age":         "detection_age",
    "published_date":        "published_date",
    "patch_released":        "patch_released",
    "category":              "category",
    "cvss_rating_labels":    "cvss_rating_label",
    "rti":                   "rti",
    "operating_system":      "operating_system",
    "last_fixed":            "last_fixed",
    "last_reopened":         "last_reopened",
    "times_detected":        "times_detected",
    "threat":                "threat",
    "vuln_patchable":        "vuln_patchable",
    "asset_critical_score":  "asset_critical_score",
    "trurisk_score":         "trurisk_score",
    "vulnerability_tags":    "vulnerability_tags",
    "results":               "results",
}


def _clean(val, default=""):
    if val is None:
        return default
    s = str(val).strip()
    return default if s in ("", "'-", "nan", "None") else s


def _read_df(file_bytes: bytes, filename: str) -> pd.DataFrame:
    ext = filename.rsplit(".", 1)[-1].lower() if filename else ""
    if ext == "csv":
        df = pd.read_csv(io.BytesIO(file_bytes))
    elif ext == "xls":
        df = pd.read_excel(io.BytesIO(file_bytes), engine="xlrd")
    else:
        try:
            df = pd.read_excel(io.BytesIO(file_bytes), engine="openpyxl")
        except Exception:
            df = pd.read_csv(io.BytesIO(file_bytes))

    df.columns = [c.strip().lower().replace(" ", "_") for c in df.columns]
    df = df.rename(columns=_COL_MAP)
    return df


def _row_to_dict(row: pd.Series) -> dict:
    return {key: _clean(row.get(key)) for key in _COL_MAP.values()}


# ── DB helpers ─────────────────────────────────────────────────────────────────

def _create_qualys_session(filename: str, total_rows: int, scan_name: str) -> dict:
    db = get_db()
    res = db.table("qualys_scans").insert({
        "filename":   filename,
        "scan_name":  scan_name or filename,
        "total_rows": total_rows,
        "status":     "processing",
    }).execute()
    return res.data[0]


def _create_qualys_rows(scan_id: str, rows: list[dict]) -> list[dict]:
    db = get_db()
    payload = [
        {
            "scan_id":    scan_id,
            "row_index":  r["row_index"],
            "status":     "pending",
            "started_at": datetime.now(timezone.utc).isoformat(),
        }
        for r in rows
    ]
    res = db.table("qualys_scan_rows").insert(payload).execute()
    return res.data


def _update_qualys_row_result(row_id: str, result: dict) -> None:
    db = get_db()
    db.table("qualys_scan_rows").update({
        "status":     "done",
        "result":     result,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }).eq("id", row_id).execute()


def _update_qualys_row_error(row_id: str, error: str) -> None:
    db = get_db()
    db.table("qualys_scan_rows").update({
        "status":     "error",
        "result":     {"error": error},
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }).eq("id", row_id).execute()


def _update_qualys_session_status(scan_id: str, status: str) -> None:
    db = get_db()
    update: dict = {"status": status}
    if status == "done":
        update["completed_at"] = datetime.now(timezone.utc).isoformat()
    db.table("qualys_scans").update(update).eq("id", scan_id).execute()


# ── Main processor ─────────────────────────────────────────────────────────────

async def process_qualys_excel(job_id: str, file_bytes: bytes, filename: str = "", scan_name: str = "") -> str:
    df = _read_df(file_bytes, filename)
    total = len(df)

    session = _create_qualys_session(filename, total, scan_name)
    scan_id = session["id"]

    rows_payload = [{"row_index": int(idx), "data": _row_to_dict(row)} for idx, row in df.iterrows()]

    db_rows = _create_qualys_rows(scan_id, rows_payload)
    row_id_map = {r["row_index"]: r["id"] for r in db_rows}

    # ── Fetch KB data for all unique QIDs in one batch ─────────────────────────
    unique_qids = list({
        int(r["data"]["qid"])
        for r in rows_payload
        if r["data"].get("qid") and str(r["data"]["qid"]).isdigit()
    })
    kb_map: dict[str, dict] = {}
    if unique_qids:
        try:
            kb_results = await asyncio.to_thread(query_by_qids, unique_qids)
            kb_map = {str(kb["qid"]): kb for kb in kb_results if kb.get("qid")}
        except Exception:
            pass  # KB enrichment is best-effort; don't fail the whole scan

    async def _process_one(row_payload: dict):
        row_id = row_id_map[row_payload["row_index"]]
        try:
            result = dict(row_payload["data"])
            kb = kb_map.get(str(result.get("qid", "")))
            if kb:
                result["kb"] = kb
            _update_qualys_row_result(row_id, result)
        except Exception as e:
            _update_qualys_row_error(row_id, str(e))

    await asyncio.gather(*[_process_one(r) for r in rows_payload])
    _update_qualys_session_status(scan_id, "done")
    return scan_id
