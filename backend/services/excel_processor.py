import io
import asyncio
import pandas as pd
from backend.db.queries import (
    create_scan_session, create_scan_rows,
    update_scan_row_result, update_scan_row_error,
    update_scan_session_status,
)
from backend.services.asset_service import run_asset_agent


# Expected Excel columns → internal keys
_COL_MAP = {
    "asset_ip":              "ip",
    "asset_role":            "declared_role",
    "data_classification":   "data_classification",
    "environment":           "environment",
    "owner_email":           "owner",
}


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

    # Normalise column names: lowercase + strip
    df.columns = [c.strip().lower().replace(" ", "_") for c in df.columns]
    df = df.rename(columns=_COL_MAP)
    return df


def _clean(val, default: str = "") -> str:
    """Convert a pandas cell to string, treating NaN/None as default."""
    if val is None:
        return default
    try:
        import math
        if math.isnan(float(val)):
            return default
    except (TypeError, ValueError):
        pass
    return str(val).strip() or default


async def process_excel(job_id: str, file_bytes: bytes, filename: str = "", scan_name: str = "") -> str:
    """
    1. Parse Excel
    2. Create scan session in DB
    3. Insert all asset rows as pending
    4. Run asset agent for each row, update DB as results come in
    Returns scan_id
    """
    df = _read_df(file_bytes, filename)
    total = len(df)

    # 1. Create scan session
    session = create_scan_session(filename=filename, total_assets=total, scan_name=scan_name)
    scan_id = session["id"]

    # 2. Build row payloads
    rows_payload = []
    for idx, row in df.iterrows():
        rows_payload.append({
            "row_index":           int(idx),
            "ip":                  _clean(row.get("ip"), ""),
            "declared_role":       _clean(row.get("declared_role"), "Unknown / Let AI infer"),
            "data_classification": _clean(row.get("data_classification"), "internal"),
            "environment":         _clean(row.get("environment"), "production"),
            "owner":               _clean(row.get("owner"), "unknown"),
        })

    # 3. Insert all rows as pending
    db_rows = create_scan_rows(scan_id, rows_payload)
    # Map row_index -> db row id
    row_id_map = {r["row_index"]: r["id"] for r in db_rows}

    # 4. Process each asset
    async def _process_one(row_payload: dict):
        row_id = row_id_map[row_payload["row_index"]]
        try:
            result = await asyncio.to_thread(
                run_asset_agent,
                row_payload["ip"],
                row_payload["declared_role"],
                row_payload["data_classification"],
                row_payload["environment"],
                row_payload["owner"],
            )
            update_scan_row_result(row_id, result)
        except Exception as e:
            update_scan_row_error(row_id, str(e))

    await asyncio.gather(*[_process_one(r) for r in rows_payload])
    update_scan_session_status(scan_id, "done")
    return scan_id
