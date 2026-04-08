import io
import pandas as pd
import asyncio
from backend.services.row_script import process_row
from backend.queue.redis_queue import push_result


async def process_excel(job_id: str, file_bytes: bytes, filename: str = ""):
    """
    Reads the uploaded file (xlsx, xls, or csv), iterates over each row,
    calls process_row(), and pushes each result to Redis.
    """
    ext = filename.rsplit(".", 1)[-1].lower() if filename else ""

    if ext == "csv":
        df = pd.read_csv(io.BytesIO(file_bytes))
    elif ext == "xls":
        df = pd.read_excel(io.BytesIO(file_bytes), engine="xlrd")
    else:
        # default: try openpyxl, fall back to csv
        try:
            df = pd.read_excel(io.BytesIO(file_bytes), engine="openpyxl")
        except Exception:
            df = pd.read_csv(io.BytesIO(file_bytes))
    total_rows = len(df)

    for index, row in df.iterrows():
        row_dict = row.to_dict()

        # Run your (potentially blocking) row script in a thread
        # so it doesn't block the async event loop
        result = await asyncio.to_thread(process_row, row_dict)

        payload = {
            "job_id": job_id,
            "row_index": int(index),
            "total_rows": total_rows,
            "row_data": row_dict,
            "result": result,
            "status": "processing",
        }

        await push_result(job_id, payload)

    # Push a final "done" signal so the WebSocket knows to close
    await push_result(job_id, {
        "job_id": job_id,
        "status": "done",
        "total_rows": total_rows,
    })
