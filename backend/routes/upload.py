from fastapi import APIRouter, UploadFile, File, BackgroundTasks
from backend.services.excel_processor import process_excel
import uuid

router = APIRouter()


@router.post("/upload")
async def upload_excel(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
):
    file_bytes = await file.read()
    # job_id passed for WS compatibility, scan_id comes from DB
    job_id = str(uuid.uuid4())
    background_tasks.add_task(process_excel, job_id, file_bytes, file.filename)
    return {
        "job_id":   job_id,
        "message":  "Processing started",
        "filename": file.filename,
    }
