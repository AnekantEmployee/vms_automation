from fastapi import APIRouter, UploadFile, File, BackgroundTasks, Form
from backend.services.excel_processor import process_excel
from typing import Optional
import uuid

router = APIRouter()


@router.post("/upload")
async def upload_excel(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    scan_name: Optional[str] = Form(None),
):
    file_bytes = await file.read()
    job_id = str(uuid.uuid4())
    background_tasks.add_task(process_excel, job_id, file_bytes, file.filename, scan_name or "")
    return {
        "job_id":   job_id,
        "message":  "Processing started",
        "filename": file.filename,
    }
