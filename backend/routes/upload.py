from fastapi import APIRouter, UploadFile, File, BackgroundTasks
from backend.services.excel_processor import process_excel
import uuid

router = APIRouter()


@router.post("/upload")
async def upload_excel(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...)
):
    """
    Accepts an Excel file, generates a unique job_id,
    and starts background processing immediately.
    Returns the job_id so the frontend can subscribe via WebSocket.
    """
    job_id = str(uuid.uuid4())
    file_bytes = await file.read()

    # Fire off processing in the background — returns immediately
    background_tasks.add_task(process_excel, job_id, file_bytes, file.filename)

    return {
        "job_id": job_id,
        "message": "Processing started",
        "filename": file.filename,
    }
