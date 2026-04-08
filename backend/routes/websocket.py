from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from backend.queue.redis_queue import pop_result, clear_queue
import json

router = APIRouter()


@router.websocket("/ws/{job_id}")
async def results_websocket(websocket: WebSocket, job_id: str):
    """
    Frontend connects here with the job_id received from /upload.
    This streams row results from Redis to the client in real time.
    Closes automatically when processing is done.
    """
    await websocket.accept()

    try:
        while True:
            result = await pop_result(job_id)

            if result is None:
                # Timeout — no new data yet, keep waiting
                continue

            # Send result to frontend
            await websocket.send_text(json.dumps(result))

            # If backend signals done, close the connection cleanly
            if result.get("status") == "done":
                break

    except WebSocketDisconnect:
        # Client navigated away or closed tab — that's fine
        # Processing continues in background, results stay in Redis
        pass

    finally:
        await clear_queue(job_id)
