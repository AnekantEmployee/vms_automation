from fastapi import APIRouter, HTTPException, Query
from asyncio import to_thread
from backend.services.qualys_service import query_by_qids

router = APIRouter()


@router.get("/qualys/kb")
async def qualys_kb(qids: list[int] = Query(...)):
    try:
        result = await to_thread(query_by_qids, qids)
        return result
    except RuntimeError as e:
        raise HTTPException(status_code=502, detail=str(e))
