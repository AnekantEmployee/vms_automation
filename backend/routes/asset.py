from fastapi import APIRouter, HTTPException, Query
from asyncio import to_thread
from backend.services.asset_service import run_asset_agent

router = APIRouter(tags=["Assets"])


@router.get("/asset")
async def analyse_asset(
    ip: str = Query(...),
    declared_role: str = Query("Unknown / Let AI infer"),
    data_classification: str = Query("internal"),
    environment: str = Query("production"),
    owner: str = Query("unknown"),
    force_refresh: bool = Query(False),
):
    try:
        result = await to_thread(run_asset_agent, ip, declared_role, data_classification, environment, owner, force_refresh)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
