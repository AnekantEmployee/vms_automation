from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from asyncio import to_thread
from backend.services.asset_service import run_asset_agent

router = APIRouter()


class AssetRequest(BaseModel):
    ip: str
    declared_role: str = "Unknown / Let AI infer"
    data_classification: str = "internal"
    environment: str = "production"
    owner: str = "unknown"


@router.post("/asset")
async def analyse_asset(req: AssetRequest):
    try:
        result = await to_thread(
            run_asset_agent,
            req.ip,
            req.declared_role,
            req.data_classification,
            req.environment,
            req.owner,
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
