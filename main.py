from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.routes.upload  import router as upload_router
from backend.routes.websocket import router as ws_router
from backend.routes.asset   import router as asset_router
from backend.routes.exploit import router as exploit_router
from backend.routes.qualys  import router as qualys_router
from backend.routes.scans   import router as scans_router
import uvicorn

app = FastAPI(title="VMS API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000", "http://localhost:8501"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(upload_router,  prefix="/api")
app.include_router(ws_router)
app.include_router(asset_router,   prefix="/api")
app.include_router(exploit_router, prefix="/api")
app.include_router(qualys_router,  prefix="/api")
app.include_router(scans_router,   prefix="/api")

@app.get("/")
def health_check():
    return {"status": "ok"}

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)