from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.core.logging import setup_logging
from app.api.v1.router import api_router
from app.services.scanner.manager import scan_manager
import asyncio
import logging

# Setup logging
setup_logging()
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan — startup/shutdown hooks."""
    logger.info("SentinalScan API starting up...")
    yield
    logger.info("SentinalScan API shutting down...")

app = FastAPI(
    title=settings.PROJECT_NAME,
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    version="2.0.0",
    docs_url="/docs",
    redoc_url=None,
    lifespan=lifespan,
)

# CORS Config
if settings.BACKEND_CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[str(origin) for origin in settings.BACKEND_CORS_ORIGINS],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

app.include_router(api_router, prefix=settings.API_V1_STR)

@app.get("/health")
def health_check():
    return {"status": "ok", "version": "2.0.0", "project": settings.PROJECT_NAME}


# ─── WebSocket endpoint for real-time scan logs ───────────────────────────
@app.websocket("/ws/logs/{scan_id}")
async def websocket_logs(websocket: WebSocket, scan_id: str):
    """Stream scan logs in real-time via WebSocket."""
    await websocket.accept()
    
    last_index = 0
    try:
        while True:
            logs = scan_manager.get_logs(scan_id)
            
            # Send only new log entries
            if len(logs) > last_index:
                new_logs = logs[last_index:]
                for log_entry in new_logs:
                    await websocket.send_json(log_entry)
                last_index = len(logs)
            
            # Check if scan is complete
            scan = scan_manager.get_scan(scan_id)
            if scan and scan.status.value in ("completed", "failed", "stopped"):
                # Send remaining logs then close
                logs = scan_manager.get_logs(scan_id)
                if len(logs) > last_index:
                    for log_entry in logs[last_index:]:
                        await websocket.send_json(log_entry)
                await websocket.send_json({
                    "type": "scan_complete",
                    "status": scan.status.value,
                    "message": f"Scan {scan.status.value}"
                })
                break
            
            await asyncio.sleep(0.5)
            
    except WebSocketDisconnect:
        logger.debug(f"WebSocket client disconnected for scan {scan_id}")
    except Exception as e:
        logger.error(f"WebSocket error for scan {scan_id}: {e}")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
