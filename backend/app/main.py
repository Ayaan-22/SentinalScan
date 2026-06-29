from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.core.version import APP_VERSION
from app.core.security import is_valid_api_key, validate_configured_api_key
from app.core.logging import setup_logging
from app.api.v1.router import api_router
from app.services.scanner.manager import scan_manager
from app.middleware import (
    SecurityHeadersMiddleware,
    SensitiveDataSanitizer,
    sanitize_log_message,
)
import asyncio
import logging

# Setup logging
setup_logging()
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan — startup validation + shutdown cleanup."""
    # ── Startup ──────────────────────────────────────────────────────────────
    validate_configured_api_key()
    logger.info(
        f"SentinalScan API starting up - key entropy OK ({len(settings.API_KEY)} chars)"
    )
    logger.warning("Authorized testing only. Scan only systems you own or have explicit permission to test.")
    yield
    # ── Shutdown ──────────────────────────────────────────────────────────────
    logger.info("SentinalScan API shutting down...")

app = FastAPI(
    title=settings.PROJECT_NAME,
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    version=APP_VERSION,
    docs_url="/docs",
    redoc_url=None,
    lifespan=lifespan,
)

# ── Middleware (order matters: outermost runs first) ──────────────────────────
# 1. Security headers — runs on every response
app.add_middleware(SecurityHeadersMiddleware)

# 2. Sensitive data sanitizer — masks secrets in error responses
app.add_middleware(SensitiveDataSanitizer)

# 3. CORS — restrict to known dev origins, lock down methods and headers
if settings.BACKEND_CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[str(origin) for origin in settings.BACKEND_CORS_ORIGINS],
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type", "X-API-Key"],
    )

app.include_router(api_router, prefix=settings.API_V1_STR)

@app.get("/health")
def health_check():
    return {"status": "ok", "version": APP_VERSION, "project": settings.PROJECT_NAME}


# ─── WebSocket endpoint for real-time scan logs ───────────────────────────
@app.websocket("/ws/logs/{scan_id}")
async def websocket_logs(websocket: WebSocket, scan_id: str):
    """Stream scan logs in real-time via WebSocket.
    
    Log messages are sanitized before transmission to prevent XSS payloads
    (e.g. '<script>alert(1)</script>') from reaching the client raw.
    """
    api_key = websocket.query_params.get("api_key") or websocket.query_params.get("token")
    if not is_valid_api_key(api_key):
        await websocket.close(code=1008)
        return

    await websocket.accept()
    if not scan_manager.get_scan(scan_id):
        await websocket.send_json({
            "type": "error",
            "status": "not_found",
            "message": "Scan not found",
        })
        await websocket.close(code=1008)
        return
    
    last_index = 0
    try:
        while True:
            logs = scan_manager.get_logs(scan_id)
            
            # Send only new log entries
            if len(logs) > last_index:
                new_logs = logs[last_index:]
                for log_entry in new_logs:
                    # Sanitize the message to escape any XSS payloads
                    safe_entry = {
                        **log_entry,
                        "message": sanitize_log_message(log_entry.get("message", "")),
                    }
                    await websocket.send_json(safe_entry)
                last_index = len(logs)
            
            # Check if scan is complete
            scan = scan_manager.get_scan(scan_id)
            if scan and scan.status.value in ("completed", "failed", "stopped"):
                # Send remaining logs then close
                logs = scan_manager.get_logs(scan_id)
                if len(logs) > last_index:
                    for log_entry in logs[last_index:]:
                        safe_entry = {
                            **log_entry,
                            "message": sanitize_log_message(log_entry.get("message", "")),
                        }
                        await websocket.send_json(safe_entry)
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
    uvicorn.run("app.main:app", host=settings.HOST, port=settings.PORT, reload=True)
