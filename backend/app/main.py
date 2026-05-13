from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
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
    # Enforce minimum API key entropy so operators cannot accidentally ship
    # with a weak default key. 32 chars ≈ 192 bits of entropy for random keys.
    _api_key = settings.API_KEY
    if not _api_key or len(_api_key) < 32 or _api_key in (
        "changeme_in_production",
        "dev_api_key_12345",
    ):
        raise RuntimeError(
            "STARTUP ABORTED: API_KEY must be at least 32 characters and must not "
            "be a known default. Set a strong random key in backend/.env  "
            '(e.g. `python -c "import secrets; print(secrets.token_hex(32))"`)' 
        )
    logger.info(
        f"SentinalScan API starting up — key entropy OK ({len(_api_key)} chars)"
    )
    yield
    # ── Shutdown ──────────────────────────────────────────────────────────────
    logger.info("SentinalScan API shutting down...")

app = FastAPI(
    title=settings.PROJECT_NAME,
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    version="2.1.0",
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
    return {"status": "ok", "version": "2.1.0", "project": settings.PROJECT_NAME}


# ─── WebSocket endpoint for real-time scan logs ───────────────────────────
@app.websocket("/ws/logs/{scan_id}")
async def websocket_logs(websocket: WebSocket, scan_id: str):
    """Stream scan logs in real-time via WebSocket.
    
    Log messages are sanitized before transmission to prevent XSS payloads
    (e.g. '<script>alert(1)</script>') from reaching the client raw.
    """
    await websocket.accept()
    
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
