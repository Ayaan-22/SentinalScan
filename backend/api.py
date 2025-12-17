import sys
import os
import asyncio
from typing import Optional, List, Dict
from pydantic import BaseModel
from fastapi import FastAPI, BackgroundTasks, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from threading import Thread, Event
import json
import logging
from queue import Queue, Empty
import time

from vuln_scanner import VulnerabilityScanner, ScanConfig, ScannerLogger

app = FastAPI(title="SentinalScan API")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global State
class ScanState:
    scanner: Optional[VulnerabilityScanner] = None
    thread: Optional[Thread] = None
    stop_event: Event = Event()
    is_scanning: bool = False
    log_queue: Queue = Queue()
    results: List[Dict] = []
    websockets: List[WebSocket] = []

state = ScanState()

# Models
class ScanRequest(BaseModel):
    target_url: str
    max_pages: int = 50
    workers: int = 5
    verify_ssl: bool = True
    obey_robots: bool = True
    timeout: int = 15
    auth_token: Optional[str] = None
    cookies_str: Optional[str] = None
    headers_str: Optional[str] = None
    exclude_paths_str: Optional[str] = None

class LogMessage(BaseModel):
    timestamp: float
    level: str
    message: str

# Custom Logger to bridge Scanner -> WebSocket
class WebSocketLogger:
    def __init__(self, queue: Queue):
        self.queue = queue
        self.verbose = True

    def _log(self, level, msg):
        log_entry = {
            "timestamp": time.time(),
            "level": level,
            "message": msg
        }
        self.queue.put(log_entry)
        # Broadcast immediately if possible
        asyncio.run_coroutine_threadsafe(broadcast_log(log_entry), loop)

    def info(self, msg): self._log("INFO", msg)
    def debug(self, msg): self._log("DEBUG", msg)
    def warning(self, msg): self._log("WARNING", msg)
    def error(self, msg): self._log("ERROR", msg)
    def critical(self, msg): self._log("CRITICAL", msg)

async def broadcast_log(log_entry: dict):
    to_remove = []
    for ws in state.websockets:
        try:
            await ws.send_json(log_entry)
        except Exception:
            to_remove.append(ws)
    for ws in to_remove:
        state.websockets.remove(ws)

def run_scan_thread(config_data: ScanRequest):
    try:
        # Parse cookies
        cookies = None
        if config_data.cookies_str:
            cookies = {}
            for pair in config_data.cookies_str.split(';'):
                if '=' in pair:
                    key, value = pair.strip().split('=', 1)
                    cookies[key] = value
        
        # Parse headers
        headers = None
        if config_data.headers_str:
            headers = {}
            for header_pair in config_data.headers_str.split(';'):
                if ':' in header_pair:
                    key, value = header_pair.split(':', 1)
                    headers[key.strip()] = value.strip()

        # Parse exclude paths
        exclude_paths = None
        if config_data.exclude_paths_str:
            exclude_paths = [p.strip() for p in config_data.exclude_paths_str.split(',')]

        config = ScanConfig(
            target_url=config_data.target_url,
            max_pages=config_data.max_pages,
            workers=config_data.workers,
            verify_ssl=config_data.verify_ssl,
            obey_robots=config_data.obey_robots,
            timeout=config_data.timeout,
            auth_token=config_data.auth_token,
            cookies=cookies,
            headers=headers,
            exclude_paths=exclude_paths,
            skip_auth_check=True
        )
        
        logger = WebSocketLogger(state.log_queue)
        state.scanner = VulnerabilityScanner(config, logger=logger) # type: ignore
        
        state.results = [v.to_dict() for v in state.scanner.scan()]
        
        # Notify completion
        logger.info("Scan finished successfully.")
    except Exception as e:
        if state.scanner and state.scanner.logger:
             state.scanner.logger.error(f"Scan failed: {str(e)}")
    finally:
        state.is_scanning = False
        state.thread = None

@app.on_event("startup")
async def startup_event():
    global loop
    loop = asyncio.get_running_loop()

@app.post("/scan/start")
async def start_scan(request: ScanRequest):
    if state.is_scanning:
        raise HTTPException(status_code=400, detail="Scan already in progress")
    
    state.is_scanning = True
    state.stop_event.clear()
    state.results = []
    
    # Threading needed because scanner is blocking
    state.thread = Thread(target=run_scan_thread, args=(request,), daemon=True)
    state.thread.start()
    
    return {"status": "started", "target": request.target_url}

@app.post("/scan/stop")
async def stop_scan():
    if not state.is_scanning or not state.scanner:
         raise HTTPException(status_code=400, detail="No scan running")
    
    state.scanner.stop_scan()
    return {"status": "stopping"}

@app.get("/scan/status")
async def get_status():
    return {
        "is_scanning": state.is_scanning,
        "results_count": len(state.results) if not state.is_scanning else 0 # Real-time results would require more changes
    }

@app.get("/scan/results")
async def get_results():
    if state.is_scanning:
        # Return what we have so far? Scanner doesn't expose partial results easily yet
        # For now, return empty or wait til done
        return []
    return state.results

@app.websocket("/ws/logs")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    state.websockets.append(websocket)
    try:
        while True:
            await websocket.receive_text() # Keep alive
    except WebSocketDisconnect:
        state.websockets.remove(websocket)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
