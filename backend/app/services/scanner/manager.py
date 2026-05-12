import uuid
import asyncio
import threading
import logging
import html
import re
from typing import Dict, Optional, List
from datetime import datetime, timezone
from app.models.scan import ScanRequest, ScanResponse, ScanStatus
from app.services.scanner.engine import ScannerEngine

logger = logging.getLogger(__name__)

# Sanitize logs to prevent XSS payloads from reflecting in the dashboard
_UNSAFE_HTML = re.compile(r'[<>"\'`&]')

def sanitize_log(msg: str) -> str:
    """Escape HTML special characters in log messages."""
    return _UNSAFE_HTML.sub(lambda m: html.escape(m.group(), quote=True), msg)


class ScanLogHandler(logging.Handler):
    """Custom handler to capture logs for a specific scan session."""
    
    def __init__(self, logs_list: List[Dict]):
        super().__init__()
        self.logs_list = logs_list
        self._list_lock = threading.Lock()
    
    def emit(self, record):
        try:
            msg = self.format(record)
            sanitized_msg = sanitize_log(msg)
            with self._list_lock:
                self.logs_list.append({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "level": record.levelname,
                    "message": sanitized_msg
                })
        except Exception:
            self.handleError(record)


class ScanManager:
    """Manages scan sessions using native asyncio orchestration."""
    
    def __init__(self):
        self.scans: Dict[str, ScanResponse] = {}
        self.engines: Dict[str, ScannerEngine] = {}
        self.logs: Dict[str, List[Dict]] = {}
        self._scan_lock = asyncio.Lock()

    async def create_scan(self, request: ScanRequest) -> ScanResponse:
        """Create a new scan session and launch it as an async background task."""
        async with self._scan_lock:
            # Rate-limit: max 1 concurrent scan (P0 Lock enforcement)
            active_scans = [
                s for s in self.scans.values()
                if s.status in (ScanStatus.RUNNING, ScanStatus.PENDING)
            ]
            if active_scans:
                raise ValueError("A scan is already in progress. Wait for completion.")

            scan_id = str(uuid.uuid4())
            scan_response = ScanResponse(
                scan_id=scan_id,
                status=ScanStatus.PENDING,
                target_url=request.target_url,
                start_time=datetime.now(timezone.utc)
            )
            self.scans[scan_id] = scan_response
            self.logs[scan_id] = []

            # Launch native coroutine
            logger.info(f"Enqueuing async scan task for {scan_id}")
            asyncio.create_task(self._run_scan(scan_id, request))

        return scan_response

    async def _run_scan(self, scan_id: str, request: ScanRequest):
        """Native async execution loop for the scanner engine."""
        logger.info(f"Starting async scan task {scan_id}")
        scan = self.scans[scan_id]
        scan.status = ScanStatus.RUNNING
        
        scan_logs = self.logs[scan_id]
        handler = ScanLogHandler(scan_logs)
        handler.setFormatter(logging.Formatter('%(message)s'))
        
        scanner_logger = logging.getLogger('app.services.scanner')
        scanner_logger.addHandler(handler)
        scanner_logger.setLevel(logging.DEBUG)
        
        try:
            engine = ScannerEngine(request)
            self.engines[scan_id] = engine
            
            # PHASE 2: Native async engine run (P0 Migration)
            vulns = await engine.run()
            
            scan.vulnerabilities_count = len(vulns)
            scan.pages_scanned = engine.pages_scanned
            scan.status = ScanStatus.COMPLETED
            scan.end_time = datetime.now(timezone.utc)
            scan.results = vulns
            
        except Exception as e:
            logger.error(f"Scan {scan_id} failed: {e}", exc_info=True)
            scan.status = ScanStatus.FAILED
            scan.end_time = datetime.now(timezone.utc)
            scan_logs.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "level": "ERROR",
                "message": f"Scan failed: {sanitize_log(str(e))}"
            })
        finally:
            scanner_logger.removeHandler(handler)
            self.engines.pop(scan_id, None)

    def get_scan(self, scan_id: str) -> Optional[ScanResponse]:
        return self.scans.get(scan_id)

    def get_logs(self, scan_id: str) -> List[Dict]:
        return self.logs.get(scan_id, [])

    def get_all_scans(self) -> List[ScanResponse]:
        return sorted(self.scans.values(), key=lambda s: s.start_time, reverse=True)

    def stop_scan(self, scan_id: str) -> bool:
        if scan_id in self.engines:
            self.engines[scan_id].stop()
        if scan_id in self.scans:
            if self.scans[scan_id].status == ScanStatus.RUNNING:
                self.scans[scan_id].status = ScanStatus.STOPPED
                self.scans[scan_id].end_time = datetime.now(timezone.utc)
                return True
        return False


scan_manager = ScanManager()
