import uuid
import asyncio
import logging
from typing import Dict, Optional, List
from datetime import datetime, timezone
from app.models.scan import ScanRequest, ScanResponse, ScanStatus
from app.services.scanner.engine import ScannerEngine

logger = logging.getLogger(__name__)


class ScanLogHandler(logging.Handler):
    """Custom handler to capture logs for a specific scan session."""
    
    def __init__(self, logs_list: List[Dict]):
        super().__init__()
        self.logs_list = logs_list
    
    def emit(self, record):
        msg = self.format(record)
        self.logs_list.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "message": msg
        })


class ScanManager:
    """Manages scan sessions — create, track, stop, retrieve results."""
    
    def __init__(self):
        self.scans: Dict[str, ScanResponse] = {}
        self.engines: Dict[str, ScannerEngine] = {}
        self.logs: Dict[str, List[Dict]] = {}

    def create_scan(self, request: ScanRequest) -> ScanResponse:
        """Create a new scan session and launch it as a background task."""
        scan_id = str(uuid.uuid4())
        scan_response = ScanResponse(
            scan_id=scan_id,
            status=ScanStatus.PENDING,
            target_url=request.target_url,
            start_time=datetime.now(timezone.utc)
        )
        self.scans[scan_id] = scan_response
        self.logs[scan_id] = []
        
        # T8: Rate-limit concurrent scans (Max 1)
        active_scans = [s for s in self.scans.values() if s.status == ScanStatus.RUNNING]
        if len(active_scans) >= 1:
            logger.warning(f"Scan request rejected: {active_scans[0].scan_id} is already running.")
            raise ValueError("A scan is already in progress. Please stop it or wait for completion.")

        # Start background task
        asyncio.create_task(self._run_scan(scan_id, request))
        
        return scan_response

    async def _run_scan(self, scan_id: str, request: ScanRequest):
        """Run the scan in a background thread with proper error handling."""
        scan = self.scans[scan_id]
        scan.status = ScanStatus.RUNNING
        
        # Setup per-scan log capture
        scan_logs = self.logs[scan_id]
        handler = ScanLogHandler(scan_logs)
        formatter = logging.Formatter('%(message)s')
        handler.setFormatter(formatter)
        
        scanner_logger = logging.getLogger('app.services.scanner')
        scanner_logger.addHandler(handler)
        scanner_logger.setLevel(logging.DEBUG)
        
        try:
            engine = ScannerEngine(request)
            self.engines[scan_id] = engine
            
            # Run the blocking scan in a thread pool
            loop = asyncio.get_running_loop()
            vulns = await loop.run_in_executor(None, engine.run)
            
            scan.vulnerabilities_count = len(vulns)
            scan.pages_scanned = engine.pages_scanned
            scan.status = ScanStatus.COMPLETED
            scan.end_time = datetime.now(timezone.utc)
            scan.results = vulns
            
        except Exception as e:
            logger.error(f"Scan {scan_id} failed: {e}", exc_info=True)
            scan.status = ScanStatus.FAILED
            scan.end_time = datetime.now(timezone.utc)
            # Log the error to the scan's log stream
            scan_logs.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "level": "ERROR",
                "message": f"Scan failed: {str(e)}"
            })
        finally:
            # ALWAYS clean up — prevents stuck states
            scanner_logger.removeHandler(handler)
            if scan_id in self.engines:
                del self.engines[scan_id]

    def get_scan(self, scan_id: str) -> Optional[ScanResponse]:
        return self.scans.get(scan_id)

    def get_logs(self, scan_id: str) -> List[Dict]:
        return self.logs.get(scan_id, [])

    def get_all_scans(self) -> List[ScanResponse]:
        """Return all scans, most recent first."""
        return sorted(
            self.scans.values(),
            key=lambda s: s.start_time,
            reverse=True
        )

    def stop_scan(self, scan_id: str) -> bool:
        """Stop a running scan. Returns True if successfully stopped."""
        if scan_id in self.engines:
            self.engines[scan_id].stop()
        if scan_id in self.scans:
            self.scans[scan_id].status = ScanStatus.STOPPED
            self.scans[scan_id].end_time = datetime.now(timezone.utc)
            return True
        return False


# Module-level singleton instance (not __new__ based)
scan_manager = ScanManager()
