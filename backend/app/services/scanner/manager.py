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
        self.tasks: Dict[str, asyncio.Task] = {}
        self.logs: Dict[str, List[Dict]] = {}
        self._scan_lock = asyncio.Lock()
        self._results_lock = asyncio.Lock()

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
            task = asyncio.create_task(self._run_scan(scan_id, request))
            self.tasks[scan_id] = task

        return scan_response

    async def _append_finding(self, scan_id: str, finding) -> None:
        async with self._results_lock:
            scan = self.scans.get(scan_id)
            if not scan:
                return
            fingerprint = (finding.url, finding.vuln_type.value, finding.description)
            existing = {
                (item.url, item.vuln_type.value, item.description)
                for item in scan.results
            }
            if fingerprint not in existing:
                scan.results.append(finding)
                scan.vulnerabilities_count = len(scan.results)
                self.logs.setdefault(scan_id, []).append({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "level": "INFO",
                    "message": (
                        f"Finding discovered: {finding.description} "
                        f"({finding.severity_level.value}, {finding.url})"
                    )
                })

    async def _run_scan(self, scan_id: str, request: ScanRequest):
        """Native async execution loop for the scanner engine."""
        logger.info(f"Starting async scan task {scan_id}")
        scan = self.scans[scan_id]
        scan.status = ScanStatus.RUNNING
        
        scan_logs = self.logs[scan_id]
        handler = ScanLogHandler(scan_logs)
        handler.setFormatter(logging.Formatter('%(message)s'))
        
        captured_loggers = [
            logging.getLogger("app.services.scanner"),
            logging.getLogger("httpx"),
        ]
        previous_levels = {captured_logger: captured_logger.level for captured_logger in captured_loggers}
        for captured_logger in captured_loggers:
            captured_logger.addHandler(handler)
            captured_logger.setLevel(logging.DEBUG if captured_logger.name.startswith("app.") else logging.INFO)
        scan_logs.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": "INFO",
            "message": f"Scan task started for {request.target_url}"
        })
        
        try:
            engine = ScannerEngine(request, on_finding=lambda finding: self._append_finding(scan_id, finding))
            self.engines[scan_id] = engine
            
            # PHASE 2: Native async engine run (P0 Migration)
            vulns = await engine.run()
            
            scan.vulnerabilities_count = len(vulns)
            scan.pages_scanned = engine.pages_scanned
            if scan.status != ScanStatus.STOPPED:
                scan.status = ScanStatus.COMPLETED
            scan.end_time = datetime.now(timezone.utc)
            scan.results = vulns
            scan.vulnerabilities_count = len(scan.results)
            scan_logs.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "level": "INFO",
                "message": (
                    f"Scan completed: {scan.pages_scanned} pages scanned, "
                    f"{scan.vulnerabilities_count} findings"
                )
            })
            
        except asyncio.CancelledError:
            logger.info(f"Scan {scan_id} stopped by user")
            scan.status = ScanStatus.STOPPED
            if scan_id in self.engines:
                scan.pages_scanned = self.engines[scan_id].pages_scanned
            scan.end_time = datetime.now(timezone.utc)
            scan_logs.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "level": "INFO",
                "message": "Scan stopped by user"
            })
        except Exception as e:
            logger.error(f"Scan {scan_id} failed: {e}", exc_info=True)
            if scan.status != ScanStatus.STOPPED:
                scan.status = ScanStatus.FAILED
            scan.end_time = datetime.now(timezone.utc)
            scan_logs.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "level": "ERROR",
                "message": f"Scan failed: {sanitize_log(str(e))}"
            })
        finally:
            for captured_logger in captured_loggers:
                captured_logger.removeHandler(handler)
                captured_logger.setLevel(previous_levels[captured_logger])
            self.engines.pop(scan_id, None)
            self.tasks.pop(scan_id, None)

    def get_scan(self, scan_id: str) -> Optional[ScanResponse]:
        return self.scans.get(scan_id)

    def get_logs(self, scan_id: str) -> List[Dict]:
        logs = self.logs.get(scan_id, [])
        if logs:
            return logs

        scan = self.scans.get(scan_id)
        if not scan:
            return []

        synthetic_logs = [{
            "timestamp": scan.start_time.isoformat(),
            "level": "INFO",
            "message": f"Scan record loaded for {scan.target_url} ({scan.status.value})",
        }]
        if scan.end_time:
            synthetic_logs.append({
                "timestamp": scan.end_time.isoformat(),
                "level": "INFO" if scan.status == ScanStatus.COMPLETED else "WARNING",
                "message": (
                    f"Scan {scan.status.value}: {scan.pages_scanned} pages scanned, "
                    f"{scan.vulnerabilities_count} findings"
                ),
            })
        return synthetic_logs

    def get_all_scans(self) -> List[ScanResponse]:
        return sorted(self.scans.values(), key=lambda s: s.start_time, reverse=True)

    async def stop_scan(self, scan_id: str) -> bool:
        if scan_id in self.engines:
            self.engines[scan_id].stop()
        if scan_id in self.scans:
            if self.scans[scan_id].status in (ScanStatus.RUNNING, ScanStatus.PENDING):
                scan = self.scans[scan_id]
                scan.status = ScanStatus.STOPPED
                scan.end_time = datetime.now(timezone.utc)
                self.logs.setdefault(scan_id, []).append({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "level": "INFO",
                    "message": "Scan stopped by user"
                })
                task = self.tasks.get(scan_id)
                if task and not task.done():
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass
                return True
        return False


scan_manager = ScanManager()
