import asyncio

import pytest

from app.models.vulnerability import SeverityLevel, Vulnerability, VulnType
from app.models.scan import ScanRequest, ScanStatus
from app.services.scanner.manager import ScanManager


class FakeEngine:
    def __init__(self, config, on_finding=None):
        self.config = config
        self.on_finding = on_finding
        self.pages_scanned = 0
        self._stopped = False

    def stop(self):
        self._stopped = True

    async def run(self):
        if self.on_finding:
            await self.on_finding(
                Vulnerability(
                    url=self.config.target_url,
                    vuln_type=VulnType.OTHER,
                    description="Partial finding",
                    severity_level=SeverityLevel.LOW,
                    severity_score=2.0,
                )
            )
        while not self._stopped:
            self.pages_scanned += 1
            await asyncio.sleep(0.01)
        return []


@pytest.mark.asyncio
async def test_stop_scan_preserves_stopped_status_and_cleans_task(monkeypatch):
    import app.services.scanner.manager as manager_module

    monkeypatch.setattr(manager_module, "ScannerEngine", FakeEngine)
    manager = ScanManager()

    scan = await manager.create_scan(ScanRequest(target_url="https://example.com"))
    await asyncio.sleep(0.03)

    assert manager.get_scan(scan.scan_id).results
    stopped = await manager.stop_scan(scan.scan_id)
    await asyncio.sleep(0)

    final_scan = manager.get_scan(scan.scan_id)
    assert stopped is True
    assert final_scan.status == ScanStatus.STOPPED
    assert final_scan.results
    assert scan.scan_id not in manager.tasks
