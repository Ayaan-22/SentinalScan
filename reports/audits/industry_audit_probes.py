"""Offline audit evidence, not regression tests or a vulnerability benchmark.

Run from the repository root: python reports/audits/industry_audit_probes.py
Assertions describe the audited defects; they should fail when those defects are fixed.
Every HTTP request uses MockTransport. DNS results are mocked. No target is contacted.
"""

import asyncio
import json
import logging
import socket
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qs

import httpx
from bs4 import BeautifulSoup

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))

from app.middleware import SensitiveDataSanitizer  # noqa: E402
from app.models.scan import ScanRequest, ScanStatus  # noqa: E402
from app.services.scanner.crawler import WebCrawler  # noqa: E402
from app.services.scanner.engine import ScannerEngine  # noqa: E402
from app.services.scanner.manager import ScanLogHandler, ScanManager  # noqa: E402
from app.services.scanner.plugins.headers import SecurityHeaders  # noqa: E402
from app.services.scanner.plugins.sensitive_files import SensitiveFiles  # noqa: E402
from app.services.scanner.plugins.sqli import SQLInjection  # noqa: E402
from app.services.scanner.plugins.xss import ReflectedXSS  # noqa: E402


def mock_client(handler, **kwargs):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler), trust_env=False, **kwargs)


async def main():
    evidence = {}

    # The engine gives plugins the raw, credential-bearing client.
    sent = []

    def record(request):
        sent.append({"url": str(request.url), "method": request.method,
                     "authorization": request.headers.get("authorization"),
                     "cookie": request.headers.get("cookie")})
        return httpx.Response(200, text="ordinary response")

    engine = ScannerEngine(ScanRequest(target_url="https://approved.invalid/", exclude_paths=["/excluded"]))
    engine.crawler.client = mock_client(record, headers={"Authorization": "Bearer audit-placeholder"},
                                        cookies={"audit_cookie": "placeholder"})
    await engine._init_plugins()
    for plugin in engine.plugins[:2]:
        form = BeautifulSoup('<form method="post" action="http://127.0.0.1/audit-only"><input name="q"></form>', "html.parser").form
        await plugin.check("https://approved.invalid/", "", [form])
        form = BeautifulSoup('<form action="/excluded"><input name="q"></form>', "html.parser").form
        await plugin.check("https://approved.invalid/", "", [form])
    assert any(r["url"].startswith("http://127.0.0.1/") and r["authorization"] for r in sent)
    assert any("/excluded" in r["url"] for r in sent)
    evidence["plugin_scope_and_credential_bypass"] = {"requests": len(sent), "first_request": sent[0], "excluded_path_requested": True}
    await engine.crawler.close()

    crawler = WebCrawler(ScanRequest(target_url="https://approved.invalid/"))
    with patch.object(crawler, "_is_safe_ip", AsyncMock(return_value=True)):
        accepted = await crawler._validate_request_url("http://approved.invalid/")
    assert accepted.startswith("http:")
    evidence["https_origin_accepts_http"] = accepted

    accepted_ips = []
    loop = asyncio.get_running_loop()
    for ip in ("::ffff:127.0.0.1", "::ffff:169.254.169.254", "224.0.0.1", "::", "ff02::1"):
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        with patch.object(loop, "getaddrinfo", AsyncMock(return_value=[(family, socket.SOCK_STREAM, 6, "", (ip, 0))])):
            if await crawler._is_safe_ip("audit.invalid"):
                accepted_ips.append(ip)
    assert len(accepted_ips) == 5
    evidence["nonpublic_dns_answers_accepted"] = accepted_ips

    # Sorting query pairs changes repeated-key order; removing slash changes relative URL semantics.
    request = ScanRequest(target_url="https://approved.invalid/app/?step=2&step=1")
    ipv6 = ScanRequest(target_url="https://[2606:4700:4700::1111]/")
    assert request.target_url == "https://approved.invalid/app?step=1&step=2"
    assert "[" not in ipv6.target_url
    evidence["url_semantics_changed"] = {"normalized": request.target_url, "ipv6_normalized": ipv6.target_url}

    def json_reflection(request):
        fields = parse_qs(request.content.decode())
        return httpx.Response(200, json={"q": fields["q"][0]})

    form = BeautifulSoup('<form method="post"><input name="q"></form>', "html.parser").form
    async with mock_client(json_reflection) as client:
        findings = await ReflectedXSS(client).check("https://approved.invalid/", "", [form])
    assert findings and findings[0].confidence == "High"
    evidence["json_reflection_reported_as_xss"] = {"severity": findings[0].severity_level.value, "confidence": findings[0].confidence}

    baseline = "SQL syntax error in MySQL database"
    async with mock_client(lambda request: httpx.Response(200, text=baseline)) as client:
        findings = await SQLInjection(client).check("https://approved.invalid/", baseline, [form])
    assert findings and findings[0].severity_score == 9.0
    evidence["unchanged_baseline_reported_as_sqli"] = {"severity": findings[0].severity_level.value, "confidence": findings[0].confidence}

    def robots_only(request):
        if request.url.path.endswith("robots.txt"):
            return httpx.Response(200, text="User-agent: *\nDisallow: /admin/\n")
        return httpx.Response(404, text="not found")

    async with mock_client(robots_only) as client:
        findings = await SensitiveFiles(client).check("https://approved.invalid/", "", [])
    assert len(findings) == 1 and findings[0].severity_score == 5.0
    evidence["ordinary_robots_file_reported_as_sensitive"] = findings[0].model_dump(mode="json")

    strong_headers = {"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
                      "Strict-Transport-Security": "max-age=31536000", "Content-Security-Policy": "default-src 'none'",
                      "Referrer-Policy": "no-referrer", "Permissions-Policy": "camera=()"}
    async with mock_client(lambda request: httpx.Response(200, headers=strong_headers)) as client:
        findings = await SecurityHeaders(client).check("https://approved.invalid/", "", [])
    assert len(findings) == 1 and "X-XSS-Protection" in findings[0].description
    evidence["deprecated_header_absence_reported"] = findings[0].description

    requested = []

    def robot_record(request):
        requested.append(str(request.url))
        if request.url.path.endswith("robots.txt"):
            return httpx.Response(200, text="User-agent: *\nDisallow: /\n")
        return httpx.Response(200, text="<html>ok</html>", headers={"Content-Type": "text/html"})

    crawler = WebCrawler(ScanRequest(target_url="https://approved.invalid/app/", max_pages=1))
    crawler.client = mock_client(robot_record)
    with patch.object(crawler, "_is_safe_ip", AsyncMock(return_value=True)):
        pages = await crawler.crawl()
    assert requested[0] == "https://approved.invalid/app/robots.txt" and pages
    evidence["robots_location_and_seed_bypass"] = {"requested": requested, "pages": pages}
    await crawler.close()

    class CountingStream(httpx.AsyncByteStream):
        consumed = 0

        async def __aiter__(self):
            for _ in range(3):
                self.consumed += 1_000_000
                yield b"x" * 1_000_000

    stream = CountingStream()
    crawler = WebCrawler(ScanRequest(target_url="https://approved.invalid/"))
    crawler.client = mock_client(lambda request: httpx.Response(200, stream=stream, headers={"Content-Type": "text/html"}))
    with patch.object(crawler, "_is_safe_ip", AsyncMock(return_value=True)):
        await crawler._fetch_page(crawler.base_url)
    assert stream.consumed == 3_000_000 > crawler.max_response_bytes
    evidence["response_limit_applied_after_full_read"] = {"configured_cap": crawler.max_response_bytes, "bytes_read": stream.consumed}
    await crawler.close()

    # Real engine + real manager: failed HTTP fetches still lead to completed/zero pages.
    def unreachable(request):
        raise httpx.ConnectError("audit simulated connection failure", request=request)

    manager = ScanManager()
    original_init = ScannerEngine.__init__

    def init_mocked(self, *args, **kwargs):
        original_init(self, *args, **kwargs)
        self.crawler.client = mock_client(unreachable)

    with patch.object(ScannerEngine, "__init__", init_mocked), patch.object(WebCrawler, "_is_safe_ip", AsyncMock(return_value=True)):
        scan = await manager.create_scan(ScanRequest(target_url="https://approved.invalid/", obey_robots=False))
        await manager.tasks[scan.scan_id]
    assert scan.status == ScanStatus.COMPLETED and scan.pages_scanned == 0
    evidence["failed_fetches_still_complete"] = {"status": scan.status.value, "pages_scanned": scan.pages_scanned, "findings": len(scan.results)}

    manager = ScanManager()
    pending = await manager.create_scan(ScanRequest(target_url="https://approved.invalid/"))
    await manager.stop_scan(pending.scan_id)
    assert pending.status == ScanStatus.STOPPED and pending.scan_id in manager.tasks
    assert manager.tasks[pending.scan_id].cancelled()
    evidence["pending_cancel_retains_task"] = True

    logs = []
    handler = ScanLogHandler(logs)
    handler.emit(logging.LogRecord("httpx", logging.INFO, "audit", 1,
                                  "GET https://approved.invalid/?api_key=audit-placeholder", (), None))
    text = SensitiveDataSanitizer.sanitize(json.dumps({"message": logs[0]["message"]}))
    assert "audit-placeholder" in text
    evidence["url_secret_not_redacted"] = True

    print(json.dumps({"scope": "offline MockTransport probes; assertions confirm current defects", "observations": evidence}, indent=2))


if __name__ == "__main__":
    logging.disable(logging.CRITICAL)
    asyncio.run(main())
