# SentinalScan — Implementation Guide

> Companion to the Architecture Analysis  
> Concrete code for the async migration, test strategy, security middleware, and CI/CD pipeline

---

## Table of Contents

1. [Async Migration — ✅ SHIPPED](#1-async-migration--shipped)
2. [Test Strategy — ✅ IMPLEMENTED](#2-test-strategy--implemented)
3. [Security Middleware — ✅ SHIPPED](#3-security-middleware--shipped)
4. [UI/UX & Monitoring — ✅ SHIPPED](#4-uiux--monitoring--shipped)
5. [Redis State Store — PENDING](#5-redis-state-store--pending)
6. [Celery Job Queue — PENDING](#6-celery-job-queue--pending)
6. [AI Triage Integration](#6-ai-triage-integration)
7. [Postgres Schema + Diff Engine](#7-postgres-schema--diff-engine)
8. [CI/CD Pipeline](#8-cicd-pipeline)
9. [Docker Compose Full Stack](#9-docker-compose-full-stack)
10. [Structured Logging](#10-structured-logging)

---

## 1. Async Migration — ✅ SHIPPED

### Sub-step 1: Swap to httpx.Client (sync, 2 hrs)

Identical API surface to `requests.Session`. Validates HTTP layer in isolation. Zero behaviour change.

```python
# backend/app/services/scanner/crawler.py
# BEFORE:
import requests
session = requests.Session()

# AFTER:
import httpx

def _create_session(self) -> httpx.Client:
    return httpx.Client(
        headers={"User-Agent": settings.USER_AGENT},
        verify=self.config.verify_ssl,
        timeout=self.config.timeout,
        follow_redirects=True,
    )

# Exception types change — update all catch blocks:
# requests.exceptions.RequestException -> httpx.RequestError
# requests.exceptions.HTTPError       -> httpx.HTTPStatusError
```

### Sub-step 2: Async crawl_page (4 hrs)

```python
# backend/app/services/scanner/crawler_async.py
import httpx
import asyncio
from urllib.parse import urljoin, urlparse
from selectolax.parser import HTMLParser
from typing import Set

class AsyncWebCrawler:
    def __init__(self, config):
        self.config = config
        self.base_url = config.target_url.rstrip("/")
        self.base_domain = urlparse(config.target_url).netloc
        self.response_cache: dict[str, str] = {}
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self):
        self._client = httpx.AsyncClient(
            headers={"User-Agent": settings.USER_AGENT},
            verify=self.config.verify_ssl,
            timeout=self.config.timeout,
            limits=httpx.Limits(
                max_connections=self.config.workers * 2,
                max_keepalive_connections=self.config.workers,
            ),
            follow_redirects=True,
        )
        return self

    async def __aexit__(self, *args):
        if self._client:
            await self._client.aclose()

    def _extract_links(self, base_url: str, html: str) -> Set[str]:
        """selectolax is 5-10x faster than BeautifulSoup for this."""
        tree = HTMLParser(html)
        links = set()
        for node in tree.css("a[href], form[action]"):
            href = (
                node.attributes.get("href") or
                node.attributes.get("action", "")
            )
            if href and self._is_valid_link(base_url, href):
                full = urljoin(base_url, href).split("#")[0]
                links.add(full)
        return links

    async def _fetch_page(self, url: str) -> tuple[str, str] | None:
        try:
            resp = await self._client.get(url)
            content_type = resp.headers.get("content-type", "").lower()
            if "html" not in content_type:
                return None
            self.response_cache[url] = resp.text
            return url, resp.text
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 429:
                await asyncio.sleep(2)  # back off on rate limit
            return None
        except httpx.RequestError:
            return None

    async def crawl(self) -> list[str]:
        self.validate_target()

        queue: asyncio.Queue[str] = asyncio.Queue()
        await queue.put(self.base_url)
        visited: set[str] = set()
        pages: list[str] = []
        sem = asyncio.Semaphore(self.config.workers)

        async def worker():
            while True:
                try:
                    url = queue.get_nowait()
                except asyncio.QueueEmpty:
                    break
                if url in visited or len(visited) >= self.config.max_pages:
                    queue.task_done()
                    continue
                visited.add(url)
                async with sem:
                    result = await self._fetch_page(url)
                if result:
                    page_url, html = result
                    pages.append(page_url)
                    for link in self._extract_links(page_url, html):
                        if link not in visited:
                            await queue.put(link)
                queue.task_done()

        # Seed workers
        tasks = [asyncio.create_task(worker())
                 for _ in range(self.config.workers)]
        await queue.join()
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        return pages
```

### Sub-step 3: Async plugin execution (6 hrs)

```python
# backend/app/services/scanner/plugins/base.py
import httpx
from abc import ABC, abstractmethod

class BaseCheck(ABC):
    def __init__(self, client: httpx.AsyncClient):
        self.client = client  # shared async client

    @abstractmethod
    async def check(
        self,
        url: str,
        content: str,
        forms: list,
    ) -> list[Vulnerability]:
        ...


# backend/app/services/scanner/plugins/xss.py
class ReflectedXSS(BaseCheck):
    PAYLOADS = [
        ("<script>alert('XSS')</script>", "script tag"),
        ("<img src=x onerror=alert(1)>", "img onerror"),
        ("<svg onload=alert(1)>", "svg onload"),
        ("'><script>alert(1)</script>", "attribute breakout"),
    ]

    async def check(self, url, content, forms) -> list[Vulnerability]:
        vulns = []
        for form in forms:
            result = await self._test_form(url, form)
            if result:
                vulns.append(result)
        return vulns

    async def _test_form(self, url, form) -> Vulnerability | None:
        for payload, desc in self.PAYLOADS:
            data = self._build_form_data(form, payload)
            try:
                resp = await self.client.post(
                    urljoin(url, form.get("action") or url),
                    data=data,
                    timeout=5,
                )
                if payload in resp.text:
                    return self._create_vuln(
                        url=url,
                        description=f"Reflected XSS via '{desc}'",
                        evidence=f"Payload reflected: {payload[:80]}",
                        severity_score=7.5,
                        severity_level=SeverityLevel.HIGH,
                        severity_icon="🟠",
                        remediation=(
                            "1. Sanitize all user input with context-aware encoding\n"
                            "2. Implement Content Security Policy (CSP) headers\n"
                            "3. Use HttpOnly and Secure flags on cookies"
                        ),
                    )
            except httpx.RequestError:
                pass
        return None
```

### Sub-step 4: Full async pipeline — remove ThreadPoolExecutor (4 hrs)

```python
# backend/app/services/scanner/engine.py
import asyncio
import httpx
import logging
import time
from typing import Set, Tuple
from bs4 import BeautifulSoup  # kept only for form traversal

logger = logging.getLogger(__name__)


class ScannerEngine:
    def __init__(self, config):
        self.config = config
        self.vulnerabilities: list[Vulnerability] = []
        self._stop_event = False
        self._pages_scanned = 0
        self._page_cache: dict[str, str] = {}

    def stop(self):
        self._stop_event = True

    async def run(self) -> list[Vulnerability]:
        start = time.time()
        logger.info("=" * 60)
        logger.info("VULNERABILITY SCAN STARTED")
        logger.info(f"Target: {self.config.target_url}")
        logger.info("=" * 60)

        try:
            await self._phase_crawl()
            await self._phase_test()
            self._deduplicate_vulnerabilities()
            self._emit_summary(time.time() - start)
        finally:
            pass  # cleanup handled by context managers inside phases

        return self.vulnerabilities

    async def _phase_crawl(self):
        logger.info("[PHASE 1] Crawling target...")
        async with AsyncWebCrawler(self.config) as crawler:
            self._pages = await crawler.crawl()
            self._page_cache = crawler.response_cache
        logger.info(f"[PHASE 1] Complete — {len(self._pages)} pages discovered")

    async def _phase_test(self):
        if self._stop_event:
            return
        logger.info(f"[PHASE 2] Testing {len(self._pages)} pages...")

        async with httpx.AsyncClient(
            verify=self.config.verify_ssl,
            timeout=self.config.timeout,
        ) as client:
            plugins = [
                ReflectedXSS(client),
                SQLInjection(client),
                SecurityHeaders(client),
                SensitiveFiles(client),
                CSRFCheck(client),
            ]

            coros = [
                self._test_page(url, plugins)
                for url in self._pages
                if not self._stop_event
            ]
            results = await asyncio.gather(*coros, return_exceptions=True)

        for i, result in enumerate(results):
            if isinstance(result, list):
                self.vulnerabilities.extend(result)
            elif isinstance(result, Exception):
                logger.error(f"Page test error: {result}")
            self._pages_scanned = i + 1

    async def _test_page(self, url: str, plugins: list) -> list[Vulnerability]:
        html = self._page_cache.get(url, "")
        forms = self._extract_forms(html)
        vulns: list[Vulnerability] = []

        # All plugins run concurrently per page
        tasks = [plugin.check(url, html, forms) for plugin in plugins]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, list):
                vulns.extend(result)
            elif isinstance(result, Exception):
                logger.debug(f"Plugin error on {url}: {result}")
        return vulns

    def _extract_forms(self, content: str) -> list:
        """Keep BeautifulSoup only for complex form traversal."""
        try:
            soup = BeautifulSoup(content, "html.parser")
            return soup.find_all("form")
        except Exception:
            return []

    def _deduplicate_vulnerabilities(self):
        seen: Set[Tuple[str, str, str]] = set()
        unique = []
        for v in self.vulnerabilities:
            key = (v.url, str(v.vuln_type), v.description)
            if key not in seen:
                seen.add(key)
                unique.append(v)
        removed = len(self.vulnerabilities) - len(unique)
        if removed:
            logger.info(f"Deduplication removed {removed} duplicate findings")
        self.vulnerabilities = unique

    def _emit_summary(self, duration: float):
        logger.info("=" * 60)
        logger.info(f"SCAN COMPLETE in {duration:.1f}s")
        logger.info(f"Pages scanned: {self._pages_scanned}")
        logger.info(f"Vulnerabilities found: {len(self.vulnerabilities)}")
        severity_counts: dict[str, int] = {}
        for v in self.vulnerabilities:
            level = str(v.severity_level.value)
            severity_counts[level] = severity_counts.get(level, 0) + 1
        for level, count in sorted(severity_counts.items()):
            logger.info(f"  {level}: {count}")
        logger.info("=" * 60)


# backend/app/services/scanner/manager.py — updated _run_scan
async def _run_scan(self, scan_id: str, request: ScanRequest):
    scan = self.scans[scan_id]
    scan.status = ScanStatus.RUNNING

    scan_logs = self.logs[scan_id]
    handler = ScanLogHandler(scan_logs)
    scanner_logger = logging.getLogger("app.services.scanner")
    scanner_logger.addHandler(handler)

    try:
        engine = ScannerEngine(request)
        self.engines[scan_id] = engine

        # Now truly async — no run_in_executor needed
        vulns = await engine.run()

        scan.vulnerabilities_count = len(vulns)
        scan.pages_scanned = engine._pages_scanned
        scan.status = ScanStatus.COMPLETED
        scan.end_time = datetime.now(timezone.utc)
        scan.results = vulns

    except Exception as e:
        logger.error(f"Scan {scan_id} failed: {e}", exc_info=True)
        scan.status = ScanStatus.FAILED
        scan.end_time = datetime.now(timezone.utc)
    finally:
        # ALWAYS clean up
        scanner_logger.removeHandler(handler)
        self.engines.pop(scan_id, None)
```

---

## 2. Test Strategy — ✅ IMPLEMENTED

Write in risk order, not coverage order. SSRF validation first — highest regression cost.

### Tier 1: Security Boundary Tests

```python
# backend/tests/test_validation.py
import pytest
from app.models.scan import ScanRequest
from app.services.scanner.crawler import WebCrawler

SSRF_CASES = [
    ("http://192.168.1.1",       "RFC-1918 class C"),
    ("http://10.0.0.1",          "RFC-1918 class A"),
    ("http://172.16.0.1",        "RFC-1918 class B"),
    ("http://169.254.169.254/",  "AWS metadata endpoint"),
    ("http://localhost",         "localhost string"),
    ("http://127.0.0.1",        "loopback numeric"),
    ("http://[::1]",             "IPv6 loopback"),
    ("http://0.0.0.0",           "zero address"),
]

@pytest.mark.parametrize("url,label", SSRF_CASES)
def test_ssrf_blocked(url: str, label: str):
    config = ScanRequest(target_url=url)
    crawler = WebCrawler.__new__(WebCrawler)
    crawler.config = config
    with pytest.raises(ValueError, match="blocked"):
        crawler.validate_target()


def test_valid_public_url_passes():
    config = ScanRequest(target_url="https://example.com")
    crawler = WebCrawler.__new__(WebCrawler)
    crawler.config = config
    crawler.validate_target()  # must not raise


def test_dedup_removes_identical_fingerprints():
    from app.services.scanner.engine import ScannerEngine
    from app.models.vulnerability import Vulnerability, VulnType, SeverityLevel

    def make_vuln(url):
        return Vulnerability(
            url=url, vuln_type=VulnType.XSS, description="test XSS",
            severity_level=SeverityLevel.HIGH, severity_score=7.5,
            severity_icon="🟠", evidence="e", remediation="r",
            confidence="High", timestamp=0.0,
        )

    engine = ScannerEngine.__new__(ScannerEngine)
    engine.vulnerabilities = [
        make_vuln("https://x.com/a"),
        make_vuln("https://x.com/a"),   # duplicate — must be removed
        make_vuln("https://x.com/b"),   # different URL — must be kept
    ]
    engine._deduplicate_vulnerabilities()
    assert len(engine.vulnerabilities) == 2


def test_api_key_short_raises_at_startup(monkeypatch):
    monkeypatch.setattr("app.core.config.settings.API_KEY", "short")
    with pytest.raises(RuntimeError, match="32 characters"):
        import importlib
        import app.main
        importlib.reload(app.main)
```

### Tier 2: Detection Tests with respx HTTP Mocking

```python
# backend/tests/test_xss.py
import respx
import httpx
import pytest

XSS_PAYLOADS = [
    ("<script>alert('XSS')</script>",  "script tag"),
    ("<img src=x onerror=alert(1)>",   "img onerror"),
    ("<svg onload=alert(1)>",          "svg onload"),
    ("'><script>alert(1)</script>",    "attribute breakout"),
]


@pytest.mark.parametrize("payload,desc", XSS_PAYLOADS)
@respx.mock
@pytest.mark.asyncio
async def test_xss_reflected_detected(payload: str, desc: str):
    form_html = (
        '<html><form method="post" action="/search">'
        '<input name="q"></form></html>'
    )
    respx.get("https://t.test/search").mock(
        return_value=httpx.Response(200, text=form_html)
    )
    respx.post("https://t.test/search").mock(
        return_value=httpx.Response(
            200, text=f"<html><body>Results: {payload}</body></html>"
        )
    )

    async with httpx.AsyncClient() as client:
        from app.services.scanner.plugins.xss import ReflectedXSS
        from bs4 import BeautifulSoup

        plugin = ReflectedXSS(client)
        soup = BeautifulSoup(form_html, "html.parser")
        forms = soup.find_all("form")
        result = await plugin.check("https://t.test/search", form_html, forms)

    assert len(result) == 1, f"XSS not detected for {desc}"
    assert result[0].confidence == "High"


@respx.mock
@pytest.mark.asyncio
async def test_xss_no_false_positive_on_encoded_output():
    """Must not fire when the app correctly encodes output."""
    form_html = '<html><form method="post"><input name="q"></form></html>'
    respx.post("https://t.test/").mock(
        return_value=httpx.Response(
            200,
            # HTML-encoded — payload is present but not executable
            text="<html><body>&lt;script&gt;alert(1)&lt;/script&gt;</body></html>",
        )
    )

    async with httpx.AsyncClient() as client:
        from app.services.scanner.plugins.xss import ReflectedXSS
        from bs4 import BeautifulSoup

        plugin = ReflectedXSS(client)
        soup = BeautifulSoup(form_html, "html.parser")
        forms = soup.find_all("form")
        result = await plugin.check("https://t.test/", form_html, forms)

    assert result == [], "False positive: XSS fired on HTML-encoded output"


# backend/tests/test_sqli.py
@respx.mock
@pytest.mark.asyncio
async def test_sqli_detects_mysql_error():
    form_html = '<html><form method="post"><input name="id"></form></html>'
    respx.post("https://t.test/db").mock(
        return_value=httpx.Response(
            200,
            text="You have an error in your SQL syntax near '1'' at line 1 — MySQL",
        )
    )

    async with httpx.AsyncClient() as client:
        from app.services.scanner.plugins.sqli import SQLInjection
        from bs4 import BeautifulSoup

        plugin = SQLInjection(client)
        soup = BeautifulSoup(form_html, "html.parser")
        forms = soup.find_all("form")
        result = await plugin.check("https://t.test/db", form_html, forms)

    assert len(result) == 1
    assert "MySQL" in result[0].description


# backend/tests/fixtures/vulnerable_app.py — integration target
from starlette.applications import Starlette
from starlette.responses import HTMLResponse
from starlette.routing import Route


async def search(request):
    q = request.query_params.get("q", "")
    return HTMLResponse(
        f"""<html>
        <form method="post" action="/search">
          <input name="q" value="{q}">
        </form>
        Results for: {q}
        </html>"""  # intentionally unescaped — XSS
    )


async def db_search(request):
    q = request.query_params.get("id", "")
    if "'" in q:
        return HTMLResponse(
            "You have an error in your SQL syntax near 'id=1''; "
            "check the manual for MySQL 8.0"
        )
    return HTMLResponse("Result: found")


vulnerable_app = Starlette(
    routes=[
        Route("/search", search, methods=["GET", "POST"]),
        Route("/db", db_search),
    ]
)
```

### Tier 3: API Integration Tests

```python
# backend/tests/test_api.py
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)
HEADERS = {"X-API-Key": "dev_api_key_12345_dev_api_key_12345"}  # 32+ chars


def test_start_scan_returns_scan_id():
    resp = client.post(
        "/api/v1/scan/",
        json={"target_url": "https://example.com"},
        headers=HEADERS,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "scan_id" in data
    assert data["status"] in ("pending", "running")


def test_missing_api_key_returns_401():
    resp = client.post("/api/v1/scan/", json={"target_url": "https://example.com"})
    assert resp.status_code == 401


def test_wrong_api_key_returns_403():
    resp = client.post(
        "/api/v1/scan/",
        json={"target_url": "https://example.com"},
        headers={"X-API-Key": "wrong"},
    )
    assert resp.status_code == 403


def test_ssrf_target_returns_400():
    resp = client.post(
        "/api/v1/scan/",
        json={"target_url": "http://192.168.1.1"},
        headers=HEADERS,
    )
    assert resp.status_code in (400, 422)


def test_scan_not_found_returns_404():
    resp = client.get("/api/v1/scan/nonexistent-uuid", headers=HEADERS)
    assert resp.status_code == 404


# conftest.py
import pytest
from httpx import AsyncClient
from app.main import app


@pytest.fixture
async def async_client():
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac


@pytest.fixture
def api_headers():
    return {"X-API-Key": "dev_api_key_12345_dev_api_key_12345"}
```

---

## 3. Security Middleware — ✅ SHIPPED

```python
# backend/app/middleware.py
import html
import re
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add defensive headers and strip stack fingerprints."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        h = response.headers
        h["X-Content-Type-Options"] = "nosniff"
        h["X-Frame-Options"]        = "DENY"
        h["Referrer-Policy"]        = "no-referrer"
        h["Permissions-Policy"]     = "camera=(), microphone=(), geolocation=()"
        h["X-XSS-Protection"]       = "0"  # disable broken legacy auditor
        h.pop("server", None)          # remove uvicorn fingerprint
        h.pop("x-powered-by", None)
        return response


class SensitiveDataSanitizer(BaseHTTPMiddleware):
    """Mask secrets from log output."""
    _MASK = re.compile(
        r'("(?:auth_token|password|cookie|secret)[^"]*":\s*")([^"]+)(")',
        re.IGNORECASE,
    )

    @classmethod
    def sanitize(cls, text: str) -> str:
        return cls._MASK.sub(r"\1[REDACTED]\3", text)

    async def dispatch(self, request: Request, call_next):
        return await call_next(request)


# Payload sanitizer for log stream
_UNSAFE_CHARS = re.compile(r'[<>"\'`&]')


def sanitize_log_message(msg: str) -> str:
    """Escape HTML-special chars from scan payloads before WebSocket streaming."""
    return _UNSAFE_CHARS.sub(
        lambda m: html.escape(m.group(), quote=True), msg
    )


# backend/app/main.py — register in correct order
from app.middleware import SecurityHeadersMiddleware, SensitiveDataSanitizer

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,  # never ["*"] in production
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-API-Key"],
)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(SensitiveDataSanitizer)


# Startup entropy check
@asynccontextmanager
async def lifespan(app):
    if len(settings.API_KEY) < 32:
        raise RuntimeError(
            "API_KEY must be at least 32 characters. "
            "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
        )
    logger.info("SentinalScan API starting up...")
    yield
    logger.info("SentinalScan API shutting down...")
```

---

## 4. UI/UX & Monitoring — ✅ SHIPPED

### Custom Scan History Sidebar

Native React component that polls the new `GET /api/v1/scan/` endpoint to provide session persistence without a database (in-process memory).

```jsx
// frontend/src/features/scan/ScanHistory.jsx
export function ScanHistory({ activeScanId, onSelectScan }) {
  const { data: scans, isLoading } = useAllScans();
  // ... renders scan list with status icons ...
}
```

### Real-time Toast Notifications

State-based notification system in `App.jsx` using `framer-motion` for smooth entry/exit animations. Triggers on scan start, success, failure, and stop.

```jsx
const showToast = (message, type = "info") => {
  setToast({ message, type });
  setTimeout(() => setToast(null), 4000);
};
```

---

## 5. Redis State Store — PENDING

```python
# backend/app/store.py
import redis.asyncio as redis
import json
import os
from typing import Any

_redis: redis.Redis | None = None

def get_redis() -> redis.Redis:
    global _redis
    if _redis is None:
        _redis = redis.from_url(
            os.environ["REDIS_URL"],
            decode_responses=True,
        )
    return _redis


async def save_scan_status(scan_id: str, status: dict, ttl: int = 86400):
    await get_redis().setex(f"scan:{scan_id}:status", ttl, json.dumps(status))


async def get_scan_status(scan_id: str) -> dict | None:
    raw = await get_redis().get(f"scan:{scan_id}:status")
    return json.loads(raw) if raw else None


async def append_result(scan_id: str, vuln: dict):
    r = get_redis()
    await r.rpush(f"scan:{scan_id}:results", json.dumps(vuln))
    await r.expire(f"scan:{scan_id}:results", 86400)


async def get_results(scan_id: str) -> list[dict]:
    raw = await get_redis().lrange(f"scan:{scan_id}:results", 0, -1)
    return [json.loads(r) for r in raw]


async def publish_log(scan_id: str, entry: dict):
    await get_redis().publish(f"logs:{scan_id}", json.dumps(entry))


async def append_log(scan_id: str, entry: dict):
    """Persist log for HTTP polling fallback."""
    r = get_redis()
    await r.rpush(f"scan:{scan_id}:logs", json.dumps(entry))
    await r.expire(f"scan:{scan_id}:logs", 3600)


async def get_logs(scan_id: str) -> list[dict]:
    raw = await get_redis().lrange(f"scan:{scan_id}:logs", 0, -1)
    return [json.loads(r) for r in raw]


# Updated WebSocket endpoint — subscribes to Redis pub/sub per scan
# backend/app/main.py
@app.websocket("/ws/logs/{scan_id}")
async def websocket_logs(websocket: WebSocket, scan_id: str):
    await websocket.accept()
    r = get_redis()

    # Send buffered logs first (in case client connects mid-scan)
    buffered = await get_logs(scan_id)
    for entry in buffered:
        await websocket.send_json(entry)

    # Subscribe to real-time stream
    try:
        async with r.pubsub() as ps:
            await ps.subscribe(f"logs:{scan_id}")
            async for msg in ps.listen():
                if msg["type"] == "message":
                    data = json.loads(msg["data"])
                    await websocket.send_json(data)
                    if data.get("type") == "scan_complete":
                        break
    except WebSocketDisconnect:
        pass
```

---

## 5. Celery Job Queue

```python
# backend/app/tasks.py
import asyncio
import os
from celery import Celery
from app.models.scan import ScanRequest, ScanStatus
from app.services.scanner.engine import ScannerEngine
from app import store

celery = Celery(
    "sentinal",
    broker=os.environ["REDIS_URL"],
    backend=os.environ["REDIS_URL"],
)

celery.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    result_expires=86400,
    worker_max_tasks_per_child=10,   # prevent memory leaks
    task_acks_late=True,             # only ack after successful completion
    task_reject_on_worker_lost=True,
)


@celery.task(bind=True, max_retries=0, name="sentinal.run_scan")
def run_scan_task(self, scan_id: str, config_dict: dict):
    """
    Celery is the ONLY threading boundary in the system.
    All async code runs inside a fresh event loop per task.
    """
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        config = ScanRequest(**config_dict)
        engine = ScannerEngine(config)

        async def _run():
            await store.save_scan_status(scan_id, {"status": "running"})
            vulns = await engine.run()

            # Persist results
            for v in vulns:
                await store.append_result(scan_id, v.model_dump())

            await store.save_scan_status(scan_id, {
                "status": "completed",
                "pages_scanned": engine._pages_scanned,
                "vulnerabilities_count": len(vulns),
            })
            await store.publish_log(scan_id, {
                "type": "scan_complete",
                "status": "completed",
                "message": f"Scan completed — {len(vulns)} findings",
            })

        loop.run_until_complete(_run())

    except Exception as e:
        loop.run_until_complete(store.save_scan_status(scan_id, {
            "status": "failed",
            "error": str(e),
        }))
        loop.run_until_complete(store.publish_log(scan_id, {
            "type": "scan_complete",
            "status": "failed",
            "message": f"Scan failed: {e}",
        }))
        raise
    finally:
        loop.close()


# Updated API endpoint — returns in <50ms
@app.post("/api/v1/scan/", response_model=ScanResponse)
async def start_scan(
    request: ScanRequest,
    _key: str = Depends(get_api_key),
):
    scan_id = str(uuid.uuid4())
    await store.save_scan_status(scan_id, {
        "scan_id": scan_id,
        "status": "pending",
        "target_url": str(request.target_url),
    })
    run_scan_task.delay(scan_id, request.model_dump(mode="json"))
    return ScanResponse(
        scan_id=scan_id,
        status=ScanStatus.PENDING,
        target_url=str(request.target_url),
        start_time=datetime.now(timezone.utc),
    )
```

---

## 6. AI Triage Integration

```python
# backend/app/ai_triage.py
import anthropic
import asyncio
import json
import logging
from app.models.vulnerability import Vulnerability

logger = logging.getLogger(__name__)
_client = anthropic.AsyncAnthropic()

TRIAGE_SYSTEM = """You are a senior security engineer writing a penetration test report.
Be direct, technical, and constructive. Respond ONLY with valid JSON — no markdown, no preamble."""

TRIAGE_PROMPT = """\
Analyze this web vulnerability finding and respond with ONLY a JSON object:
{{
  "adjusted_severity": "Critical"|"High"|"Medium"|"Low"|"Info",
  "exploitability": "<one sentence, max 20 words, concrete impact>",
  "code_fix": "<minimal code snippet in {lang}, with a comment explaining the fix>",
  "cvss_vector": "<CVSS 3.1 vector string>",
  "confidence_note": "<why severity was adjusted or confirmed>"
}}

Finding:
  Type: {vuln_type}
  URL: {url}
  Description: {description}
  Evidence: {evidence}
  Current severity: {severity_level}
  Severity score: {severity_score}"""


def _detect_language(url: str) -> str:
    url_lower = url.lower()
    if any(x in url_lower for x in [".php", "wp-", "wordpress"]):
        return "PHP"
    if any(x in url_lower for x in [".asp", ".aspx"]):
        return "C# / ASP.NET"
    if any(x in url_lower for x in [".jsp", ".java"]):
        return "Java"
    if any(x in url_lower for x in [".rb", "rails"]):
        return "Ruby"
    return "Python"  # default for FastAPI targets


async def triage_finding(vuln: Vulnerability) -> dict | None:
    lang = _detect_language(vuln.url)
    prompt = TRIAGE_PROMPT.format(
        lang=lang,
        vuln_type=vuln.vuln_type.value,
        url=vuln.url,
        description=vuln.description,
        evidence=vuln.evidence,
        severity_level=vuln.severity_level.value,
        severity_score=vuln.severity_score,
    )
    try:
        msg = await _client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=600,
            system=TRIAGE_SYSTEM,
            messages=[{"role": "user", "content": prompt}],
        )
        return json.loads(msg.content[0].text)
    except Exception as e:
        logger.warning(f"AI triage failed for {vuln.url}: {e}")
        return None


async def triage_all(
    vulns: list[Vulnerability],
    concurrency: int = 5,
) -> list[dict | None]:
    """Triage all findings concurrently, respecting API rate limits."""
    sem = asyncio.Semaphore(concurrency)

    async def _guarded(v: Vulnerability) -> dict | None:
        async with sem:
            return await triage_finding(v)

    return await asyncio.gather(*[_guarded(v) for v in vulns])


# Add to scan completion in tasks.py:
# triages = await triage_all(vulns)
# for vuln, triage in zip(vulns, triages):
#     if triage:
#         vuln_dict = {**vuln.model_dump(), "ai_triage": triage}
#         await store.append_result(scan_id, vuln_dict)
```

---

## 7. Postgres Schema + Diff Engine

```sql
-- migrations/001_create_scans.sql
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE scans (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    target_url    TEXT        NOT NULL,
    started_at    TIMESTAMPTZ DEFAULT now(),
    completed_at  TIMESTAMPTZ,
    status        TEXT        NOT NULL DEFAULT 'queued'
                              CHECK (status IN ('queued','running','completed','failed','stopped')),
    config        JSONB,
    pages_scanned INT         DEFAULT 0,
    user_id       UUID        -- populated in Phase 4
);

CREATE TABLE findings (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id        UUID        NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    vuln_type      TEXT        NOT NULL,
    url            TEXT        NOT NULL,
    description    TEXT,
    severity_level TEXT        NOT NULL,
    severity_score FLOAT,
    evidence       TEXT,
    remediation    TEXT,
    confidence     TEXT,
    ai_triage      JSONB,
    discovered_at  TIMESTAMPTZ DEFAULT now(),
    -- Generated fingerprint for deduplication and diffing
    fingerprint    TEXT GENERATED ALWAYS AS (
                       md5(vuln_type || '|' || url || '|' || coalesce(description, ''))
                   ) STORED
);

CREATE INDEX idx_findings_scan_id    ON findings(scan_id);
CREATE INDEX idx_findings_fingerprint ON findings(fingerprint);
CREATE INDEX idx_scans_target        ON scans(target_url, started_at DESC);
CREATE INDEX idx_scans_status        ON scans(status);
```

```python
# backend/app/diff_engine.py
import asyncpg
import os
from dataclasses import dataclass

@dataclass
class DiffResult:
    new_findings: list[dict]
    fixed_findings: list[dict]
    unchanged_count: int


async def diff_scans(
    new_scan_id: str,
    baseline_scan_id: str,
    conn: asyncpg.Connection,
) -> DiffResult:
    """
    Compare two scans for the same target.
    Returns findings that are new (regression) and findings that were fixed.
    """
    # New findings: in new scan but not in baseline
    new_rows = await conn.fetch("""
        SELECT f2.*
        FROM findings f2
        WHERE f2.scan_id = $1
          AND f2.fingerprint NOT IN (
              SELECT fingerprint FROM findings WHERE scan_id = $2
          )
        ORDER BY
            CASE f2.severity_level
                WHEN 'Critical' THEN 1
                WHEN 'High'     THEN 2
                WHEN 'Medium'   THEN 3
                ELSE 4
            END
    """, new_scan_id, baseline_scan_id)

    # Fixed findings: in baseline but not in new scan
    fixed_rows = await conn.fetch("""
        SELECT f1.*
        FROM findings f1
        WHERE f1.scan_id = $1
          AND f1.fingerprint NOT IN (
              SELECT fingerprint FROM findings WHERE scan_id = $2
          )
    """, baseline_scan_id, new_scan_id)

    # Unchanged: in both scans
    unchanged = await conn.fetchval("""
        SELECT COUNT(*)
        FROM findings f1
        WHERE f1.scan_id = $1
          AND f1.fingerprint IN (
              SELECT fingerprint FROM findings WHERE scan_id = $2
          )
    """, new_scan_id, baseline_scan_id)

    return DiffResult(
        new_findings=[dict(r) for r in new_rows],
        fixed_findings=[dict(r) for r in fixed_rows],
        unchanged_count=unchanged or 0,
    )


# backend/app/api/v1/endpoints/scan.py — diff endpoint
@router.get("/{scan_id}/diff/{baseline_id}", dependencies=[Depends(get_api_key)])
async def get_scan_diff(scan_id: str, baseline_id: str):
    """Compare a new scan against a baseline and return only new findings."""
    async with asyncpg.connect(os.environ["DATABASE_URL"]) as conn:
        result = await diff_scans(scan_id, baseline_id, conn)
    return {
        "new_findings":    result.new_findings,
        "fixed_findings":  result.fixed_findings,
        "unchanged_count": result.unchanged_count,
        "regression":      len(result.new_findings) > 0,
    }
```

---

## 8. CI/CD Pipeline

```yaml
# .github/workflows/ci.yml
name: CI

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

jobs:
  backend:
    name: Backend — lint · security · test
    runs-on: ubuntu-latest
    services:
      redis:
        image: redis:7-alpine
        ports: ["6379:6379"]
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-retries 5

    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
          cache: pip

      - name: Install dependencies
        run: |
          pip install -r backend/requirements.txt
          pip install pytest pytest-asyncio pytest-cov respx ruff bandit pip-audit

      - name: Lint (ruff)
        run: ruff check backend/

      - name: Security lint (bandit)
        run: bandit -r backend/ -ll -x backend/tests/

      - name: CVE check (pip-audit)
        run: pip-audit -r backend/requirements.txt

      - name: Verify lockfile is current
        run: |
          pip-compile backend/requirements.in --dry-run --quiet || \
            (echo "requirements.txt is out of date — run pip-compile" && exit 1)

      - name: Run tests
        env:
          SENTINAL_API_KEY: test_api_key_for_ci_only_32_chars_minimum
          REDIS_URL: redis://localhost:6379
        run: |
          pytest backend/tests/ \
            --cov=backend \
            --cov-report=xml \
            --cov-report=term-missing \
            --cov-fail-under=70 \
            -v --tb=short

      - name: Upload coverage
        uses: codecov/codecov-action@v4
        with:
          files: ./coverage.xml
          fail_ci_if_error: false

  frontend:
    name: Frontend — lint · audit · build
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-node@v4
        with:
          node-version: "20"
          cache: npm
          cache-dependency-path: frontend/package-lock.json

      - run: cd frontend && npm ci
      - run: cd frontend && npm run lint
      - run: cd frontend && npm audit --audit-level=high
      - run: cd frontend && npm run build
        env:
          VITE_API_URL: http://localhost:8000/api/v1
          VITE_API_KEY: test_key

      - uses: actions/upload-artifact@v4
        with:
          name: frontend-dist-${{ github.sha }}
          path: frontend/dist/
          retention-days: 7

  docker:
    name: Docker build check
    runs-on: ubuntu-latest
    needs: [backend, frontend]
    if: github.ref == 'refs/heads/main'

    steps:
      - uses: actions/checkout@v4
      - uses: docker/setup-buildx-action@v3

      - name: Build API image
        uses: docker/build-push-action@v5
        with:
          context: ./backend
          push: false
          tags: sentinalscan/api:${{ github.sha }}
          cache-from: type=gha
          cache-to: type=gha,mode=max


# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: pip
    directory: /backend
    schedule: { interval: weekly, day: monday }
    groups:
      python-deps: { patterns: ["*"] }
    labels: [dependencies, python]

  - package-ecosystem: npm
    directory: /frontend
    schedule: { interval: weekly, day: monday }
    labels: [dependencies, javascript]

  - package-ecosystem: github-actions
    directory: /
    schedule: { interval: monthly }
    labels: [dependencies, github-actions]
```

---

## 9. Docker Compose Full Stack — ✅ SHIPPED

```yaml
# docker-compose.yml
services:
  api:
    build:
      context: ./backend
      dockerfile: Dockerfile
    ports: ["8000:8000"]
    environment:
      - REDIS_URL=redis://redis:6379
      - SENTINAL_API_KEY=${SENTINAL_API_KEY}
      - SECRET_KEY=${SECRET_KEY}
      - DATABASE_URL=postgresql+asyncpg://sentinal:${POSTGRES_PASSWORD}@postgres:5432/sentinal
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY:-}
      - LOG_LEVEL=INFO
    depends_on:
      redis:    { condition: service_healthy }
      postgres: { condition: service_healthy }
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      retries: 3

  worker:
    build: ./backend
    command: celery -A app.tasks worker -l info -c 4 --max-tasks-per-child 10
    environment:
      - REDIS_URL=redis://redis:6379
      - DATABASE_URL=postgresql+asyncpg://sentinal:${POSTGRES_PASSWORD}@postgres:5432/sentinal
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY:-}
    depends_on:
      redis:    { condition: service_healthy }
      postgres: { condition: service_healthy }
    restart: unless-stopped
    profiles: [celery]   # opt-in: docker compose --profile celery up

  frontend:
    build: ./frontend
    ports: ["5173:80"]
    environment:
      - VITE_API_URL=http://localhost:8000/api/v1
      - VITE_API_KEY=${SENTINAL_API_KEY}
    depends_on: [api]

  redis:
    image: redis:7-alpine
    ports: ["6379:6379"]
    volumes: ["redis_data:/data"]
    command: redis-server --save 60 1 --loglevel warning
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5

  postgres:
    image: postgres:16-alpine
    environment:
      - POSTGRES_USER=sentinal
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
      - POSTGRES_DB=sentinal
    volumes: ["postgres_data:/var/lib/postgresql/data"]
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U sentinal"]
      interval: 10s
      retries: 5

volumes:
  redis_data:
  postgres_data:


# backend/Dockerfile
FROM python:3.12-slim AS base
WORKDIR /app

# Install system deps for WeasyPrint (PDF) and Playwright
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl libpango-1.0-0 libpangoft2-1.0-0 \
    && rm -rf /var/lib/apt/lists/*

FROM base AS deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

FROM deps AS app
COPY . .

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", \
     "--workers", "2", "--log-level", "info"]


# .env.example
# Generate API_KEY: python -c "import secrets; print(secrets.token_hex(32))"
SENTINAL_API_KEY=
SECRET_KEY=
POSTGRES_PASSWORD=
ANTHROPIC_API_KEY=   # optional — enables AI triage and PDF reports
```

---

## 10. Structured Logging

```python
# backend/app/core/logging.py
import structlog
import logging
import sys


def setup_logging(log_level: str = "INFO"):
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.stdlib.add_log_level,
            structlog.stdlib.add_logger_name,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, log_level.upper())
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
        cache_logger_on_first_use=True,
    )

    # Quiet noisy libraries
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)


# Usage in ScanManager — bind context once per scan
import structlog

log = structlog.get_logger()

async def _run_scan(self, scan_id: str, request: ScanRequest):
    # Bind scan context to all log calls in this coroutine
    structlog.contextvars.clear_contextvars()
    structlog.contextvars.bind_contextvars(
        scan_id=scan_id,
        target=str(request.target_url),
    )

    log.info("scan_started", max_pages=request.max_pages, workers=request.workers)
    try:
        engine = ScannerEngine(request)
        vulns = await engine.run()
        log.info("scan_completed", findings=len(vulns))
    except Exception as e:
        log.error("scan_failed", error=str(e), exc_info=True)
        raise
    finally:
        structlog.contextvars.clear_contextvars()

# Output (auto-parseable by ELK, Datadog, CloudWatch Insights):
# {"event":"scan_started","scan_id":"abc-123","target":"https://example.com",
#  "max_pages":50,"workers":5,"level":"info","timestamp":"2026-04-27T10:00:00Z"}
```

---

*SentinalScan Implementation Guide · Companion to the Architecture Analysis*  
*Execute sub-steps in sequence. Each sub-step must pass the full test suite before proceeding.*
