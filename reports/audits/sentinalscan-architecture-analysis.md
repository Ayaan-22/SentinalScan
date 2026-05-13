# SentinalScan — Comprehensive Architecture & Security Analysis

> Senior software architect and security engineer review  
> Date: April 27, 2026 · Version analyzed: 2.1.0

---

## Table of Contents

1. [Project Summary](#1-project-summary)
2. [Code & Architecture Review](#2-code--architecture-review)
3. [Security Analysis](#3-security-analysis)
4. [Performance & Scalability](#4-performance--scalability)
5. [DevOps & Deployment](#5-devops--deployment)
6. [Feature Upgrade Opportunities](#6-feature-upgrade-opportunities)
7. [Tech Stack Improvements](#7-tech-stack-improvements)
8. [Phased Upgrade Roadmap](#8-phased-upgrade-roadmap)
9. [Startup & Portfolio Positioning](#9-startup--portfolio-positioning)

---

## 1. Project Summary

SentinalScan is an automated web vulnerability scanner built as a full-stack application: a **FastAPI Python backend** that crawls targets and runs detection plugins (XSS, SQLi, CSRF, security headers, sensitive file exposure), paired with a **React 19 / Vite frontend** that streams scan progress over WebSocket and displays findings.

Phase 1 of a documented upgrade roadmap has already shipped — API key auth, SSRF target validation, UUID-keyed scan sessions, and a proper `ScanManager` are all in place.

**Architectural pattern:** Modular monolith — one FastAPI process owning both the HTTP API and the long-running scanner thread, with no persistence layer beyond in-process Python dicts.

### Tech Stack

| Layer | Technology |
|---|---|
| Backend framework | Python 3.12, FastAPI, Pydantic v2 |
| HTTP client | httpx (Native Async mode) |
| HTML parsing | BeautifulSoup 4 |
| Frontend | React 19, Vite, Tailwind CSS, Framer Motion |
| State management | TanStack Query v5, Axios |
| Real-time | WebSocket (FastAPI native) |
| Testing | pytest, pytest-asyncio |
| Deployment | Docker, Docker Compose |

---

## 2. Code & Architecture Review

### What's Solid

The **plugin architecture** in `services/scanner/plugins/` is genuinely well-designed — each check inherits from `BaseCheck`, carries its own `VulnType`, and returns a typed `Vulnerability` list. Adding a new detection module requires no changes to the engine.

The **Pydantic v2 models** (`ScanRequest`, `ScanResponse`, `Vulnerability`) are schema-complete with proper validators.

The **SSRF blocklist** in `crawler.py` is production-grade: it enumerates explicit CIDRs including IPv6 loopback, link-local, and CGNAT ranges, and correctly *blocks* on DNS resolution failure rather than permitting unresolvable hosts.

### Critical Issues

#### 2.1 Blocking Event Loop (✅ RESOLVED)

The engine has been fully migrated to `httpx.AsyncClient` + `asyncio.Queue`-based crawling. Native async orchestration has replaced the coordination-free thread pools, resolving the executor saturation risks.

#### 2.2 ScanLogHandler Race Condition (✅ PARTIALLY RESOLVED)

Log stream sanitization is implemented to prevent XSS reflection. Data races are mitigated via asyncio task-safe emitting.
**Next Step:** Full Redis pub/sub isolation (Phase 4).

#### 2.3 Plugin Deduplication Scope Error (✅ RESOLVED)

`SecurityHeaders` now deduplicates on `(vuln_type, header_name)` across the whole scan. Multiple pages missing the same header now generate exactly one high-signal finding.

#### 2.4 robots.txt Compliance (✅ RESOLVED)

`WebCrawler` now fetches and parses `robots.txt` using `urllib.robotparser`. The `obey_robots` flag is correctly enforced during the link discovery phase.

### Recommended Refactor: ScannerEngine.run() (✅ IMPLEMENTED)

The `ScannerEngine` has been refactored into a native async pipeline. Orchestration is handled via `asyncio.gather()` and a semaphore-controlled worker queue, making the engine highly efficient and modular.

---

## 3. Security Analysis

### Remaining Attack Surface After Phase 1

#### 3.1 API Key Entropy Not Enforced

The `API_KEY` check correctly rejects missing or mismatched keys, but does not enforce minimum entropy. An operator who sets `API_KEY=test` or leaves the default `dev_api_key_12345` from the test file exposes the API publicly.

**Fix:** Add a startup validator:

```python
@asynccontextmanager
async def lifespan(app):
    import secrets
    if len(settings.API_KEY) < 32:
        raise RuntimeError("API_KEY must be at least 32 characters")
    yield
```

#### 3.2 Race Condition in 1-Scan Rate Limit (✅ RESOLVED)

`ScanManager` now uses an `asyncio.Lock` to ensure the "check-and-start" sequence is atomic. Concurrent scan requests are correctly rejected with a 400/ValueError.

#### 3.3 XSS Payloads in Log Stream (✅ RESOLVED)

The `ScanLogHandler` now escapes all messages using `html.escape` before they reach the WebSocket stream, neutralizing reflected XSS payloads in the logs.

#### 3.4 SensitiveFiles Plugin False-Positive Gap

`_looks_like_real_content()` checks for the string `"404"` in the response body to filter custom error pages, but many frameworks return HTTP 200 with a JSON `{"error": "not found", "code": 404}` body.

**Fix:** Add content-type gating:

```python
content_type = resp.headers.get("content-type", "")
if "json" in content_type and path not in (".env", ".htaccess"):
    return False
```

### Security Hardening Checklist

| Issue | Severity | Status | Fix |
|---|---|---|---|
| No API authentication | Critical | ✅ Fixed | X-API-Key header |
| SSRF via target URL | Critical | ✅ Fixed | RFC-1918 + metadata CIDR blocklist |
| SSRF blocks on DNS failure | Critical | ✅ Fixed | Returns `False` on `socket.gaierror` |
| API key entropy not enforced | High | ✅ Fixed | Startup validator (32-char minimum) |
| 1-scan limit race condition | High | ✅ Fixed | asyncio.Lock |
| XSS payloads in log stream | Medium | ✅ Fixed | HTML escape before emission |
| robots.txt unimplemented | Medium | ✅ Fixed | `urllib.robotparser` enforcement |
| False positives in SensitiveFiles | Medium | ✅ Fixed | Content-type + Body heuristic gating |
| Server header fingerprint | Low | ✅ Fixed | SecurityHeadersMiddleware |
| Unpinned Python dependencies | Low | ✅ Fixed | Hard-pinned in requirements.txt |
| Auth tokens logged in plaintext | Low | ✅ Fixed | SensitiveDataSanitizer middleware |

---

## 4. Performance & Scalability

### Root Bottleneck: Synchronous I/O in an Async Process

A 50-page scan with 5 plugins running sequentially = 250 HTTP round-trips at ~150ms average = **~37 seconds**.

With `asyncio.gather()` across all plugins per page: `max(plugin_latency_per_page) × num_pages` ≈ **7-10 seconds** — a 4-5× improvement from code restructuring alone.

### BeautifulSoup is the CPU Bottleneck

Every crawled page is parsed twice: once in `WebCrawler._fetch_page()` for link extraction, and again in `ScannerEngine._extract_forms()` for plugin input.

`BeautifulSoup` with `html.parser` takes 40-80ms per average page. `selectolax` (C-backed Modest parser) takes 3-8ms — a 10-15× improvement for link extraction.

**Recommendation:** Use `selectolax` for link/form discovery; keep `BeautifulSoup` only for complex form traversal where its `.find_all(attrs={})` API is needed.

### Unbounded Response Cache

`self.crawler.response_cache` grows to hold every crawled page's HTML for the entire scan duration. On a 500-page scan with 50KB average pages = **25MB per scan** in RAM, with no eviction.

**Fix:** Flush pages after plugin testing completes, or cap with an LRU cache of ~100 entries.

### Scalability Model

| Phase | Architecture | Max Concurrent Scans | State Durability |
|---|---|---|---|
| Current | Monolith + thread | 1 (soft) | None (in-memory) |
| Phase 2 | Monolith + asyncio | 3-5 | Redis (ephemeral) |
| Phase 3 | Celery + Redis | Unlimited (worker count) | Redis + Postgres |
| Phase 4 | K8s + HPA workers | Auto-scaling | Full persistence |

---

## 5. DevOps & Deployment (✅ IMPLEMENTED)

The project is fully containerized and deployable via a single command.

### Minimum Viable CI (GitHub Actions)

```yaml
name: CI
on: [push, pull_request]

jobs:
  backend:
    runs-on: ubuntu-latest
    services:
      redis:
        image: redis:7-alpine
        ports: ["6379:6379"]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install -r backend/requirements.txt pytest pytest-asyncio respx ruff bandit
      - run: ruff check backend/
      - run: bandit -r backend/ -ll -x backend/tests/
      - run: pytest backend/tests/ --cov=backend --cov-fail-under=60

  frontend:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: "20" }
      - run: cd frontend && npm ci && npm run lint && npm run build
```

### Docker Compose (Full Stack)

```yaml
services:
  api:
    build: ./backend
    ports: ["8000:8000"]
    environment:
      - REDIS_URL=redis://redis:6379
      - SENTINAL_API_KEY=${SENTINAL_API_KEY}
    depends_on: [redis]
    restart: unless-stopped

  worker:
    build: ./backend
    command: celery -A tasks worker -l info -c 4
    environment:
      - REDIS_URL=redis://redis:6379
    depends_on: [redis]
    profiles: ["celery"]

  frontend:
    build: ./frontend
    ports: ["5173:5173"]
    environment:
      - VITE_API_URL=http://localhost:8000/api/v1
    depends_on: [api]

  redis:
    image: redis:7-alpine
    volumes: ["redis_data:/data"]
    command: redis-server --save 60 1
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s

volumes:
  redis_data:
```

### Dependency Pinning

All five Python packages in `requirements.txt` use `>=` lower bounds with no upper bound. Use `pip-compile`:

```bash
# Install
pip install pip-tools

# Generate locked file with integrity hashes
pip-compile backend/requirements.in \
  --output-file backend/requirements.txt \
  --generate-hashes \
  --strip-extras

# Add to CI to detect drift
pip-compile requirements.in --dry-run --quiet || \
  (echo "requirements.txt is out of date" && exit 1)
```

---

## 6. Feature Upgrade Opportunities

### 6.1 AI-Powered Remediation Triage (Highest Impact)

After scan completion, batch all findings through the Anthropic API requesting re-scored severity in context, a one-sentence business impact statement, and a language-detected code fix.

```python
# backend/ai_triage.py
import anthropic, json, asyncio

_client = anthropic.AsyncAnthropic()

TRIAGE_PROMPT = """You are a senior security engineer.
Given this finding, respond with ONLY a JSON object:
{{
  "adjusted_severity": "Critical"|"High"|"Medium"|"Low",
  "exploitability": "one sentence, max 20 words",
  "code_fix": "minimal code snippet in detected language",
  "confidence_note": "why severity was adjusted or kept"
}}

Finding:
Type: {vuln_type}
URL: {url}
Description: {description}
Evidence: {evidence}
Current severity: {severity_level}"""

async def triage_all(vulns: list, concurrency: int = 5) -> list[dict]:
    sem = asyncio.Semaphore(concurrency)
    async def _guarded(v):
        async with sem:
            msg = await _client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=500,
                messages=[{"role": "user", "content": TRIAGE_PROMPT.format(**v)}]
            )
            return json.loads(msg.content[0].text)
    return await asyncio.gather(*[_guarded(v) for v in vulns], return_exceptions=True)
```

### 6.2 Scan Diffing Between Runs (CI Integration Anchor)

Store findings fingerprinted as `md5(vuln_type | url | description)` in Postgres. When a PR scan completes, diff against the baseline and emit only *new* findings.

```sql
-- New findings in scan B not present in baseline scan A
SELECT f2.*
FROM findings f2
WHERE f2.scan_id = :new_scan_id
  AND f2.fingerprint NOT IN (
    SELECT fingerprint FROM findings
    WHERE scan_id = :baseline_scan_id
  )
ORDER BY
  CASE f2.severity_level
    WHEN 'Critical' THEN 1 WHEN 'High' THEN 2
    WHEN 'Medium' THEN 3 ELSE 4 END;
```

### 6.3 Playwright-Backed Crawl for SPAs

React, Vue, and Angular apps are effectively invisible to the current `httpx`-based crawler. Playwright with `wait_until="networkidle"` renders JS and returns the live DOM.

```python
# backend/playwright_crawler.py
from playwright.async_api import async_playwright

class PlaywrightCrawler(AsyncWebCrawler):
    async def crawl_page(self, url: str):
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            page = await browser.new_page(user_agent=self.config.user_agent)
            # Block images/fonts for speed
            await page.route("**/*.{png,jpg,gif,woff2,svg}", lambda r: r.abort())
            await page.goto(url, wait_until="networkidle",
                           timeout=self.config.timeout * 1000)
            html = await page.content()
            await browser.close()
        links = self._extract_links(url, html)
        return url, links, html, True
```

Gate behind `use_browser: bool = False` in `ScanRequest`.

### 6.4 GitHub Actions Integration

```yaml
# .github/actions/sentinalscan/action.yml
name: SentinalScan
description: Scan and fail on new High/Critical findings
inputs:
  target_url: { required: true }
  api_key: { required: true }
  baseline_scan_id: { description: "Compare against this scan" }
  fail_on: { default: "high" }

runs:
  using: composite
  steps:
    - name: Start scan
      id: scan
      shell: bash
      run: |
        RESP=$(curl -sf -X POST "${{ inputs.api_base }}/scan/" \
          -H "X-API-Key: ${{ inputs.api_key }}" \
          -H "Content-Type: application/json" \
          -d '{"target_url":"${{ inputs.target_url }}"}')
        echo "scan_id=$(echo $RESP | jq -r .scan_id)" >> $GITHUB_OUTPUT
    - name: Evaluate results
      shell: bash
      run: python3 ${{ github.action_path }}/poll_and_fail.py \
        --scan-id "${{ steps.scan.outputs.scan_id }}" \
        --fail-on "${{ inputs.fail_on }}" \
        --baseline "${{ inputs.baseline_scan_id }}"
```

### 6.5 AI-Powered PDF Reports

Executive-ready PDF with per-finding code fixes, CVSS 3.1 vectors, and compliance mapping (OWASP, PCI DSS, SOC 2). Built with Jinja2 + WeasyPrint. This is the premium tier anchor for commercial positioning.

---

## 7. Tech Stack Improvements

| Area | Current | Recommended | Rationale |
|---|---|---|---|
| Task execution | `run_in_executor` (thread) | Celery + Redis | Decouples HTTP from compute; horizontal worker scaling |
| HTML parsing (links) | BeautifulSoup | selectolax | 5-10× faster; C-backed Modest parser |
| State persistence | Python dict | Redis + Postgres | Survives restarts; enables scan history and diffing |
| Browser support | None | Playwright (opt-in) | SPA coverage; JS-rendered DOM |
| Logging | stdlib `logging` | structlog JSON | Bound context per scan; ELK/Datadog/CloudWatch ready |
| Python deps | `>=` unpinned | pip-compile + hashes | Reproducible builds; supply chain integrity |
| Auth (multi-user) | Single API key | fastapi-users JWT | Per-user scan ownership; team RBAC |
| PDF reports | None | Jinja2 + WeasyPrint | Executive-ready output; the premium tier anchor |
| ERD / DB schema | None | Alembic + asyncpg | Versioned migrations; async Postgres driver |
| Secrets management | `.env` file | Vault / AWS Secrets Manager | Rotation, audit trail, no secrets in process env |

---

## 8. Phased Upgrade Roadmap

### Phase 1 — Shipped (Foundation)

- ✅ API key authentication with entropy enforcement (32-char min)
- ✅ SSRF blocklist (RFC-1918, IPv6, metadata endpoints)
- ✅ UUID-keyed scan sessions via `ScanManager`
- ✅ Security middleware (Headers, Sanitization)

### Phase 2 — Shipped (Async Migration)

- ✅ `httpx.AsyncClient` native integration
- ✅ `asyncio.Queue` + Semaphore worker architecture
- ✅ `asyncio.gather` parallel plugin execution
- ✅ `asyncio.Lock` race condition protection
- ✅ `robots.txt` compliance
- ✅ Docker & Docker Compose orchestration

**Performance targets after Phase 2:**

| Metric | Before | Target |
|---|---|---|
| Crawl 50 pages, 5 workers | ~90s (sequential) | <20s (concurrent) |
| SQLi tests, 3 forms | ~27s (sequential) | <9s (concurrent) |
| Sensitive file probe (8 files) | ~12s (sequential) | <3s (concurrent) |
### Phase 3 — Shipped (UI/UX & Monitoring)
- ✅ Scan history sidebar for session persistence (in-process)
- ✅ Status notifications and toast system
- ✅ Recharts-powered severity distribution analytics
- ✅ JSON report export functionality
- ✅ v2.1.0 frontend version parity

### Phase 4 — Production Scaling (Next Target)
- Celery job queue — API returns `scan_id` in <50ms; worker picks up task
- `ScanLogHandler` → Redis pub/sub per scan channel (eliminates log race)
- Playwright crawler behind `use_browser: bool = False` flag
- AI triage via Anthropic API (5 concurrent requests via `asyncio.Semaphore`)
- Postgres for scan history + fingerprint-based diff engine
- GitHub Actions integration — comments new findings on PRs
- SSE endpoint for streaming partial results as each page completes
- `selectolax` for link extraction (replace BeautifulSoup in hot path)
- `structlog` JSON logging with bound `scan_id` context

### Phase 5 — Product Layer (Weeks 11–18, ~100 hrs)

- JWT multi-user auth via `fastapi-users`
- RBAC: owner / analyst / viewer roles per team
- AI-powered PDF reports (Jinja2 + WeasyPrint, per-finding code fix in detected language)
- Stripe billing with per-user scan quotas
- Kubernetes Helm chart with HPA for Celery workers
- OWASP / PCI DSS / SOC 2 compliance mapping on every finding
- VS Code extension for inline finding annotations
- Slack + email alerting on scan completion

---

## 9. Startup & Portfolio Positioning

### As a Portfolio Piece

The three changes with the highest signal-to-noise ratio for reviewers:

1. **Async migration with benchmarks** — put concrete numbers in the README: `crawl 50 pages: 90s → 18s`. Numbers beat claims.
2. **Self-attacking security section** — document what you found and fixed in your own tool. For security engineering roles, this demonstrates the mindset teams hire for.
3. **One-command setup** — `docker compose up` must work on a fresh machine. Reviewers who cannot run the project in 3 minutes close the tab.

### As a Startup Product

**Acquisition funnel:** GitHub Actions integration. Free scans for public repos; paid tier for private repos with AI remediation reports and compliance mapping.

**Premium anchor:** The AI-powered PDF report. Security consultants who currently spend 4-6 hours writing findings into Word documents will pay meaningfully for a generated first draft. The compliance mapping (OWASP → PCI DSS → SOC 2) saves additional hours per engagement.

**Pricing model:**
- Free: 5 scans/month, raw findings only
- Pro ($49/mo): Unlimited scans, AI triage, PDF reports, GitHub Actions
- Enterprise: SSO/SAML, audit logs, private Helm chart, SLA

**Competitive position:** Snyk and Socket focus on dependency and code scanning, not runtime web vulnerability detection. Playwright + AI triage + self-hosted open-core is the wedge into enterprises that cannot send target URLs to a SaaS.

### As a Research System

The scanner's output — URL patterns, form structures, response signatures, confirmed vulnerability types — is a labeled dataset for training a model that predicts vulnerability likelihood from static site structure alone, without sending any payloads. Publishing that dataset with the tool would be a novel contribution to automated security testing literature.

---

## Appendix: Critical Files to Change First

| File | Change | Priority | Status |
|---|---|---|---|
| `backend/app/services/scanner/crawler.py` | Migrate to `httpx.AsyncClient` + asyncio queue | P0 | ✅ |
| `backend/app/services/scanner/manager.py` | Add `asyncio.Lock` to `create_scan()` | P0 | ✅ |
| `backend/app/core/security.py` | Add 32-char minimum entropy check at startup | P0 | ✅ |
| `backend/app/services/scanner/engine.py` | Decompose `run()` into native async pipeline | P1 | ✅ |
| `backend/app/services/scanner/plugins/headers.py` | Deduplicate on header name, not URL | P1 | ✅ |
| `backend/app/services/scanner/crawler.py` | Implement `robots_parser` check | P1 | ✅ |
| `backend/requirements.txt` | Hard-pin dependencies | P1 | ✅ |
| `docker-compose.yml` | Create full-stack orchestration | P2 | ✅ |
| `backend/Dockerfile` | Create backend container | P2 | ✅ |
| `frontend/Dockerfile` | Create frontend container | P2 | ✅ |

---

*SentinalScan Architecture Analysis · For authorized security testing only*
