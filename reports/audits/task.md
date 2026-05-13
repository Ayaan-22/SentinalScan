# SentinalScan Upgrade — Execution Task List

## Phase 1: Backend Hardening

- [x] Fix `backend/.env` — API_KEY set to 64 chars, entropy check passes
- [x] Create `backend/app/middleware.py` — SecurityHeadersMiddleware + SensitiveDataSanitizer + log sanitizer
- [x] Update `backend/app/main.py` — Register security middleware, restrict CORS methods/headers
- [x] Fix `.gitignore` — Removed potential binary corruption, cleaned structure

## Phase 2: Frontend Integration

- [x] Update `scan.hooks.js` — Live results fetching enabled (3s poll)
- [x] Update `ScanForm.jsx` — Added URL format validation feedback with visual error states
- [x] Update `FindingsDashboard.jsx` — Severity distribution chart with recharts implemented

## Phase 3: Async Migration & Production Hardening (Audit Recommendations)

- [x] Migrate `WebCrawler` to `httpx.AsyncClient` + `asyncio.Queue`
- [x] Implement `robots.txt` compliance checking
- [x] Refactor `ScannerEngine` to use parallel plugin execution with `asyncio.gather`
- [x] Convert all vulnerability plugins to `async def`
- [x] Implement `asyncio.Lock` in `ScanManager` (P0 race condition fix)
- [x] Add XSS sanitization to WebSocket log stream
- [x] Create `Dockerfile` (Backend/Frontend) and `docker-compose.yml`
- [x] Pin all backend dependencies in `requirements.txt`

## Phase 4: Future Features (Roadmap)

- [ ] Implement Redis-based task queue (Celery)
- [ ] Add Postgres persistence for scan history
- [ ] AI-Powered Remediation Triage via Anthropic API
- [ ] Playwright-backed crawler for SPAs
