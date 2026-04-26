# SentinalScan — Complete Upgrade & Refactor

Comprehensive analysis of the entire SentinalScan project covering architecture, code quality, UI/UX, performance, and maintainability — with a full upgrade plan to fix every detected issue.

---

## Critical Issues Detected

> [!CAUTION]
> **3 show-stopper bugs** make the app non-functional end-to-end right now.

### 🔴 Bug 1: Results Table renders blank rows (CRITICAL)
[ResultsTable.jsx](file:///c:/Users/Home/Desktop/Projects/CyberSecurity_Projects/Automated_Web_Vulnerability_Scanner/SentinalScan/frontend/src/components/ResultsTable.jsx#L105) uses `r.vulnerability_type` and `r.details` — but the backend [Vulnerability model](file:///c:/Users/Home/Desktop/Projects/CyberSecurity_Projects/Automated_Web_Vulnerability_Scanner/SentinalScan/backend/app/models/vulnerability.py#L29-L30) serializes as `vuln_type` and `description`. Every scan renders empty cells.

### 🔴 Bug 2: vuln_gui.py crashes on scan start (CRITICAL)
[vuln_gui.py:374](file:///c:/Users/Home/Desktop/Projects/CyberSecurity_Projects/Automated_Web_Vulnerability_Scanner/SentinalScan/vuln_gui.py#L374) — `self.obey_ssl.get()` should be `self.obey_robots.get()`. Typo causes `AttributeError` crash.

### 🔴 Bug 3: ScanForm sends wrong field names (CRITICAL)
[components/ScanForm.jsx:29](file:///c:/Users/Home/Desktop/Projects/CyberSecurity_Projects/Automated_Web_Vulnerability_Scanner/SentinalScan/frontend/src/components/ScanForm.jsx#L29) sends `threads` but backend expects `workers`. Scan starts with wrong concurrency config.

---

## Full Issue Inventory

### Backend Issues

| # | Severity | File | Issue |
|---|----------|------|-------|
| B1 | 🔴 Critical | `vuln_gui.py:374` | `self.obey_ssl` → should be `self.obey_robots` |
| B2 | 🟠 High | `crawler.py` | Uses `requests` library; `httpx` is in requirements but unused |
| B3 | 🟠 High | `crawler.py:66` | SSRF check returns `True` on DNS failure — should block |
| B4 | 🟠 High | `security.py:8` | No null check — if `API_KEY` not set, `None == None` passes auth |
| B5 | 🟡 Medium | `config.py:16` | CORS allows `["*"]` — wildcard in production |
| B6 | 🟡 Medium | `manager.py` | Singleton via `__new__` — fragile, untestable |
| B7 | 🟡 Medium | `engine.py` | No vulnerability deduplication |
| B8 | 🟡 Medium | `engine.py` | Sequential page testing (no concurrency) |
| B9 | 🟡 Medium | Root | Stale `.bak` files (`api.py.bak`, `vuln_scanner.py.bak`) |
| B10 | 🟢 Low | `requirements.txt` | `requests` listed but should be replaced by `httpx` |
| B11 | 🟢 Low | Various | Missing `__init__.py` in plugins, endpoints, api/v1 |
| B12 | 🟢 Low | `logging.py:10` | `datetime.utcnow()` deprecated in Python 3.12+ |

### Frontend Issues

| # | Severity | File | Issue |
|---|----------|------|-------|
| F1 | 🔴 Critical | `ResultsTable.jsx:105` | `r.vulnerability_type` → should be `r.vuln_type` |
| F2 | 🔴 Critical | `ResultsTable.jsx:119` | `r.details` → should be `r.description` |
| F3 | 🔴 Critical | `components/ScanForm.jsx:29` | Sends `threads` instead of `workers` |
| F4 | 🟠 High | `scan.hooks.js:10` | `query.state?.status` checks query status not scan status; should be `query.state.data?.status` |
| F5 | 🟠 High | `LogViewer.jsx:54` | Shows `new Date()` (current time) instead of `log.timestamp` |
| F6 | 🟡 Medium | `src/App.css` | Vite boilerplate CSS — dead file, never imported |
| F7 | 🟡 Medium | `components/ScanForm.jsx` | Duplicate of `features/scan/ScanForm.jsx` — only features version is used |
| F8 | 🟡 Medium | `components/ResultsTable.jsx` | Unused component — `FindingsTable.jsx` is the active one |
| F9 | 🟡 Medium | `websocket.js` | Defined but never used anywhere in the app |
| F10 | 🟡 Medium | `features/scan/ScanForm.jsx` | Missing `workers` and `timeout` fields in payload |
| F11 | 🟢 Low | `StatsCard.jsx:25` | Fake percentage `(value * 0.1)` — misleading metric |
| F12 | 🟢 Low | `SeverityBadge.jsx` | Groups CRITICAL + HIGH together — should differentiate |

### Architecture Issues

| # | Severity | Issue |
|---|----------|-------|
| A1 | 🟠 High | No WebSocket endpoint on backend — frontend has WS code but nothing to connect to |
| A2 | 🟡 Medium | `vuln_gui.py` imports from `backend.vuln_scanner` which doesn't exist (only `.bak`) |
| A3 | 🟡 Medium | Empty `reports/` directory with no report generation in the web API |
| A4 | 🟡 Medium | No `__init__.py` in several packages causing import issues |

---

## Proposed Changes

### Phase 1: Backend Fixes & Hardening

#### [MODIFY] [security.py](file:///c:/Users/Home/Desktop/Projects/CyberSecurity_Projects/Automated_Web_Vulnerability_Scanner/SentinalScan/backend/app/core/security.py)
- Add null check for API_KEY — prevent `None == None` auth bypass
- Return 401 for missing key, 403 for wrong key

#### [MODIFY] [config.py](file:///c:/Users/Home/Desktop/Projects/CyberSecurity_Projects/Automated_Web_Vulnerability_Scanner/SentinalScan/backend/app/core/config.py)
- Restrict default CORS to localhost origins only
- Use `datetime.now(timezone.utc)` instead of deprecated `utcnow()`

#### [MODIFY] [crawler.py](file:///c:/Users/Home/Desktop/Projects/CyberSecurity_Projects/Automated_Web_Vulnerability_Scanner/SentinalScan/backend/app/services/scanner/crawler.py)
- Switch from `requests.Session` to `httpx.Client`
- Fix SSRF: block on DNS failure instead of allowing
- Add explicit blocked CIDR list for cloud metadata endpoints

#### [MODIFY] [engine.py](file:///c:/Users/Home/Desktop/Projects/CyberSecurity_Projects/Automated_Web_Vulnerability_Scanner/SentinalScan/backend/app/services/scanner/engine.py)
- Add vulnerability deduplication
- Add `try/finally` to always reset scan state
- Add more vulnerability check plugins (headers, sensitive files, CSRF)

#### [MODIFY] [manager.py](file:///c:/Users/Home/Desktop/Projects/CyberSecurity_Projects/Automated_Web_Vulnerability_Scanner/SentinalScan/backend/app/services/scanner/manager.py)
- Replace `__new__` singleton with module-level instance
- Add `try/finally` to `_run_scan` so status always gets set

#### [MODIFY] [base.py](file:///c:/Users/Home/Desktop/Projects/CyberSecurity_Projects/Automated_Web_Vulnerability_Scanner/SentinalScan/backend/app/services/scanner/plugins/base.py)
- Switch from `requests.Session` to `httpx.Client`

#### [MODIFY] [xss.py](file:///c:/Users/Home/Desktop/Projects/CyberSecurity_Projects/Automated_Web_Vulnerability_Scanner/SentinalScan/backend/app/services/scanner/plugins/xss.py)
- Update to use httpx client

#### [MODIFY] [sqli.py](file:///c:/Users/Home/Desktop/Projects/CyberSecurity_Projects/Automated_Web_Vulnerability_Scanner/SentinalScan/backend/app/services/scanner/plugins/sqli.py)
- Update to use httpx client

#### [NEW] headers.py, csrf.py, sensitive_files.py plugins
- Add missing security check plugins referenced in the roadmap

#### [MODIFY] [logging.py](file:///c:/Users/Home/Desktop/Projects/CyberSecurity_Projects/Automated_Web_Vulnerability_Scanner/SentinalScan/backend/app/core/logging.py)
- Fix deprecated `datetime.utcnow()`

#### [MODIFY] [main.py](file:///c:/Users/Home/Desktop/Projects/CyberSecurity_Projects/Automated_Web_Vulnerability_Scanner/SentinalScan/backend/app/main.py)
- Add WebSocket endpoint for real-time scan logs
- Add lifespan context manager

#### [MODIFY] [requirements.txt](file:///c:/Users/Home/Desktop/Projects/CyberSecurity_Projects/Automated_Web_Vulnerability_Scanner/SentinalScan/backend/requirements.txt)
- Remove `requests`, keep `httpx`
- Add `websockets` for WS support

#### [NEW] __init__.py files
- Add missing `__init__.py` in `api/v1/endpoints/`, `services/scanner/plugins/`

#### [MODIFY] [vuln_gui.py](file:///c:/Users/Home/Desktop/Projects/CyberSecurity_Projects/Automated_Web_Vulnerability_Scanner/SentinalScan/vuln_gui.py)
- Fix `self.obey_ssl` → `self.obey_robots` typo

#### [DELETE] Stale files
- `backend/api.py.bak`
- `backend/vuln_scanner.py.bak`

---

### Phase 2: Frontend Bug Fixes & Integration

#### [DELETE] Dead files
- `src/App.css` (Vite boilerplate, never imported)
- `src/components/ScanForm.jsx` (duplicate of features version)
- `src/components/ResultsTable.jsx` (duplicate of FindingsTable)
- `src/components/LogViewer.jsx` (duplicate of LiveLogs)
- `src/components/StatsCard.jsx` (not used by active App.jsx)
- `src/services/websocket.js` (unused standalone WS class)

#### [MODIFY] [FindingsTable.jsx](file:///c:/Users/Home/Desktop/Projects/CyberSecurity_Projects/Automated_Web_Vulnerability_Scanner/SentinalScan/frontend/src/features/findings/FindingsTable.jsx)
- Already uses correct field names (`vuln_type`, `description`) ✅
- Add confidence column and score display

#### [MODIFY] [SeverityBadge.jsx](file:///c:/Users/Home/Desktop/Projects/CyberSecurity_Projects/Automated_Web_Vulnerability_Scanner/SentinalScan/frontend/src/features/findings/SeverityBadge.jsx)
- Differentiate CRITICAL from HIGH with distinct styles

#### [MODIFY] [scan.hooks.js](file:///c:/Users/Home/Desktop/Projects/CyberSecurity_Projects/Automated_Web_Vulnerability_Scanner/SentinalScan/frontend/src/features/scan/scan.hooks.js)
- Fix `refetchInterval` — check `query.state.data?.status` not `query.state?.status`
- Enable results fetching during scan (live updates)

#### [MODIFY] [ScanForm.jsx (features)](file:///c:/Users/Home/Desktop/Projects/CyberSecurity_Projects/Automated_Web_Vulnerability_Scanner/SentinalScan/frontend/src/features/scan/ScanForm.jsx)
- Add missing `workers` and `timeout` fields to the payload
- Add input validation

#### [MODIFY] [LiveLogs.jsx](file:///c:/Users/Home/Desktop/Projects/CyberSecurity_Projects/Automated_Web_Vulnerability_Scanner/SentinalScan/frontend/src/features/scan-logs/LiveLogs.jsx)
- Already uses `log.timestamp` from backend ✅ — verify format

---

### Phase 3: UI/UX Enhancement

#### [MODIFY] [App.jsx](file:///c:/Users/Home/Desktop/Projects/CyberSecurity_Projects/Automated_Web_Vulnerability_Scanner/SentinalScan/frontend/src/app/App.jsx)
- Add footer with version info
- Improve responsive layout for mobile
- Add scan history sidebar
- Add status notifications/toasts

#### [MODIFY] [FindingsDashboard.jsx](file:///c:/Users/Home/Desktop/Projects/CyberSecurity_Projects/Automated_Web_Vulnerability_Scanner/SentinalScan/frontend/src/features/findings/FindingsDashboard.jsx)
- Add severity distribution chart (recharts is already a dependency)
- Better empty state with animated illustration
- Add export/download results button

#### [MODIFY] [index.css](file:///c:/Users/Home/Desktop/Projects/CyberSecurity_Projects/Automated_Web_Vulnerability_Scanner/SentinalScan/frontend/src/index.css)
- Add animation keyframes for `shine` effect referenced in ScanForm
- Add `animate-in` utility classes
- Polish scrollbar and glass effects

#### [MODIFY] [index.html](file:///c:/Users/Home/Desktop/Projects/CyberSecurity_Projects/Automated_Web_Vulnerability_Scanner/SentinalScan/frontend/index.html)
- Add meta description for SEO
- Add proper favicon

---

### Phase 4: Cleanup & Polish

#### [MODIFY] [README.md](file:///c:/Users/Home/Desktop/Projects/CyberSecurity_Projects/Automated_Web_Vulnerability_Scanner/SentinalScan/README.md)
- Update with accurate architecture, setup instructions, and screenshots

#### [MODIFY] [.gitignore](file:///c:/Users/Home/Desktop/Projects/CyberSecurity_Projects/Automated_Web_Vulnerability_Scanner/SentinalScan/.gitignore)
- Add `.env` files, `.bak` files, `__pycache__`

#### [NEW] [backend/.env.example](file:///c:/Users/Home/Desktop/Projects/CyberSecurity_Projects/Automated_Web_Vulnerability_Scanner/SentinalScan/backend/.env.example)
- Document all required env vars with safe defaults

#### [NEW] [frontend/.env.example](file:///c:/Users/Home/Desktop/Projects/CyberSecurity_Projects/Automated_Web_Vulnerability_Scanner/SentinalScan/frontend/.env.example)  
- Document frontend env vars

---

## Verification Plan

### Automated Tests
- Run existing `pytest backend/tests/` — verify all pass
- Run `npm run build` in frontend — verify zero errors
- Manual browser test of scan → results flow

### Manual Verification
- Start backend with `uvicorn app.main:app`
- Start frontend with `npm run dev`
- Execute a test scan and verify:
  - Results table shows correct field values
  - Logs stream in real-time
  - Scan can be stopped
  - Findings dashboard renders severity stats

---

> [!IMPORTANT]
> This is a large refactor touching **~30 files** across backend and frontend. I will execute in the phase order above, validating each phase before moving to the next. The critical bug fixes (Phase 1-2) take priority over UI polish (Phase 3-4).
