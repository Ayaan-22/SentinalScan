# SentinalScan Full Repository Audit

Audit date: 2026-06-24  
Auditor: Codex

## Current Architecture Summary

SentinalScan is a FastAPI backend and React/Vite frontend for authorized web vulnerability scanning. The backend exposes authenticated REST scan endpoints under `/api/v1`, an unauthenticated WebSocket log endpoint at `/ws/logs/{scan_id}`, and an in-memory `ScanManager` that launches asynchronous scanner tasks. The scanner uses an async `WebCrawler`, `httpx.AsyncClient`, BeautifulSoup parsing, and plugins for XSS, SQL injection, CSRF, security headers, and sensitive-file exposure.

The frontend is a Vite/React dashboard using TanStack Query for REST polling, Tailwind for styling, Framer Motion for animation, Recharts for charts, Axios for API calls, and Lucide icons. It provides scan configuration, history, findings, and log views.

## Backend Issues

- Version is inconsistent: FastAPI app and `/health` report `2.1.0`, while README advertises `2.2.0`.
- `ScanResponse.results` uses a mutable list default.
- API key comparison uses direct string comparison.
- Configuration still defines weak default API and secret keys.
- WebSocket log streaming accepts unauthenticated clients before validation.
- `ScanManager.stop_scan()` sets `STOPPED`, but `_run_scan()` can later overwrite status to `COMPLETED`.
- Background scan tasks are not tracked, so cancellation and cleanup are incomplete.
- Scanner only publishes findings at the end of `engine.run()`, so frontend "live findings" are not actually live.
- Middleware rewrites JSON responses while copying stale response headers, including potentially stale `content-length`.
- Crawler has no real stop flag or cancellation-aware loop.
- Crawler follows redirects automatically, so redirects to internal/private IPs can bypass pre-request SSRF checks.
- Crawler URL normalization is minimal and does not canonicalize fragments, default ports, or query ordering.
- Crawler response cache is unbounded for a scan.

## Frontend Issues

- `api.js` defaults to `dev_api_key_12345`; that key should not exist client-side.
- API key handling is build-time only; users need a local UI/session mechanism.
- Docker Compose sets `VITE_API_URL=http://localhost:8000`, missing `/api/v1`.
- `VITE_WS_URL` is not wired into the app.
- Live logs component uses REST polling through `useScanLogs` instead of the backend WebSocket.
- Start/stop mutations do not invalidate all scan history consistently.
- Scan start errors are logged to console but not shown clearly to users.
- `FindingsTable` uses array indexes as keys.
- Several controls use clickable `div`s instead of native controls.
- Advanced fields are cramped single-line inputs.
- UI has a good theme direction but lacks strong dashboard hierarchy, API key onboarding, robust empty/error states, filtering/export controls, and mobile sticky scan action.

## Security Issues

- Real `.env` files exist in the workspace. They are currently ignored and not tracked, but the examples use backend variable names that do not match the `SENTINAL_` prefix.
- Frontend environment variables are not documented as public after build.
- WebSocket logs can be streamed by guessing a `scan_id`.
- API key defaults and known weak values should be rejected centrally at startup.
- Redirect-based SSRF protection is incomplete.
- SQLi plugin includes a destructive-looking payload: `1; DROP TABLE test --`.
- Sensitive-file plugin may probe page-relative paths such as `/about/.env` instead of root-origin paths only.
- Security headers plugin checks presence but not weak or invalid values.

## Scanner Correctness Issues

- Sensitive-file plugin can create duplicates because it runs for every crawled page.
- Sensitive-file false-positive detection misses SPA index fallbacks, login pages, redirects, and JSON 404 patterns.
- HSTS should only be required for HTTPS targets.
- `X-XSS-Protection` is legacy/deprecated and should not be treated as a major modern security fix.
- Crawler should validate hostname/IP before every request and every redirect hop.
- Crawler should reject unsupported schemes, private/loopback/link-local/metadata/CGNAT targets, and DNS failures.
- Crawler should preserve same-origin scope, respect exclude paths, skip static files, and dedupe fragments consistently.

## UI/UX Issues

- Header lacks a high-signal operational summary: target, risk score, pages scanned, findings count.
- Scan form lacks an explicit authorization checkbox.
- Advanced configuration fields need multiline headers/cookies, exclude path chips, and auth-token reveal.
- Live logs need WebSocket status, pause/resume auto-scroll, search, filters, copy/download/clear actions, and duplicate suppression.
- Findings need severity/risk cards, affected URL count, JSON/CSV export, filtering, sorting, and richer expandable details.
- Scan history should refresh immediately on start/stop/completion and show clearer statuses.
- Accessibility can be improved with native buttons/checkboxes, focus states, labels, ARIA labels, and reduced-motion handling.

## Docker/Env Issues

- `docker-compose.yml` frontend build does not pass Vite build args.
- `VITE_API_URL` in Compose is missing `/api/v1`.
- `VITE_WS_URL` is missing from Compose.
- Frontend Docker image builds static assets, so Vite env must be supplied at build time or documented via `.env.production`.
- Backend `.env.example` uses unprefixed names even though `SettingsConfigDict(env_prefix="SENTINAL_")` is configured.

## Test Coverage Gaps

- Config/env example naming and config loading.
- API key missing/wrong/correct behavior and constant-time helper.
- WebSocket auth required and WebSocket streaming.
- Stop lifecycle and task cleanup.
- Partial result availability while a scan is running.
- SSRF private target and redirect blocking.
- Sensitive-file true positive and false-positive filtering.
- Security-header value validation.
- Middleware redaction and correct `content-length`.
- Crawler canonicalization, exclude paths, same-origin filtering, static-file filtering, max pages, and stop behavior.

## Prioritized Fix Plan

### P0

- Align version to `2.2.0` across backend, frontend, tests, README, and user agent.
- Fix env examples, document public frontend env variables, and verify real env files are ignored/untracked.
- Replace API key comparison with `secrets.compare_digest()` and centralize weak/default key rejection.
- Authenticate WebSocket log endpoint.
- Track background tasks, support cancellation, add crawler stop flag, and prevent stopped scans from becoming completed.
- Disable automatic redirects and manually validate each redirect target for SSRF.
- Remove destructive SQLi payload.
- Fix middleware `content-length` handling.
- Add core backend tests for auth, WebSocket auth, lifecycle, SSRF, middleware, and plugin correctness.

### P1

- Add incremental finding callback so results update while scans run.
- Root-origin dedupe sensitive-file probes and improve false-positive heuristics.
- Validate security header values, HTTPS-only HSTS, weak CSP, acceptable referrer policies, and legacy X-XSS treatment.
- Improve URL canonicalization, same-origin checks, exclude paths, cache caps, and response size limits.
- Implement real WebSocket log hook with REST fallback and connection status.
- Add API key entry UI with session-only storage by default.
- Improve scan form, history refresh, error display, and findings filters/export.

### P2

- Polish dashboard layout, responsive behavior, accessibility details, reduced-motion handling, and reusable UI components.
- Update README and Docker setup for build-time Vite env.
- Run backend compile/tests, frontend lint/build, and document any remaining limitations.

## Remediation Completed

- Centralized application version at `2.2.0` and aligned backend health, FastAPI metadata, tests, frontend display, user agent, and README.
- Updated backend and frontend env examples. Backend examples now use `SENTINAL_` names; frontend examples explain that `VITE_*` values are public.
- Confirmed real `backend/.env` and `frontend/.env` are ignored and not tracked by git.
- Removed frontend default API key and added session-only API-key entry in the UI.
- Replaced direct API-key comparison with `secrets.compare_digest()` and centralized startup validation for missing/default/short keys.
- Authenticated WebSocket log streaming with an API key query parameter and unknown-scan closure.
- Implemented frontend WebSocket log streaming with reconnection, REST fallback, duplicate suppression, status badge, filtering, copy/download/clear, and pauseable auto-scroll.
- Tracked scan background tasks, added cancellation-aware stop handling, preserved partial results, and prevented stopped scans from becoming completed.
- Added incremental finding callbacks so `/results` can return partial findings while scans run.
- Disabled automatic redirects in the crawler and added manual redirect validation before each hop.
- Added crawler stop support, URL canonicalization, default-port normalization, fragment removal, query ordering, response-size cap, and per-request safety validation.
- Removed destructive SQLi payload and documented safe read-only probes.
- Changed sensitive-file probing to once per origin/root and added false-positive filters for JSON 404s, login pages, SPA fallbacks, and weak content matches.
- Upgraded security-header checks to validate values, skip HSTS for HTTP, flag weak CSP/referrer policies, and treat X-XSS-Protection as legacy.
- Fixed JSON sanitization middleware to avoid stale `content-length`.
- Added/updated backend tests for auth, WebSocket auth, lifecycle stop, partial results, SSRF redirects, env examples, middleware, sensitive files, security headers, and crawler canonicalization.
- Upgraded frontend scan form, dashboard hierarchy, findings filters/export, scan history refresh behavior, and accessibility-minded controls.
- Updated Docker Compose and frontend Dockerfile so Vite receives `VITE_API_URL=http://localhost:8000/api/v1` and `VITE_WS_URL=ws://localhost:8000` at build time.

## Verification Results

- `python -m compileall -q app`: passed.
- `python -m pytest -q`: 25 passed, 5 httpx deprecation warnings from TestClient.
- `npm run lint` equivalent (`eslint .`): passed.
- `npm run build` equivalent (`vite build`): passed.
- `docker compose config`: passed.
- `docker compose build`: blocked because Docker Desktop's Linux engine is not running (`dockerDesktopLinuxEngine` pipe missing).
- `bandit -r backend/app/ -ll --skip B101`: passed.
- `ruff check backend/`: not locally runnable because the temporary Windows target install did not create the Ruff native binary; CI installs Ruff normally.
