# SentinalScan frontend

React 19 and Vite security assessment workspace. The graphite and lime interface uses Manrope, JetBrains Mono, Lucide icons, and responsive CSS.

## Run locally

```powershell
npm ci
Copy-Item .env.example .env
npm run dev
```

Configure `VITE_API_URL` and `VITE_WS_URL` in `.env`. Open the local URL printed by Vite. Use **Connection settings** to enter the backend API key for the browser session. See the repository README for backend setup.

## Workspace

- **Overview:** assessment totals, page totals, selected-scan findings, highest reported severity, detector relationship map, severity distribution, recent assessment activity, and priority findings.
- **Findings:** severity and detection-module filters, full-text search, sorting, pagination, and expandable descriptions, affected URLs, confidence, scores, timestamps, evidence, and remediation.
- **Scan history:** searchable assessment archive with status filters and session selection.
- **Live console:** authenticated WebSocket stream with REST fallback, search, level filters, scroll control, copy, and text download.
- **Reports:** full selected-assessment JSON and CSV exports. JSON includes scan metadata and provenance; CSV includes every finding field and escapes spreadsheet formulas.
- **New scan:** target URL, crawl/concurrency/timeout limits, TLS and robots controls, authentication, custom headers, cookies, exclusions, internal-target opt-in, and explicit authorization.

**Explore demo** explicitly loads illustrative samples without launching a scan. Live mode is the default. Demo sessions and exports are labeled. The attack surface map groups finding indicators by the five supported detectors; it does not claim network topology or full coverage. Assessment activity shows findings per scan rather than an invented time series. Highest severity uses the scanner's reported score, not a calculated site risk score.

Use the assessment selector to change the session being reviewed. Counts in the overview distinguish selected-scan metrics from totals across available sessions. History is provided by the current backend process and is not durable historical storage.

Dialogs support Escape, keyboard focus containment, and focus restoration. Mobile navigation collapses to a drawer, and motion respects reduced-motion settings. `Ctrl/Cmd+K` focuses workspace search.

## Validate

```powershell
npm test
npm run lint
npm run build
```

The dependency-free Node tests cover safe finding links, report provenance, CSV formula escaping, multiline evidence, and demo consistency. Browser testing can use demo mode without a backend. Verify authenticated scan launch, stop, and live streaming against a configured backend and an authorized target.
