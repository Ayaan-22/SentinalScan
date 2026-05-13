# Implementation Plan - SentinalScan Phase 4 & 5

This plan outlines the next major upgrades for SentinalScan, focusing on production scaling, persistence, and AI-driven security analysis, as identified in the recent architectural audits.

## User Review Required

> [!IMPORTANT]
> **Persistence Strategy**: We are introducing Redis for task management and Postgres for long-term scan history. This requires updating the `docker-compose.yml` to include these services.
> **AI Costs**: The AI Triage feature uses the Anthropic API. You will need an `ANTHROPIC_API_KEY` in your `.env` file.

## Proposed Changes

### [Component] Backend Infrastructure

#### [MODIFY] [docker-compose.yml](file:///c:/Users/Home/Desktop/Projects/CyberSecurity_Projects/Automated_Web_Vulnerability_Scanner/SentinalScan/docker-compose.yml)
- Add **Postgres** service for persistent scan results.
- Add **Redis** service for Celery broker and result backend.
- Define a **Worker** service to run the scanner engine asynchronously.

#### [MODIFY] [requirements.txt](file:///c:/Users/Home/Desktop/Projects/CyberSecurity_Projects/Automated_Web_Vulnerability_Scanner/SentinalScan/backend/requirements.txt)
- Add `celery`, `redis`, `sqlalchemy`, `alembic`, `asyncpg`.
- Add `anthropic` for AI triage.
- Add `playwright` for SPA crawling.

### [Component] Task Queue & Scaling (Phase 4)

#### [NEW] [worker.py](file:///c:/Users/Home/Desktop/Projects/CyberSecurity_Projects/Automated_Web_Vulnerability_Scanner/SentinalScan/backend/app/worker.py)
- Initialize Celery app.
- Define `run_scan_task` that wraps `ScannerEngine.run()`.

#### [MODIFY] [manager.py](file:///c:/Users/Home/Desktop/Projects/CyberSecurity_Projects/Automated_Web_Vulnerability_Scanner/SentinalScan/backend/app/services/scanner/manager.py)
- Update `create_scan` to dispatch to Celery instead of running in the main process.
- Implement scan status retrieval from Redis/Postgres.

### [Component] Persistence & History (Phase 4)

#### [NEW] [database.py](file:///c:/Users/Home/Desktop/Projects/CyberSecurity_Projects/Automated_Web_Vulnerability_Scanner/SentinalScan/backend/app/core/database.py)
- Setup SQLAlchemy async engine and sessionmaker.

#### [NEW] models/db.py
- Define `ScanTable` and `VulnerabilityTable` for Postgres.

### [Component] AI Triage (Phase 4)

#### [NEW] [ai_triage.py](file:///c:/Users/Home/Desktop/Projects/CyberSecurity_Projects/Automated_Web_Vulnerability_Scanner/SentinalScan/backend/app/services/ai_triage.py)
- Implement `TriageEngine` using Anthropic API to analyze vulnerabilities and provide remediation code fixes.

### [Component] SPA Crawling (Phase 5)

#### [NEW] [playwright_crawler.py](file:///c:/Users/Home/Desktop/Projects/CyberSecurity_Projects/Automated_Web_Vulnerability_Scanner/SentinalScan/backend/app/services/scanner/playwright_crawler.py)
- Implement a headless browser-based crawler to support React/SPA targets.

## Cleanup

#### [DELETE] Stale Audit Files
- [x] `vuln_gui.py` (Already removed)
- [MODIFY] `reports/audits/` - Consolidate historical audits into a single `ARCHIVE.md` if needed.

## Verification Plan

### Automated Tests
- Run `pytest` to ensure existing async logic still works with the new Celery dispatcher.
- Use `celery inspect` to verify workers are receiving tasks.

### Manual Verification
- Start the full stack with `docker compose up`.
- Trigger a scan via the frontend and monitor the Celery logs.
- Verify scan history persists after restarting the containers.
