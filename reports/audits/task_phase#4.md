# Task List - SentinalScan Phase 4

## Infrastructure & Dependencies
- [ ] Update `backend/requirements.txt` with Celery, Redis, SQLAlchemy, and Anthropic
- [ ] Update `docker-compose.yml` with Redis and Postgres services
- [ ] Add `ANTHROPIC_API_KEY` and `DATABASE_URL` to `.env.example`

## Scaling (Celery)
- [ ] Create `backend/app/worker.py` (Celery initialization)
- [ ] Refactor `backend/app/services/scanner/manager.py` to use Celery tasks
- [ ] Implement `ScanLogHandler` update for Redis pub/sub

## Persistence (Postgres)
- [ ] Create `backend/app/core/database.py` (SQLAlchemy setup)
- [ ] Create `backend/app/models/db.py` (Scan & Vuln schemas)
- [ ] Implement async save/load logic for scan results

## AI Triage
- [ ] Create `backend/app/services/ai_triage.py` (Anthropic integration)
- [ ] Add AI Triage step to the scan worker pipeline

## Cleanup
- [ ] Remove stale audit files or consolidate to `reports/ARCHIVE.md`
- [x] Remove `vuln_gui.py`
