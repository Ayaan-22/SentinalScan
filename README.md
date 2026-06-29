# SentinalScan

Automated web vulnerability scanner for authorized security testing.

![Version](https://img.shields.io/badge/version-2.2.0-blue)
![Python](https://img.shields.io/badge/python-3.12-blue)
![React](https://img.shields.io/badge/react-19-cyan)
![FastAPI](https://img.shields.io/badge/FastAPI-0.110.0-teal)

## Authorized Use Only

SentinalScan is intended only for systems you own or have explicit permission to test. It includes SSRF protections, bounded defaults, authentication, and non-destructive payloads, but operators are still responsible for scope, rate limits, and authorization.

## Features

- FastAPI backend with authenticated REST endpoints under `/api/v1`.
- Authenticated WebSocket log stream at `/ws/logs/{scan_id}`.
- Async crawler with same-origin scope, exclude paths, stop support, response-size limits, and redirect-aware SSRF checks.
- Private/internal RFC1918 targets are blocked by default and require explicit UI opt-in for authorized internal testing.
- Scanner plugins for reflected XSS, SQL injection, CSRF, security headers, and sensitive-file exposure.
- Live partial findings while a scan is running.
- React/Vite dashboard with session API-key entry, scan history, live logs, severity cards, charts, filters, and JSON/CSV export.
- Docker Compose setup for the backend and built frontend.

## Project Structure

```text
backend/app/          FastAPI app, config, middleware, scanner engine
backend/tests/        Pytest suite
frontend/src/         React app, scan UI, logs, findings dashboard
reports/audits/       Architecture and audit reports
docker-compose.yml    Full-stack local deployment
```

## Environment

Real `.env` files are ignored by git. Copy the examples and fill them locally.

Backend variables use the `SENTINAL_` prefix:

```bash
cd backend
cp .env.example .env
python -c "import secrets; print(secrets.token_hex(32))"
```

Set at least:

```env
SENTINAL_API_KEY=<64-char-random-hex>
SENTINAL_SECRET_KEY=<separate-64-char-random-hex>
SENTINAL_BACKEND_CORS_ORIGINS=["http://localhost:5173","http://localhost:3000","http://127.0.0.1:5173"]
```

Frontend variables are public after Vite builds the app. Do not treat `VITE_API_KEY` as a secret. The UI provides a session-only API key field backed by `sessionStorage`.

```bash
cd frontend
cp .env.example .env
```

Required frontend values:

```env
VITE_API_URL=http://localhost:8000/api/v1
VITE_WS_URL=ws://localhost:8000
```

## Docker Setup

Create `backend/.env` first, then run:

```bash
docker compose up --build
```

Open:

- Frontend: http://localhost:5173
- Backend health: http://localhost:8000/health
- API docs: http://localhost:8000/docs

The frontend Docker build receives these build args from `docker-compose.yml`:

```yaml
VITE_API_URL: http://localhost:8000/api/v1
VITE_WS_URL: ws://localhost:8000
```

Because Vite embeds these at build time, rebuild the frontend image after changing them.

## Local Backend

```bash
cd backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
python -c "import secrets; print(secrets.token_hex(32))"
uvicorn app.main:app --reload
```

Startup fails if `SENTINAL_API_KEY` is missing, shorter than 32 characters, or set to a known default such as `dev_api_key_12345` or `changeme_in_production`.

## Local Frontend

```bash
cd frontend
npm ci
copy .env.example .env
npm run dev
```

Open http://localhost:5173, paste the backend `SENTINAL_API_KEY` into the dashboard's Session API Key field, confirm authorization, and start a scan.

For authorized internal testing where DNS resolves to RFC1918 addresses such as `10.0.0.0/8`, `172.16.0.0/12`, or `192.168.0.0/16`, expand Advanced Configuration and enable **Allow private/internal target**. Loopback, link-local, CGNAT, reserved ranges, and cloud metadata-style addresses remain blocked.

## Testing

```bash
cd backend
python -m compileall -q app
python -m pytest -q

cd ../frontend
npm run lint
npm run build
```

## Live Logs

The frontend connects to:

```text
ws://localhost:8000/ws/logs/{scan_id}?api_key=<SENTINAL_API_KEY>
```

If the WebSocket cannot stay connected during an active scan, the UI falls back to authenticated REST polling of `/api/v1/scan/{scan_id}/logs`.

## Troubleshooting

- API key mismatch: REST returns `401` for missing keys and `403` for wrong keys. Paste the same value as `SENTINAL_API_KEY` into the frontend Session API Key field.
- Backend startup API key entropy error: generate a new key with `python -c "import secrets; print(secrets.token_hex(32))"` and set `SENTINAL_API_KEY`.
- CORS issue: include the frontend origin in `SENTINAL_BACKEND_CORS_ORIGINS`.
- Docker frontend calls `/scan/` instead of `/api/v1/scan/`: rebuild after confirming `VITE_API_URL=http://localhost:8000/api/v1`.
- WebSocket fails: confirm `VITE_WS_URL=ws://localhost:8000` and that the Session API Key is set.
- Target resolves to a blocked private IP: verify DNS with `nslookup <host>`. Enable **Allow private/internal target** only when you have explicit authorization for that internal system.

## Reports

- [Full Codex Audit](reports/audits/codex-full-audit.md)
- [Architecture Analysis](reports/audits/sentinalscan-architecture-analysis.md)
- [Implementation Guide](reports/audits/sentinalscan-implementation-guide.md)
