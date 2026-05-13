# 🛡️ SentinalScan - Advanced Web Vulnerability Scanner

> **Professional-Grade Automated Security Assessment Tool**
> _High-performance scanning with a native async engine and premium cyber aesthetics._

![Version](https://img.shields.io/badge/version-2.2.0-blue)
![Python](https://img.shields.io/badge/python-3.12-blue)
![React](https://img.shields.io/badge/react-19-cyan)
![FastAPI](https://img.shields.io/badge/FastAPI-0.110.0-teal)
![License](https://img.shields.io/badge/license-MIT-green)

---

## 🚀 Overview

**SentinalScan** is a high-performance, asynchronous web vulnerability scanner designed for security researchers and developers. It automates the detection of common vulnerabilities (XSS, SQLi, CSRF, etc.) while providing a premium, interactive experience via a modernized frontend.

### ⚡ The Async Migration

The core engine has been fully migrated from a synchronous thread-pooled model to a native **asyncio-driven pipeline**:

- **Crawl Phase**: Utilizes `httpx.AsyncClient` with an `asyncio.Queue` worker pattern for high-speed discovery.
- **Test Phase**: Employs `asyncio.gather` for parallel plugin execution per page.
- **Performance**: Benchmarked at **<20s for a 50-page crawl**, a 4.5x improvement over the legacy sequential implementation.

---

## ✨ Key Features

### 🎨 Premium Interface & UX

- **Cyber/Glassmorphism UI**: A stunning dark-mode aesthetic built with Tailwind CSS and Framer Motion.
- **Real-Time Log Stream**: A "Hacker Terminal" style log viewer powered by WebSockets, featuring auto-scroll and XSS-safe sanitization.
- **Interactive Dashboard**: Live stats, findings distribution charts (Recharts), and confidence scoring for every vulnerability.

### 🔍 Advanced Scanning Engine

- **Intelligent Crawler**: Respects `robots.txt` (configurable), handles recursive discovery, and maintains a strict scope based on the target domain.
- **Parallel Testing**: All vulnerability plugins run concurrently for every discovered page, maximizing bandwidth and minimizing scan time.
- **Vulnerability Deduplication**: Smart fingerprinting ensures that identical findings (e.g., missing headers across 50 pages) are consolidated into high-signal reports.

### 🛡️ Security & Hardening

- **SSRF Protection**: Production-grade blocklist for internal CIDRs (RFC-1918), IPv6 loopback, and cloud metadata endpoints.
- **API Key Entropy**: Mandatory 32+ character API key with automated startup validation.
- **Data Sanitization**: Automatic masking of PII (passwords, tokens, cookies) in logs and responses via `SensitiveDataSanitizer` middleware.
- **Defensive Headers**: Backend hardened with automatic `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, and `CSP` hints.

---

## 🛡️ Vulnerability Coverage

| Plugin | Vuln Type | Detection Logic |
| :--- | :--- | :--- |
| **Reflected XSS** | Client-Side | Injects payloads into forms/params and verifies execution/reflection in the DOM. |
| **SQL Injection** | Injection | Tests for error signatures (MySQL, PG, SQLite) and time-based sleep verification. |
| **Sensitive Files** | Information Leak | Probes for common exposures like `.env`, `.git`, `.bak`, and configuration backups. |
| **CSRF Check** | Broken Access Control | Analyzes state-changing forms for missing or weak anti-forgery token implementations. |
| **Security Headers** | Configuration | Audits `HSTS`, `Content-Security-Policy`, `Referrer-Policy`, and `CORS` settings. |

---

## 🏗️ Project Structure

```bash
SentinalScan/
├── backend/               # FastAPI Asynchronous Backend
│   ├── app/
│   │   ├── api/           # V1 Endpoints & Auth Logic
│   │   ├── core/          # Security, Config & Log Sanitizers
│   │   ├── middleware.py  # Security Headers & PII Redaction
│   │   ├── models/        # Pydantic v2 Schema Definitions
│   │   └── services/
│   │       └── scanner/
│   │           ├── crawler.py    # Async httpx crawler w/ SSRF protection
│   │           ├── engine.py     # Two-phase async orchestrator
│   │           ├── manager.py    # Session control & asyncio.Lock management
│   │           └── plugins/      # XSS, SQLi, CSRF, Headers, Sensitive Files
│   ├── Dockerfile         # Multi-stage production build
│   ├── .env.example       # Template for API_KEY & CORS settings
│   └── requirements.txt   # Hard-pinned async dependencies
├── frontend/              # React 19 / Vite Frontend
│   ├── src/
│   │   ├── app/           # UI Providers & Global Layout
│   │   ├── features/      # Modular Scan, Findings, & Log features
│   │   └── services/      # Axios API client with X-API-Key integration
│   ├── .env.example       # Frontend environment template
│   └── package.json       # Vite / Tailwind / Framer configuration
├── reports/
│   └── audits/            # Architectural & Security Audit Reports
├── docker-compose.yml     # Unified stack orchestration
└── task.md                # Development roadmap & phase tracking
```

---

## 🛠️ Installation & Setup

### Prerequisites

- **Python 3.12+**
- **Node.js 20+** & npm
- **Docker** (Recommended)

### Option A: Docker Deployment (Fastest)

```bash
# Clone the repository
git clone https://github.com/Ayaan-22/SentinalScan.git
cd SentinalScan

# Build and start the full stack
docker compose up --build
```

_Access the Dashboard at [http://localhost:5173](http://localhost:5173)_

### Option B: Local Setup (Development)

#### 1. Backend Setup

```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt

# Generate a high-entropy API key
python -c "import secrets; print(secrets.token_hex(32))"

# Create .env and paste your key
cp .env.example .env
```

#### 2. Frontend Setup

```bash
cd ../frontend
npm install

# Create .env and update VITE_API_KEY
cp .env.example .env
```

---

## 📖 Usage Guide

### 1. Start the Services

- **Backend**: `uvicorn app.main:app --reload` (Port 8000)
- **Frontend**: `npm run dev` (Port 5173)

### 2. Configure a Scan

- Navigate to the Dashboard.
- Enter your **API Key** in Advanced Configuration.
- Enter a **Target URL** (Note: Internal IPs are blocked by SSRF protection).
- Toggle **Obey Robots** if you want to respect the target's `robots.txt`.

### 3. Analyze Results

- Monitor **Live Logs** for real-time discovery events.
- Review **Security Findings** as they are discovered (live-updated).
- Use the **Distribution Chart** to triage by severity.

---

## 🧪 Testing & Validation

We maintain a rigorous testing suite using `pytest-asyncio`:

```bash
cd backend
pytest -v  # Runs SSRF, Plugin, and API security tests
```

---

## 📝 Engineering Reports

For detailed technical analysis, refer to our internal audits:

- [Architecture Analysis](reports/audits/sentinalscan-architecture-analysis.md)
- [Implementation Guide](reports/audits/sentinalscan-implementation-guide.md)

---

## ⚠️ Disclaimer

> [!CAUTION]
> **This tool is for AUTHORIZED SECURITY TESTING ONLY.**
>
> 1. **NEVER** scan a target without explicit written permission.
> 2. The developers assume **NO LIABILITY** for misuse or damage caused by this tool.
> 3. Use responsibly and follow ethical disclosure protocols.

---

### © 2026 SentinalScan | Automated Security Assessment
