# 🛡️ SentinalScan - Advanced Web Vulnerability Scanner

> **Professional-Grade Automated Security Assessment Tool**  
> _Built with Python, FastAPI, and React (Cyber Aesthetic)_

![Version](https://img.shields.io/badge/version-2.1.0-blue)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![React](https://img.shields.io/badge/react-19-cyan)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-teal)
![License](https://img.shields.io/badge/license-MIT-green)

---

## 🚀 Overview

**SentinalScan** is a high-performance, asynchronous web vulnerability scanner designed for security researchers and developers. It automates the detection of common vulnerabilities while providing a premium, interactive experience via a modernized frontend.

The project features a **Premium Cyber/Glassmorphism Interface** built with React, Tailwind CSS, and Framer Motion, offering real-time feedback through WebSocket streams.

---

## ✨ Key Features

- **🎨 Premium Cyber UI**: Dark-mode "Glassmorphism" aesthetic with neon accents, smooth Framer Motion animations, and responsive layout.
- **🔍 Intelligent Async Crawling**: High-speed discovery using `httpx` with configurable depth, breadth, and `robots.txt` compliance.
- **⚡ Real-Time WebSocket Logs**: Live "Hacker Terminal" style execution logs streamed directly from the scanner engine.
- **🛡️ Secure By Design**: API Key authentication, SSRF protection, and WAF-evasion delays.
- **📊 Detailed Analytics**: Animated statistics dashboard with severity-coded finding badges.
- **📝 Multiple Interfaces**:
  - **Modern Web Dashboard**: Full-featured React app.
  - **Standalone Legacy GUI**: Tkinter-based desktop tool for quick local scans.

### 🛡️ Vulnerability Coverage

SentinalScan actively detects:

- **Injection Attacks**: Error-based and Time-based SQL Injection (SQLi).
- **Client-Side Attacks**: Reflected Cross-Site Scripting (XSS).
- **Broken Access Control**: Sensitive file exposure (`.env`, `.git`, backups).
- **Session Security**: Missing CSRF tokens on sensitive forms.
- **Infrastructure Security**: Missing critical security headers (`HSTS`, `CSP`, `CORS`).

---

## 💻 Tech Stack

| Component | Technology |
| :--- | :--- |
| **Backend** | Python 3.11, FastAPI, Pydantic v2, Httpx |
| **Frontend** | React 19, Vite, Tailwind CSS, Framer Motion |
| **Messaging** | WebSockets (Real-time logs) |
| **Testing** | Pytest, Pytest-asyncio |

---

## 🏗️ Project Structure

```bash
SentinalScan/
├── backend/               # Python FastAPI Backend
│   ├── app/
│   │   ├── api/           # API Endpoints & Routes
│   │   ├── core/          # Security & Global Config
│   │   ├── models/        # Data Schemas (Pydantic)
│   │   └── services/      # Scanner Logic & Plugin System
│   ├── tests/             # Integration & Unit Tests
│   └── requirements.txt
├── frontend/              # React + Vite Frontend
│   ├── src/               # Application Source
│   │   ├── app/           # Layout & Global State
│   │   ├── features/      # Modular Domain Logic
│   │   └── services/      # API/WS Client Implementation
│   └── package.json
└── vuln_gui.py            # Legacy Desktop Interface
```

---

## 🛠️ Installation & Setup

### 1. Prerequisites

- **Python 3.11+**
- **Node.js 18+** & npm

### 2. Backend Setup

```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
```

_Edit `.env` to set your `API_KEY` and other configurations._

### 3. Frontend Setup

```bash
cd frontend
npm install
cp .env.example .env.local
```

---

## 📖 Usage Guide

### Running the Full Suite (Web)

1. **Start Backend**:

   ```bash
   cd backend
   uvicorn app.main:app --reload
   ```

   _API available at <http://localhost:8000>_

2. **Start Frontend**:

   ```bash
   cd frontend
   npm run dev
   ```

   _Client available at <http://localhost:5173>_

3. Access the dashboard at <http://localhost:5173>, enter your target, and hit **Initiate Active Scan**.

### Running Legacy Desktop GUI

```bash
python vuln_gui.py
```

---

## 🧪 Testing

We use `pytest` for backend testing. To run the suite:

```bash
cd backend
pytest
```

---

## ⚠️ Disclaimer

> [!CAUTION]
> **This tool is for AUTHORIZED SECURITY TESTING ONLY.**
>
> 1. **NEVER** scan a target without explicit written permission.
> 2. The developers assume **NO LIABILITY** for misuse or damage caused by this tool.
> 3. Use responsibly and follow ethical disclosure protocols.

---

### © 2026 SentinalScan | Modernizing Web Security
