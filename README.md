# 🛡️ SentinalScan - Advanced Web Vulnerability Scanner

> **Professional-Grade Automated Security Assessment Tool**  
> _Built with Python, FastAPI, and React_

![Version](https://img.shields.io/badge/version-2.0.0-blue)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![React](https://img.shields.io/badge/react-18-cyan)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-teal)

## 🚀 Overview

**SentinalScan** is a powerful, production-ready web vulnerability scanner designed for security professionals and developers. It automates the detection of common web vulnerabilities, providing real-time feedback and detailed reports.

The project features a modern **React-based Web Interface** with glassmorphism aesthetics, a robust **FastAPI Backend**, and a legacy CLI/GUI for quick scans.

## ✨ Key Features

- **🔍 Comprehensive Crawling**: Intelligent multi-threaded crawler with scope control and `robots.txt` compliance.
- **⚡ Real-Time Scanning**: View logs and findings instantly via WebSockets.
- **🖥️ Modern Dashboard**: Beautiful, dark-mode web interface for managing scans and visualizing data.
- **📊 Multiple Report Formats**: Export findings to **HTML**, **JSON**, and **Text**.

### Vulnerability Checks

SentinalScan actively tests for:

- **SQL Injection (SQLi)**: Error-based and Time-based detection.
- **Cross-Site Scripting (XSS)**: Reflected XSS payload testing.
- **Cross-Site Request Forgery (CSRF)**: Missing token detection on forms.
- **Security Headers**: Missing `HSTS`, `Content-Security-Policy`, `X-Content-Type-Options`.
- **Sensitive File Exposure**: Detection of `.env`, `.git`, backups, and config files.
- **Clickjacking**: Missing `X-Frame-Options` or CSP frame ancestors.
- **Cookie Security**: Missing `Secure` and `HttpOnly` flags.
- **Open Redirects** & **Path Traversal**.

---

## 🏗️ Architecture

The project is organized into a modular structure:

```
SentinalScan/
├── backend/               # Python Backend
│   ├── api.py             # FastAPI REST Server w/ WebSockets
│   └── vuln_scanner.py    # Core Scanning Logic & Engine
├── frontend/              # React Frontend
│   ├── src/               # Application Source
│   └── public/            # Static Assets
├── reports/               # Generated Scan Reports
└── vuln_gui.py            # Legacy Tkinter Interface
```

---

## 🛠️ Installation

### Prerequisites

- Python 3.9+
- Node.js 18+ & npm

### 1. Backend Setup

Navigate to the project root:

```bash
# Install Python dependencies
pip install -r backend/requirements.txt
```

### 2. Frontend Setup

Navigate to the frontend directory:

```bash
cd frontend

# Install Node modules
npm install
```

---

## 📖 Usage

### Option A: Modern Web Application (Recommended)

1.  **Start the Backend API**:

    ```bash
    # From project root
    python backend/api.py
    ```

    _Server runs at http://localhost:8000_

2.  **Start the Frontend**:

    ```bash
    # From frontend/ directory
    npm run dev
    ```

    _Client runs at http://localhost:5173_

3.  Open **http://localhost:5173** in your browser.
4.  Enter a Target URL and click **Start Scan**.

### Option B: Command Line Interface (CLI)

For quick, headless scans:

```bash
# Basic scan
python backend/vuln_scanner.py -u https://example.com

# Advanced usage
python backend/vuln_scanner.py -u https://example.com --max-pages 100 --workers 10 --no-verify-ssl
```

### Option C: Legacy GUI

To run the standalone desktop version (Tkinter):

```bash
python vuln_gui.py
```

---

## ⚙️ Configuration

You can customize scans via the UI or CLI arguments:

- **Max Pages**: Limit the crawl depth and breadth.
- **Concurrency**: Number of worker threads.
- **Delays**: Throttling requests to avoid WAF blocking.
- **Auth**: Bearer tokens and custom cookies support.

---

## ⚠️ Disclaimer

> **CRITICAL WARNING**:
> This tool is for **EDUCATIONAL PURPOSES** and **AUTHORIZED SECURITY TESTING ONLY**.
>
> 1.  **DO NOT** scan targets you do not own or have explicit written permission to test.
> 2.  The authors are not responsible for any damage or legal consequences caused by misuse of this tool.
> 3.  Always follow responsible disclosure guidelines.

---

**© 2025 SentinalScan Team**
