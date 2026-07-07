# GuardAPI: API Vulnerability Scanner

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110.0%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![Render Deployment](https://img.shields.io/badge/deployed-Render-brightgreen.svg)](https://guardap.onrender.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

GuardAPI is a lightweight security auditing tool designed to check REST API endpoints against common security vulnerabilities. The project focuses on key risk areas highlighted in the **OWASP API Security Top 10 (2023)**, providing passive analysis and non-intrusive checks for compliance and configuration audits.

---

## 1. Project Overview

This project was built to explore automated vulnerability detection and REST API security compliance. GuardAPI parses endpoint patterns, inspects HTTP response headers, performs basic rate-limiting checks, and searches for leakage in database errors. It provides developers with a local dashboard to evaluate the security configuration of their API endpoints.

---

## 2. Features

- **Transport Security Verification**: Confirms whether the target endpoint enforces HTTPS to prevent MitM exposure.
- **Security Headers Audit**: Verifies the presence and values of key security headers:
  - `Content-Security-Policy`
  - `X-Frame-Options`
  - `X-Content-Type-Options`
  - `Strict-Transport-Security` (HSTS)
  - `Referrer-Policy`
- **Predictable Resource Identifier (IDOR) Analysis**: Analyzes paths and query strings for sequential numeric IDs (e.g., `/api/v1/users/12` vs UUIDs) that are vulnerable to enumeration.
- **SQL Injection (SQLi) Error-Based Detection**: Safely injects control characters (`'`, `"`) into parameters to check if response bodies contain leakage or system error logs (SQLite, MySQL, PostgreSQL, Oracle).
- **Resource Consumption / Rate-Limiting Check**: Sends a concurrent request burst (5-8 requests) in a short window to determine if the endpoint responds with `429 Too Many Requests`.
- **Auditing Dashboard**: Interactive interface presenting real-time risk scores, vulnerability descriptions, OWASP categories, evidence logs, and remediation instructions.

---

## 3. Technology Stack

- **Backend**: FastAPI, Uvicorn, HTTPX
- **Frontend**: Single-page UI built with HTML5, CSS3 (using custom variables and modern layout), and Vanilla JavaScript
- **DevOps/Deployment**: Render (YAML blueprint-ready), Railway (Procfile-ready)

---

## 4. Project Structure

```text
API-Vulnerability-Scanner-Lite/
├── main.py              # FastAPI server, security scanner modules, and embedded HTML frontend
├── requirements.txt     # Python application dependencies
├── render.yaml          # Blueprint deployment specification for Render.com
├── Procfile             # Process manager runner config for Heroku/Railway
├── run.bat              # Script to automate local setup and launch on Windows
└── README.md            # Project documentation and specifications
```

---

## 5. Installation

### Prerequisites
- Python 3.8 or higher installed on your system.

### Steps
1. Clone the repository:
   ```bash
   git clone https://github.com/sahananaikar104-coder/GuardAP.git
   cd GuardAP
   ```

2. Create a virtual environment:
   ```bash
   python -m venv .venv
   ```

3. Activate the virtual environment:
   - **Windows (Command Prompt)**:
     ```cmd
     .venv\Scripts\activate.bat
     ```
   - **macOS / Linux**:
     ```bash
     source .venv/bin/activate
     ```

4. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

---

## 6. Running Locally

### Option A: Windows Quick Run
Double-click the `run.bat` file in the root directory. It will automate the environment setup, install dependencies, and start the local server.

### Option B: Command Line Run
From your activated terminal, start the server using Uvicorn:
```bash
uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```
Open your browser and navigate to `http://localhost:8000`.

---

## 7. Live Demo

The application is deployed and available for live verification at:
**[https://guardap.onrender.com](https://guardap.onrender.com)**

---

## 8. Example Scan

Below is a sample JSON result returned by the backend scan API:

```json
{
  "target_url": "https://httpbin.org/get",
  "scan_time": "2026-07-07 15:49:13",
  "response_time_seconds": 2.03,
  "risk_score": 74,
  "risk_level": "Medium",
  "vulnerabilities": [
    {
      "name": "Missing Security Header: Content-Security-Policy",
      "severity": "Medium",
      "owasp": "API8:2023 - Security Misconfiguration",
      "description": "Prevents Cross-Site Scripting (XSS) and injection attacks by restricting resources.",
      "evidence": "Response headers lack 'Content-Security-Policy' key.",
      "remediation": "Configure the web server or API routing framework to append 'Content-Security-Policy' with strict policies to responses."
    }
  ]
}
```

---

## 9. Future Improvements

- **Authentication Flows**: Support for custom login flows, OAuth2, and multi-step scans (e.g. testing authenticated API paths).
- **Expanded OWASP Mapping**: Implementation of passive checks for JWT configuration verification, CORS wildcard setups, and server version disclosures.
- **Reporting Engine**: Dynamic PDF generation containing remediation checklists and executive summaries.

---

## 10. License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
