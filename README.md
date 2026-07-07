# GuardAPI - API Vulnerability Scanner Lite

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/sahananaikar104-coder/GuardAP)

GuardAPI is an enterprise-grade, lightweight, and zero-configuration API Security Scanner designed to audit REST endpoints against critical security weaknesses. It is particularly optimized for compliance checks inspired by the **OWASP API Security Top 10 (2023)**.

Built with a high-performance **FastAPI** backend and a premium, responsive **Vanilla HTML5/CSS3/JS glassmorphism dashboard**, GuardAPI offers immediate security feedback with no database or build-system prerequisites.

---

## 🚀 Key Features & OWASP API Top 10 Mapping

GuardAPI scans and reports on major API security vulnerabilities:

1. **HTTPS & Transport Encryption Audit**
   - **OWASP Category**: *API5:2023 - Broken Function Level Authorization / Unencrypted Transport*
   - **Check**: Verifies target protocol (HTTPS vs HTTP).
   - **Impact**: Protects against credentials and authorization token exposure to Man-in-the-Middle (MITM) attacks.

2. **Security Headers Compliance Audit**
   - **OWASP Category**: *API8:2023 - Security Misconfiguration*
   - **Check**: Checks the presence of `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Strict-Transport-Security`, and `Referrer-Policy`.
   - **Impact**: Mitigates Cross-Site Scripting (XSS), Clickjacking, MIME-sniffing, and protocol downgrading.

3. **Predictable Resource Identifiers (IDOR Check)**
   - **OWASP Category**: *API1:2023 - Broken Object Level Authorization (IDOR)*
   - **Check**: Scans URL paths and query strings for sequential numeric IDs (e.g. `/api/users/12` vs UUIDs).
   - **Impact**: Prevents object iteration attacks where unauthorized users fetch resources by enumeration.

4. **Passive SQL Injection (SQLi) Probing**
   - **OWASP Category**: *API8:2023 - Security Misconfiguration / Injection*
   - **Check**: Safe injection testing using harmless inputs (`'`, `"`) to detect raw query concatenation through database syntax errors in the server response.
   - **Impact**: Flags vulnerabilities that could lead to unauthorized database access, leakage, or takeover.

5. **Rate-limiting & Unrestricted Resource Consumption Check**
   - **OWASP Category**: *API4:2023 - Unrestricted Resource Consumption*
   - **Check**: Simulates rapid concurrent requests (5-8 requests) to verify if throttling (HTTP 429 Too Many Requests) is configured.
   - **Impact**: Mitigates risk of Denial of Service (DoS) and API abuse.

---

## 🛠️ Technology Stack
- **Backend**: FastAPI (Python 3.8+), Uvicorn, HTTPX
- **Frontend**: Single-Page App (HTML5, Vanilla CSS with custom glassmorphism design tokens, Async JavaScript)
- **Deployment-Ready**: Render, Railway, Heroku configs pre-integrated.

---

## 💻 Local Setup & Installation

### Windows (Quick Start)
Simply double-click the `run.bat` file in the root directory. It will automate python virtual environment setup, install requirements, and run the server on:
`http://localhost:8000`

### Manual Setup (Multi-platform)
1. Clone the repository and navigate to the directory:
   ```bash
   cd API-Vulnerability-Scanner-Lite
   ```
2. Create and activate a Python virtual environment:
   ```bash
   python -m venv .venv
   # Windows:
   .venv\Scripts\activate
   # macOS/Linux:
   source .venv/bin/activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Run the FastAPI application:
   ```bash
   uvicorn main:app --host 127.0.0.1 --port 8000 --reload
   ```
5. Open your browser and go to `http://localhost:8000`.

---

## 🌐 Public Cloud Deployment Guide

GuardAPI is built to be deployed on cloud platforms for remote verification.

### Option 1: Render.com (Fastest Free Option)
Render detects `render.yaml` automatically and configures the environment.
1. Push this folder to a GitHub repository.
2. Sign in to [Render](https://render.com) and click **New +** -> **Blueprints**.
3. Connect your GitHub repository.
4. Render will auto-detect the configuration and deploy.
*Alternatively, create a **Web Service**, set the runtime to **Python**, the Build Command to `pip install -r requirements.txt`, and the Start Command to `uvicorn main:app --host 0.0.0.0 --port $PORT`.*

### Option 2: Railway.app / Heroku
Railway uses the root `Procfile` automatically.
1. Push this folder to GitHub.
2. Sign in to [Railway](https://railway.app), click **New Project** -> **Deploy from GitHub repo**.
3. Choose the repository and deploy.
