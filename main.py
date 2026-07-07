import time
import re
import urllib.parse
import asyncio
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse

app = FastAPI(
    title="API Vulnerability Scanner Lite",
    description="A lightweight, zero-configuration API security scanner for OWASP API Top 10.",
    version="1.0.0"
)

# Enable CORS for local development flexibility
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory history for temporary storage
scan_history = []

class ScanRequest(BaseModel):
    url: str = Field(..., example="https://httpbin.org/get")
    headers: Optional[Dict[str, str]] = Field(default=None, example={"Authorization": "Bearer token123"})

# SQL Injection Error Patterns to check response body for DB leakage
SQL_ERROR_PATTERNS = [
    # SQLite
    r"sqlite3\.OperationalError",
    r"OperationalError: near",
    r"sqlite3\.DatabaseError",
    # MySQL
    r"SQL syntax; check the manual that corresponds to your MySQL",
    r"MySQLServerException",
    r"Operand should contain",
    # PostgreSQL
    r"PostgreSQL query failed",
    r"PSQLException",
    r"syntax error at or near",
    # Oracle
    r"ORA-00933",
    r"Oracle Database Exception",
    # General
    r"unclosed quotation mark after the character string",
    r"SQLState",
    r"database error",
    r"syntax error in SQL"
]

def analyze_headers(headers: httpx.Headers) -> List[Dict[str, Any]]:
    security_headers = {
        "Content-Security-Policy": {
            "desc": "Prevents Cross-Site Scripting (XSS) and injection attacks by restricting resources.",
            "severity": "Medium",
            "deduct": 8,
            "owasp": "API8:2023 - Security Misconfiguration"
        },
        "X-Frame-Options": {
            "desc": "Prevents clickjacking attacks by controlling whether the site can be embedded in an iframe.",
            "severity": "Low",
            "deduct": 4,
            "owasp": "API8:2023 - Security Misconfiguration"
        },
        "X-Content-Type-Options": {
            "desc": "Prevents browsers from MIME-sniffing a response away from the declared content-type.",
            "severity": "Low",
            "deduct": 4,
            "owasp": "API8:2023 - Security Misconfiguration"
        },
        "Strict-Transport-Security": {
            "desc": "Enforces HTTPS connections, protecting against protocol downgrade attacks.",
            "severity": "Medium",
            "deduct": 8,
            "owasp": "API8:2023 - Security Misconfiguration"
        },
        "Referrer-Policy": {
            "desc": "Controls how much referrer information is sent along with requests.",
            "severity": "Low",
            "deduct": 2,
            "owasp": "API8:2023 - Security Misconfiguration"
        }
    }
    
    results = []
    for header, meta in security_headers.items():
        val = headers.get(header)
        if val:
            results.append({
                "header": header,
                "status": "Found",
                "value": val,
                "description": meta["desc"],
                "deduct": 0
            })
        else:
            results.append({
                "header": header,
                "status": "Missing",
                "value": None,
                "description": meta["desc"],
                "deduct": meta["deduct"],
                "severity": meta["severity"],
                "owasp": meta["owasp"]
            })
    return results

def check_idor_patterns(url: str) -> Optional[Dict[str, Any]]:
    # Look for sequential numeric resource identifiers in path or query
    # e.g., /api/users/123 or ?id=45
    parsed = urllib.parse.urlparse(url)
    path_segments = parsed.path.split("/")
    query_params = urllib.parse.parse_qs(parsed.query)
    
    numeric_ids = []
    
    for segment in path_segments:
        if segment.isdigit() and len(segment) < 6: # short sequential IDs
            numeric_ids.append(f"Path segment: '{segment}'")
            
    for param, values in query_params.items():
        for val in values:
            if val.isdigit() and len(val) < 6:
                numeric_ids.append(f"Query parameter '{param}': '{val}'")
                
    if numeric_ids:
        return {
            "name": "Predictable Resource Identifiers (Potential IDOR)",
            "severity": "Medium",
            "owasp": "API1:2023 - Broken Object Level Authorization",
            "description": "The API endpoint uses predictable integer identifiers in the path or query parameters. Attackers can iterate through sequential IDs to access unauthorized resources if proper object-level authorization is missing.",
            "evidence": f"Identified numeric IDs: {', '.join(numeric_ids)}. Predictable IDs are highly susceptible to IDOR.",
            "remediation": "Replace sequential integer IDs with cryptographically secure UUIDs (v4) or Hashids, and enforce fine-grained object-level authorization on the backend."
        }
    return None

async def check_sqli_vulnerability(client: httpx.AsyncClient, base_url: str, custom_headers: Optional[Dict[str, str]]) -> Optional[Dict[str, Any]]:
    # Attempt to inject a single quote or double quote to check for SQL errors in responses
    parsed = urllib.parse.urlparse(base_url)
    query_params = urllib.parse.parse_qs(parsed.query)
    
    if not query_params:
        # If no query parameters, append a dummy query parameter to test SQLi on query parsing
        test_url = base_url + ("?" if not parsed.query else "&") + "id=1'"
    else:
        # Append single quote to existing parameters
        new_params = {}
        for k, v in query_params.items():
            new_params[k] = [val + "'" for val in v]
        # Reconstruct url
        query_str = urllib.parse.urlencode(new_params, doseq=True)
        test_url = urllib.parse.urlunparse((
            parsed.scheme, parsed.netloc, parsed.path, parsed.params, query_str, parsed.fragment
        ))
        
    try:
        headers = {"User-Agent": "API Security Scanner Lite/1.0.0"}
        if custom_headers:
            headers.update(custom_headers)
            
        response = await client.get(test_url, headers=headers, timeout=4.0)
        
        # Scan body for database syntax errors
        body = response.text
        for pattern in SQL_ERROR_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                return {
                    "name": "SQL Injection (SQLi) Vulnerability Detected",
                    "severity": "Critical",
                    "owasp": "API8:2023 - Security Misconfiguration / Injection",
                    "description": "Probing query parameters with security test inputs triggered detailed database error messages in the HTTP response. This indicates raw query concatenation and lack of input sanitization.",
                    "evidence": f"Database error detected in response body: '{pattern}' on endpoint {test_url}",
                    "remediation": "Implement parameterized queries (prepared statements) using modern ORMs, validate and sanitize all inputs, and disable detailed backend error messages in production."
                }
    except Exception as e:
        # Connection issues or timeout can occur, do not block scan
        pass
    return None

async def check_rate_limiting(client: httpx.AsyncClient, target_url: str, custom_headers: Optional[Dict[str, str]]) -> Optional[Dict[str, Any]]:
    # Send a burst of requests to evaluate if rate limiting (HTTP 429) is enforced
    burst_count = 6
    tasks = []
    
    headers = {"User-Agent": "API Security Scanner Lite/1.0.0"}
    if custom_headers:
        headers.update(custom_headers)
        
    # Perform concurrent requests
    for _ in range(burst_count):
        tasks.append(client.get(target_url, headers=headers, timeout=3.0))
        
    try:
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        status_codes = []
        for r in results:
            if isinstance(r, httpx.Response):
                status_codes.append(r.status_code)
                
        # If any request was rate limited with 429
        if 429 in status_codes:
            return None # Rate limit exists and is working
            
        # If all requests succeeded with 200 or 2xx without throttling
        ok_count = sum(1 for code in status_codes if 200 <= code < 300)
        if ok_count == burst_count:
            return {
                "name": "Unrestricted Resource Consumption (Missing Rate Limiting)",
                "severity": "Medium",
                "owasp": "API4:2023 - Unrestricted Resource Consumption",
                "description": "The API accepted multiple rapid requests in a short time frame without throttling or returning HTTP 429. This leaves the API vulnerable to Denial of Service (DoS) and brute force attacks.",
                "evidence": f"Successfully performed {burst_count} concurrent requests with 2xx status codes and no throttling.",
                "remediation": "Implement rate limiting using token bucket or leaky bucket algorithms (e.g., via API Gateways, NGINX, or middleware like FastAPI's slowapi) set to reasonable requests-per-minute limits."
            }
    except Exception:
        pass
    return None

@app.post("/api/scan")
async def perform_scan(request: ScanRequest):
    target = request.url.strip()
    if not (target.startswith("http://") or target.startswith("https://")):
        target = "https://" + target
        
    parsed_url = urllib.parse.urlparse(target)
    if not parsed_url.netloc:
        raise HTTPException(status_code=400, detail="Invalid URL format. Provide a valid web hostname.")
        
    start_time = time.time()
    
    vulnerabilities = []
    risk_score = 100
    
    # 1. HTTPS Check
    is_https = parsed_url.scheme.lower() == "https"
    if not is_https:
        risk_score -= 25
        vulnerabilities.append({
            "name": "Insecure HTTP Protocol",
            "severity": "High",
            "owasp": "API5:2023 - Broken Function Level Authorization / Transport Security",
            "description": "The API uses HTTP rather than HTTPS. Communications are unencrypted, leaving credentials and sensitive data vulnerable to eavesdropping and Man-in-the-Middle (MITM) attacks.",
            "evidence": f"URL scheme resolved to: '{parsed_url.scheme}'",
            "remediation": "Enforce TLS (HTTPS) across all endpoints, redirect HTTP traffic to HTTPS, and configure HSTS headers."
        })
        
    # Execute network tests inside AsyncClient
    async with httpx.AsyncClient(verify=False) as client:
        # Check target availability and fetch headers
        headers = {"User-Agent": "API Security Scanner Lite/1.0.0"}
        if request.headers:
            headers.update(request.headers)
            
        try:
            response = await client.get(target, headers=headers, timeout=5.0)
            target_headers = response.headers
            response_time = round(time.time() - start_time, 3)
        except Exception as e:
            # If server connection fails
            raise HTTPException(status_code=502, detail=f"Failed to connect to the target API host: {str(e)}")
            
        # 2. Header analysis
        header_results = analyze_headers(target_headers)
        for h in header_results:
            if h["status"] == "Missing":
                risk_score -= h["deduct"]
                vulnerabilities.append({
                    "name": f"Missing Security Header: {h['header']}",
                    "severity": h["severity"],
                    "owasp": h["owasp"],
                    "description": h["description"],
                    "evidence": f"Response headers lack '{h['header']}' key.",
                    "remediation": f"Configure the web server or API routing framework to append '{h['header']}' with strict policies to responses."
                })
                
        # 3. SQL Injection check
        sqli_result = await check_sqli_vulnerability(client, target, request.headers)
        if sqli_result:
            risk_score -= 40
            vulnerabilities.append(sqli_result)
            
        # 4. IDOR check
        idor_result = check_idor_patterns(target)
        if idor_result:
            risk_score -= 15
            vulnerabilities.append(idor_result)
            
        # 5. Rate limiting check
        rate_result = await check_rate_limiting(client, target, request.headers)
        if rate_result:
            risk_score -= 15
            vulnerabilities.append(rate_result)

    # Ensure risk score is within [0, 100]
    risk_score = max(0, risk_score)
    
    # Calculate Risk Level
    if risk_score >= 85:
        risk_level = "Low"
    elif risk_score >= 55:
        risk_level = "Medium"
    else:
        risk_level = "High"
        
    report = {
        "target_url": target,
        "scan_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
        "response_time_seconds": response_time,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "vulnerabilities": vulnerabilities,
        "headers_inspected": [{
            "header": h["header"],
            "status": h["status"],
            "value": h["value"],
            "description": h["description"]
        } for h in header_results]
    }
    
    # Add to in-memory history (limit to 10 latest scans)
    scan_history.insert(0, {
        "url": target,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "scan_time": report["scan_time"],
        "vuln_count": len(vulnerabilities)
    })
    if len(scan_history) > 10:
        scan_history.pop()
        
    return report

@app.get("/api/history")
async def get_history():
    return scan_history

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    # Premium glassmorphism dashboard UI single file
    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GuardAPI - API Security Vulnerability Scanner</title>
    <!-- Google Fonts -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700;800&family=Plus+Jakarta+Sans:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-color: #0b0f19;
            --glass-bg: rgba(17, 24, 39, 0.6);
            --glass-border: rgba(255, 255, 255, 0.08);
            --glass-glow: rgba(59, 130, 246, 0.1);
            
            --primary: #3b82f6;
            --primary-glow: rgba(59, 130, 246, 0.4);
            --accent: #8b5cf6;
            --accent-glow: rgba(139, 92, 246, 0.4);
            
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: 'Plus Jakarta Sans', sans-serif;
            scrollbar-width: thin;
            scrollbar-color: var(--glass-border) transparent;
        }

        body {
            background-color: var(--bg-color);
            background-image: 
                radial-gradient(at 10% 20%, rgba(59, 130, 246, 0.15) 0px, transparent 50%),
                radial-gradient(at 90% 80%, rgba(139, 92, 246, 0.15) 0px, transparent 50%);
            background-attachment: fixed;
            color: var(--text-main);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            overflow-x: hidden;
        }

        /* Glassmorphism utility card */
        .glass-card {
            background: var(--glass-bg);
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
            border: 1px solid var(--glass-border);
            border-radius: 16px;
            box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }

        .glass-card:hover {
            border-color: rgba(255, 255, 255, 0.15);
            box-shadow: 0 12px 40px 0 rgba(0, 0, 0, 0.5);
        }

        header {
            width: 100%;
            padding: 20px 40px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--glass-border);
            background: rgba(11, 15, 25, 0.8);
            backdrop-filter: blur(8px);
            position: sticky;
            top: 0;
            z-index: 100;
        }

        .logo-container {
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .logo-icon {
            width: 40px;
            height: 40px;
            background: linear-gradient(135deg, var(--primary), var(--accent));
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            box-shadow: 0 0 15px var(--primary-glow);
            font-weight: 800;
            font-size: 1.2rem;
            color: white;
            font-family: 'Outfit', sans-serif;
        }

        .logo-text {
            font-family: 'Outfit', sans-serif;
            font-size: 1.5rem;
            font-weight: 700;
            background: linear-gradient(to right, #ffffff, #93c5fd);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .engine-badge {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 6px 14px;
            border-radius: 50px;
            background: rgba(16, 185, 129, 0.1);
            border: 1px solid rgba(16, 185, 129, 0.2);
            color: var(--success);
            font-size: 0.85rem;
            font-weight: 600;
        }

        .engine-dot {
            width: 8px;
            height: 8px;
            background-color: var(--success);
            border-radius: 50%;
            box-shadow: 0 0 10px var(--success);
            animation: pulse 1.8s infinite;
        }

        @keyframes pulse {
            0% { transform: scale(0.9); opacity: 0.7; }
            50% { transform: scale(1.2); opacity: 1; }
            100% { transform: scale(0.9); opacity: 0.7; }
        }

        main {
            flex: 1;
            max-width: 1400px;
            width: 100%;
            margin: 0 auto;
            padding: 30px 40px;
            display: grid;
            grid-template-columns: 320px 1fr;
            gap: 30px;
        }

        /* Sidebar styling */
        .sidebar {
            display: flex;
            flex-direction: column;
            gap: 25px;
        }

        .sidebar-title {
            font-size: 1rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--text-muted);
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .history-list {
            display: flex;
            flex-direction: column;
            gap: 12px;
            max-height: 400px;
            overflow-y: auto;
            padding-right: 5px;
        }

        .history-item {
            padding: 14px;
            border-radius: 12px;
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid rgba(255, 255, 255, 0.04);
            cursor: pointer;
            transition: all 0.2s ease;
        }

        .history-item:hover {
            background: rgba(255, 255, 255, 0.05);
            border-color: rgba(255, 255, 255, 0.1);
            transform: translateX(4px);
        }

        .history-item-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 6px;
        }

        .history-url {
            font-size: 0.85rem;
            font-weight: 600;
            color: #ffffff;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            max-width: 180px;
        }

        .history-time {
            font-size: 0.75rem;
            color: var(--text-muted);
        }

        .history-badges {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .score-pill {
            font-size: 0.75rem;
            font-weight: 700;
            padding: 3px 8px;
            border-radius: 6px;
        }

        .score-pill.low { background: rgba(16, 185, 129, 0.15); color: var(--success); }
        .score-pill.medium { background: rgba(245, 158, 11, 0.15); color: var(--warning); }
        .score-pill.high { background: rgba(239, 68, 68, 0.15); color: var(--danger); }

        /* Main panel styling */
        .workspace {
            display: flex;
            flex-direction: column;
            gap: 30px;
        }

        .search-panel {
            padding: 24px;
            display: flex;
            flex-direction: column;
            gap: 16px;
            position: relative;
            overflow: hidden;
        }

        .search-panel::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 4px;
            background: linear-gradient(to right, var(--primary), var(--accent));
        }

        .input-group {
            display: flex;
            gap: 12px;
        }

        .url-input {
            flex: 1;
            padding: 16px 20px;
            border-radius: 12px;
            border: 1px solid var(--glass-border);
            background: rgba(15, 23, 42, 0.6);
            color: #ffffff;
            font-size: 1rem;
            outline: none;
            transition: all 0.2s ease;
        }

        .url-input:focus {
            border-color: var(--primary);
            box-shadow: 0 0 10px rgba(59, 130, 246, 0.25);
        }

        .btn-scan {
            padding: 16px 32px;
            border-radius: 12px;
            border: none;
            background: linear-gradient(135deg, var(--primary), var(--accent));
            color: white;
            font-weight: 700;
            font-size: 1rem;
            cursor: pointer;
            box-shadow: 0 4px 15px rgba(59, 130, 246, 0.3);
            display: flex;
            align-items: center;
            gap: 8px;
            transition: all 0.2s ease;
        }

        .btn-scan:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(59, 130, 246, 0.45);
        }

        .btn-scan:active {
            transform: translateY(0);
        }

        .scanner-options-toggle {
            font-size: 0.85rem;
            color: var(--text-muted);
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            gap: 6px;
            align-self: flex-start;
        }

        .scanner-options-toggle:hover {
            color: #ffffff;
        }

        .scanner-options {
            display: none;
            padding: 14px;
            border-radius: 8px;
            background: rgba(0, 0, 0, 0.2);
            border: 1px solid var(--glass-border);
            margin-top: 5px;
        }

        .scanner-options.active {
            display: block;
        }

        .opt-row {
            display: flex;
            flex-direction: column;
            gap: 6px;
        }

        .opt-row label {
            font-size: 0.8rem;
            font-weight: 600;
            color: var(--text-muted);
        }

        .opt-row input {
            padding: 10px;
            border-radius: 6px;
            background: rgba(15, 23, 42, 0.8);
            border: 1px solid var(--glass-border);
            color: white;
            font-size: 0.85rem;
        }

        /* Scan Progress Loader */
        .scan-loader {
            display: none;
            padding: 40px;
            text-align: center;
            align-items: center;
            justify-content: center;
            flex-direction: column;
            gap: 20px;
        }

        .spinner {
            width: 60px;
            height: 60px;
            border: 4px solid rgba(59, 130, 246, 0.1);
            border-top-color: var(--primary);
            border-bottom-color: var(--accent);
            border-radius: 50%;
            animation: spin 1.2s linear infinite;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        .loader-log {
            font-size: 0.95rem;
            color: var(--text-muted);
            min-height: 24px;
            font-style: italic;
        }

        /* Results dashboard styling */
        .results-container {
            display: none;
            flex-direction: column;
            gap: 30px;
            animation: fadeIn 0.4s ease;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .overview-row {
            display: grid;
            grid-template-columns: 240px 1fr;
            gap: 30px;
        }

        /* Gauge score chart */
        .score-gauge-card {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 30px;
            position: relative;
        }

        .gauge-svg {
            width: 140px;
            height: 140px;
            transform: rotate(-90deg);
        }

        .gauge-track {
            fill: none;
            stroke: rgba(255, 255, 255, 0.05);
            stroke-width: 12;
        }

        .gauge-fill {
            fill: none;
            stroke: var(--primary);
            stroke-width: 12;
            stroke-dasharray: 400;
            stroke-dashoffset: 400;
            stroke-linecap: round;
            transition: stroke-dashoffset 1.5s cubic-bezier(0.4, 0, 0.2, 1);
        }

        .gauge-text {
            position: absolute;
            font-size: 2.2rem;
            font-weight: 800;
            font-family: 'Outfit', sans-serif;
            color: white;
            display: flex;
            flex-direction: column;
            align-items: center;
        }

        .gauge-subtext {
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--text-muted);
            margin-top: -2px;
            font-weight: 700;
        }

        .risk-rating-label {
            margin-top: 15px;
            font-size: 1.1rem;
            font-weight: 700;
        }

        /* Metrics boxes */
        .metrics-card {
            padding: 24px;
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 20px;
        }

        .metric-box {
            padding: 16px;
            border-radius: 12px;
            background: rgba(255, 255, 255, 0.015);
            border: 1px solid rgba(255, 255, 255, 0.03);
            text-align: center;
        }

        .metric-label {
            font-size: 0.8rem;
            color: var(--text-muted);
            font-weight: 600;
            margin-bottom: 8px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .metric-value {
            font-size: 1.6rem;
            font-weight: 700;
            color: #ffffff;
            font-family: 'Outfit', sans-serif;
        }

        /* Vulnerabilities details layout */
        .detail-section-title {
            font-family: 'Outfit', sans-serif;
            font-size: 1.25rem;
            font-weight: 700;
            margin-bottom: 18px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .export-btn {
            font-size: 0.85rem;
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid var(--glass-border);
            padding: 6px 16px;
            border-radius: 8px;
            cursor: pointer;
            color: white;
            display: flex;
            align-items: center;
            gap: 6px;
            transition: all 0.2s ease;
        }

        .export-btn:hover {
            background: rgba(255, 255, 255, 0.1);
        }

        .vuln-list {
            display: flex;
            flex-direction: column;
            gap: 16px;
        }

        .vuln-item {
            padding: 20px;
            border-left: 4px solid var(--primary);
        }

        .vuln-item.critical { border-left-color: var(--danger); }
        .vuln-item.high { border-left-color: var(--danger); }
        .vuln-item.medium { border-left-color: var(--warning); }
        .vuln-item.low { border-left-color: var(--primary); }

        .vuln-header-row {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 8px;
            cursor: pointer;
        }

        .vuln-title-group {
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .vuln-title {
            font-size: 1.05rem;
            font-weight: 700;
            color: white;
        }

        .vuln-badge {
            font-size: 0.75rem;
            font-weight: 700;
            padding: 3px 8px;
            border-radius: 6px;
            text-transform: uppercase;
        }

        .vuln-badge.critical { background: rgba(239, 68, 68, 0.15); color: var(--danger); }
        .vuln-badge.high { background: rgba(239, 68, 68, 0.15); color: var(--danger); }
        .vuln-badge.medium { background: rgba(245, 158, 11, 0.15); color: var(--warning); }
        .vuln-badge.low { background: rgba(59, 130, 246, 0.15); color: var(--primary); }

        .vuln-owasp {
            font-size: 0.75rem;
            color: var(--text-muted);
            background: rgba(255, 255, 255, 0.05);
            padding: 2px 8px;
            border-radius: 4px;
            font-weight: 600;
        }

        .vuln-expand-btn {
            font-size: 0.8rem;
            color: var(--text-muted);
            background: none;
            border: none;
            cursor: pointer;
        }

        .vuln-details {
            margin-top: 15px;
            padding-top: 15px;
            border-top: 1px solid rgba(255, 255, 255, 0.05);
            display: flex;
            flex-direction: column;
            gap: 12px;
        }

        .vuln-desc {
            font-size: 0.9rem;
            color: var(--text-main);
            line-height: 1.5;
        }

        .vuln-meta-item {
            font-size: 0.85rem;
            background: rgba(0, 0, 0, 0.2);
            padding: 12px;
            border-radius: 8px;
            border: 1px solid rgba(255, 255, 255, 0.03);
        }

        .vuln-meta-title {
            font-weight: 700;
            color: #ffffff;
            margin-bottom: 4px;
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .vuln-meta-content {
            font-family: monospace;
            color: var(--text-muted);
            word-break: break-all;
            white-space: pre-wrap;
        }

        .vuln-meta-content.rem {
            font-family: inherit;
            color: #d1d5db;
        }

        /* Headers checked styling */
        .headers-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }

        .headers-table th, .headers-table td {
            text-align: left;
            padding: 14px 16px;
            font-size: 0.85rem;
            border-bottom: 1px solid rgba(255, 255, 255, 0.04);
        }

        .headers-table th {
            font-weight: 700;
            color: var(--text-muted);
            text-transform: uppercase;
            font-size: 0.75rem;
            letter-spacing: 0.5px;
        }

        .headers-table td.hdr-name {
            font-weight: 700;
            color: white;
            font-family: monospace;
        }

        .headers-table td.hdr-val {
            font-family: monospace;
            color: var(--text-muted);
            max-width: 250px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }

        .hdr-status-badge {
            font-size: 0.75rem;
            font-weight: 700;
            padding: 3px 8px;
            border-radius: 6px;
            display: inline-block;
        }

        .hdr-status-badge.found { background: rgba(16, 185, 129, 0.15); color: var(--success); }
        .hdr-status-badge.missing { background: rgba(239, 68, 68, 0.15); color: var(--danger); }

        /* No Vulnerabilities Success Banner */
        .no-vulns-banner {
            padding: 40px;
            text-align: center;
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 15px;
        }

        .shield-icon {
            width: 64px;
            height: 64px;
            background: rgba(16, 185, 129, 0.1);
            border: 2px solid var(--success);
            color: var(--success);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 2rem;
            box-shadow: 0 0 20px rgba(16, 185, 129, 0.2);
        }

        /* Footer */
        footer {
            padding: 20px 40px;
            text-align: center;
            font-size: 0.8rem;
            color: var(--text-muted);
            border-top: 1px solid var(--glass-border);
            margin-top: auto;
            background: rgba(11, 15, 25, 0.9);
        }

        @media (max-width: 1024px) {
            main {
                grid-template-columns: 1fr;
            }
            .sidebar {
                order: 2;
            }
            .workspace {
                order: 1;
            }
        }
    </style>
</head>
<body>
    <header>
        <div class="logo-container">
            <div class="logo-icon">🛡️</div>
            <div class="logo-text">GuardAPI</div>
        </div>
        <div class="engine-badge">
            <div class="engine-dot"></div>
            <span>Scanner Engine: Online</span>
        </div>
    </header>

    <main>
        <!-- Sidebar containing History and Stats -->
        <div class="sidebar">
            <div class="glass-card" style="padding: 20px;">
                <div class="sidebar-title">
                    <span>📊 Scanner Statistics</span>
                </div>
                <div style="display: flex; flex-direction: column; gap: 12px; margin-top: 10px;">
                    <div style="display: flex; justify-content: space-between; font-size: 0.85rem;">
                        <span style="color: var(--text-muted);">Total Runs:</span>
                        <span id="stat-runs" style="font-weight: 700;">0</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; font-size: 0.85rem;">
                        <span style="color: var(--text-muted);">Avg. Risk Score:</span>
                        <span id="stat-avg" style="font-weight: 700; color: var(--success);">100/100</span>
                    </div>
                </div>
            </div>

            <div class="glass-card" style="padding: 20px; flex: 1;">
                <div class="sidebar-title">
                    <span>🕒 Scan History</span>
                </div>
                <div class="history-list" id="history-list">
                    <div style="color: var(--text-muted); font-size: 0.85rem; font-style: italic; text-align: center; margin-top: 20px;">
                        No scans recorded yet.
                    </div>
                </div>
            </div>
        </div>

        <!-- Main scanner workspace -->
        <div class="workspace">
            <!-- Search Panel -->
            <div class="glass-card search-panel">
                <h2 style="font-family: 'Outfit', sans-serif; font-size: 1.35rem; font-weight: 700; color: white;">Run Security Audit</h2>
                <p style="font-size: 0.85rem; color: var(--text-muted); margin-top: -8px;">
                    Input a target API endpoint or website URL to scan for OWASP API Top 10 vulnerabilities.
                </p>
                <div class="input-group">
                    <input type="text" class="url-input" id="target-url" placeholder="e.g. https://httpbin.org/get" value="https://httpbin.org/get">
                    <button class="btn-scan" id="btn-scan" onclick="startScan()">
                        <span>🚀</span> Start Scan
                    </button>
                </div>
                <div class="scanner-options-toggle" onclick="toggleOptions()">
                    <span>⚙️</span> Custom Request Headers (Optional)
                </div>
                <div class="scanner-options" id="scanner-options">
                    <div class="opt-row">
                        <label for="custom-auth">Authorization Header</label>
                        <input type="text" id="custom-auth" placeholder="e.g., Bearer eyJhbGciOi...">
                    </div>
                </div>
            </div>

            <!-- Loader status -->
            <div class="glass-card scan-loader" id="scan-loader">
                <div class="spinner"></div>
                <div style="font-family: 'Outfit', sans-serif; font-size: 1.25rem; font-weight: 700; color: white;">Audit In Progress</div>
                <div class="loader-log" id="loader-log">Initializing scanner agent...</div>
            </div>

            <!-- Results Report Panel -->
            <div class="results-container" id="results-panel">
                <div class="overview-row">
                    <!-- Gauge Card -->
                    <div class="glass-card score-gauge-card">
                        <svg class="gauge-svg">
                            <circle class="gauge-track" cx="70" cy="70" r="55"></circle>
                            <circle class="gauge-fill" id="gauge-fill" cx="70" cy="70" r="55"></circle>
                        </svg>
                        <div class="gauge-text">
                            <span id="gauge-value">100</span>
                            <span class="gauge-subtext">Score</span>
                        </div>
                        <div class="risk-rating-label" id="risk-rating-label">Low Risk</div>
                    </div>

                    <!-- Metrics summary -->
                    <div class="glass-card metrics-card">
                        <div class="metric-box">
                            <div class="metric-label">Vulnerabilities</div>
                            <div class="metric-value" id="metric-vulns" style="color: var(--danger);">0</div>
                        </div>
                        <div class="metric-box">
                            <div class="metric-label">Response Time</div>
                            <div class="metric-value" id="metric-resp">0.00s</div>
                        </div>
                        <div class="metric-box">
                            <div class="metric-label">Server Status</div>
                            <div class="metric-value" id="metric-status" style="color: var(--success);">ONLINE</div>
                        </div>
                    </div>
                </div>

                <!-- Vulnerabilities Found -->
                <div class="glass-card" style="padding: 24px;">
                    <div class="detail-section-title">
                        <span>⚠️ Vulnerability Details</span>
                        <button class="export-btn" onclick="window.print()">
                            <span>🖨️</span> Export PDF Report
                        </button>
                    </div>

                    <div class="vuln-list" id="vuln-list">
                        <!-- Dynamic list -->
                    </div>
                </div>

                <!-- Inspected Security Headers -->
                <div class="glass-card" style="padding: 24px; overflow-x: auto;">
                    <div class="detail-section-title">🛡️ Security Headers Audit</div>
                    <table class="headers-table">
                        <thead>
                            <tr>
                                <th>Header</th>
                                <th>Status</th>
                                <th>Value</th>
                                <th>Security Description</th>
                            </tr>
                        </thead>
                        <tbody id="headers-tbody">
                            <!-- Dynamic rows -->
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </main>

    <footer>
        GuardAPI - College Placement Eligibility Verification Demo - Local Host Instance
    </footer>

    <script>
        const logs = [
            "Resolving DNS for API host...",
            "Establishing TLS secure handshake...",
            "Analyzing response protocols and SSL configs...",
            "Checking HTTP security headers compliance...",
            "Probing endpoint parameters for IDOR vulnerabilities...",
            "Testing parameterized input with SQL Injection patterns...",
            "Initiating resource consumption / rate-limiting check...",
            "Compiling final risk scores and generating report..."
        ];

        function toggleOptions() {
            const opts = document.getElementById("scanner-options");
            opts.classList.toggle("active");
        }

        async function updateStatsAndHistory() {
            try {
                const response = await fetch("/api/history");
                const data = await response.json();
                
                const historyList = document.getElementById("history-list");
                if (data.length === 0) {
                    historyList.innerHTML = `<div style="color: var(--text-muted); font-size: 0.85rem; font-style: italic; text-align: center; margin-top: 20px;">No scans recorded yet.</div>`;
                    document.getElementById("stat-runs").textContent = "0";
                    document.getElementById("stat-avg").textContent = "100/100";
                    return;
                }
                
                document.getElementById("stat-runs").textContent = data.length;
                
                let sum = 0;
                data.forEach(item => sum += item.risk_score);
                const avg = Math.round(sum / data.length);
                const statAvg = document.getElementById("stat-avg");
                statAvg.textContent = `${avg}/100`;
                if (avg < 55) {
                    statAvg.style.color = "var(--danger)";
                } else if (avg < 85) {
                    statAvg.style.color = "var(--warning)";
                } else {
                    statAvg.style.color = "var(--success)";
                }
                
                historyList.innerHTML = "";
                data.forEach(item => {
                    const lowUrl = item.url.replace(/^https?:\/\//i, '');
                    const badgeClass = item.risk_level.toLowerCase();
                    historyList.innerHTML += `
                        <div class="history-item" onclick="document.getElementById('target-url').value='${item.url}'; startScan();">
                            <div class="history-item-header">
                                <div class="history-url" title="${item.url}">${lowUrl}</div>
                                <div class="history-time">${item.scan_time.split(' ')[1]}</div>
                            </div>
                            <div class="history-badges">
                                <span class="score-pill ${badgeClass}">Score: ${item.risk_score}</span>
                                <span style="font-size: 0.75rem; color: var(--text-muted);">${item.vuln_count} vulns</span>
                            </div>
                        </div>
                    `;
                });
            } catch (e) {
                console.error("Failed to load history stats", e);
            }
        }

        async function startScan() {
            const urlInput = document.getElementById("target-url").value.trim();
            if (!urlInput) {
                alert("Please enter a valid target URL.");
                return;
            }

            const btnScan = document.getElementById("btn-scan");
            const loader = document.getElementById("scan-loader");
            const resultsPanel = document.getElementById("results-panel");
            const logText = document.getElementById("loader-log");

            btnScan.disabled = true;
            resultsPanel.style.display = "none";
            loader.style.display = "flex";

            // Run artificial log ticker for better presentation
            let logIdx = 0;
            logText.textContent = logs[0];
            const interval = setInterval(() => {
                logIdx++;
                if (logIdx < logs.length) {
                    logText.textContent = logs[logIdx];
                }
            }, 500);

            const payload = { url: urlInput };
            const authHeader = document.getElementById("custom-auth").value.trim();
            if (authHeader) {
                payload.headers = { "Authorization": authHeader };
            }

            try {
                const response = await fetch("/api/scan", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(payload)
                });

                clearInterval(interval);

                if (!response.ok) {
                    const err = await response.json();
                    throw new Error(err.detail || "Scan request failed.");
                }

                const result = await response.json();
                displayResults(result);
            } catch (err) {
                clearInterval(interval);
                alert("Scan failed: " + err.message);
                loader.style.display = "none";
                btnScan.disabled = false;
            } finally {
                btnScan.disabled = false;
                updateStatsAndHistory();
            }
        }

        function displayResults(data) {
            document.getElementById("scan-loader").style.display = "none";
            const resultsPanel = document.getElementById("results-panel");
            resultsPanel.style.display = "flex";

            // Update Risk Score Gauge
            const score = data.risk_score;
            document.getElementById("gauge-value").textContent = score;
            
            const circle = document.getElementById("gauge-fill");
            const radius = circle.r.baseVal.value;
            const circumference = 2 * Math.PI * radius;
            circle.style.strokeDasharray = circumference;
            
            const offset = circumference - (score / 100) * circumference;
            circle.style.strokeDashoffset = offset;

            // Gauge Color matching score
            let color = "var(--success)";
            let rating = "Low Risk";
            if (score < 55) {
                color = "var(--danger)";
                rating = "High Risk";
            } else if (score < 85) {
                color = "var(--warning)";
                rating = "Medium Risk";
            }
            circle.style.stroke = color;
            const ratingLabel = document.getElementById("risk-rating-label");
            ratingLabel.textContent = rating;
            ratingLabel.style.color = color;

            // Metrics
            document.getElementById("metric-vulns").textContent = data.vulnerabilities.length;
            document.getElementById("metric-resp").textContent = data.response_time_seconds.toFixed(2) + "s";
            
            const totalVulns = data.vulnerabilities.length;
            const vulnValElement = document.getElementById("metric-vulns");
            if (totalVulns > 0) {
                vulnValElement.style.color = "var(--danger)";
            } else {
                vulnValElement.style.color = "var(--success)";
            }

            // Vulnerabilities list
            const vulnList = document.getElementById("vuln-list");
            vulnList.innerHTML = "";
            if (data.vulnerabilities.length === 0) {
                vulnList.innerHTML = `
                    <div class="no-vulns-banner">
                        <div class="shield-icon">🛡️</div>
                        <div style="font-size: 1.15rem; font-weight: 700; color: white;">Perfect Security Posture!</div>
                        <div style="font-size: 0.85rem; color: var(--text-muted); max-width: 450px;">
                            No major vulnerabilities were identified during the automated audit of this endpoint. Ensure that deep backend authorization scans are performed routinely.
                        </div>
                    </div>
                `;
            } else {
                data.vulnerabilities.forEach((v, index) => {
                    const sev = v.severity.toLowerCase();
                    vulnList.innerHTML += `
                        <div class="glass-card vuln-item ${sev}">
                            <div class="vuln-header-row" onclick="toggleVulnDetails(${index})">
                                <div class="vuln-title-group">
                                    <span class="vuln-badge ${sev}">${v.severity}</span>
                                    <span class="vuln-title">${v.name}</span>
                                </div>
                                <div style="display: flex; align-items: center; gap: 10px;">
                                    <span class="vuln-owasp">${v.owasp}</span>
                                    <button class="vuln-expand-btn" id="expand-btn-${index}">Expand ▼</button>
                                </div>
                            </div>
                            <div class="vuln-details" id="details-${index}" style="display: none;">
                                <div class="vuln-desc">${v.description}</div>
                                <div class="vuln-meta-item">
                                    <div class="vuln-meta-title">Evidence & Observation</div>
                                    <div class="vuln-meta-content">${escapeHTML(v.evidence)}</div>
                                </div>
                                <div class="vuln-meta-item">
                                    <div class="vuln-meta-title">Remediation Steps</div>
                                    <div class="vuln-meta-content rem">${v.remediation}</div>
                                </div>
                            </div>
                        </div>
                    `;
                });
            }

            // Headers Table
            const tbody = document.getElementById("headers-tbody");
            tbody.innerHTML = "";
            data.headers_inspected.forEach(h => {
                const statusClass = h.status.toLowerCase();
                const valContent = h.value ? escapeHTML(h.value) : "<i>N/A</i>";
                tbody.innerHTML += `
                    <tr>
                        <td class="hdr-name">${h.header}</td>
                        <td><span class="hdr-status-badge ${statusClass}">${h.status}</span></td>
                        <td class="hdr-val" title="${h.value || ''}">${valContent}</td>
                        <td style="color: var(--text-muted); line-height: 1.4;">${h.description}</td>
                    </tr>
                `;
            });
        }

        function toggleVulnDetails(idx) {
            const details = document.getElementById(`details-${idx}`);
            const btn = document.getElementById(`expand-btn-${idx}`);
            if (details.style.display === "none") {
                details.style.display = "flex";
                btn.textContent = "Collapse ▲";
            } else {
                details.style.display = "none";
                btn.textContent = "Expand ▼";
            }
        }

        function escapeHTML(str) {
            if (!str) return '';
            return str
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;")
                .replace(/'/g, "&#039;");
        }

        // Initialize history list on load
        updateStatsAndHistory();
    </script>
</body>
</html>
"""
    return html_content
