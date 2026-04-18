# AuditShield — Startup Security Auditor

A Python + FastAPI web application that audits startup codebases for:
- Hardcoded secrets & credentials
- Auth & authorization weaknesses  
- API security issues (injection, CORS, rate limiting)
- Cloud misconfiguration (Terraform, K8s, Docker)
- Privacy & compliance gaps (GDPR, CCPA, SOC2)
- Vulnerable dependencies (CVEs)

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run the server
uvicorn main:app --reload

# 3. Open in browser
open http://localhost:8000
```

## Project Structure

```
auditshield/
├── main.py              # FastAPI app + all scanning logic
├── requirements.txt     # Python dependencies
├── templates/
│   ├── base.html        # Shared layout & styles
│   ├── index.html       # Upload screen
│   ├── scan.html        # Live scan progress
│   └── report.html      # Full findings report
└── static/              # CSS/JS assets (empty for now)
```

## How It Works

1. User uploads a ZIP file or enters a GitHub URL
2. FastAPI extracts and reads all source files
3. Six scanning modules run concurrently (async)
4. Each module returns structured `Finding` objects
5. Risk score (0–100) and grade (A–F) are computed
6. Results displayed in a filterable report

## Scanning Modules

| Module | What it detects | Key patterns |
|--------|----------------|--------------|
| Secret detection | API keys, tokens, DSNs | AWS AKIA*, Stripe sk_live_, private keys |
| Auth review | Weak crypto, debug mode, SSL off | MD5, SHA1, verify=False |
| API security | SQL injection, CORS, rate limiting | String concat SQL, wildcard CORS |
| Cloud config | S3 public, RDS exposed, IAM wildcard | publicly_accessible, acl=public-read |
| Privacy | PII fields, logging PII, no policy | ssn, dob, credit_card field names |
| Dependencies | Known CVEs | lodash, jsonwebtoken, requests versions |

## Phase 2: Real Scanning (coming next)

Uncomment in `requirements.txt` and wire in:
- `truffleHog3` for git history secret scanning
- `semgrep` with OWASP community rules
- `pip-audit` / `npm audit` for real CVE checking
- `PyGitHub` for direct repo integration
- `celery` + `redis` for async job queuing
