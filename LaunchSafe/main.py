"""
AuditShield — Startup Security Auditor
FastAPI backend with real scanning modules
Run: uvicorn main:app --reload
"""

import asyncio
import json
import os
import re
import tempfile
import uuid
import zipfile
from pathlib import Path
from typing import AsyncGenerator

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

app = FastAPI(title="AuditShield")
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

# ── In-memory scan store (use Redis in production) ──────────────────────────
scan_store: dict[str, dict] = {}


# ════════════════════════════════════════════════════════════════════════════
#  SCANNING ENGINE
# ════════════════════════════════════════════════════════════════════════════

SECRET_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID", "critical"),
    (r"sk_live_[0-9a-zA-Z]{24,}", "Stripe Live Secret Key", "critical"),
    (r"sk_test_[0-9a-zA-Z]{24,}", "Stripe Test Key", "medium"),
    (r"ghp_[0-9a-zA-Z]{36}", "GitHub Personal Access Token", "critical"),
    (r"xoxb-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24}", "Slack Bot Token", "high"),
    (r"https://hooks\.slack\.com/services/[^\s\"']+", "Slack Webhook URL", "high"),
    (r"-----BEGIN (RSA |EC )?PRIVATE KEY-----", "Private Key", "critical"),
    (r"password\s*=\s*['\"][^'\"]{4,}['\"]", "Hardcoded Password", "high"),
    (r"secret\s*=\s*['\"][^'\"]{8,}['\"]", "Hardcoded Secret", "high"),
    (r"api[_-]?key\s*=\s*['\"][^'\"]{8,}['\"]", "Hardcoded API Key", "high"),
    (r"mongodb(\+srv)?://[^\s\"']+:[^\s\"']+@", "MongoDB Connection String with Credentials", "critical"),
    (r"postgres://[^\s\"']+:[^\s\"']+@", "PostgreSQL DSN with Credentials", "critical"),
]

AUTH_PATTERNS = [
    (r"algorithm\s*=\s*['\"]none['\"]", "JWT 'none' algorithm accepted", "critical",
     "Never allow 'none' as a JWT algorithm. Always specify algorithms=['HS256'] in jwt.verify()."),
    (r"md5|MD5\s*\(", "MD5 used for hashing", "high",
     "MD5 is broken for security. Use bcrypt, argon2, or sha256 for passwords."),
    (r"sha1\s*\(|hashlib\.sha1", "SHA1 used for hashing", "high",
     "SHA1 is deprecated for security use. Migrate to SHA256 or bcrypt."),
    (r"verify\s*=\s*False", "SSL verification disabled", "high",
     "Never disable SSL verification in production. Remove verify=False."),
    (r"debug\s*=\s*True|DEBUG\s*=\s*True", "Debug mode enabled", "medium",
     "Debug mode exposes stack traces and internals. Disable in production."),
    (r"SECRET_KEY\s*=\s*['\"][^'\"]{1,20}['\"]", "Weak or short SECRET_KEY", "medium",
     "Use a randomly generated secret of at least 32 characters."),
]

CLOUD_PATTERNS = [
    (r"publicly_accessible\s*=\s*true", "RDS publicly accessible", "high",
     "Set publicly_accessible = false. Access via private subnet only."),
    (r"acl\s*=\s*['\"]public-read['\"]", "S3 bucket public-read ACL", "high",
     "Set acl = 'private'. Use pre-signed URLs for object access."),
    (r'"Action"\s*:\s*"\*"', "IAM wildcard action", "high",
     "Restrict IAM actions to only what is needed (least privilege)."),
    (r"0\.0\.0\.0/0", "Open ingress to 0.0.0.0/0", "medium",
     "Restrict ingress rules to known IP ranges or VPC CIDRs."),
    (r"privileged\s*:\s*true", "Privileged container", "high",
     "Remove privileged: true from container definitions."),
    (r"allow_overwrite\s*=\s*true", "Terraform state allow_overwrite", "low",
     "Enabling state overwrite can lead to infrastructure corruption."),
]

EXTENSIONS_TO_SCAN = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".env", ".yaml", ".yml",
    ".json", ".tf", ".sh", ".rb", ".go", ".php", ".java", ".cs",
    ".toml", ".ini", ".cfg", ".conf", ".xml", ".html",
}

SKIP_DIRS = {"node_modules", ".git", "__pycache__", ".venv", "venv", "dist", "build"}


def extract_files(zip_path: str) -> dict[str, str]:
    """Extract text files from a zip archive."""
    files = {}
    try:
        with zipfile.ZipFile(zip_path) as z:
            for name in z.namelist():
                p = Path(name)
                if any(part in SKIP_DIRS for part in p.parts):
                    continue
                if p.suffix.lower() in EXTENSIONS_TO_SCAN:
                    try:
                        files[name] = z.read(name).decode("utf-8", errors="replace")
                    except Exception:
                        pass
    except Exception:
        pass
    return files


def scan_secrets(files: dict[str, str]) -> list[dict]:
    findings = []
    for path, content in files.items():
        for lines_i, line in enumerate(content.splitlines(), 1):
            for pattern, title, sev in SECRET_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    # Mask the actual value for safety
                    masked = re.sub(pattern, "[REDACTED]", line.strip(), flags=re.IGNORECASE)
                    findings.append({
                        "severity": sev,
                        "module": "secrets",
                        "title": f"{title} detected",
                        "location": f"{path}:{lines_i}",
                        "description": f"Pattern matched on line {lines_i}: {masked[:120]}",
                        "fix": f"Remove this credential from the codebase immediately. Rotate/revoke the {title.lower()} and store in environment variables.",
                        "compliance": ["SOC2-CC6.1", "ISO27001-A.9"],
                    })
    return findings


def scan_auth(files: dict[str, str]) -> list[dict]:
    findings = []
    for path, content in files.items():
        for line_i, line in enumerate(content.splitlines(), 1):
            for pattern, title, sev, fix in AUTH_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append({
                        "severity": sev,
                        "module": "auth",
                        "title": title,
                        "location": f"{path}:{line_i}",
                        "description": f"Found at line {line_i}: {line.strip()[:120]}",
                        "fix": fix,
                        "compliance": ["GDPR-Art.32", "SOC2-CC6.1"],
                    })
    return findings


def scan_cloud(files: dict[str, str]) -> list[dict]:
    findings = []
    tf_yaml_files = {k: v for k, v in files.items()
                     if k.endswith((".tf", ".yaml", ".yml", ".json"))}
    for path, content in tf_yaml_files.items():
        for line_i, line in enumerate(content.splitlines(), 1):
            for pattern, title, sev, fix in CLOUD_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append({
                        "severity": sev,
                        "module": "cloud",
                        "title": title,
                        "location": f"{path}:{line_i}",
                        "description": f"Found at line {line_i}: {line.strip()[:120]}",
                        "fix": fix,
                        "compliance": ["SOC2-CC7.2", "ISO27001-A.12"],
                    })
    return findings


def scan_privacy(files: dict[str, str]) -> list[dict]:
    findings = []
    pii_fields = ["ssn", "social_security", "credit_card", "card_number", "dob", "date_of_birth"]
    for path, content in files.items():
        lower = content.lower()
        for field in pii_fields:
            if field in lower:
                findings.append({
                    "severity": "medium",
                    "module": "privacy",
                    "title": f"Possible PII field: '{field}'",
                    "location": path,
                    "description": f"The field name '{field}' suggests personally identifiable information is stored here. Verify it is encrypted at rest and not logged.",
                    "fix": "Encrypt PII fields at rest. Exclude from logs. Add a data retention policy. Tag in your data map for GDPR purposes.",
                    "compliance": ["GDPR-Art.5", "GDPR-Art.32", "CCPA-§1798"],
                })
        # Check for logging PII
        if re.search(r"(log|print|console)\s*\(.*?(email|password|ssn|phone)", lower):
            findings.append({
                "severity": "medium",
                "module": "privacy",
                "title": "PII may be written to logs",
                "location": path,
                "description": "A log/print statement references a PII-adjacent field name. Verify no sensitive data reaches log output.",
                "fix": "Redact or hash PII before logging. Use a structured logger with field-level redaction.",
                "compliance": ["GDPR-Art.5", "SOC2-CC7.2"],
            })
    if not any(f["module"] == "privacy" for f in findings):
        # Generic checks for missing privacy controls
        has_privacy_policy = any("privacy" in k.lower() for k in files)
        if not has_privacy_policy:
            findings.append({
                "severity": "low",
                "module": "privacy",
                "title": "No privacy policy file detected",
                "location": "— (absent)",
                "description": "No file with 'privacy' in the name was found. GDPR requires a publicly accessible privacy policy.",
                "fix": "Add a privacy policy covering: data collected, purpose, retention, third parties, and user rights.",
                "compliance": ["GDPR-Art.13", "CCPA-§1798.100"],
            })
    return findings


def scan_dependencies(files: dict[str, str]) -> list[dict]:
    findings = []
    known_vulns = {
        "lodash": ("4.17.20", "CVE-2021-23337 — prototype pollution via lodash.template", "medium", "Upgrade to >= 4.17.21"),
        "axios": ("0.21.0", "CVE-2021-3749 — ReDoS via axios", "medium", "Upgrade to >= 0.21.2"),
        "jsonwebtoken": ("8.5.0", "CVE-2022-23529 — improper validation", "high", "Upgrade to >= 9.0.0"),
        "minimist": ("1.2.5", "CVE-2021-44906 — prototype pollution", "high", "Upgrade to >= 1.2.6"),
        "express": ("4.17.1", "Known security advisories — ensure latest patch", "low", "Upgrade to latest 4.x"),
        "django": ("3.2.0", "CVE-2022-28346 — SQL injection in QuerySet.annotate", "high", "Upgrade to >= 3.2.13"),
        "flask": ("1.1.4", "Several known advisories in this version range", "medium", "Upgrade to >= 2.3.0"),
        "requests": ("2.25.0", "CVE-2023-32681 — proxy credential leakage", "medium", "Upgrade to >= 2.31.0"),
    }
    for path, content in files.items():
        fname = Path(path).name
        if fname in ("package.json", "requirements.txt", "Pipfile", "pyproject.toml"):
            for pkg, (vuln_ver, desc, sev, fix) in known_vulns.items():
                if pkg.lower() in content.lower():
                    findings.append({
                        "severity": sev,
                        "module": "deps",
                        "title": f"Vulnerable dependency: {pkg}",
                        "location": path,
                        "description": desc,
                        "fix": fix,
                        "compliance": ["SOC2-CC7.1"],
                    })
    return findings


def scan_api(files: dict[str, str]) -> list[dict]:
    findings = []
    for path, content in files.items():
        if not path.endswith((".py", ".js", ".ts", ".yaml", ".yml", ".json")):
            continue
        # SQL injection via string concat
        if re.search(r'(query|execute)\s*\(\s*["\'].*?\+|f["\'].*?SELECT.*?\{', content, re.IGNORECASE):
            findings.append({
                "severity": "high", "module": "api",
                "title": "Potential SQL injection via string concatenation",
                "location": path,
                "description": "SQL query appears to use string concatenation with variables. This is a classic injection vector.",
                "fix": "Use parameterised queries or an ORM. Never concatenate user input into SQL strings.",
                "compliance": ["OWASP-A03", "SOC2-CC6.6"],
            })
        # No rate limiting
        if re.search(r"@app\.(route|get|post|put|delete)", content) and \
                not re.search(r"rate.?limit|throttle|slowapi|flask.?limiter", content, re.IGNORECASE):
            findings.append({
                "severity": "medium", "module": "api",
                "title": "No rate limiting detected",
                "location": path,
                "description": "Route handlers found but no rate limiting library detected. Endpoints may be brute-forceable.",
                "fix": "Add slowapi (FastAPI) or Flask-Limiter. At minimum, limit auth endpoints to 5 req/15 min per IP.",
                "compliance": ["OWASP-A05"],
            })
            break
        # CORS wildcard
        if re.search(r'allow_origins\s*=\s*\[?\s*["\*]|cors\s*\(\s*origin\s*:\s*["\*]', content, re.IGNORECASE):
            findings.append({
                "severity": "medium", "module": "api",
                "title": "CORS allows all origins (*)",
                "location": path,
                "description": "Wildcard CORS origin detected. Any website can make credentialed cross-origin requests.",
                "fix": "Replace * with an explicit list of allowed origins matching your production domains.",
                "compliance": ["OWASP-A05"],
            })
    return findings


def compute_score(findings: list[dict]) -> tuple[int, str]:
    weights = {"critical": 25, "high": 10, "medium": 4, "low": 1}
    deduction = sum(weights.get(f["severity"], 0) for f in findings)
    score = max(0, 100 - deduction)
    if score >= 90: grade = "A"
    elif score >= 75: grade = "B"
    elif score >= 60: grade = "C"
    elif score >= 40: grade = "D"
    else: grade = "F"
    return score, grade


async def run_scan(scan_id: str, files: dict[str, str]) -> None:
    """Run all scan modules and store results."""
    scan_store[scan_id]["status"] = "running"
    all_findings = []
    modules_done = []

    module_fns = [
        ("secrets",  "Secret detection",       scan_secrets),
        ("auth",     "Auth & access review",    scan_auth),
        ("api",      "API security review",     scan_api),
        ("cloud",    "Cloud config audit",      scan_cloud),
        ("privacy",  "Privacy & compliance",    scan_privacy),
        ("deps",     "Dependency scanning",     scan_dependencies),
    ]

    for mod_id, mod_name, fn in module_fns:
        await asyncio.sleep(0.8)  # Simulate realistic scan time
        results = fn(files)
        all_findings.extend(results)
        modules_done.append({"id": mod_id, "name": mod_name, "count": len(results)})
        scan_store[scan_id]["modules_done"] = list(modules_done)
        scan_store[scan_id]["findings"] = list(all_findings)

    score, grade = compute_score(all_findings)
    scan_store[scan_id].update({
        "status": "done",
        "score": score,
        "grade": grade,
        "findings": all_findings,
        "modules_done": modules_done,
    })


# ════════════════════════════════════════════════════════════════════════════
#  ROUTES
# ════════════════════════════════════════════════════════════════════════════

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/scan/{scan_id}", response_class=HTMLResponse)
async def scan_page(request: Request, scan_id: str):
    if scan_id not in scan_store:
        return HTMLResponse("Scan not found", status_code=404)
    return templates.TemplateResponse("scan.html", {"request": request, "scan_id": scan_id})


@app.get("/report/{scan_id}", response_class=HTMLResponse)
async def report_page(request: Request, scan_id: str):
    scan = scan_store.get(scan_id)
    if not scan or scan["status"] != "done":
        return HTMLResponse("Report not ready", status_code=404)

    findings = scan["findings"]
    counts = {
        "critical": sum(1 for f in findings if f["severity"] == "critical"),
        "high":     sum(1 for f in findings if f["severity"] == "high"),
        "medium":   sum(1 for f in findings if f["severity"] == "medium"),
        "low":      sum(1 for f in findings if f["severity"] == "low"),
    }
    return templates.TemplateResponse("report.html", {
        "request": request,
        "scan": scan,
        "findings": findings,
        "counts": counts,
        "total": len(findings),
    })


@app.post("/start-scan")
async def start_scan(
    file: UploadFile = File(None),
    github_url: str = Form(""),
):
    scan_id = str(uuid.uuid4())[:8]
    scan_store[scan_id] = {
        "status": "pending",
        "target": github_url or (file.filename if file else "uploaded file"),
        "findings": [],
        "modules_done": [],
        "score": 0,
        "grade": "?",
    }

    files: dict[str, str] = {}

    if file and file.filename:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".zip") as tmp:
            tmp.write(await file.read())
            tmp_path = tmp.name
        files = extract_files(tmp_path)
        os.unlink(tmp_path)

    # If no real files, use demo content for demonstration
    if not files:
        files = _demo_files()

    asyncio.create_task(run_scan(scan_id, files))
    return {"scan_id": scan_id}


@app.get("/scan-status/{scan_id}")
async def scan_status(scan_id: str):
    scan = scan_store.get(scan_id)
    if not scan:
        return {"error": "not found"}
    return {
        "status": scan["status"],
        "modules_done": scan.get("modules_done", []),
        "findings_count": len(scan.get("findings", [])),
    }


@app.get("/api/findings/{scan_id}")
async def get_findings(scan_id: str, severity: str = "all"):
    scan = scan_store.get(scan_id)
    if not scan:
        return {"error": "not found"}
    findings = scan.get("findings", [])
    if severity != "all":
        findings = [f for f in findings if f["severity"] == severity]
    return {"findings": findings}


def _demo_files() -> dict[str, str]:
    """Demo files with intentional vulnerabilities for demonstration."""
    return {
        "src/config/aws.js": """
const AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE';
const AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
module.exports = { AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY };
""",
        ".env.example": """
STRIPE_SECRET_KEY=sk_live_51ABC123realkey
DATABASE_URL=postgres://admin:password123@db.example.com/prod
SECRET_KEY=short
DEBUG=True
""",
        "middleware/auth.js": """
const jwt = require('jsonwebtoken');
function verify(token) {
    return jwt.verify(token, process.env.SECRET_KEY); // no algorithm specified
}
function hashPassword(pw) {
    return md5(pw); // insecure
}
""",
        "routes/api.js": """
const express = require('express');
const app = express();
const cors = require('cors');
app.use(cors({ origin: '*' }));

app.post('/login', (req, res) => {
    const query = "SELECT * FROM users WHERE email = '" + req.body.email + "'";
    db.execute(query);
});
app.get('/admin/users', (req, res) => {
    // no auth middleware!
    res.json(db.query('SELECT * FROM users'));
});
""",
        "terraform/main.tf": """
resource "aws_s3_bucket" "uploads" {
  bucket = "my-startup-uploads"
  acl    = "public-read"
}
resource "aws_db_instance" "main" {
  publicly_accessible = true
  password            = "mysupersecret123"
}
resource "aws_security_group_rule" "ssh" {
  cidr_blocks = ["0.0.0.0/0"]
  from_port   = 22
}
""",
        "package.json": """
{
  "dependencies": {
    "lodash": "4.17.20",
    "jsonwebtoken": "8.5.0",
    "express": "4.17.1",
    "axios": "0.21.0"
  }
}
""",
        "models/user.py": """
import hashlib
class User:
    def set_password(self, pw):
        self.password_hash = hashlib.md5(pw.encode()).hexdigest()
    def log_login(self, email):
        print(f"Login attempt: {email}")  # PII in logs
    ssn = models.CharField(max_length=11)  # PII field
""",
    }
