"""Deterministic regex-based security scanners.

These are the cheap, reliable first-pass detectors. Subagents invoke them
before any LLM reasoning, then triage/enrich the raw findings via DSPy.
"""

from __future__ import annotations

import re
from pathlib import Path

from core.config import EXPOSURE_MULTIPLIER, GRADE_THRESHOLDS, SEVERITY_DEFAULT_CVSS

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
    # Web + scripting
    ".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".vue", ".svelte",
    ".rb", ".php", ".pl", ".lua", ".sh", ".bash", ".zsh", ".fish",
    # Compiled languages
    ".go", ".rs", ".java", ".kt", ".scala", ".cs", ".fs",
    ".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".hh", ".m", ".mm",
    ".swift", ".dart", ".ex", ".exs", ".erl", ".hrl", ".clj", ".cljs",
    # Config + IaC + data
    ".env", ".yaml", ".yml", ".json", ".json5", ".jsonc",
    ".tf", ".tfvars", ".hcl", ".bicep",
    ".toml", ".ini", ".cfg", ".conf", ".xml", ".properties",
    # Docs + web
    ".html", ".htm", ".md", ".mdx", ".rst", ".txt",
    # Misc
    ".sql", ".graphql", ".proto", ".dockerfile",
}

# Extensionless files worth reading (by basename, case-insensitive).
FILENAMES_TO_SCAN = {
    "makefile", "dockerfile", "containerfile", "jenkinsfile", "vagrantfile",
    "readme", "license", "notice", "authors", "contributors",
    "procfile", "caddyfile", ".env", ".gitignore", ".gitattributes",
    ".dockerignore", ".editorconfig", ".npmrc", ".yarnrc", ".nvmrc",
    "gemfile", "rakefile", "pipfile", "poetry.lock", "yarn.lock",
    "package-lock.json", "go.mod", "go.sum", "cargo.toml", "cargo.lock",
}

SKIP_DIRS = {"node_modules", ".git", "__pycache__", ".venv", "venv",
             "dist", "build", "target", ".next", ".nuxt", ".svelte-kit",
             "vendor", "Pods", ".gradle", ".idea", ".vscode"}


def is_scannable(path_or_name: str) -> bool:
    """Return True if this file should be ingested for scanning."""
    path = Path(path_or_name)
    if path.suffix.lower() in EXTENSIONS_TO_SCAN:
        return True
    if path.name.lower() in FILENAMES_TO_SCAN:
        return True
    return False


def scan_secrets(files: dict[str, str]) -> list[dict]:
    findings = []
    for path, content in files.items():
        for line_number, line in enumerate(content.splitlines(), 1):
            for pattern, title, sev in SECRET_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    masked = re.sub(pattern, "[REDACTED]", line.strip(), flags=re.IGNORECASE)
                    findings.append({
                        "severity": sev,
                        "module": "secrets",
                        "title": f"{title} detected",
                        "location": f"{path}:{line_number}",
                        "description": f"Pattern matched on line {line_number}: {masked[:120]}",
                        "fix": f"Remove this credential from the codebase immediately. Rotate/revoke the {title.lower()} and store in environment variables.",
                        "compliance": ["SOC2-CC6.1", "ISO27001-A.9"],
                    })
    return findings


def scan_auth(files: dict[str, str]) -> list[dict]:
    findings = []
    for path, content in files.items():
        for line_number, line in enumerate(content.splitlines(), 1):
            for pattern, title, sev, fix in AUTH_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append({
                        "severity": sev,
                        "module": "auth",
                        "title": title,
                        "location": f"{path}:{line_number}",
                        "description": f"Found at line {line_number}: {line.strip()[:120]}",
                        "fix": fix,
                        "compliance": ["GDPR-Art.32", "SOC2-CC6.1"],
                    })
    return findings


def scan_cloud(files: dict[str, str]) -> list[dict]:
    findings = []
    tf_yaml_files = {
        file_path: file_content
        for file_path, file_content in files.items()
        if file_path.endswith((".tf", ".yaml", ".yml", ".json"))
    }
    for path, content in tf_yaml_files.items():
        for line_number, line in enumerate(content.splitlines(), 1):
            for pattern, title, sev, fix in CLOUD_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append({
                        "severity": sev,
                        "module": "cloud",
                        "title": title,
                        "location": f"{path}:{line_number}",
                        "description": f"Found at line {line_number}: {line.strip()[:120]}",
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
    if not any(finding["module"] == "privacy" for finding in findings):
        has_privacy_policy = any("privacy" in file_path.lower() for file_path in files)
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
            for package_name, (vuln_ver, desc, sev, fix) in known_vulns.items():
                if package_name.lower() in content.lower():
                    findings.append({
                        "severity": sev,
                        "module": "deps",
                        "title": f"Vulnerable dependency: {package_name}",
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
        if re.search(r'(query|execute)\s*\(\s*["\'].*?\+|f["\'].*?SELECT.*?\{', content, re.IGNORECASE):
            findings.append({
                "severity": "high", "module": "api",
                "title": "Potential SQL injection via string concatenation",
                "location": path,
                "description": "SQL query appears to use string concatenation with variables. This is a classic injection vector.",
                "fix": "Use parameterised queries or an ORM. Never concatenate user input into SQL strings.",
                "compliance": ["OWASP-A03", "SOC2-CC6.6"],
            })
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



# Risk scoring — CVSS-aligned with exposure context

#
# The headline grade and 0–100 score come from a per-finding contribution:
#
#     contribution = cvss_base × exposure_multiplier
#     risk_total   = sum(contribution for f in findings if is_true_positive)
#     score        = clamp(round(100 - 2 × risk_total), 0, 100)
#
# `cvss_base` is the LLM's CVSS v3.1-aligned 0.0–10.0 score for the finding
# (it picks a number inside the band of its chosen severity — see
# CVSS_AND_EXPOSURE_RUBRIC in agents.prompts.audit_rubrics).
#
# `exposure_multiplier` reflects whether the vulnerable code actually ships:
#   production  1.00   - live request handlers, prod IaC, prod auth code
#   internal    0.60   - admin tools, debug-only endpoints, ops scripts
#   test        0.15   - tests/, __tests__, conftest.py, fixtures
#   example     0.05   - examples/, samples/, demo/, cookbook
#   doc         0.03   - docs/ snippets, README samples
#
# A scary-looking eval() in `examples/advanced.py` therefore contributes
# 9.0 × 0.05 = 0.45 to risk, not 9.0. That is what stops a library repo
# (FastAPI, Django, …) from getting an F because of pedagogical code.
#
# Grade thresholds (calibrated on real repos):
#   A   risk_total ≤ 5      score ≥ 90
#   B   risk_total ≤ 12.5   score ≥ 75
#   C   risk_total ≤ 20     score ≥ 60
#   D   risk_total ≤ 30     score ≥ 40
#   F   risk_total > 30     score < 40
#
# Backwards compat: if a finding is missing `cvss_base` (e.g. salvaged
# from a partial run) we fall back to the band default for its severity,
# and exposure defaults to "production" (worst case).

# EXPOSURE_MULTIPLIER, SEVERITY_DEFAULT_CVSS, and GRADE_THRESHOLDS
# are now imported from agents.config


def _normalize_severity(severity_raw: object) -> str:
    return str(severity_raw or "low").strip().lower()


def _cvss_for(finding: dict) -> float:
    """Return the CVSS base score for a finding, with sane fallbacks."""
    raw = finding.get("cvss_base")
    try:
        cvss_value = float(raw)
        if 0.0 < cvss_value <= 10.0:
            return cvss_value
    except (TypeError, ValueError):
        pass
    return SEVERITY_DEFAULT_CVSS.get(_normalize_severity(finding.get("severity")), 0.0)


def infer_exposure_from_path(location: str) -> str:
    """Conservative path-based inference for `exposure`. Anything ambiguous
    stays 'production' (worst case for the score)."""
    normalized_path = (location or "").lower().replace("\\", "/")
    if not normalized_path:
        return "production"
    parts = normalized_path.split("/")
    name = parts[-1] if parts else ""

    if any(seg in parts for seg in ("tests", "test", "__tests__", "spec", "specs", "fixtures")):
        return "test"
    if name.startswith("test_") or name.endswith(
        ("_test.py", ".test.ts", ".test.tsx", ".spec.ts", ".spec.js", ".spec.tsx")
    ):
        return "test"
    if name == "conftest.py":
        return "test"

    if any(seg in parts for seg in ("examples", "example", "samples", "sample", "demo", "demos", "cookbook")):
        return "example"

    if any(seg in parts for seg in ("docs", "doc", "documentation")):
        return "doc"
    if name == "readme.md" or (name.endswith(".md") and "docs" in parts):
        return "doc"

    return "production"


def _exposure_for(finding: dict) -> str:
    raw = (finding.get("exposure") or "").strip().lower()
    if raw in EXPOSURE_MULTIPLIER:
        return raw
    return infer_exposure_from_path(finding.get("location", ""))


def score_finding(finding: dict) -> dict:
    """Compute the risk contribution of one finding. Returns the inputs
    plus the contribution so the UI can show its math row-by-row."""
    cvss = _cvss_for(finding)
    exposure = _exposure_for(finding)
    exposure_multiplier = EXPOSURE_MULTIPLIER[exposure]
    contribution = round(cvss * exposure_multiplier, 2)
    return {
        "cvss_base": cvss,
        "exposure": exposure,
        "exposure_multiplier": exposure_multiplier,
        "contribution": contribution,
        "counted": bool(finding.get("is_true_positive", True)),
    }


def compute_score(findings: list[dict]) -> tuple[int, str]:
    """Headline (score, grade). See module-level docstring for the math."""
    risk_total = 0.0
    for finding in findings:
        if not finding.get("is_true_positive", True):
            continue
        score_row = score_finding(finding)
        risk_total += score_row["contribution"]

    score = max(0, min(100, round(100 - 2.0 * risk_total)))

    grade = "F"
    for grade_letter, risk_threshold in GRADE_THRESHOLDS:
        if risk_total <= risk_threshold:
            grade = grade_letter
            break
    return score, grade


def score_breakdown(findings: list[dict]) -> dict:
    """Detailed math suitable for the report sidebar / methodology box."""
    rows = []
    risk_total = 0.0
    counted = 0
    skipped_low_confidence = 0
    by_exposure: dict[str, int] = {
        exposure_kind: 0 for exposure_kind in EXPOSURE_MULTIPLIER
    }
    for finding in findings:
        score_row = score_finding(finding)
        rows.append(score_row)
        by_exposure[score_row["exposure"]] = by_exposure.get(score_row["exposure"], 0) + 1
        if score_row["counted"]:
            risk_total += score_row["contribution"]
            counted += 1
        else:
            skipped_low_confidence += 1
    score, grade = compute_score(findings)
    return {
        "rows": rows,
        "risk_total": round(risk_total, 2),
        "score": score,
        "grade": grade,
        "counted": counted,
        "skipped_low_confidence": skipped_low_confidence,
        "by_exposure": by_exposure,
        "thresholds": GRADE_THRESHOLDS,
    }
