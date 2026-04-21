# LaunchSafe — Startup Security Auditor

LaunchSafe scans a GitHub repo and returns a prioritized,
CVSS-scored security report in a few minutes. It is built on a small
**multi-agent LangGraph pipeline** powered by Claude — a recon agent
profiles the repo, then specialist sub-agents fan out in parallel
against the parts of the codebase that actually matter, and a final
synthesize step dedupes and grades the results.

### Note: Very computationally intensive, the process will take a few minutes (around 5-10 mins max)

## What it checks

| Specialist   | Focus                                                                      |
|--------------|----------------------------------------------------------------------------|
| `recon`      | Profiles the repo: language, framework, payments / IaC / auth / CI flags   |
| `payments`   | Stripe / PCI exposure, webhook signature verification, key handling        |
| `iac`        | Terraform / K8s / Docker — public buckets, exposed DBs, IAM wildcards      |
| `auth`       | Login, session, JWT, password hashing, RBAC / IDOR                         |
| `cicd`       | GitHub Actions / GitLab CI — secrets, untrusted PR triggers, OIDC          |
| `general`    | Secrets, crypto, SQLi, SSRF, deserialization, CORS, dependency CVEs        |
| `synthesize` | Dedupes across branches, writes the executive summary + top fixes          |

Each finding gets a CVSS v3.1-aligned base score and a deployment-context
**exposure** tag (`production` / `internal` / `test` / `example` / `doc`)
so test-fixture findings don't drag a library repo's grade down to F.

## Architecture

```
        FastAPI (backend/main.py)
        /start-scan  /scan-status  /report/<id>
                     │
                     ▼
              LangGraph orchestrator
                     │
                  ┌──┴──┐
                  │recon│  ← mini ReAct agent (list_files, read_files)
                  └──┬──┘
                     │  RepoProfile + flags
                     ▼
            route_after_recon  (conditional fan-out)
        ┌──────┬──────┬──────┬──────┐
        ▼      ▼      ▼      ▼      ▼
     payments iac   auth   cicd  general    ← parallel ReAct sub-agents
        └──────┴──────┴──────┴──────┘          (each calls AI scanning tools)
                     │
                     ▼
                synthesize  ← dedupe + LLM exec summary
                     │
                     ▼
                Report JSON
```

Sub-agents stream their `think → call → result` events live to the
frontend over `/scan-status?since=<seq>`, so the user sees what each
branch is doing as it happens.

## Quick start

```bash
git clone https://github.com/SahibKazimli/LaunchSafe.git
cd LaunchSafe

python3 -m venv venv
source venv/bin/activate
pip install -r backend/requirements.txt

cp backend/.env.example backend/.env
# edit backend/.env and paste your ANTHROPIC_API_KEY

cd backend
uvicorn main:app --reload
# → http://127.0.0.1:8000
```

The boot log prints the first 12 chars of the loaded API key so you
can confirm which one is being used:

```
[LaunchSafe] ANTHROPIC_API_KEY loaded: sk-ant-api03…
```

Without an API key the app falls back to a regex-only scan (useful for
local dev, but the AI specialists are where the real value is).

## Repo layout

```
LaunchSafe/
├── README.md
├── Dockerfile                   
├── .dockerignore
├── backend/
│   ├── main.py                   # FastAPI app, scan orchestration, event stream
│   ├── requirements.txt
│   ├── .env.example
│   └── agents/
│       ├── graph.py              # LangGraph StateGraph wiring
│       ├── state.py              # ScanAgentState (shared agent state)
│       ├── recon.py              # Recon mini-agent
│       ├── specialists.py        # payments / iac / auth / cicd / general
│       ├── synthesize.py         # Dedupe + executive summary LLM call
│       ├── runtime_log.py        # Event bus for live UI streaming
│       ├── schemas.py            # Pydantic models + LLM rubrics
│       └── tools/
│           ├── ingest.py         # GitHub clone + zip extraction
│           ├── scanners.py       # Regex scanners + CVSS scoring engine
│           ├── ai_tools.py       # ai_scan_file / ai_scan_cicd / ai_audit_auth_flow
│           └── agent_tools.py    # list_files / read_file / read_files
└── frontend/
    ├── base.html                 # Shared layout
    ├── index.html                # Upload page
    ├── scan.html                 # Live scan progress (branches + event log)
    └── report.html               # Final findings report
```

## Risk scoring

```
contribution = cvss_base × exposure_multiplier        # per finding
risk_total   = Σ contribution (only is_true_positive=True findings)
score        = clamp(100 − 2 × risk_total, 0, 100)
```

Exposure multipliers: `production 1.00`, `internal 0.60`, `test 0.15`,
`example 0.05`, `doc 0.03`.

Grade is bucketed on `risk_total` (lower = better):

| risk_total | grade |
|------------|-------|
| ≤ 5        | A     |
| ≤ 12.5     | B     |
| ≤ 20       | C     |
| ≤ 30       | D     |
| > 30       | F     |

The full per-finding math (CVSS, exposure, contribution) is shown in
the report sidebar.


## Tech stack

- **FastAPI** + **Jinja2** — web layer, no JS framework
- **LangGraph** — agent orchestration (conditional fan-out, parallel branches, state reducers)
- **LangChain** + **Anthropic Claude** — sub-agent reasoning and structured output
- **Pydantic** — typed schemas for `Finding` / `AuditReport` / `ComplianceRef`
- **GitPython** — repo cloning
- **python-dotenv** — `.env` loading


