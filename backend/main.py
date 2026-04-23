"""LaunchSafe — Startup Security Auditor
FastAPI backend + LangGraph multi-agent pipeline powered by Claude.
Run: uvicorn main:app --reload

This file is pure wiring. All logic lives in dedicated
modules:
  - core/routes.py       → HTTP endpoints
  - core/orchestrator.py → scan orchestration
  - core/scan_store.py   → in-memory scan state
  - core/events.py       → live event-bus wiring
  - core/config.py       → centralized configuration
  - agents/              → graph, recon, specialists, tools
  - tools/               → scanners, AI tools, ingest
"""

from __future__ import annotations

import os
from pathlib import Path


try:
    from dotenv import load_dotenv

    # `override=True`: variables in backend/.env replace the process environment — update .env to change keys.
    load_dotenv(Path(__file__).resolve().parent / ".env", override=True)
except ImportError:
    pass

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from core.events import setup_event_bus
from core.routes import router

app = FastAPI(title="LaunchSafe")

_gemini_key = os.environ.get("GEMINI_API_KEY", "")
_anthropic_key = os.environ.get("ANTHROPIC_API_KEY", "")

# Log the **active** provider from the configured model, not "whichever key exists first".
try:
    from core.config import LLM_MODEL
except Exception:  # noqa: BLE001
    LLM_MODEL = os.environ.get("LAUNCHSAFE_LLM_MODEL", "claude-sonnet-4-6")

_m = (LLM_MODEL or "").lower()
if _m.startswith("gemini"):
    _active = "gemini"
    _key = _gemini_key
else:
    _active = "anthropic"
    _key = _anthropic_key

if not _key:
    print(
        f"[LaunchSafe] LLM model: {LLM_MODEL}  no API key for active provider "
        f"({_active}) — regex-only fallback mode"
    )
else:
    print(
        f"[LaunchSafe] LLM model: {LLM_MODEL}  provider: {_active}  key: {_key[:12]}…"
    )

# Wire the event-bus that graph nodes use to push live UI events.
setup_event_bus()

# Mount routes
app.include_router(router)

# Serve static assets if the directory exists
_STATIC = Path(__file__).resolve().parent / "static"
if _STATIC.is_dir():
    app.mount("/static", StaticFiles(directory=str(_STATIC)), name="static")
