"""In-memory scan state management.

Centralises all access to the scan_store dict so that no other module
needs to manipulate the raw dict directly. This makes it straightforward
to add locking, TTL eviction, or a persistence backend later.
"""

from __future__ import annotations

import time
from typing import Any


# The authoritative scan store. Keys are scan IDs (short UUIDs).
_store: dict[str, dict[str, Any]] = {}



# Public API

def create_scan(scan_id: str, target: str) -> dict[str, Any]:
    """Initialise a new scan record with all default fields and return it."""
    record: dict[str, Any] = {
        "status": "pending",
        "target": target,
        "findings": [],
        "modules_done": [],
        "events": [],
        "event_seq": 0,
        "branches": {},
        "started_at": None,
        "score": 0,
        "grade": "?",
        "summary": "",
        "top_fixes": [],
        "overall_risk": "",
        "repo_profile": None,
    }
    _store[scan_id] = record
    return record


def get_scan(scan_id: str) -> dict[str, Any] | None:
    """Return the scan record, or ``None`` if it doesn't exist."""
    return _store.get(scan_id)


def update_scan(scan_id: str, **fields: Any) -> None:
    """Merge *fields* into an existing scan record.

    Silently no-ops if *scan_id* is unknown (mirrors old behaviour).
    """
    scan = _store.get(scan_id)
    if scan is not None:
        scan.update(fields)


def mark_running(scan_id: str) -> None:
    """Transition a scan to ``running`` and record the start time."""
    update_scan(scan_id, status="running", started_at=time.time())


def exists(scan_id: str) -> bool:
    return scan_id in _store


def all_ids() -> list[str]:
    """Return a snapshot of all current scan IDs."""
    return list(_store.keys())
