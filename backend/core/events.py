"""Event-bus wiring for live scan progress.

Registers a ``push_event`` sink that graph nodes call (via
``agents.runtime_log.emit``) to stream live events into the scan store.
The frontend polls ``/scan-status`` and picks up whatever it finds.

Import this module early in app bootstrap to wire the sink before any
graph node runs.
"""

from __future__ import annotations

import time as _time

from core.config import EVENT_RING_CAP
from agents.runtime_log import set_event_sink
from core import scan_store as _ss


from core import fix_store as _fs

def push_event(
    scan_id: str,
    kind: str,
    text: str,
    branch: str | None = None,
    **extra: object,
) -> None:
    """Append a timestamped event to a scan or fix event ring buffer."""
    # scan_id could actually be a fix_id if emitted from the fix graph
    scan = _ss.get_scan(scan_id)
    if scan is None:
        scan = _fs.get_fix_session(scan_id)
    if scan is None:
        return

    started = scan.get("started_at") or _time.time()
    seq = scan.get("event_seq", 0) + 1
    scan["event_seq"] = seq

    ev: dict = {
        "seq": seq,
        "t": round(_time.time() - started, 1),
        "kind": kind,
        "text": (text or "")[:280],
        "branch": branch or "outer",
    }
    if extra:
        ev.update(extra)

    events = scan.setdefault("events", [])
    events.append(ev)
    if len(events) > EVENT_RING_CAP:
        del events[: len(events) - EVENT_RING_CAP]

    # Track per-branch progress metadata
    if branch and branch != "outer":
        branch_state = scan.setdefault("branches", {}).setdefault(
            branch, {"status": "pending", "tool_calls": 0, "count": 0}
        )
        if kind == "branch_start":
            branch_state["status"] = "running"
        elif kind == "branch_done":
            branch_state["status"] = "done"
            if "count" in extra:
                branch_state["count"] = extra["count"]
            if "tool_calls" in extra:
                branch_state["tool_calls"] = extra["tool_calls"]
        elif kind == "call":
            branch_state["tool_calls"] = branch_state.get("tool_calls", 0) + 1


def setup_event_bus() -> None:
    """Register the event sink.  Call once during app startup."""
    set_event_sink(push_event)
