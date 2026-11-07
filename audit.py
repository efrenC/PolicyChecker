"""Append-only audit log, one JSON object per line.

Both outcomes are recorded: "classified" for completed requests and
"rejected" for requests refused at the API or by the pipeline's rules.
"""

from __future__ import annotations

import json
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import config

_lock = threading.Lock()


def new_audit_id() -> str:
    return f"audit-{uuid.uuid4()}"


def bounded_input(value: Any) -> Any:
    """Keep a copy of caller input, truncated if it is very large."""
    text = json.dumps(value, default=str)
    if len(text) <= config.MAX_AUDITED_INPUT_CHARS:
        return value
    return {"truncated": True, "preview": text[: config.MAX_AUDITED_INPUT_CHARS]}


def append_audit_entry(entry: dict[str, Any], log_path: Path | None = None) -> str:
    """Write one entry and return its audit ID."""
    log_path = Path(log_path) if log_path else config.AUDIT_LOG_PATH
    record = {
        "audit_log_id": entry.pop("audit_log_id", None) or new_audit_id(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **entry,
    }
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with _lock, log_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, default=str) + "\n")
    return record["audit_log_id"]


def audit_rejection(
    stage: str, errors: list[Any], received: Any = None, log_path: Path | None = None
) -> str:
    return append_audit_entry(
        {
            "outcome": "rejected",
            "stage": stage,
            "errors": errors,
            "received": bounded_input(received),
        },
        log_path=log_path,
    )
