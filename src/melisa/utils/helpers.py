"""Utility helpers for MELISA Core."""

from datetime import datetime, timezone
from typing import Any


def utc_now() -> str:
    """Return current UTC timestamp in ISO format."""
    return datetime.now(timezone.utc).isoformat()


def safe_get(data: dict, *keys, default: Any = None) -> Any:
    """Safely navigate nested dictionaries."""
    current = data
    for key in keys:
        if not isinstance(current, dict) or key not in current:
            return default
        current = current[key]
    return current
