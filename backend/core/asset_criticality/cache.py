"""
Simple JSON-based file cache with TTL support.
Used to avoid re-scanning the same IP within a configurable window.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

CACHE_DIR  = Path(__file__).parent.parent / "cache"
CACHE_TTL_H = 24  # hours before a cached result expires


def _cache_path(name: str) -> Path:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    return CACHE_DIR / f"{name}.json"


def cache_get(store: str, key: str) -> dict | None:
    """Return cached value for key if it exists and is not expired, else None."""
    path = _cache_path(store)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return None

    entry = data.get(key)
    if not entry:
        return None

    try:
        cached_at = datetime.fromisoformat(entry["cached_at"])
        if cached_at.tzinfo is None:
            cached_at = cached_at.replace(tzinfo=timezone.utc)
        age_h = (datetime.now(timezone.utc) - cached_at).total_seconds() / 3600
    except (ValueError, KeyError):
        return None

    if age_h >= CACHE_TTL_H:
        return None  # expired

    return entry["value"]


def cache_set(store: str, key: str, value: dict) -> None:
    """Write value into the cache store under key with current timestamp."""
    path = _cache_path(store)
    try:
        data = json.loads(path.read_text()) if path.exists() else {}
    except (json.JSONDecodeError, OSError):
        data = {}

    data[key] = {
        "cached_at": datetime.now(timezone.utc).isoformat(),
        "value": value,
    }
    path.write_text(json.dumps(data, indent=2, default=str))