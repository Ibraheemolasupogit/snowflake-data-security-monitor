"""Shared helpers for metadata-driven security checks."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime


def get_record_value(record: dict[str, object], *keys: str) -> object | None:
    """Return a value from a record using case-insensitive key matching."""
    normalized = {key.lower(): value for key, value in record.items()}
    for key in keys:
        value = normalized.get(key.lower())
        if value is not None:
            return value
    return None


def is_truthy(value: object) -> bool:
    """Interpret common Snowflake string booleans safely."""
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "t", "yes", "y"}


def parse_datetime(value: object) -> datetime | None:
    """Parse common datetime values returned by mocked metadata records."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if not isinstance(value, str) or not value.strip():
        return None

    normalized = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def first_non_empty(record: dict[str, object], keys: Iterable[str]) -> object | None:
    """Return the first non-empty record value for the provided keys."""
    for key in keys:
        value = get_record_value(record, key)
        if value not in (None, ""):
            return value
    return None
