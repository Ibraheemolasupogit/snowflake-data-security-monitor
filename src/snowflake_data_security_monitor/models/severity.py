"""Severity model definitions."""

from __future__ import annotations

from enum import StrEnum


class Severity(StrEnum):
    """Supported finding severities."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"
