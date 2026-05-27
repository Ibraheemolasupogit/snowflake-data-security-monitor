"""Check base skeleton."""

from __future__ import annotations

from typing import Protocol

from snowflake_data_security_monitor.models import Finding


class SecurityCheck(Protocol):
    """Protocol for future security checks."""

    control_id: str

    def evaluate(self, records: list[dict[str, object]]) -> list[Finding]:
        """Evaluate collected records and return findings."""
        ...
