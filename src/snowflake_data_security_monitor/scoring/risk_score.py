"""Risk scoring placeholder."""

from __future__ import annotations

from snowflake_data_security_monitor.models import Finding


def calculate_risk_score(findings: list[Finding]) -> int:
    """Calculate a risk score when scoring rules are implemented."""
    raise NotImplementedError("Risk scoring is not implemented yet.")
