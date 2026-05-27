"""Compliance mapping placeholder."""

from __future__ import annotations

from snowflake_data_security_monitor.models import Finding


def map_findings_to_frameworks(findings: list[Finding]) -> list[dict[str, object]]:
    """Map findings to compliance frameworks when mappings are implemented."""
    raise NotImplementedError("Compliance mapping is not implemented yet.")
