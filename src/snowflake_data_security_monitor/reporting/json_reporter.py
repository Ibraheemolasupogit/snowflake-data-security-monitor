"""JSON reporting placeholder."""

from __future__ import annotations

from pathlib import Path

from snowflake_data_security_monitor.models import Finding


def write_findings_json(findings: list[Finding], output_path: Path) -> None:
    """Write findings JSON when reporting is implemented."""
    raise NotImplementedError("JSON reporting is not implemented yet.")
