"""Markdown reporting placeholder."""

from __future__ import annotations

from pathlib import Path

from snowflake_data_security_monitor.models import Finding


def write_technical_report(findings: list[Finding], output_path: Path) -> None:
    """Write a technical report when reporting is implemented."""
    raise NotImplementedError("Markdown reporting is not implemented yet.")
