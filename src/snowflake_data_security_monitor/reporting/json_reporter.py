"""JSON output exporters."""

from __future__ import annotations

import json
from pathlib import Path

from snowflake_data_security_monitor.models import Finding


def write_findings_json(findings: list[Finding], output_path: Path) -> None:
    """Write findings to a JSON file."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = [finding.model_dump(mode="json") for finding in findings]
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
