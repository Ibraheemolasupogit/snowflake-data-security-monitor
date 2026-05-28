"""CSV output exporters."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from snowflake_data_security_monitor.models import Finding


def write_findings_csv(findings: list[Finding], output_path: Path) -> None:
    """Write findings to a CSV file."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "control_id",
        "title",
        "severity",
        "resource_type",
        "resource_name",
        "description",
        "remediation",
    ]
    with output_path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        for finding in findings:
            writer.writerow(
                {
                    "control_id": finding.control_id,
                    "title": finding.title,
                    "severity": finding.severity.value,
                    "resource_type": finding.resource_type,
                    "resource_name": finding.resource_name,
                    "description": finding.description,
                    "remediation": finding.remediation,
                }
            )


def write_risk_score_summary_csv(summary: dict[str, Any], output_path: Path) -> None:
    """Write risk score summary rows to a CSV file."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    rows = _summary_rows(summary)
    with output_path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=["metric", "name", "value"])
        writer.writeheader()
        writer.writerows(rows)


def _summary_rows(summary: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = [
        {"metric": "total_findings", "name": "all", "value": summary["total_findings"]},
        {"metric": "total_risk_score", "name": "all", "value": summary["total_risk_score"]},
        {
            "metric": "average_risk_score",
            "name": "all",
            "value": summary["average_risk_score"],
        },
    ]
    if "demo_notice" in summary:
        rows.append({"metric": "demo_notice", "name": "all", "value": summary["demo_notice"]})

    for severity, count in summary.get("findings_by_severity", {}).items():
        rows.append({"metric": "findings_by_severity", "name": severity, "value": count})

    for category, count in summary.get("findings_by_category", {}).items():
        rows.append({"metric": "findings_by_category", "name": category, "value": count})

    return rows
