from __future__ import annotations

from pathlib import Path

from snowflake_data_security_monitor.models import Finding, Severity
from snowflake_data_security_monitor.reporting import (
    write_executive_summary,
    write_markdown_reports,
    write_remediation_plan,
    write_technical_report,
)


def make_report_finding(
    control_id: str,
    severity: Severity,
    category: str,
    owner: str = "Data Security",
    status: str = "Open",
) -> Finding:
    return Finding(
        control_id=control_id,
        title=f"Finding {control_id}",
        severity=severity,
        resource_type="USER",
        resource_name="EXAMPLE_RESOURCE",
        description="Example finding description.",
        remediation="Review and remediate the risky configuration.",
        evidence={
            "category": category,
            "owner": owner,
            "status": status,
            "detail": "fake metadata only",
            "demo_data": True,
        },
    )


def test_write_executive_summary_contains_risk_overview(tmp_path: Path) -> None:
    output_path = tmp_path / "reports" / "executive_summary.md"
    findings = [
        make_report_finding("SFM-001", Severity.CRITICAL, "identity"),
        make_report_finding("SFM-005", Severity.HIGH, "access"),
    ]

    write_executive_summary(findings, output_path)

    report = output_path.read_text(encoding="utf-8")
    assert "# Executive Summary" in report
    assert "synthetic sample findings only" in report
    assert "Total findings: 2" in report
    assert "- critical: 1" in report
    assert "- high: 1" in report
    assert "[CRITICAL] Finding SFM-001" in report
    assert "Prioritize critical and high severity access-control findings." in report


def test_write_technical_report_contains_detailed_findings(tmp_path: Path) -> None:
    output_path = tmp_path / "reports" / "technical_report.md"
    findings = [make_report_finding("SFM-007", Severity.MEDIUM, "stage")]

    write_technical_report(findings, output_path)

    report = output_path.read_text(encoding="utf-8")
    assert "# Technical Report" in report
    assert "### 1. Finding SFM-007" in report
    assert "Control ID: `SFM-007`" in report
    assert "Category: `stage`" in report
    assert "detail=fake metadata only" in report


def test_write_remediation_plan_contains_action_table(tmp_path: Path) -> None:
    output_path = tmp_path / "reports" / "remediation_plan.md"
    findings = [make_report_finding("SFM-009", Severity.MEDIUM, "data-protection")]

    write_remediation_plan(findings, output_path)

    report = output_path.read_text(encoding="utf-8")
    assert "# Remediation Plan" in report
    assert "| Severity | Category | Owner | Status | Action |" in report
    assert "| medium | data-protection | Data Security | Open |" in report


def test_write_markdown_reports_creates_expected_report_files(tmp_path: Path) -> None:
    report_dir = tmp_path / "reports"
    findings = [make_report_finding("SFM-010", Severity.MEDIUM, "data-protection")]

    write_markdown_reports(findings, report_dir)

    assert (report_dir / "executive_summary.md").exists()
    assert (report_dir / "technical_report.md").exists()
    assert (report_dir / "remediation_plan.md").exists()


def test_markdown_reports_handle_empty_findings(tmp_path: Path) -> None:
    output_path = tmp_path / "reports" / "executive_summary.md"

    write_executive_summary([], output_path)

    report = output_path.read_text(encoding="utf-8")
    assert "Total findings: 0" in report
    assert "- None" in report
    assert "- No findings identified." in report
