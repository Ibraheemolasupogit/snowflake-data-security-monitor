"""Markdown report generation utilities."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from string import Template
from typing import Any

from snowflake_data_security_monitor.models import Finding
from snowflake_data_security_monitor.scoring import (
    build_risk_score_summary,
    get_finding_category,
)

TEMPLATE_DIR = Path(__file__).parent / "templates"


def write_executive_summary(findings: list[Finding], output_path: Path) -> None:
    """Write an executive summary Markdown report."""
    context = _build_report_context(findings)
    _write_template("executive_summary.md.tmpl", output_path, context)


def write_technical_report(findings: list[Finding], output_path: Path) -> None:
    """Write a detailed technical Markdown report."""
    context = _build_report_context(findings)
    _write_template("technical_report.md.tmpl", output_path, context)


def write_remediation_plan(findings: list[Finding], output_path: Path) -> None:
    """Write a remediation plan Markdown report."""
    context = _build_report_context(findings)
    _write_template("remediation_plan.md.tmpl", output_path, context)


def write_markdown_reports(findings: list[Finding], report_dir: Path) -> None:
    """Write all Milestone 7 Markdown reports to a directory."""
    write_executive_summary(findings, report_dir / "executive_summary.md")
    write_technical_report(findings, report_dir / "technical_report.md")
    write_remediation_plan(findings, report_dir / "remediation_plan.md")


def _write_template(template_name: str, output_path: Path, context: dict[str, str]) -> None:
    template = Template((TEMPLATE_DIR / template_name).read_text(encoding="utf-8"))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(template.safe_substitute(context), encoding="utf-8")


def _build_report_context(findings: list[Finding]) -> dict[str, str]:
    summary = build_risk_score_summary(findings)
    return {
        "total_findings": str(summary["total_findings"]),
        "total_risk_score": str(summary["total_risk_score"]),
        "average_risk_score": str(summary["average_risk_score"]),
        "severity_summary": _format_counts(summary["findings_by_severity"]),
        "category_summary": _format_counts(summary["findings_by_category"]),
        "top_risks": _format_top_risks(findings),
        "recommended_priorities": _format_recommended_priorities(findings),
        "technical_findings": _format_technical_findings(findings),
        "remediation_actions": _format_remediation_actions(findings),
        "data_notice": _format_data_notice(findings),
    }


def _format_counts(counts: dict[str, int]) -> str:
    if not counts:
        return "- None"
    return "\n".join(f"- {name}: {count}" for name, count in counts.items())


def _format_data_notice(findings: list[Finding]) -> str:
    if findings and all(finding.evidence.get("demo_data") is True for finding in findings):
        return (
            "Demo data notice: this report uses synthetic sample findings only and was "
            "not generated from a real Snowflake environment."
        )
    return "Data notice: review report provenance before sharing outside the security team."


def _format_top_risks(findings: list[Finding], limit: int = 5) -> str:
    top_findings = sorted(
        findings,
        key=lambda finding: (
            _severity_rank(finding.severity.value),
            finding.control_id,
            finding.resource_name,
        ),
    )[:limit]
    if not top_findings:
        return "- No findings identified."
    return "\n".join(
        f"- [{finding.severity.value.upper()}] {finding.title} on "
        f"{finding.resource_type} `{finding.resource_name}`"
        for finding in top_findings
    )


def _format_recommended_priorities(findings: list[Finding]) -> str:
    if not findings:
        return "- Continue monitoring and validate controls regularly."

    priorities = []
    severity_counts: defaultdict[str, int] = defaultdict(int)
    for finding in findings:
        severity_counts[finding.severity.value] += 1

    if severity_counts["critical"] or severity_counts["high"]:
        priorities.append("- Prioritize critical and high severity access-control findings.")
    if any(get_finding_category(finding) in {"identity", "user"} for finding in findings):
        priorities.append("- Review privileged and dormant user access.")
    if any(get_finding_category(finding) in {"stage", "share"} for finding in findings):
        priorities.append("- Review external data movement and sharing paths.")
    priorities.append("- Track remediation owners and status until closure.")
    return "\n".join(priorities)


def _format_technical_findings(findings: list[Finding]) -> str:
    if not findings:
        return "No technical findings identified."

    sections = []
    for index, finding in enumerate(findings, start=1):
        sections.append(
            "\n".join(
                [
                    f"### {index}. {finding.title}",
                    "",
                    f"- Control ID: `{finding.control_id}`",
                    f"- Severity: `{finding.severity.value}`",
                    f"- Category: `{get_finding_category(finding)}`",
                    f"- Resource: `{finding.resource_type}/{finding.resource_name}`",
                    f"- Description: {finding.description}",
                    f"- Evidence: {_format_evidence(finding.evidence)}",
                    f"- Recommendation: {finding.remediation}",
                ]
            )
        )
    return "\n\n".join(sections)


def _format_remediation_actions(findings: list[Finding]) -> str:
    if not findings:
        return (
            "| Severity | Category | Owner | Status | Action |\n"
            "| --- | --- | --- | --- | --- |\n"
        )

    rows = ["| Severity | Category | Owner | Status | Action |", "| --- | --- | --- | --- | --- |"]
    for finding in sorted(
        findings,
        key=lambda item: (_severity_rank(item.severity.value), get_finding_category(item)),
    ):
        owner = _evidence_string(finding.evidence.get("owner"), default="Unassigned")
        status = _evidence_string(finding.evidence.get("status"), default="Open")
        rows.append(
            "| "
            f"{finding.severity.value} | "
            f"{get_finding_category(finding)} | "
            f"{owner} | "
            f"{status} | "
            f"{finding.remediation} |"
        )
    return "\n".join(rows)


def _format_evidence(evidence: dict[str, Any]) -> str:
    if not evidence:
        return "None provided"
    return ", ".join(f"{key}={_evidence_string(value)}" for key, value in evidence.items())


def _evidence_string(value: object, default: str = "") -> str:
    if value in (None, ""):
        return default
    return str(value).replace("|", "/")


def _severity_rank(severity: str) -> int:
    return {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "informational": 4,
    }.get(severity, 99)
