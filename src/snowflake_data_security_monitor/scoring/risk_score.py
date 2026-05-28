"""Risk scoring utilities."""

from __future__ import annotations

from collections import Counter
from typing import Any

from snowflake_data_security_monitor.models import Finding
from snowflake_data_security_monitor.models.severity import Severity

DEFAULT_SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.CRITICAL: 100,
    Severity.HIGH: 70,
    Severity.MEDIUM: 40,
    Severity.LOW: 15,
    Severity.INFORMATIONAL: 5,
}


def calculate_finding_score(
    finding: Finding,
    severity_weights: dict[Severity, int] | None = None,
) -> int:
    """Return the configured score for a single finding severity."""
    weights = severity_weights or DEFAULT_SEVERITY_WEIGHTS
    return weights[finding.severity]


def calculate_risk_score(
    findings: list[Finding],
    severity_weights: dict[Severity, int] | None = None,
) -> int:
    """Calculate total risk score across findings."""
    return sum(calculate_finding_score(finding, severity_weights) for finding in findings)


def calculate_average_risk_score(
    findings: list[Finding],
    severity_weights: dict[Severity, int] | None = None,
) -> float:
    """Calculate average risk score across findings."""
    if not findings:
        return 0.0
    return round(calculate_risk_score(findings, severity_weights) / len(findings), 2)


def group_findings_by_severity(findings: list[Finding]) -> dict[str, int]:
    """Count findings by severity."""
    counts = Counter(finding.severity.value for finding in findings)
    return dict(sorted(counts.items()))


def get_finding_category(finding: Finding) -> str:
    """Return a finding category for aggregation."""
    category = finding.evidence.get("category")
    if isinstance(category, str) and category.strip():
        return category.strip()
    return finding.resource_type.lower()


def group_findings_by_category(findings: list[Finding]) -> dict[str, int]:
    """Count findings by category."""
    counts = Counter(get_finding_category(finding) for finding in findings)
    return dict(sorted(counts.items()))


def build_risk_score_summary(
    findings: list[Finding],
    severity_weights: dict[Severity, int] | None = None,
) -> dict[str, Any]:
    """Build a summary structure for dashboarding and CSV export."""
    return {
        "total_findings": len(findings),
        "total_risk_score": calculate_risk_score(findings, severity_weights),
        "average_risk_score": calculate_average_risk_score(findings, severity_weights),
        "findings_by_severity": group_findings_by_severity(findings),
        "findings_by_category": group_findings_by_category(findings),
    }
