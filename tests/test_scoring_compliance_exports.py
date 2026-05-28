from __future__ import annotations

import csv
import json
from pathlib import Path

from snowflake_data_security_monitor.compliance import (
    load_compliance_mapping,
    map_finding_to_frameworks,
    map_findings_to_frameworks,
)
from snowflake_data_security_monitor.models import Finding, Severity
from snowflake_data_security_monitor.reporting import (
    write_findings_csv,
    write_findings_json,
    write_risk_score_summary_csv,
)
from snowflake_data_security_monitor.scoring import (
    build_risk_score_summary,
    calculate_average_risk_score,
    calculate_risk_score,
    group_findings_by_category,
    group_findings_by_severity,
)


def make_finding(
    control_id: str,
    severity: Severity,
    resource_type: str = "USER",
    category: str | None = None,
) -> Finding:
    evidence: dict[str, str | int | float | bool | None] = {}
    if category:
        evidence["category"] = category

    return Finding(
        control_id=control_id,
        title=f"Finding {control_id}",
        severity=severity,
        resource_type=resource_type,
        resource_name="RESOURCE",
        description="Description",
        remediation="Remediation",
        evidence=evidence,
    )


def test_risk_score_summary_calculates_totals_and_average() -> None:
    findings = [
        make_finding("SFM-001", Severity.CRITICAL),
        make_finding("SFM-005", Severity.HIGH),
        make_finding("SFM-009", Severity.MEDIUM),
    ]

    summary = build_risk_score_summary(findings)

    assert summary["total_findings"] == 3
    assert summary["total_risk_score"] == 210
    assert summary["average_risk_score"] == 70.0


def test_empty_risk_score_summary_is_safe() -> None:
    summary = build_risk_score_summary([])

    assert summary == {
        "total_findings": 0,
        "total_risk_score": 0,
        "average_risk_score": 0.0,
        "findings_by_severity": {},
        "findings_by_category": {},
    }


def test_severity_and_category_aggregation() -> None:
    findings = [
        make_finding("SFM-001", Severity.CRITICAL, category="identity"),
        make_finding("SFM-005", Severity.HIGH, category="access"),
        make_finding("SFM-006", Severity.HIGH, resource_type="ROLE"),
    ]

    assert group_findings_by_severity(findings) == {"critical": 1, "high": 2}
    assert group_findings_by_category(findings) == {"access": 1, "identity": 1, "role": 1}


def test_calculate_risk_score_supports_custom_weights() -> None:
    findings = [
        make_finding("SFM-001", Severity.CRITICAL),
        make_finding("SFM-002", Severity.HIGH),
    ]
    weights = {
        Severity.CRITICAL: 10,
        Severity.HIGH: 5,
        Severity.MEDIUM: 3,
        Severity.LOW: 1,
        Severity.INFORMATIONAL: 0,
    }

    assert calculate_risk_score(findings, weights) == 15
    assert calculate_average_risk_score(findings, weights) == 7.5


def test_compliance_mapping_lookup_returns_configured_frameworks(tmp_path: Path) -> None:
    mapping_path = tmp_path / "compliance_mapping.yaml"
    mapping_path.write_text(
        """
        mappings:
          SFM-001:
            cis:
              - CIS administrative access
            nist:
              - AC-6
            iso:
              - A.5.15
        """,
        encoding="utf-8",
    )
    mapping = load_compliance_mapping(mapping_path)
    finding = make_finding("SFM-001", Severity.CRITICAL)

    mapped = map_finding_to_frameworks(finding, mapping)

    assert mapped["cis"] == ["CIS administrative access"]
    assert mapped["nist"] == ["AC-6"]
    assert mapped["iso"] == ["A.5.15"]


def test_missing_compliance_mapping_returns_empty_framework_lists(tmp_path: Path) -> None:
    mapping_path = tmp_path / "compliance_mapping.yaml"
    mapping_path.write_text(
        """
        mappings:
          SFM-001:
            nist:
              - AC-6
        """,
        encoding="utf-8",
    )
    mapping = load_compliance_mapping(mapping_path)
    finding = make_finding("SFM-999", Severity.LOW)

    mapped = map_finding_to_frameworks(finding, mapping)

    assert mapped["cis"] == []
    assert mapped["nist"] == []
    assert mapped["iso"] == []


def test_map_findings_to_frameworks_maps_multiple_findings(tmp_path: Path) -> None:
    mapping_path = tmp_path / "compliance_mapping.yaml"
    mapping_path.write_text(
        """
        mappings:
          SFM-001:
            nist:
              - AC-6
        """,
        encoding="utf-8",
    )
    mapping = load_compliance_mapping(mapping_path)

    mapped = map_findings_to_frameworks(
        [
            make_finding("SFM-001", Severity.CRITICAL),
            make_finding("SFM-999", Severity.LOW),
        ],
        mapping,
    )

    assert len(mapped) == 2
    assert mapped[0]["nist"] == ["AC-6"]
    assert mapped[1]["nist"] == []


def test_write_findings_json_exports_findings(tmp_path: Path) -> None:
    output_path = tmp_path / "outputs" / "findings.json"
    finding = make_finding("SFM-001", Severity.CRITICAL)

    write_findings_json([finding], output_path)

    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload[0]["control_id"] == "SFM-001"
    assert payload[0]["severity"] == "critical"


def test_write_findings_csv_exports_findings(tmp_path: Path) -> None:
    output_path = tmp_path / "outputs" / "findings.csv"
    finding = make_finding("SFM-005", Severity.HIGH, resource_type="ROLE")

    write_findings_csv([finding], output_path)

    with output_path.open("r", encoding="utf-8", newline="") as file:
        rows = list(csv.DictReader(file))

    assert rows == [
        {
            "control_id": "SFM-005",
            "title": "Finding SFM-005",
            "severity": "high",
            "resource_type": "ROLE",
            "resource_name": "RESOURCE",
            "description": "Description",
            "remediation": "Remediation",
        }
    ]


def test_write_risk_score_summary_csv_exports_summary(tmp_path: Path) -> None:
    output_path = tmp_path / "outputs" / "risk_score_summary.csv"
    summary = build_risk_score_summary(
        [
            make_finding("SFM-001", Severity.CRITICAL, category="identity"),
            make_finding("SFM-005", Severity.HIGH, category="access"),
        ]
    )

    write_risk_score_summary_csv(summary, output_path)

    with output_path.open("r", encoding="utf-8", newline="") as file:
        rows = list(csv.DictReader(file))

    assert {"metric": "total_findings", "name": "all", "value": "2"} in rows
    assert {"metric": "findings_by_severity", "name": "critical", "value": "1"} in rows
    assert {"metric": "findings_by_category", "name": "identity", "value": "1"} in rows
