"""Generate fake/demo sample outputs for portfolio review."""

from __future__ import annotations

from pathlib import Path

from snowflake_data_security_monitor.models import Finding, Severity
from snowflake_data_security_monitor.reporting import (
    write_findings_csv,
    write_findings_json,
    write_markdown_reports,
    write_risk_score_summary_csv,
)
from snowflake_data_security_monitor.scoring import build_risk_score_summary

DEMO_NOTICE = (
    "DEMO DATA ONLY: this sample is synthetic and was not collected from a real "
    "Snowflake environment."
)
DEMO_NOTICE_CSV = (
    "DEMO DATA ONLY - synthetic sample output, not collected from a real Snowflake "
    "environment"
)


def build_demo_findings() -> list[Finding]:
    """Return deterministic fake findings for sample outputs."""
    return [
        Finding(
            control_id="SFM-001",
            title="User has ACCOUNTADMIN role",
            severity=Severity.CRITICAL,
            resource_type="USER",
            resource_name="DEMO_ADMIN_USER",
            description=f"{DEMO_NOTICE} A demo user is directly assigned ACCOUNTADMIN.",
            remediation="Review and remove ACCOUNTADMIN unless explicitly required.",
            evidence={
                "category": "identity",
                "role": "ACCOUNTADMIN",
                "owner": "Data Security",
                "status": "Open",
                "demo_data": True,
            },
        ),
        Finding(
            control_id="SFM-003",
            title="Dormant user detected",
            severity=Severity.MEDIUM,
            resource_type="USER",
            resource_name="DEMO_DORMANT_USER",
            description=f"{DEMO_NOTICE} A demo user has no recent login activity.",
            remediation="Confirm ownership and disable or remove unused access.",
            evidence={
                "category": "identity",
                "last_success_login": "2025-01-01T00:00:00+00:00",
                "owner": "IAM",
                "status": "Open",
                "demo_data": True,
            },
        ),
        Finding(
            control_id="SFM-005",
            title="Risky privilege granted to PUBLIC",
            severity=Severity.HIGH,
            resource_type="ROLE",
            resource_name="PUBLIC",
            description=f"{DEMO_NOTICE} PUBLIC has a risky demo privilege.",
            remediation="Revoke broad or write-capable privileges from PUBLIC.",
            evidence={
                "category": "access",
                "privilege": "OWNERSHIP",
                "granted_on": "DATABASE",
                "owner": "Platform Security",
                "status": "Open",
                "demo_data": True,
            },
        ),
        Finding(
            control_id="SFM-007",
            title="External stage detected",
            severity=Severity.MEDIUM,
            resource_type="STAGE",
            resource_name="DEMO_EXTERNAL_STAGE",
            description=f"{DEMO_NOTICE} A demo external stage points to object storage.",
            remediation="Review storage integration, stage grants, and business approval.",
            evidence={
                "category": "stage",
                "stage_url": "s3://demo-bucket/path",
                "owner": "Data Platform",
                "status": "In Review",
                "demo_data": True,
            },
        ),
        Finding(
            control_id="SFM-008",
            title="Outbound share detected",
            severity=Severity.MEDIUM,
            resource_type="SHARE",
            resource_name="DEMO_OUTBOUND_SHARE",
            description=f"{DEMO_NOTICE} A demo outbound share has external consumers.",
            remediation="Validate consumers, shared objects, and approval evidence.",
            evidence={
                "category": "share",
                "accounts": "DEMO_CONSUMER_ACCOUNT",
                "owner": "Data Governance",
                "status": "Open",
                "demo_data": True,
            },
        ),
        Finding(
            control_id="SFM-009",
            title="Missing masking policy indicator",
            severity=Severity.MEDIUM,
            resource_type="TABLE",
            resource_name="DEMO_CUSTOMERS",
            description=f"{DEMO_NOTICE} A sensitive demo table lacks a masking indicator.",
            remediation="Review whether masking should protect sensitive columns.",
            evidence={
                "category": "data-protection",
                "sensitive": True,
                "owner": "Data Governance",
                "status": "Planned",
                "demo_data": True,
            },
        ),
    ]


def generate_sample_outputs(
    output_dir: Path = Path("outputs/sample"),
    report_dir: Path = Path("reports/sample"),
) -> None:
    """Generate fake sample JSON, CSV, risk summary, and Markdown reports."""
    findings = build_demo_findings()
    write_findings_json(findings, output_dir / "findings.json")
    write_findings_csv(findings, output_dir / "findings.csv")
    risk_score_summary = build_risk_score_summary(findings)
    risk_score_summary["demo_notice"] = DEMO_NOTICE_CSV
    write_risk_score_summary_csv(
        risk_score_summary,
        output_dir / "risk_score_summary.csv",
    )
    write_markdown_reports(findings, report_dir)


def main() -> None:
    """Generate sample output files."""
    generate_sample_outputs()


if __name__ == "__main__":
    main()
