"""Policy coverage checks."""

from __future__ import annotations

from snowflake_data_security_monitor.checks.helpers import (
    first_non_empty,
    get_record_value,
    is_truthy,
)
from snowflake_data_security_monitor.models import Finding, Severity


class MissingMaskingPolicyIndicatorsCheck:
    """Detect sensitive tables or columns without masking policy indicators."""

    control_id = "SFM-009"

    def evaluate(self, records: list[dict[str, object]]) -> list[Finding]:
        """Return findings for records missing masking policy indicators."""
        findings: list[Finding] = []
        for record in records:
            if _is_sensitive(record) and not _has_policy_indicator(
                record,
                "has_masking_policy",
                "masking_policy",
                "masking_policy_name",
                "masking_policy_count",
            ):
                resource_name = first_non_empty(record, ("table_name", "column_name", "name"))
                findings.append(
                    Finding(
                        control_id=self.control_id,
                        title="Missing masking policy indicator",
                        severity=Severity.MEDIUM,
                        resource_type="TABLE",
                        resource_name=str(resource_name or "UNKNOWN_TABLE"),
                        description="Sensitive metadata lacks a masking policy indicator.",
                        remediation="Review whether a masking policy should protect this data.",
                        evidence={"sensitive": True},
                    )
                )
        return findings


class MissingRowAccessPolicyIndicatorsCheck:
    """Detect sensitive tables without row access policy indicators."""

    control_id = "SFM-010"

    def evaluate(self, records: list[dict[str, object]]) -> list[Finding]:
        """Return findings for records missing row access policy indicators."""
        findings: list[Finding] = []
        for record in records:
            if _is_sensitive(record) and not _has_policy_indicator(
                record,
                "has_row_access_policy",
                "row_access_policy",
                "row_access_policy_name",
                "row_access_policy_count",
            ):
                resource_name = first_non_empty(record, ("table_name", "name"))
                findings.append(
                    Finding(
                        control_id=self.control_id,
                        title="Missing row access policy indicator",
                        severity=Severity.MEDIUM,
                        resource_type="TABLE",
                        resource_name=str(resource_name or "UNKNOWN_TABLE"),
                        description="Sensitive metadata lacks a row access policy indicator.",
                        remediation="Review whether a row access policy should restrict this data.",
                        evidence={"sensitive": True},
                    )
                )
        return findings


def _is_sensitive(record: dict[str, object]) -> bool:
    sensitivity = first_non_empty(
        record,
        (
            "is_sensitive",
            "sensitive",
            "contains_sensitive_data",
            "classification",
            "data_classification",
        ),
    )
    if isinstance(sensitivity, str) and sensitivity.upper() in {"PII", "PHI", "PCI", "SENSITIVE"}:
        return True
    return is_truthy(sensitivity)


def _has_policy_indicator(record: dict[str, object], *keys: str) -> bool:
    for key in keys:
        value = get_record_value(record, key)
        if isinstance(value, int | float):
            return value > 0
        if is_truthy(value):
            return True
        if isinstance(value, str) and value.strip():
            return True
    return False
