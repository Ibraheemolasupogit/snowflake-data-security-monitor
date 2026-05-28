"""Stage security checks."""

from __future__ import annotations

from snowflake_data_security_monitor.checks.helpers import first_non_empty, get_record_value
from snowflake_data_security_monitor.models import Finding, Severity

EXTERNAL_STAGE_URL_PREFIXES = ("s3://", "azure://", "gcs://", "http://", "https://")


class ExternalStagesCheck:
    """Detect external stages."""

    control_id = "SFM-007"

    def evaluate(self, records: list[dict[str, object]]) -> list[Finding]:
        """Return findings for external stages."""
        findings: list[Finding] = []
        for record in records:
            stage_name = first_non_empty(record, ("stage_name", "name"))
            stage_url = get_record_value(record, "stage_url", "url")
            stage_type = get_record_value(record, "stage_type", "type")
            if _is_external_stage(stage_url, stage_type):
                findings.append(
                    Finding(
                        control_id=self.control_id,
                        title="External stage detected",
                        severity=Severity.MEDIUM,
                        resource_type="STAGE",
                        resource_name=str(stage_name or "UNKNOWN_STAGE"),
                        description="An external stage may allow data movement outside Snowflake.",
                        remediation=(
                            "Review external stage ownership, access, and storage location."
                        ),
                        evidence={
                            "stage_url": str(stage_url or ""),
                            "stage_type": str(stage_type or ""),
                        },
                    )
                )
        return findings


def _is_external_stage(stage_url: object, stage_type: object) -> bool:
    if str(stage_type or "").upper() == "EXTERNAL":
        return True
    normalized_url = str(stage_url or "").lower()
    return normalized_url.startswith(EXTERNAL_STAGE_URL_PREFIXES)
