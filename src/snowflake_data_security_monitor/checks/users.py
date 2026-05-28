"""User lifecycle security checks."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from snowflake_data_security_monitor.checks.helpers import (
    get_record_value,
    is_truthy,
    parse_datetime,
)
from snowflake_data_security_monitor.models import Finding, Severity


class DormantUsersCheck:
    """Detect users with old or missing successful login activity."""

    control_id = "SFM-003"

    def __init__(self, dormant_user_days: int = 90, reference_time: datetime | None = None) -> None:
        self.dormant_user_days = dormant_user_days
        self.reference_time = reference_time or datetime.now(UTC)

    def evaluate(self, records: list[dict[str, object]]) -> list[Finding]:
        """Return findings for dormant users."""
        findings: list[Finding] = []
        cutoff = self.reference_time - timedelta(days=self.dormant_user_days)

        for record in records:
            user_name = get_record_value(record, "name", "user_name", "grantee_name")
            last_login_value = get_record_value(
                record, "last_success_login", "last_login", "event_timestamp"
            )
            last_login = parse_datetime(last_login_value)
            if last_login is None or last_login < cutoff:
                findings.append(
                    Finding(
                        control_id=self.control_id,
                        title="Dormant user detected",
                        severity=Severity.MEDIUM,
                        resource_type="USER",
                        resource_name=str(user_name or "UNKNOWN_USER"),
                        description="A user has no recent successful login activity.",
                        remediation="Review whether the account is still required.",
                        evidence={
                            "last_success_login": str(last_login_value or ""),
                            "dormant_user_days": self.dormant_user_days,
                        },
                    )
                )
        return findings


class DisabledUsersWithActiveGrantsCheck:
    """Detect disabled users that still have active grants."""

    control_id = "SFM-004"

    def evaluate(self, records: list[dict[str, object]]) -> list[Finding]:
        """Return findings for disabled users retaining active grants."""
        findings: list[Finding] = []
        for record in records:
            disabled = get_record_value(record, "disabled", "is_disabled")
            deleted_on = get_record_value(record, "deleted_on", "revoked_on")
            grant_name = get_record_value(record, "role", "role_name", "granted_role", "privilege")
            user_name = get_record_value(record, "name", "user_name", "grantee_name")

            if is_truthy(disabled) and grant_name and not deleted_on:
                findings.append(
                    Finding(
                        control_id=self.control_id,
                        title="Disabled user has active grants",
                        severity=Severity.HIGH,
                        resource_type="USER",
                        resource_name=str(user_name or "UNKNOWN_USER"),
                        description="A disabled user still has one or more active grants.",
                        remediation="Revoke active grants from disabled users.",
                        evidence={
                            "grant": str(grant_name),
                            "disabled": True,
                        },
                    )
                )
        return findings
