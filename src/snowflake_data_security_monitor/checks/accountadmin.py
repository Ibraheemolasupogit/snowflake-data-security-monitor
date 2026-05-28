"""ACCOUNTADMIN risk checks."""

from __future__ import annotations

from snowflake_data_security_monitor.checks.helpers import get_record_value, is_truthy
from snowflake_data_security_monitor.models import Finding, Severity


class AccountAdminUsersCheck:
    """Detect users directly assigned the ACCOUNTADMIN role."""

    control_id = "SFM-001"

    def evaluate(self, records: list[dict[str, object]]) -> list[Finding]:
        """Return findings for direct ACCOUNTADMIN user grants."""
        findings: list[Finding] = []
        for record in records:
            role = get_record_value(record, "role", "role_name", "granted_role", "name")
            grantee_type = get_record_value(record, "grantee_type", "granted_to")
            grantee_name = get_record_value(record, "grantee_name", "user_name", "name")

            if _is_accountadmin_role(role) and _is_user_grant(grantee_type):
                findings.append(
                    Finding(
                        control_id=self.control_id,
                        title="User has ACCOUNTADMIN role",
                        severity=Severity.CRITICAL,
                        resource_type="USER",
                        resource_name=str(grantee_name or "UNKNOWN_USER"),
                        description="A user is directly assigned the ACCOUNTADMIN role.",
                        remediation=(
                            "Review the assignment and remove ACCOUNTADMIN unless it is "
                            "explicitly required."
                        ),
                        evidence={
                            "role": str(role),
                            "grantee_type": str(grantee_type or "USER"),
                            "grantee_name": str(grantee_name or "UNKNOWN_USER"),
                        },
                    )
                )
        return findings


class ExcessiveAccountAdminUsersCheck:
    """Detect when ACCOUNTADMIN user assignments exceed a threshold."""

    control_id = "SFM-002"

    def __init__(self, max_accountadmin_users: int = 5) -> None:
        self.max_accountadmin_users = max_accountadmin_users

    def evaluate(self, records: list[dict[str, object]]) -> list[Finding]:
        """Return one finding when ACCOUNTADMIN user count is excessive."""
        accountadmin_users = {
            str(get_record_value(record, "grantee_name", "user_name", "name"))
            for record in records
            if _is_accountadmin_role(
                get_record_value(record, "role", "role_name", "granted_role", "name")
            )
            and _is_user_grant(get_record_value(record, "grantee_type", "granted_to"))
            and get_record_value(record, "grantee_name", "user_name", "name")
        }

        if len(accountadmin_users) <= self.max_accountadmin_users:
            return []

        return [
            Finding(
                control_id=self.control_id,
                title="Excessive ACCOUNTADMIN users",
                severity=Severity.HIGH,
                resource_type="ROLE",
                resource_name="ACCOUNTADMIN",
                description="The number of users assigned ACCOUNTADMIN exceeds the threshold.",
                remediation="Reduce ACCOUNTADMIN assignments and use least-privilege roles.",
                evidence={
                    "accountadmin_user_count": len(accountadmin_users),
                    "max_accountadmin_users": self.max_accountadmin_users,
                },
            )
        ]


def _is_accountadmin_role(role: object) -> bool:
    return str(role or "").upper() == "ACCOUNTADMIN"


def _is_user_grant(grantee_type: object) -> bool:
    if grantee_type is None:
        return True
    return str(grantee_type).upper() == "USER" or is_truthy(grantee_type)
