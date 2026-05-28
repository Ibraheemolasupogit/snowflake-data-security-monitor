"""Role privilege risk checks."""

from __future__ import annotations

from snowflake_data_security_monitor.checks.helpers import get_record_value
from snowflake_data_security_monitor.models import Finding, Severity

RISKY_PUBLIC_PRIVILEGES = {
    "ALL",
    "ALL PRIVILEGES",
    "OWNERSHIP",
    "MODIFY",
    "MONITOR",
    "OPERATE",
    "CREATE ACCOUNT",
    "CREATE DATABASE",
    "CREATE INTEGRATION",
    "CREATE SHARE",
    "CREATE STAGE",
    "CREATE WAREHOUSE",
    "INSERT",
    "UPDATE",
    "DELETE",
    "TRUNCATE",
}

BROAD_PRIVILEGES = {
    "ALL",
    "ALL PRIVILEGES",
    "OWNERSHIP",
    "MODIFY",
    "CREATE DATABASE",
    "CREATE INTEGRATION",
    "CREATE SHARE",
    "CREATE WAREHOUSE",
}


class PublicRoleRiskyPrivilegesCheck:
    """Detect risky privileges granted to PUBLIC."""

    control_id = "SFM-005"

    def evaluate(self, records: list[dict[str, object]]) -> list[Finding]:
        """Return findings for risky PUBLIC grants."""
        findings: list[Finding] = []
        for record in records:
            grantee_name = get_record_value(record, "grantee_name", "role", "role_name")
            privilege = get_record_value(record, "privilege")
            if str(grantee_name or "").upper() == "PUBLIC" and _is_risky_public_privilege(
                privilege
            ):
                findings.append(
                    Finding(
                        control_id=self.control_id,
                        title="Risky privilege granted to PUBLIC",
                        severity=Severity.HIGH,
                        resource_type="ROLE",
                        resource_name="PUBLIC",
                        description="A risky privilege is granted to the PUBLIC role.",
                        remediation="Revoke broad or write-capable privileges from PUBLIC.",
                        evidence={
                            "privilege": str(privilege),
                            "granted_on": str(get_record_value(record, "granted_on") or ""),
                            "object_name": str(get_record_value(record, "name") or ""),
                        },
                    )
                )
        return findings


class BroadRolePrivilegesCheck:
    """Detect broad privileges granted to roles."""

    control_id = "SFM-006"

    def evaluate(self, records: list[dict[str, object]]) -> list[Finding]:
        """Return findings for broad role privileges."""
        findings: list[Finding] = []
        for record in records:
            privilege = get_record_value(record, "privilege")
            granted_on = get_record_value(record, "granted_on")
            grantee_name = get_record_value(record, "grantee_name", "role_name", "role")
            object_name = get_record_value(record, "name", "object_name")

            if _is_broad_privilege(privilege, granted_on):
                findings.append(
                    Finding(
                        control_id=self.control_id,
                        title="Broad role privilege detected",
                        severity=Severity.HIGH,
                        resource_type="ROLE",
                        resource_name=str(grantee_name or "UNKNOWN_ROLE"),
                        description="A role has a broad or highly privileged grant.",
                        remediation=(
                            "Review the grant and replace broad privileges with narrowly "
                            "scoped permissions."
                        ),
                        evidence={
                            "privilege": str(privilege),
                            "granted_on": str(granted_on or ""),
                            "object_name": str(object_name or ""),
                        },
                    )
                )
        return findings


def _is_risky_public_privilege(privilege: object) -> bool:
    return str(privilege or "").upper() in RISKY_PUBLIC_PRIVILEGES


def _is_broad_privilege(privilege: object, granted_on: object) -> bool:
    normalized_privilege = str(privilege or "").upper()
    normalized_granted_on = str(granted_on or "").upper()
    return normalized_privilege in BROAD_PRIVILEGES or (
        normalized_granted_on == "ACCOUNT"
        and normalized_privilege not in {"USAGE", "MONITOR USAGE"}
    )
