"""Share security checks."""

from __future__ import annotations

from snowflake_data_security_monitor.checks.helpers import first_non_empty, get_record_value
from snowflake_data_security_monitor.models import Finding, Severity


class OutboundSharesCheck:
    """Detect outbound shares."""

    control_id = "SFM-008"

    def evaluate(self, records: list[dict[str, object]]) -> list[Finding]:
        """Return findings for outbound shares."""
        findings: list[Finding] = []
        for record in records:
            share_name = first_non_empty(record, ("share_name", "name"))
            direction = get_record_value(record, "direction", "kind")
            accounts = first_non_empty(record, ("accounts", "consumer_accounts"))
            if _is_outbound_share(direction, accounts):
                findings.append(
                    Finding(
                        control_id=self.control_id,
                        title="Outbound share detected",
                        severity=Severity.MEDIUM,
                        resource_type="SHARE",
                        resource_name=str(share_name or "UNKNOWN_SHARE"),
                        description="An outbound share exposes governed data to consumers.",
                        remediation=(
                            "Review share consumers, shared objects, and business approval."
                        ),
                        evidence={
                            "direction": str(direction or ""),
                            "accounts": str(accounts or ""),
                        },
                    )
                )
        return findings


def _is_outbound_share(direction: object, accounts: object) -> bool:
    normalized_direction = str(direction or "").upper()
    return normalized_direction in {"OUTBOUND", "TO"} or bool(accounts)
