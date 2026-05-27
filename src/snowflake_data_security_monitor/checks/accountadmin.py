"""ACCOUNTADMIN risk check placeholder."""

from __future__ import annotations

from snowflake_data_security_monitor.models import Finding


class AccountAdminUsersCheck:
    """Future check for users assigned the ACCOUNTADMIN role."""

    control_id = "SFM-001"

    def evaluate(self, records: list[dict[str, object]]) -> list[Finding]:
        """Evaluate ACCOUNTADMIN usage when grant models are implemented."""
        raise NotImplementedError("ACCOUNTADMIN checks are not implemented yet.")
