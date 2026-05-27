"""PUBLIC role risk check placeholder."""

from __future__ import annotations

from snowflake_data_security_monitor.models import Finding


class PublicRoleRiskyPrivilegesCheck:
    """Future check for risky grants to PUBLIC."""

    control_id = "SFM-002"

    def evaluate(self, records: list[dict[str, object]]) -> list[Finding]:
        """Evaluate PUBLIC role grants when grant models are implemented."""
        raise NotImplementedError("PUBLIC role checks are not implemented yet.")
