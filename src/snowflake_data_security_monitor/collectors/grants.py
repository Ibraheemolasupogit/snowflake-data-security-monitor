"""Grant metadata collector."""

from __future__ import annotations

from snowflake_data_security_monitor.collectors.base import BaseSnowflakeCollector


class GrantsCollector(BaseSnowflakeCollector):
    """Collect Snowflake grants to users and roles."""

    sql_file_name = "grants_to_users.sql"
    grants_to_roles_sql_file_name = "grants_to_roles.sql"

    def collect_grants_to_users(self) -> list[dict[str, object]]:
        """Collect role grants assigned directly to users."""
        return self._execute_sql_file(self.sql_file_name)

    def collect_grants_to_roles(self) -> list[dict[str, object]]:
        """Collect object and role grants assigned to roles."""
        return self._execute_sql_file(self.grants_to_roles_sql_file_name)

    def collect(self) -> list[dict[str, object]]:
        """Collect all grant records."""
        return self.collect_grants_to_users() + self.collect_grants_to_roles()


GrantCollector = GrantsCollector
