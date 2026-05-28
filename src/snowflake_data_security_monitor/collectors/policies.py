"""Policy metadata collector."""

from __future__ import annotations

from snowflake_data_security_monitor.collectors.base import BaseSnowflakeCollector


class PoliciesCollector(BaseSnowflakeCollector):
    """Collect Snowflake masking and row access policy metadata."""

    sql_file_name = "masking_policies.sql"
    row_access_policies_sql_file_name = "row_access_policies.sql"

    def collect_masking_policies(self) -> list[dict[str, object]]:
        """Collect masking policies."""
        return self._execute_sql_file(self.sql_file_name)

    def collect_row_access_policies(self) -> list[dict[str, object]]:
        """Collect row access policies."""
        return self._execute_sql_file(self.row_access_policies_sql_file_name)

    def collect(self) -> list[dict[str, object]]:
        """Collect all policy records."""
        return self.collect_masking_policies() + self.collect_row_access_policies()
