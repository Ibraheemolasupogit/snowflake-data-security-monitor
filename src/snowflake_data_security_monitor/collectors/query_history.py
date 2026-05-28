"""Query and access history metadata collector."""

from __future__ import annotations

from snowflake_data_security_monitor.collectors.base import BaseSnowflakeCollector


class QueryHistoryCollector(BaseSnowflakeCollector):
    """Collect Snowflake query and access history metadata."""

    sql_file_name = "query_history.sql"
    access_history_sql_file_name = "access_history.sql"

    def collect_query_history(self) -> list[dict[str, object]]:
        """Collect query history metadata."""
        return self._execute_sql_file(self.sql_file_name)

    def collect_access_history(self) -> list[dict[str, object]]:
        """Collect access history metadata."""
        return self._execute_sql_file(self.access_history_sql_file_name)

    def collect(self) -> list[dict[str, object]]:
        """Collect query and access history records."""
        return self.collect_query_history() + self.collect_access_history()
