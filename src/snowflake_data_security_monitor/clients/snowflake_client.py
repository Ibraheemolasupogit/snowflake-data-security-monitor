"""Snowflake client placeholder."""

from __future__ import annotations


class SnowflakeClient:
    """Future thin wrapper around Snowflake connector operations."""

    def execute_query(self, query: str) -> list[dict[str, object]]:
        """Execute a query when Snowflake connectivity is implemented."""
        raise NotImplementedError("Snowflake query execution is not implemented yet.")
