"""Role metadata collector."""

from __future__ import annotations

from snowflake_data_security_monitor.collectors.base import BaseSnowflakeCollector


class RolesCollector(BaseSnowflakeCollector):
    """Collect Snowflake role metadata."""

    sql_file_name = "roles.sql"
