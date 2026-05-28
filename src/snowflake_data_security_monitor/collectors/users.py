"""User metadata collector."""

from __future__ import annotations

from snowflake_data_security_monitor.collectors.base import BaseSnowflakeCollector


class UsersCollector(BaseSnowflakeCollector):
    """Collect Snowflake user metadata."""

    sql_file_name = "users.sql"


UserCollector = UsersCollector
