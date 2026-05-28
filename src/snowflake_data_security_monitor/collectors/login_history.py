"""Login history metadata collector."""

from __future__ import annotations

from snowflake_data_security_monitor.collectors.base import BaseSnowflakeCollector


class LoginHistoryCollector(BaseSnowflakeCollector):
    """Collect Snowflake login history metadata."""

    sql_file_name = "login_history.sql"
