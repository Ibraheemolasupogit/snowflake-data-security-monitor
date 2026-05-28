"""Share metadata collector."""

from __future__ import annotations

from snowflake_data_security_monitor.collectors.base import BaseSnowflakeCollector


class SharesCollector(BaseSnowflakeCollector):
    """Collect Snowflake share metadata."""

    sql_file_name = "shares.sql"
