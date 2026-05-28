"""Stage metadata collector."""

from __future__ import annotations

from snowflake_data_security_monitor.collectors.base import BaseSnowflakeCollector


class StagesCollector(BaseSnowflakeCollector):
    """Collect Snowflake stage metadata."""

    sql_file_name = "stages.sql"
