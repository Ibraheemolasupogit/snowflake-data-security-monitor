"""Base classes for Snowflake metadata collectors."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from snowflake_data_security_monitor.clients import SnowflakeClient, SnowflakeQueryError


class Collector(Protocol):
    """Protocol for metadata collectors."""

    def collect(self) -> list[dict[str, object]]:
        """Collect normalized records from a metadata source."""
        ...


class CollectorError(RuntimeError):
    """Base exception for collector failures."""


class CollectorSqlFileNotFoundError(CollectorError):
    """Raised when a collector SQL template is missing."""


class CollectorQueryError(CollectorError):
    """Raised when a collector query fails."""


class BaseSnowflakeCollector:
    """Base collector that loads SQL templates and delegates execution to SnowflakeClient."""

    sql_file_name: str

    def __init__(self, client: SnowflakeClient, sql_dir: Path | str = "sql") -> None:
        self._client = client
        self._sql_dir = Path(sql_dir)

    def collect(self) -> list[dict[str, object]]:
        """Collect records using the collector's primary SQL file."""
        return self._execute_sql_file(self.sql_file_name)

    def _load_sql(self, sql_file_name: str) -> str:
        """Load a SQL template from disk."""
        sql_path = self._sql_dir / sql_file_name
        if not sql_path.exists() or not sql_path.is_file():
            raise CollectorSqlFileNotFoundError(f"Missing SQL file: {sql_path}")
        return sql_path.read_text(encoding="utf-8")

    def _execute_sql_file(self, sql_file_name: str) -> list[dict[str, object]]:
        """Execute one SQL template and return Snowflake rows."""
        query = self._load_sql(sql_file_name)
        try:
            return self._client.execute_query(query)
        except SnowflakeQueryError as exc:
            raise CollectorQueryError(f"Query failed for SQL file: {sql_file_name}") from exc
