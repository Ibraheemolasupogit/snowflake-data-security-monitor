"""Snowflake client wrapper."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from snowflake_data_security_monitor.auth import SnowflakeAuthConfig


class SnowflakeClientError(RuntimeError):
    """Base exception for Snowflake client failures."""


class SnowflakeConnectionError(SnowflakeClientError):
    """Raised when a Snowflake connection cannot be established."""


class SnowflakeQueryError(SnowflakeClientError):
    """Raised when query execution fails."""


ConnectionFactory = Callable[..., Any]


class SnowflakeClient:
    """Thin wrapper around Snowflake connector operations.

    The connector factory is injectable so tests can use mocks without Snowflake access.
    """

    def __init__(
        self,
        auth_config: SnowflakeAuthConfig,
        connector_factory: ConnectionFactory | None = None,
    ) -> None:
        self._auth_config = auth_config
        self._connector_factory = connector_factory
        self._connection: Any | None = None

    @property
    def is_connected(self) -> bool:
        """Return whether the wrapper currently holds a connection object."""
        return self._connection is not None

    def connect(self) -> None:
        """Open a Snowflake connection."""
        if self._connection is not None:
            return

        try:
            connector_factory = self._connector_factory or _default_connector_factory()
            self._connection = connector_factory(**self._auth_config.to_connection_parameters())
        except Exception as exc:
            raise SnowflakeConnectionError("Failed to connect to Snowflake") from exc

    def close(self) -> None:
        """Close the active Snowflake connection if one exists."""
        if self._connection is None:
            return

        try:
            self._connection.close()
        finally:
            self._connection = None

    def execute_query(self, query: str) -> list[dict[str, object]]:
        """Execute a SQL query and return rows as dictionaries."""
        connection = self._require_connection()

        try:
            cursor = connection.cursor()
            try:
                cursor.execute(query)
                columns = [column[0] for column in cursor.description or []]
                return [dict(zip(columns, row, strict=False)) for row in cursor.fetchall()]
            finally:
                cursor.close()
        except Exception as exc:
            raise SnowflakeQueryError("Failed to execute Snowflake query") from exc

    def execute_query_as_dataframe(self, query: str) -> Any:
        """Execute a SQL query and return a pandas DataFrame."""
        connection = self._require_connection()

        try:
            cursor = connection.cursor()
            try:
                cursor.execute(query)
                return cursor.fetch_pandas_all()
            finally:
                cursor.close()
        except Exception as exc:
            raise SnowflakeQueryError("Failed to execute Snowflake query as DataFrame") from exc

    def _require_connection(self) -> Any:
        """Return the active connection or raise a safe error."""
        if self._connection is None:
            raise SnowflakeConnectionError("Snowflake client is not connected")
        return self._connection


def _default_connector_factory() -> ConnectionFactory:
    """Load the Snowflake connector lazily to keep tests mock-friendly."""
    try:
        import snowflake.connector
    except ImportError as exc:
        raise SnowflakeConnectionError("snowflake-connector-python is not installed") from exc

    return snowflake.connector.connect
