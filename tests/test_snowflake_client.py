from __future__ import annotations

from typing import Any
from unittest.mock import Mock

import pandas as pd
import pytest

from snowflake_data_security_monitor.auth import SnowflakeAuthConfig
from snowflake_data_security_monitor.clients import (
    SnowflakeClient,
    SnowflakeConnectionError,
    SnowflakeQueryError,
)


def build_auth_config() -> SnowflakeAuthConfig:
    return SnowflakeAuthConfig(
        account="example-account",
        user="monitor_user",
        password="not-a-real-password",
        role="SECURITY_MONITOR_ROLE",
        warehouse="MONITORING_WH",
    )


def test_connect_uses_injected_connector_factory() -> None:
    connection = Mock()
    connector_factory = Mock(return_value=connection)
    client = SnowflakeClient(build_auth_config(), connector_factory=connector_factory)

    client.connect()

    assert client.is_connected is True
    connector_factory.assert_called_once_with(
        account="example-account",
        user="monitor_user",
        password="not-a-real-password",
        role="SECURITY_MONITOR_ROLE",
        warehouse="MONITORING_WH",
        database="SNOWFLAKE",
        schema="ACCOUNT_USAGE",
    )


def test_connect_wraps_connector_failures() -> None:
    connector_factory = Mock(side_effect=RuntimeError("network failure"))
    client = SnowflakeClient(build_auth_config(), connector_factory=connector_factory)

    with pytest.raises(SnowflakeConnectionError, match="Failed to connect"):
        client.connect()


def test_close_closes_existing_connection() -> None:
    connection = Mock()
    client = SnowflakeClient(build_auth_config(), connector_factory=Mock(return_value=connection))

    client.connect()
    client.close()

    connection.close.assert_called_once_with()
    assert client.is_connected is False


def test_execute_query_requires_connection() -> None:
    client = SnowflakeClient(build_auth_config(), connector_factory=Mock())

    with pytest.raises(SnowflakeConnectionError, match="not connected"):
        client.execute_query("SELECT 1")


def test_execute_query_returns_dict_rows() -> None:
    cursor = Mock()
    cursor.description = [("USER_NAME",), ("ROLE_NAME",)]
    cursor.fetchall.return_value = [("ALICE", "ACCOUNTADMIN"), ("BOB", "ANALYST")]
    connection = Mock()
    connection.cursor.return_value = cursor
    client = connected_client(connection)

    rows = client.execute_query("SELECT * FROM grants")

    assert rows == [
        {"USER_NAME": "ALICE", "ROLE_NAME": "ACCOUNTADMIN"},
        {"USER_NAME": "BOB", "ROLE_NAME": "ANALYST"},
    ]
    cursor.execute.assert_called_once_with("SELECT * FROM grants")
    cursor.close.assert_called_once_with()


def test_execute_query_wraps_query_errors() -> None:
    cursor = Mock()
    cursor.execute.side_effect = RuntimeError("bad query")
    connection = Mock()
    connection.cursor.return_value = cursor
    client = connected_client(connection)

    with pytest.raises(SnowflakeQueryError, match="Failed to execute"):
        client.execute_query("SELECT broken")

    cursor.close.assert_called_once_with()


def test_execute_query_as_dataframe_uses_cursor_fetch_pandas_all() -> None:
    dataframe = pd.DataFrame([{"USER_NAME": "ALICE"}])
    cursor = Mock()
    cursor.fetch_pandas_all.return_value = dataframe
    connection = Mock()
    connection.cursor.return_value = cursor
    client = connected_client(connection)

    result = client.execute_query_as_dataframe("SELECT * FROM users")

    assert result.equals(dataframe)
    cursor.execute.assert_called_once_with("SELECT * FROM users")
    cursor.fetch_pandas_all.assert_called_once_with()
    cursor.close.assert_called_once_with()


def connected_client(connection: Any) -> SnowflakeClient:
    client = SnowflakeClient(build_auth_config(), connector_factory=Mock(return_value=connection))
    client.connect()
    return client
