from __future__ import annotations

from pathlib import Path
from unittest.mock import Mock

import pytest

from snowflake_data_security_monitor.clients import SnowflakeQueryError
from snowflake_data_security_monitor.collectors import (
    CollectorQueryError,
    CollectorSqlFileNotFoundError,
    GrantsCollector,
    LoginHistoryCollector,
    PoliciesCollector,
    QueryHistoryCollector,
    RolesCollector,
    SharesCollector,
    StagesCollector,
    UsersCollector,
)


def test_single_file_collectors_load_expected_sql_and_return_records(tmp_path: Path) -> None:
    expected_records = [{"name": "record"}]

    collector_cases = [
        (UsersCollector, "users.sql"),
        (RolesCollector, "roles.sql"),
        (StagesCollector, "stages.sql"),
        (SharesCollector, "shares.sql"),
        (LoginHistoryCollector, "login_history.sql"),
    ]

    for collector_type, sql_file_name in collector_cases:
        sql_query = f"SELECT '{sql_file_name}'"
        (tmp_path / sql_file_name).write_text(sql_query, encoding="utf-8")
        client = Mock()
        client.execute_query.return_value = expected_records

        records = collector_type(client, sql_dir=tmp_path).collect()

        assert records == expected_records
        client.execute_query.assert_called_once_with(sql_query)


def test_grants_collector_loads_user_and_role_grants(tmp_path: Path) -> None:
    grants_to_users_query = "SELECT * FROM grants_to_users"
    grants_to_roles_query = "SELECT * FROM grants_to_roles"
    (tmp_path / "grants_to_users.sql").write_text(grants_to_users_query, encoding="utf-8")
    (tmp_path / "grants_to_roles.sql").write_text(grants_to_roles_query, encoding="utf-8")
    client = Mock()
    client.execute_query.side_effect = [
        [{"source": "users"}],
        [{"source": "roles"}],
    ]

    records = GrantsCollector(client, sql_dir=tmp_path).collect()

    assert records == [{"source": "users"}, {"source": "roles"}]
    assert [call.args[0] for call in client.execute_query.call_args_list] == [
        grants_to_users_query,
        grants_to_roles_query,
    ]


def test_policies_collector_loads_masking_and_row_access_policies(tmp_path: Path) -> None:
    masking_query = "SELECT * FROM masking_policies"
    row_access_query = "SELECT * FROM row_access_policies"
    (tmp_path / "masking_policies.sql").write_text(masking_query, encoding="utf-8")
    (tmp_path / "row_access_policies.sql").write_text(row_access_query, encoding="utf-8")
    client = Mock()
    client.execute_query.side_effect = [
        [{"policy_type": "masking"}],
        [{"policy_type": "row_access"}],
    ]

    records = PoliciesCollector(client, sql_dir=tmp_path).collect()

    assert records == [{"policy_type": "masking"}, {"policy_type": "row_access"}]
    assert [call.args[0] for call in client.execute_query.call_args_list] == [
        masking_query,
        row_access_query,
    ]


def test_query_history_collector_loads_query_and_access_history(tmp_path: Path) -> None:
    query_history_query = "SELECT * FROM query_history"
    access_history_query = "SELECT * FROM access_history"
    (tmp_path / "query_history.sql").write_text(query_history_query, encoding="utf-8")
    (tmp_path / "access_history.sql").write_text(access_history_query, encoding="utf-8")
    client = Mock()
    client.execute_query.side_effect = [
        [{"history_type": "query"}],
        [{"history_type": "access"}],
    ]

    records = QueryHistoryCollector(client, sql_dir=tmp_path).collect()

    assert records == [{"history_type": "query"}, {"history_type": "access"}]
    assert [call.args[0] for call in client.execute_query.call_args_list] == [
        query_history_query,
        access_history_query,
    ]


def test_missing_sql_file_raises_clear_collector_error(tmp_path: Path) -> None:
    client = Mock()

    with pytest.raises(CollectorSqlFileNotFoundError, match="Missing SQL file"):
        UsersCollector(client, sql_dir=tmp_path).collect()

    client.execute_query.assert_not_called()


def test_query_failure_raises_clear_collector_error(tmp_path: Path) -> None:
    sql_query = "SELECT * FROM users"
    (tmp_path / "users.sql").write_text(sql_query, encoding="utf-8")
    client = Mock()
    client.execute_query.side_effect = SnowflakeQueryError("mock query failure")

    with pytest.raises(CollectorQueryError, match="Query failed for SQL file: users.sql"):
        UsersCollector(client, sql_dir=tmp_path).collect()
