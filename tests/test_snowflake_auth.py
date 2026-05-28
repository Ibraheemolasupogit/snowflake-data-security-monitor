from __future__ import annotations

import pytest

from snowflake_data_security_monitor.auth import (
    SnowflakeAuthConfig,
    SnowflakeAuthConfigError,
    SnowflakeAuthProvider,
)

BASE_ENV = {
    "SNOWFLAKE_ACCOUNT": "example-account",
    "SNOWFLAKE_USER": "monitor_user",
    "SNOWFLAKE_PASSWORD": "not-a-real-password",
    "SNOWFLAKE_ROLE": "SECURITY_MONITOR_ROLE",
    "SNOWFLAKE_WAREHOUSE": "MONITORING_WH",
}


def test_auth_config_loads_required_env_vars() -> None:
    config = SnowflakeAuthConfig.from_env(BASE_ENV)

    assert config.account == "example-account"
    assert config.user == "monitor_user"
    assert config.role == "SECURITY_MONITOR_ROLE"
    assert config.warehouse == "MONITORING_WH"
    assert config.database == "SNOWFLAKE"
    assert config.schema_name == "ACCOUNT_USAGE"


def test_auth_config_uses_optional_database_and_schema_defaults() -> None:
    config = SnowflakeAuthConfig.from_env(BASE_ENV)

    params = config.to_connection_parameters()

    assert params["database"] == "SNOWFLAKE"
    assert params["schema"] == "ACCOUNT_USAGE"


def test_auth_config_allows_optional_database_and_schema_overrides() -> None:
    env = {
        **BASE_ENV,
        "SNOWFLAKE_DATABASE": "CUSTOM_DB",
        "SNOWFLAKE_SCHEMA": "CUSTOM_SCHEMA",
    }

    config = SnowflakeAuthConfig.from_env(env)

    assert config.database == "CUSTOM_DB"
    assert config.schema_name == "CUSTOM_SCHEMA"


def test_auth_config_reports_missing_required_env_vars() -> None:
    env = {key: value for key, value in BASE_ENV.items() if key != "SNOWFLAKE_PASSWORD"}

    with pytest.raises(SnowflakeAuthConfigError, match="SNOWFLAKE_PASSWORD"):
        SnowflakeAuthConfig.from_env(env)


def test_auth_provider_builds_connection_parameters() -> None:
    provider = SnowflakeAuthProvider(BASE_ENV)

    params = provider.build_connection_parameters()

    assert params == {
        "account": "example-account",
        "user": "monitor_user",
        "password": "not-a-real-password",
        "role": "SECURITY_MONITOR_ROLE",
        "warehouse": "MONITORING_WH",
        "database": "SNOWFLAKE",
        "schema": "ACCOUNT_USAGE",
    }
