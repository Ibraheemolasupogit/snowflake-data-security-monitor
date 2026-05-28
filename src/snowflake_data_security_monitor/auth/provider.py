"""Snowflake authentication configuration."""

from __future__ import annotations

import os
from collections.abc import Mapping

from pydantic import BaseModel, ConfigDict, Field, SecretStr

REQUIRED_SNOWFLAKE_ENV_VARS = (
    "SNOWFLAKE_ACCOUNT",
    "SNOWFLAKE_USER",
    "SNOWFLAKE_PASSWORD",
    "SNOWFLAKE_ROLE",
    "SNOWFLAKE_WAREHOUSE",
)


class SnowflakeAuthConfigError(ValueError):
    """Raised when Snowflake authentication configuration is incomplete."""


class SnowflakeAuthConfig(BaseModel):
    """Snowflake connection settings sourced from environment variables."""

    model_config = ConfigDict(extra="forbid")

    account: str = Field(min_length=1)
    user: str = Field(min_length=1)
    password: SecretStr = Field(min_length=1)
    role: str = Field(min_length=1)
    warehouse: str = Field(min_length=1)
    database: str = "SNOWFLAKE"
    schema_name: str = Field(default="ACCOUNT_USAGE", alias="schema")

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> SnowflakeAuthConfig:
        """Build auth config from environment variables."""
        source = environ if environ is not None else os.environ
        missing = [name for name in REQUIRED_SNOWFLAKE_ENV_VARS if not source.get(name)]
        if missing:
            joined = ", ".join(missing)
            raise SnowflakeAuthConfigError(f"Missing required Snowflake env vars: {joined}")

        return cls(
            account=source["SNOWFLAKE_ACCOUNT"],
            user=source["SNOWFLAKE_USER"],
            password=SecretStr(source["SNOWFLAKE_PASSWORD"]),
            role=source["SNOWFLAKE_ROLE"],
            warehouse=source["SNOWFLAKE_WAREHOUSE"],
            database=source.get("SNOWFLAKE_DATABASE", "SNOWFLAKE"),
            schema=source.get("SNOWFLAKE_SCHEMA", "ACCOUNT_USAGE"),
        )

    def to_connection_parameters(self) -> dict[str, str]:
        """Return parameters accepted by snowflake-connector-python."""
        return {
            "account": self.account,
            "user": self.user,
            "password": self.password.get_secret_value(),
            "role": self.role,
            "warehouse": self.warehouse,
            "database": self.database,
            "schema": self.schema_name,
        }


class SnowflakeAuthProvider:
    """Provider for environment-backed Snowflake connector parameters."""

    def __init__(self, environ: Mapping[str, str] | None = None) -> None:
        self._environ = environ

    def build_connection_parameters(self) -> dict[str, str]:
        """Return validated Snowflake connector parameters."""
        return SnowflakeAuthConfig.from_env(self._environ).to_connection_parameters()
