"""Snowflake asset model skeletons."""

from __future__ import annotations

from pydantic import BaseModel


class SnowflakeUser(BaseModel):
    """Minimal future representation of a Snowflake user."""

    name: str
    disabled: bool | None = None
    last_success_login: str | None = None


class SnowflakeGrant(BaseModel):
    """Minimal future representation of a Snowflake grant."""

    grantee_name: str
    grantee_type: str
    privilege: str
    granted_on: str
    name: str
