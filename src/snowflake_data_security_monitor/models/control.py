"""Control model skeleton."""

from __future__ import annotations

from pydantic import BaseModel, Field

from snowflake_data_security_monitor.models.severity import Severity


class Control(BaseModel):
    """Configuration-backed security control definition."""

    control_id: str
    name: str
    severity: Severity
    enabled: bool = True
    framework_tags: list[str] = Field(default_factory=list)
