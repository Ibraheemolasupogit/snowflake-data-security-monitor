"""Finding model skeleton."""

from __future__ import annotations

from pydantic import BaseModel, Field

from snowflake_data_security_monitor.models.severity import Severity


class Finding(BaseModel):
    """Normalized security finding produced by future checks."""

    control_id: str = Field(..., examples=["SFM-001"])
    title: str
    severity: Severity
    resource_type: str
    resource_name: str
    description: str
    remediation: str
    evidence: dict[str, str | int | float | bool | None] = Field(default_factory=dict)
