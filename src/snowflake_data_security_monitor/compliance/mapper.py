"""Compliance mapping utilities."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from snowflake_data_security_monitor.models import Finding
from snowflake_data_security_monitor.models.config import ComplianceMappingConfig
from snowflake_data_security_monitor.utils.config_loader import (
    ConfigValidationError,
    load_yaml_config,
)

FRAMEWORK_KEYS = ("cis", "nist", "iso")


def load_compliance_mapping(config_path: Path) -> ComplianceMappingConfig:
    """Load compliance mappings from a YAML config file."""
    data = load_yaml_config(config_path)
    try:
        return ComplianceMappingConfig.model_validate(data)
    except ValueError as exc:
        message = f"Invalid compliance mapping file {config_path}: {exc}"
        raise ConfigValidationError(message) from exc


def map_finding_to_frameworks(
    finding: Finding,
    mapping_config: ComplianceMappingConfig,
) -> dict[str, Any]:
    """Map one finding to configured compliance framework references."""
    mappings = mapping_config.mappings.get(finding.control_id, {})
    return {
        "control_id": finding.control_id,
        "title": finding.title,
        "resource_type": finding.resource_type,
        "resource_name": finding.resource_name,
        "cis": list(mappings.get("cis", [])),
        "nist": list(mappings.get("nist", [])),
        "iso": list(mappings.get("iso", [])),
    }


def map_findings_to_frameworks(
    findings: list[Finding],
    mapping_config: ComplianceMappingConfig,
) -> list[dict[str, Any]]:
    """Map findings to configured compliance framework references."""
    return [map_finding_to_frameworks(finding, mapping_config) for finding in findings]
