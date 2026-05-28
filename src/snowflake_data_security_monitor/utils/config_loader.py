"""Configuration loading and validation utilities."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ValidationError

from snowflake_data_security_monitor.models.config import (
    ComplianceMappingConfig,
    ControlsConfig,
    RepositoryConfig,
    RiskScoringConfig,
    SettingsConfig,
    validate_named_config,
)

EXPECTED_CONFIG_FILES = (
    "settings.yaml",
    "controls.yaml",
    "risk_scoring.yaml",
    "compliance_mapping.yaml",
)


class ConfigError(Exception):
    """Base exception for configuration loading failures."""


class ConfigFileNotFoundError(ConfigError):
    """Raised when an expected configuration file is missing."""


class ConfigYamlError(ConfigError):
    """Raised when YAML cannot be parsed."""


class ConfigValidationError(ConfigError):
    """Raised when parsed configuration fails schema validation."""


def load_yaml_config(path: Path) -> dict[str, Any]:
    """Load one YAML config file and return a dictionary payload."""
    if not path.exists():
        raise ConfigFileNotFoundError(f"Missing config file: {path}")
    if not path.is_file():
        raise ConfigFileNotFoundError(f"Config path is not a file: {path}")

    try:
        with path.open("r", encoding="utf-8") as file:
            loaded = yaml.safe_load(file)
    except yaml.YAMLError as exc:
        raise ConfigYamlError(f"Invalid YAML in config file: {path}") from exc

    if loaded is None:
        return {}
    if not isinstance(loaded, dict):
        raise ConfigValidationError(f"Config file must contain a YAML mapping: {path}")

    return loaded


def load_and_validate_config_file(path: Path) -> BaseModel:
    """Load and validate one expected config file."""
    data = load_yaml_config(path)

    try:
        return validate_named_config(path.name, data)
    except ValueError as exc:
        raise ConfigValidationError(str(exc)) from exc
    except ValidationError as exc:
        raise ConfigValidationError(f"Invalid config file {path}: {exc}") from exc


def load_repository_config(config_dir: Path) -> RepositoryConfig:
    """Load and validate all expected repository config files."""
    validated = {
        file_name: load_and_validate_config_file(config_dir / file_name)
        for file_name in EXPECTED_CONFIG_FILES
    }

    return RepositoryConfig(
        settings=_cast_config(validated["settings.yaml"], SettingsConfig),
        controls=_cast_config(validated["controls.yaml"], ControlsConfig),
        risk_scoring=_cast_config(validated["risk_scoring.yaml"], RiskScoringConfig),
        compliance_mapping=_cast_config(
            validated["compliance_mapping.yaml"], ComplianceMappingConfig
        ),
    )


def _cast_config(config: BaseModel, expected_type: type[BaseModel]) -> Any:
    """Return a validated model after checking its concrete type."""
    if not isinstance(config, expected_type):
        raise ConfigValidationError(
            f"Expected {expected_type.__name__}, got {type(config).__name__}"
        )
    return config
