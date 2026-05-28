from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from snowflake_data_security_monitor.models.config import (
    ControlsConfig,
    RepositoryConfig,
    RiskScoringConfig,
    SettingsConfig,
)
from snowflake_data_security_monitor.utils.config_loader import (
    ConfigFileNotFoundError,
    ConfigValidationError,
    ConfigYamlError,
    load_and_validate_config_file,
    load_repository_config,
    load_yaml_config,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_load_repository_config_validates_expected_config_files() -> None:
    config = load_repository_config(PROJECT_ROOT / "config")

    assert isinstance(config, RepositoryConfig)
    assert config.settings.thresholds.max_accountadmin_users == 5
    assert config.controls.controls[0].id == "SFM-001"
    assert config.risk_scoring.risk_score_bands["critical"].max == 100
    assert "SFM-001" in config.compliance_mapping.mappings


def test_load_and_validate_config_file_returns_expected_model() -> None:
    settings = load_and_validate_config_file(PROJECT_ROOT / "config" / "settings.yaml")

    assert isinstance(settings, SettingsConfig)
    assert settings.runtime.sql_dir == "sql"


def test_controls_config_validates_expected_model() -> None:
    controls = load_and_validate_config_file(PROJECT_ROOT / "config" / "controls.yaml")

    assert isinstance(controls, ControlsConfig)
    assert controls.controls[0].severity == "critical"


def test_risk_scoring_config_validates_expected_model() -> None:
    risk_scoring = load_and_validate_config_file(PROJECT_ROOT / "config" / "risk_scoring.yaml")

    assert isinstance(risk_scoring, RiskScoringConfig)
    assert risk_scoring.severity_weights["high"] == 70


def test_missing_config_file_raises_clear_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigFileNotFoundError, match="Missing config file"):
        load_yaml_config(tmp_path / "missing.yaml")


def test_invalid_yaml_raises_clear_error(tmp_path: Path) -> None:
    config_path = tmp_path / "settings.yaml"
    config_path.write_text("runtime: [\n", encoding="utf-8")

    with pytest.raises(ConfigYamlError, match="Invalid YAML"):
        load_yaml_config(config_path)


def test_missing_required_top_level_key_raises_validation_error(tmp_path: Path) -> None:
    config_path = tmp_path / "settings.yaml"
    config_path.write_text(
        textwrap.dedent(
            """
            runtime:
              output_dir: outputs
              report_dir: reports
              sql_dir: sql
            collection:
              login_history_days: 90
              query_history_days: 30
              access_history_days: 30
            """
        ),
        encoding="utf-8",
    )

    with pytest.raises(ConfigValidationError, match="thresholds"):
        load_and_validate_config_file(config_path)


def test_invalid_threshold_values_raise_validation_error(tmp_path: Path) -> None:
    config_path = tmp_path / "settings.yaml"
    config_path.write_text(
        textwrap.dedent(
            """
            runtime:
              output_dir: outputs
              report_dir: reports
              sql_dir: sql
            collection:
              login_history_days: 90
              query_history_days: 30
              access_history_days: 30
            thresholds:
              max_accountadmin_users: 0
              dormant_user_days: -1
            """
        ),
        encoding="utf-8",
    )

    with pytest.raises(ConfigValidationError, match="greater than 0"):
        load_and_validate_config_file(config_path)


def test_invalid_risk_score_band_bounds_raise_validation_error(tmp_path: Path) -> None:
    config_path = tmp_path / "risk_scoring.yaml"
    config_path.write_text(
        textwrap.dedent(
            """
            severity_weights:
              critical: 100
              high: 70
              medium: 40
              low: 15
              informational: 5
            modifiers:
              privileged_role_multiplier: 1.5
            risk_score_bands:
              low:
                min: 50
                max: 40
            """
        ),
        encoding="utf-8",
    )

    with pytest.raises(ConfigValidationError, match="max must be greater than or equal to min"):
        load_and_validate_config_file(config_path)


def test_overlapping_risk_score_bands_raise_validation_error(tmp_path: Path) -> None:
    config_path = tmp_path / "risk_scoring.yaml"
    config_path.write_text(
        textwrap.dedent(
            """
            severity_weights:
              critical: 100
              high: 70
              medium: 40
              low: 15
              informational: 5
            modifiers:
              privileged_role_multiplier: 1.5
            risk_score_bands:
              low:
                min: 0
                max: 50
              medium:
                min: 50
                max: 70
            """
        ),
        encoding="utf-8",
    )

    with pytest.raises(ConfigValidationError, match="overlaps"):
        load_and_validate_config_file(config_path)
