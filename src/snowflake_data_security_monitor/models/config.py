"""Configuration model definitions."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

from snowflake_data_security_monitor.models.severity import Severity


class RuntimeSettings(BaseModel):
    """Filesystem locations used by the monitor."""

    output_dir: str
    report_dir: str
    sql_dir: str


class CollectionSettings(BaseModel):
    """Collection lookback settings."""

    login_history_days: int = Field(gt=0)
    query_history_days: int = Field(gt=0)
    access_history_days: int = Field(gt=0)


class ThresholdSettings(BaseModel):
    """Risk threshold settings."""

    max_accountadmin_users: int = Field(gt=0)
    dormant_user_days: int = Field(gt=0)


class SettingsConfig(BaseModel):
    """Validated settings.yaml structure."""

    runtime: RuntimeSettings
    collection: CollectionSettings
    thresholds: ThresholdSettings


class ControlConfig(BaseModel):
    """Single security control configuration."""

    id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    severity: Severity
    enabled: bool = True
    framework_tags: list[str] = Field(default_factory=list)


class ControlsConfig(BaseModel):
    """Validated controls.yaml structure."""

    controls: list[ControlConfig] = Field(min_length=1)

    @field_validator("controls")
    @classmethod
    def control_ids_must_be_unique(cls, controls: list[ControlConfig]) -> list[ControlConfig]:
        """Reject duplicate control IDs before checks rely on them."""
        control_ids = [control.id for control in controls]
        if len(control_ids) != len(set(control_ids)):
            raise ValueError("control IDs must be unique")
        return controls


class RiskScoreBand(BaseModel):
    """Named risk score range."""

    min: int = Field(ge=0, le=100)
    max: int = Field(ge=0, le=100)

    @model_validator(mode="after")
    def max_must_be_at_least_min(self) -> RiskScoreBand:
        """Validate band bounds."""
        if self.max < self.min:
            raise ValueError("risk score band max must be greater than or equal to min")
        return self


class RiskScoringConfig(BaseModel):
    """Validated risk_scoring.yaml structure."""

    severity_weights: dict[Severity, int]
    modifiers: dict[str, float]
    risk_score_bands: dict[str, RiskScoreBand]

    @field_validator("severity_weights")
    @classmethod
    def severity_weights_must_be_positive(
        cls, severity_weights: dict[Severity, int]
    ) -> dict[Severity, int]:
        """Require positive weights for every supported severity."""
        missing = set(Severity) - set(severity_weights)
        if missing:
            missing_values = ", ".join(sorted(severity.value for severity in missing))
            raise ValueError(f"missing severity weights: {missing_values}")
        if any(weight <= 0 for weight in severity_weights.values()):
            raise ValueError("severity weights must be positive")
        return severity_weights

    @field_validator("modifiers")
    @classmethod
    def modifiers_must_be_positive(cls, modifiers: dict[str, float]) -> dict[str, float]:
        """Require positive scoring modifiers."""
        if any(value <= 0 for value in modifiers.values()):
            raise ValueError("risk scoring modifiers must be positive")
        return modifiers

    @field_validator("risk_score_bands")
    @classmethod
    def risk_score_bands_must_not_overlap(
        cls, risk_score_bands: dict[str, RiskScoreBand]
    ) -> dict[str, RiskScoreBand]:
        """Reject overlapping score bands."""
        if not risk_score_bands:
            raise ValueError("at least one risk score band is required")

        sorted_bands = sorted(risk_score_bands.items(), key=lambda item: item[1].min)
        previous_name: str | None = None
        previous_max: int | None = None

        for band_name, band in sorted_bands:
            if previous_max is not None and band.min <= previous_max:
                raise ValueError(
                    f"risk score band '{band_name}' overlaps with '{previous_name}'"
                )
            previous_name = band_name
            previous_max = band.max

        return risk_score_bands


class ComplianceMappingConfig(BaseModel):
    """Validated compliance_mapping.yaml structure."""

    mappings: dict[str, dict[str, list[str]]]

    @field_validator("mappings")
    @classmethod
    def mappings_must_not_be_empty(
        cls, mappings: dict[str, dict[str, list[str]]]
    ) -> dict[str, dict[str, list[str]]]:
        """Require at least one mapping and non-empty framework entries."""
        if not mappings:
            raise ValueError("at least one compliance mapping is required")

        for control_id, frameworks in mappings.items():
            if not control_id:
                raise ValueError("compliance mapping control IDs must not be empty")
            if not frameworks:
                raise ValueError(f"compliance mapping for {control_id} must not be empty")
            for framework, references in frameworks.items():
                if not framework:
                    raise ValueError(f"framework name for {control_id} must not be empty")
                if not references:
                    raise ValueError(
                        f"framework references for {control_id}/{framework} must not be empty"
                    )

        return mappings


class RepositoryConfig(BaseModel):
    """Combined validated repository configuration."""

    settings: SettingsConfig
    controls: ControlsConfig
    risk_scoring: RiskScoringConfig
    compliance_mapping: ComplianceMappingConfig


CONFIG_MODELS: dict[str, type[BaseModel]] = {
    "settings.yaml": SettingsConfig,
    "controls.yaml": ControlsConfig,
    "risk_scoring.yaml": RiskScoringConfig,
    "compliance_mapping.yaml": ComplianceMappingConfig,
}


def validate_named_config(file_name: str, data: dict[str, Any]) -> BaseModel:
    """Validate a config payload using the model registered for its file name."""
    try:
        model = CONFIG_MODELS[file_name]
    except KeyError as exc:
        raise ValueError(f"unsupported config file: {file_name}") from exc

    return model.model_validate(data)
