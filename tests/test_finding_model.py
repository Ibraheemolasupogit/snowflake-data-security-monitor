from snowflake_data_security_monitor.models import Finding, Severity


def test_finding_model_skeleton() -> None:
    finding = Finding(
        control_id="SFM-001",
        title="Example finding",
        severity=Severity.HIGH,
        resource_type="USER",
        resource_name="EXAMPLE_USER",
        description="Placeholder description.",
        remediation="Placeholder remediation.",
    )

    assert finding.control_id == "SFM-001"
    assert finding.evidence == {}
