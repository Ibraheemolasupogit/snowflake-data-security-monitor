from __future__ import annotations

from datetime import UTC, datetime

from snowflake_data_security_monitor.checks import (
    AccountAdminUsersCheck,
    BroadRolePrivilegesCheck,
    DisabledUsersWithActiveGrantsCheck,
    DormantUsersCheck,
    ExcessiveAccountAdminUsersCheck,
    ExternalStagesCheck,
    MissingMaskingPolicyIndicatorsCheck,
    MissingRowAccessPolicyIndicatorsCheck,
    OutboundSharesCheck,
    PublicRoleRiskyPrivilegesCheck,
)


def test_accountadmin_users_check_detects_direct_user_grants() -> None:
    records = [
        {"ROLE": "ACCOUNTADMIN", "GRANTEE_NAME": "ALICE", "GRANTEE_TYPE": "USER"},
        {"ROLE": "ACCOUNTADMIN", "GRANTEE_NAME": "ANALYST_ROLE", "GRANTEE_TYPE": "ROLE"},
    ]

    findings = AccountAdminUsersCheck().evaluate(records)

    assert len(findings) == 1
    assert findings[0].control_id == "SFM-001"
    assert findings[0].resource_name == "ALICE"


def test_accountadmin_users_check_ignores_non_accountadmin_grants() -> None:
    records = [{"ROLE": "ANALYST", "GRANTEE_NAME": "ALICE", "GRANTEE_TYPE": "USER"}]

    assert AccountAdminUsersCheck().evaluate(records) == []


def test_excessive_accountadmin_users_check_detects_threshold_breach() -> None:
    records = [
        {"ROLE": "ACCOUNTADMIN", "GRANTEE_NAME": "ALICE", "GRANTEE_TYPE": "USER"},
        {"ROLE": "ACCOUNTADMIN", "GRANTEE_NAME": "BOB", "GRANTEE_TYPE": "USER"},
    ]

    findings = ExcessiveAccountAdminUsersCheck(max_accountadmin_users=1).evaluate(records)

    assert len(findings) == 1
    assert findings[0].control_id == "SFM-002"
    assert findings[0].evidence["accountadmin_user_count"] == 2


def test_excessive_accountadmin_users_check_allows_threshold() -> None:
    records = [{"ROLE": "ACCOUNTADMIN", "GRANTEE_NAME": "ALICE", "GRANTEE_TYPE": "USER"}]

    assert ExcessiveAccountAdminUsersCheck(max_accountadmin_users=1).evaluate(records) == []


def test_dormant_users_check_detects_old_and_missing_login_dates() -> None:
    reference_time = datetime(2026, 5, 28, tzinfo=UTC)
    records = [
        {"NAME": "OLD_USER", "LAST_SUCCESS_LOGIN": "2025-01-01T00:00:00+00:00"},
        {"NAME": "NEVER_LOGGED_IN", "LAST_SUCCESS_LOGIN": None},
        {"NAME": "ACTIVE_USER", "LAST_SUCCESS_LOGIN": "2026-05-20T00:00:00+00:00"},
    ]

    findings = DormantUsersCheck(dormant_user_days=90, reference_time=reference_time).evaluate(
        records
    )

    assert [finding.resource_name for finding in findings] == ["OLD_USER", "NEVER_LOGGED_IN"]


def test_dormant_users_check_ignores_recent_login_dates() -> None:
    reference_time = datetime(2026, 5, 28, tzinfo=UTC)
    records = [{"NAME": "ACTIVE_USER", "LAST_SUCCESS_LOGIN": "2026-05-20T00:00:00+00:00"}]

    assert DormantUsersCheck(reference_time=reference_time).evaluate(records) == []


def test_disabled_users_with_active_grants_check_detects_active_grants() -> None:
    records = [
        {"USER_NAME": "DISABLED_USER", "DISABLED": "true", "ROLE": "ANALYST"},
        {"USER_NAME": "REVOKED_USER", "DISABLED": "true", "ROLE": "ANALYST", "DELETED_ON": "x"},
    ]

    findings = DisabledUsersWithActiveGrantsCheck().evaluate(records)

    assert len(findings) == 1
    assert findings[0].resource_name == "DISABLED_USER"


def test_disabled_users_with_active_grants_check_ignores_enabled_users() -> None:
    records = [{"USER_NAME": "ACTIVE_USER", "DISABLED": False, "ROLE": "ANALYST"}]

    assert DisabledUsersWithActiveGrantsCheck().evaluate(records) == []


def test_public_role_risky_privileges_check_detects_risky_privileges_only() -> None:
    records = [
        {"GRANTEE_NAME": "PUBLIC", "PRIVILEGE": "OWNERSHIP", "GRANTED_ON": "DATABASE"},
        {"GRANTEE_NAME": "PUBLIC", "PRIVILEGE": "USAGE", "GRANTED_ON": "DATABASE"},
        {"GRANTEE_NAME": "ANALYST", "PRIVILEGE": "OWNERSHIP", "GRANTED_ON": "DATABASE"},
    ]

    findings = PublicRoleRiskyPrivilegesCheck().evaluate(records)

    assert len(findings) == 1
    assert findings[0].control_id == "SFM-005"
    assert findings[0].evidence["privilege"] == "OWNERSHIP"


def test_public_role_risky_privileges_check_ignores_low_risk_privileges() -> None:
    records = [{"GRANTEE_NAME": "PUBLIC", "PRIVILEGE": "USAGE", "GRANTED_ON": "SCHEMA"}]

    assert PublicRoleRiskyPrivilegesCheck().evaluate(records) == []


def test_broad_role_privileges_check_detects_broad_privileges() -> None:
    records = [
        {"GRANTEE_NAME": "ANALYST", "PRIVILEGE": "ALL PRIVILEGES", "GRANTED_ON": "SCHEMA"},
        {"GRANTEE_NAME": "VIEWER", "PRIVILEGE": "SELECT", "GRANTED_ON": "TABLE"},
    ]

    findings = BroadRolePrivilegesCheck().evaluate(records)

    assert len(findings) == 1
    assert findings[0].resource_name == "ANALYST"


def test_broad_role_privileges_check_ignores_narrow_privileges() -> None:
    records = [{"GRANTEE_NAME": "VIEWER", "PRIVILEGE": "SELECT", "GRANTED_ON": "TABLE"}]

    assert BroadRolePrivilegesCheck().evaluate(records) == []


def test_external_stages_check_detects_external_stage_urls() -> None:
    records = [
        {"STAGE_NAME": "EXT_STAGE", "STAGE_URL": "s3://bucket/path"},
        {"STAGE_NAME": "INT_STAGE", "STAGE_URL": ""},
    ]

    findings = ExternalStagesCheck().evaluate(records)

    assert len(findings) == 1
    assert findings[0].resource_name == "EXT_STAGE"


def test_external_stages_check_ignores_internal_stages() -> None:
    records = [{"STAGE_NAME": "INT_STAGE", "STAGE_TYPE": "INTERNAL"}]

    assert ExternalStagesCheck().evaluate(records) == []


def test_outbound_shares_check_detects_outbound_shares() -> None:
    records = [
        {"SHARE_NAME": "OUTBOUND_SHARE", "KIND": "OUTBOUND"},
        {"SHARE_NAME": "INBOUND_SHARE", "KIND": "INBOUND"},
    ]

    findings = OutboundSharesCheck().evaluate(records)

    assert len(findings) == 1
    assert findings[0].resource_name == "OUTBOUND_SHARE"


def test_outbound_shares_check_ignores_inbound_shares() -> None:
    records = [{"SHARE_NAME": "INBOUND_SHARE", "KIND": "INBOUND"}]

    assert OutboundSharesCheck().evaluate(records) == []


def test_missing_masking_policy_indicators_check_detects_sensitive_unmasked_metadata() -> None:
    records = [
        {"TABLE_NAME": "CUSTOMERS", "IS_SENSITIVE": True, "HAS_MASKING_POLICY": False},
        {"TABLE_NAME": "PUBLIC_DIM", "IS_SENSITIVE": False, "HAS_MASKING_POLICY": False},
        {"TABLE_NAME": "PAYMENTS", "CLASSIFICATION": "PCI", "MASKING_POLICY": "MASK_CARD"},
    ]

    findings = MissingMaskingPolicyIndicatorsCheck().evaluate(records)

    assert len(findings) == 1
    assert findings[0].resource_name == "CUSTOMERS"


def test_missing_masking_policy_indicators_check_ignores_masked_sensitive_metadata() -> None:
    records = [{"TABLE_NAME": "CUSTOMERS", "IS_SENSITIVE": True, "MASKING_POLICY_COUNT": 1}]

    assert MissingMaskingPolicyIndicatorsCheck().evaluate(records) == []


def test_missing_row_access_policy_check_detects_sensitive_unprotected_metadata() -> None:
    records = [
        {"TABLE_NAME": "CUSTOMERS", "SENSITIVE": "yes", "HAS_ROW_ACCESS_POLICY": False},
        {"TABLE_NAME": "PUBLIC_DIM", "SENSITIVE": False, "HAS_ROW_ACCESS_POLICY": False},
        {"TABLE_NAME": "REGIONAL_SALES", "SENSITIVE": True, "ROW_ACCESS_POLICY": "RAP_REGION"},
    ]

    findings = MissingRowAccessPolicyIndicatorsCheck().evaluate(records)

    assert len(findings) == 1
    assert findings[0].resource_name == "CUSTOMERS"


def test_missing_row_access_policy_indicators_check_ignores_protected_metadata() -> None:
    records = [{"TABLE_NAME": "CUSTOMERS", "SENSITIVE": True, "ROW_ACCESS_POLICY_COUNT": 1}]

    assert MissingRowAccessPolicyIndicatorsCheck().evaluate(records) == []
