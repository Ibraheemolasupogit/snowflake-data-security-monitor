# Technical Report

Demo data notice: this report uses synthetic sample findings only and was not generated from a real Snowflake environment.

## Summary

- Total findings: 6
- Total risk score: 330
- Average risk score: 55.0

## Severity Summary

- critical: 1
- high: 1
- medium: 4

## Category Summary

- access: 1
- data-protection: 1
- identity: 2
- share: 1
- stage: 1

## Detailed Findings

### 1. User has ACCOUNTADMIN role

- Control ID: `SFM-001`
- Severity: `critical`
- Category: `identity`
- Resource: `USER/DEMO_ADMIN_USER`
- Description: DEMO DATA ONLY: this sample is synthetic and was not collected from a real Snowflake environment. A demo user is directly assigned ACCOUNTADMIN.
- Evidence: category=identity, role=ACCOUNTADMIN, owner=Data Security, status=Open, demo_data=True
- Recommendation: Review and remove ACCOUNTADMIN unless explicitly required.

### 2. Dormant user detected

- Control ID: `SFM-003`
- Severity: `medium`
- Category: `identity`
- Resource: `USER/DEMO_DORMANT_USER`
- Description: DEMO DATA ONLY: this sample is synthetic and was not collected from a real Snowflake environment. A demo user has no recent login activity.
- Evidence: category=identity, last_success_login=2025-01-01T00:00:00+00:00, owner=IAM, status=Open, demo_data=True
- Recommendation: Confirm ownership and disable or remove unused access.

### 3. Risky privilege granted to PUBLIC

- Control ID: `SFM-005`
- Severity: `high`
- Category: `access`
- Resource: `ROLE/PUBLIC`
- Description: DEMO DATA ONLY: this sample is synthetic and was not collected from a real Snowflake environment. PUBLIC has a risky demo privilege.
- Evidence: category=access, privilege=OWNERSHIP, granted_on=DATABASE, owner=Platform Security, status=Open, demo_data=True
- Recommendation: Revoke broad or write-capable privileges from PUBLIC.

### 4. External stage detected

- Control ID: `SFM-007`
- Severity: `medium`
- Category: `stage`
- Resource: `STAGE/DEMO_EXTERNAL_STAGE`
- Description: DEMO DATA ONLY: this sample is synthetic and was not collected from a real Snowflake environment. A demo external stage points to object storage.
- Evidence: category=stage, stage_url=s3://demo-bucket/path, owner=Data Platform, status=In Review, demo_data=True
- Recommendation: Review storage integration, stage grants, and business approval.

### 5. Outbound share detected

- Control ID: `SFM-008`
- Severity: `medium`
- Category: `share`
- Resource: `SHARE/DEMO_OUTBOUND_SHARE`
- Description: DEMO DATA ONLY: this sample is synthetic and was not collected from a real Snowflake environment. A demo outbound share has external consumers.
- Evidence: category=share, accounts=DEMO_CONSUMER_ACCOUNT, owner=Data Governance, status=Open, demo_data=True
- Recommendation: Validate consumers, shared objects, and approval evidence.

### 6. Missing masking policy indicator

- Control ID: `SFM-009`
- Severity: `medium`
- Category: `data-protection`
- Resource: `TABLE/DEMO_CUSTOMERS`
- Description: DEMO DATA ONLY: this sample is synthetic and was not collected from a real Snowflake environment. A sensitive demo table lacks a masking indicator.
- Evidence: category=data-protection, sensitive=True, owner=Data Governance, status=Planned, demo_data=True
- Recommendation: Review whether masking should protect sensitive columns.
