# Executive Summary

Demo data notice: this report uses synthetic sample findings only and was not generated from a real Snowflake environment.

## Risk Overview

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

## Top Risks

- [CRITICAL] User has ACCOUNTADMIN role on USER `DEMO_ADMIN_USER`
- [HIGH] Risky privilege granted to PUBLIC on ROLE `PUBLIC`
- [MEDIUM] Dormant user detected on USER `DEMO_DORMANT_USER`
- [MEDIUM] External stage detected on STAGE `DEMO_EXTERNAL_STAGE`
- [MEDIUM] Outbound share detected on SHARE `DEMO_OUTBOUND_SHARE`

## Recommended Priorities

- Prioritize critical and high severity access-control findings.
- Review privileged and dormant user access.
- Review external data movement and sharing paths.
- Track remediation owners and status until closure.
