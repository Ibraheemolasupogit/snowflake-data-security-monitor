# Snowflake Data Security Monitor

A portfolio-ready foundation for a Python and SQL-based Snowflake security posture monitoring tool. The future MVP will collect Snowflake metadata about users, roles, grants, stages, shares, login activity, masking policies, and row access policies, then evaluate that data against configurable security controls.

This repository is intentionally at the project foundation stage. It does not connect to Snowflake, does not include credentials, and does not implement the full scanner yet.

## Build Status / Current Milestone

Current milestone: **Milestone 4 — Metadata Collectors**.

Milestone 1 established the production-style repository structure and module boundaries. Milestone 2 added local YAML loading and validation. Milestone 3 added environment-backed Snowflake authentication configuration and a safe client wrapper. Milestone 4 adds metadata collectors that load SQL templates and delegate execution to the client wrapper while tests continue to use mocks only.

## Why This Matters

Snowflake often holds sensitive enterprise data and is commonly connected to BI, analytics, data science, SaaS, and data-sharing workflows. Weak role design, broad grants, unmanaged external stages, exposed shares, and stale accounts can create meaningful data security risk even when the underlying platform is well managed.

Continuous monitoring helps security and data teams identify risky configuration drift, validate access controls, support compliance evidence, and prioritize remediation before access issues become incidents.

## Security Risks Monitored

The future monitor is designed to identify risks such as:

- Users assigned highly privileged roles such as `ACCOUNTADMIN`
- Excessive number of administrative users
- Dormant users and users without recent login activity
- Disabled users that still retain active grants
- Broad privileges on databases, schemas, tables, stages, and shares
- Risky grants to the `PUBLIC` role
- External stages that may expose data movement paths
- Outbound shares that require governance review
- Missing masking policy or row access policy indicators

## Planned MVP Checks

Initial checks will be implemented as modular control classes or functions under `src/snowflake_data_security_monitor/checks/`.

- `accountadmin_users`
- `excessive_accountadmin_users`
- `dormant_users`
- `disabled_users_with_active_grants`
- `users_without_recent_login`
- `broad_privileges`
- `public_role_risky_privileges`
- `external_stages`
- `outbound_shares`
- `missing_masking_policy_indicators`
- `missing_row_access_policy_indicators`

## Milestone Roadmap

### Milestone 1 — Repository Foundation and Security Engineering Scaffold

- Create production-style repo structure
- Add configuration skeletons
- Add SQL query skeletons
- Add Python package skeleton
- Add placeholder collectors, checks, models, scoring, reporting, dashboard, scripts, tests, and CI
- Do not connect to Snowflake
- Do not add real credentials

### Milestone 2 — Configuration Loading and Validation

- Implement configuration loading and validation
- Add tests for config loading
- Validate YAML files
- Keep Snowflake connection mocked and inactive

### Milestone 3 — Snowflake Client Wrapper

- Implement Snowflake authentication configuration and Snowflake client wrapper
- Add safe error handling
- Add tests with mocks
- Do not require real Snowflake access in CI

### Milestone 4 — Metadata Collectors

- Implement metadata collectors for users, roles, grants, stages, shares, policies, login history, and query history
- Use SQL files from the `sql/` directory
- Add mocked collector tests

### Milestone 5 — MVP Security Checks

- Implement `ACCOUNTADMIN` users check
- Implement excessive `ACCOUNTADMIN` users check
- Implement dormant users check
- Implement disabled users with active grants check
- Implement `PUBLIC` role risky privileges check
- Implement broad role privileges check
- Implement external stages check
- Implement outbound shares check
- Implement missing masking policy indicators check
- Implement missing row access policy indicators check

### Milestone 6 — Risk Scoring and Exports

- Implement risk scoring and compliance mapping
- Export findings to JSON and CSV
- Generate risk score summary

### Milestone 7 — Report Generation

- Generate executive summary, technical report, and remediation plan using templates

### Milestone 8 — Portfolio Polish

- Add sample outputs
- Build out the dashboard
- Improve CI
- Add portfolio polish

## Architecture

```text
SQL query skeletons -> collectors -> normalized models -> checks -> scoring -> reports
```

Planned components:

- `sql/`: read-only query templates for Snowflake metadata collection
- `collectors/`: future Snowflake metadata collection modules
- `models/`: typed data structures for findings, controls, assets, grants, and users
- `checks/`: risk detection logic mapped to controls
- `scoring/`: severity and risk score calculation
- `compliance/`: mappings to frameworks such as CIS and NIST
- `reporting/`: JSON, CSV, Markdown, and dashboard-ready output generation
- `dashboard/`: placeholder Streamlit interface for future visualization

## Tech Stack

- Python 3.11+
- SQL query templates for Snowflake metadata
- Pydantic for typed models
- PyYAML for configuration
- Pandas for tabular output handling
- Pytest for validation
- Ruff and mypy for code quality
- GitHub Actions for placeholder CI and security checks
- Streamlit placeholder for future dashboarding

## Setup

```bash
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e ".[dev]"
```

Copy the environment template only when you are ready to configure local development:

```bash
cp .env.example .env
```

Do not commit `.env` or any real Snowflake credentials.

## Basic Validation

```bash
python -m pytest
python -m ruff check .
python -m mypy src
```

At this stage, tests validate package imports, model skeletons, configuration loading, the Snowflake client wrapper, and metadata collectors through mocks. They do not require Snowflake access.

## Expected Future Outputs

The scanner will eventually produce:

- `outputs/findings.json`
- `outputs/findings.csv`
- `outputs/risk_score_summary.csv`
- `reports/executive_summary.md`
- `reports/technical_report.md`
- `reports/remediation_plan.md`

Sample outputs will live under `outputs/sample/` and `reports/sample/` once the MVP is implemented.

## Security Notes

- No real credentials should be committed to this repository.
- `.env.example` contains placeholder variable names only.
- The future Snowflake connection should use least-privilege monitoring roles.
- Queries should collect metadata needed for security posture assessment, not sensitive table data.
- Generated findings and reports may contain sensitive access-control details and should be protected.

## Portfolio Relevance

This project is designed to demonstrate practical Data Security Engineer and SaaS Security Engineer skills:

- Securing enterprise data platforms such as Snowflake
- Engineering continuous security monitoring workflows
- Building custom API and SQL-based checks
- Assessing access, configuration, and control effectiveness
- Supporting SSPM-style risk identification and remediation
- Producing evidence-oriented reporting for compliance and governance
- Mapping technical findings to frameworks such as CIS and NIST

## Current Status

Milestone 4 adds metadata collectors that use SQL files from `sql/` and delegate execution to the Snowflake client wrapper. The next approved task should begin Milestone 5 by adding MVP security checks.
