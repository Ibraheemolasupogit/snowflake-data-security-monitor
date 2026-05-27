# Architecture

Placeholder for the production architecture of the Snowflake data security monitor.

Current milestone: **Milestone 1 — Repository Foundation and Security Engineering Scaffold**.

Milestone 1 defines the repository structure and module boundaries only. It does not include Snowflake connectivity, credential handling beyond placeholders, collector execution, scanner orchestration, scoring, or report generation.

Planned flow:

1. Load non-secret settings from `config/`.
2. Read SQL templates from `sql/`.
3. Collect Snowflake metadata through collector modules.
4. Normalize records into typed models.
5. Run modular security checks.
6. Score findings and map them to compliance frameworks.
7. Write JSON, CSV, Markdown, and dashboard-ready outputs.

Roadmap alignment:

- Milestone 2 will add configuration loading and validation.
- Milestone 3 will add the Snowflake authentication configuration and client wrapper with mocked tests.
- Milestone 4 will add metadata collectors that use the SQL templates.
- Milestone 5 will add MVP security checks.
- Milestones 6 and 7 will add scoring, exports, and reports.
- Milestone 8 will add dashboard and portfolio polish.
