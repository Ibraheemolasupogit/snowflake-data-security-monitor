# Setup Guide

Placeholder setup guide for local development and future Snowflake configuration.

Current milestone: **Milestone 5 — MVP Security Checks**.

This project includes Snowflake authentication configuration, a client wrapper, metadata collectors, and MVP security checks, but tests and CI do not connect to Snowflake. Do not add real credentials or commit a `.env` file.

Milestone-based setup documentation should cover:

- Python environment setup
- Configuration loading and YAML validation in Milestone 2
- Least-privilege Snowflake monitoring role
- Required Snowflake views and privileges
- Secret handling
- Local validation commands

Run local tests with:

```bash
python -m pytest
```

The Milestone 5 tests validate local YAML configuration, Snowflake client behavior, metadata collector behavior, and security checks through mocks and fake metadata only. They do not require Snowflake access.
