# Setup Guide

Placeholder setup guide for local development and future Snowflake configuration.

Current milestone: **Milestone 2 — Configuration Loading and Validation**.

This project does not connect to Snowflake yet. Do not add real credentials. Snowflake access should remain mocked or inactive until the approved milestone introduces client configuration and tests.

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

The Milestone 2 tests validate local YAML configuration only and do not require Snowflake access.
