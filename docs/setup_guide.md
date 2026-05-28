# Setup Guide

Placeholder setup guide for local development and future Snowflake configuration.

Current milestone: **Milestone 3 — Snowflake Client Wrapper**.

This project includes Snowflake authentication configuration and a client wrapper, but tests and CI do not connect to Snowflake. Do not add real credentials or commit a `.env` file.

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

The Milestone 3 tests validate local YAML configuration and Snowflake client behavior through mocks only. They do not require Snowflake access.
