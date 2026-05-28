# Setup Guide

Placeholder setup guide for local development and future Snowflake configuration.

Current milestone: **Milestone 8 — Portfolio MVP Complete**.

This project includes Snowflake authentication configuration, a client wrapper, metadata collectors, MVP security checks, risk scoring, compliance mapping, JSON/CSV export utilities, Markdown report generation utilities, fake sample outputs, and a sample-aware dashboard. Tests and CI do not connect to Snowflake. Do not add real credentials or commit a `.env` file.

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

The Milestone 8 tests validate local YAML configuration, Snowflake client behavior, metadata collector behavior, security checks, risk scoring, compliance mapping, JSON/CSV exporters, Markdown report generation, sample generation, and dashboard fallback behavior through mocks and fake metadata only. They do not require Snowflake access.

Generate fake sample outputs and reports with:

```bash
python scripts/generate_sample_outputs.py
```

Run the dashboard against real generated findings or the included fake sample findings:

```bash
pip install -e ".[dashboard]"
streamlit run dashboard/streamlit_app.py
```
