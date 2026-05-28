"""Streamlit dashboard for generated or sample findings."""

from __future__ import annotations

from pathlib import Path

import pandas as pd

DEFAULT_FINDINGS_PATH = Path("outputs/findings.csv")
SAMPLE_FINDINGS_PATH = Path("outputs/sample/findings.csv")


def resolve_findings_path(
    findings_path: Path = DEFAULT_FINDINGS_PATH,
    sample_path: Path = SAMPLE_FINDINGS_PATH,
) -> Path:
    """Return real findings when available, otherwise the bundled sample findings."""
    if findings_path.exists():
        return findings_path
    return sample_path


def load_findings_dataframe(findings_path: Path) -> pd.DataFrame:
    """Load findings from CSV."""
    return pd.read_csv(findings_path)


def main() -> None:
    """Render the findings dashboard."""
    try:
        import streamlit as st
    except ImportError as exc:
        message = "Install the dashboard extra to run Streamlit: pip install -e '.[dashboard]'"
        raise SystemExit(message) from exc

    st.title("Snowflake Data Security Monitor")
    findings_path = resolve_findings_path()
    if not findings_path.exists():
        st.warning("No findings CSV found. Run `python scripts/generate_sample_outputs.py`.")
        return

    findings = load_findings_dataframe(findings_path)
    if findings_path == SAMPLE_FINDINGS_PATH:
        st.info("Displaying fake demo data from outputs/sample/findings.csv.")

    st.metric("Total Findings", len(findings))

    severity_counts = findings["severity"].value_counts().sort_index()
    st.subheader("Findings by Severity")
    st.bar_chart(severity_counts)

    st.subheader("Findings")
    display_columns = [
        "control_id",
        "title",
        "severity",
        "resource_type",
        "resource_name",
        "remediation",
    ]
    st.dataframe(findings[display_columns], use_container_width=True)


if __name__ == "__main__":
    main()
