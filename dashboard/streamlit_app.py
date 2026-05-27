"""Streamlit dashboard placeholder."""

from __future__ import annotations


def main() -> None:
    """Render the future dashboard."""
    try:
        import streamlit as st
    except ImportError as exc:
        raise SystemExit("Install the dashboard extra to run Streamlit: pip install -e '.[dashboard]'") from exc

    st.title("Snowflake Data Security Monitor")
    st.info("Dashboard implementation will be added after scanner outputs are defined.")


if __name__ == "__main__":
    main()
