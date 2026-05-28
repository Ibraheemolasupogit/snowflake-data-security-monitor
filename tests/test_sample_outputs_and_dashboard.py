from __future__ import annotations

import csv
import json
from pathlib import Path

from dashboard.streamlit_app import load_findings_dataframe, resolve_findings_path
from scripts.generate_sample_outputs import DEMO_NOTICE, generate_sample_outputs


def test_generate_sample_outputs_writes_fake_outputs_and_reports(tmp_path: Path) -> None:
    output_dir = tmp_path / "outputs" / "sample"
    report_dir = tmp_path / "reports" / "sample"

    generate_sample_outputs(output_dir=output_dir, report_dir=report_dir)

    findings_json = output_dir / "findings.json"
    findings_csv = output_dir / "findings.csv"
    risk_summary_csv = output_dir / "risk_score_summary.csv"

    assert findings_json.exists()
    assert findings_csv.exists()
    assert risk_summary_csv.exists()
    assert (report_dir / "executive_summary.md").exists()
    assert (report_dir / "technical_report.md").exists()
    assert (report_dir / "remediation_plan.md").exists()

    payload = json.loads(findings_json.read_text(encoding="utf-8"))
    assert payload[0]["evidence"]["demo_data"] is True
    assert DEMO_NOTICE in payload[0]["description"]

    with findings_csv.open("r", encoding="utf-8", newline="") as file:
        rows = list(csv.DictReader(file))
    assert rows[0]["resource_name"] == "DEMO_ADMIN_USER"

    with risk_summary_csv.open("r", encoding="utf-8", newline="") as file:
        summary_rows = list(csv.DictReader(file))
    assert {
        "metric": "demo_notice",
        "name": "all",
        "value": "DEMO DATA ONLY - synthetic sample output, not collected from a real "
        "Snowflake environment",
    } in summary_rows


def test_dashboard_resolves_real_findings_before_sample(tmp_path: Path) -> None:
    real_path = tmp_path / "outputs" / "findings.csv"
    sample_path = tmp_path / "outputs" / "sample" / "findings.csv"
    real_path.parent.mkdir(parents=True)
    sample_path.parent.mkdir(parents=True)
    real_path.write_text("control_id\nSFM-001\n", encoding="utf-8")
    sample_path.write_text("control_id\nSFM-999\n", encoding="utf-8")

    assert resolve_findings_path(real_path, sample_path) == real_path


def test_dashboard_falls_back_to_sample_findings(tmp_path: Path) -> None:
    real_path = tmp_path / "outputs" / "findings.csv"
    sample_path = tmp_path / "outputs" / "sample" / "findings.csv"
    sample_path.parent.mkdir(parents=True)
    sample_path.write_text("control_id,title\nSFM-001,Demo\n", encoding="utf-8")

    resolved_path = resolve_findings_path(real_path, sample_path)
    dataframe = load_findings_dataframe(resolved_path)

    assert resolved_path == sample_path
    assert dataframe.iloc[0]["control_id"] == "SFM-001"
