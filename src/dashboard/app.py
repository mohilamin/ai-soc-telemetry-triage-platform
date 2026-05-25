"""Streamlit SOC dashboard."""

import json
from pathlib import Path

import pandas as pd
import streamlit as st

from src.common.paths import ALERTS, DOC_RUNBOOKS, INCIDENTS, RULES, SCORECARDS, TELEMETRY, TIMELINES, TRIAGE


def _csv(path: Path) -> pd.DataFrame:
    return pd.read_csv(path) if path.exists() else pd.DataFrame()


def _json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def main() -> None:
    """Render SOC dashboard."""
    st.set_page_config(page_title="AI SOC Telemetry Triage Platform", layout="wide")
    st.title("AI SOC Telemetry Triage Platform")
    score = _json(SCORECARDS / "soc_performance_report.json")
    cols = st.columns(4)
    cols[0].metric("Events", score.get("total_events_processed", 0))
    cols[1].metric("Alerts", score.get("total_alerts", 0))
    cols[2].metric("Incidents", score.get("total_incidents", 0))
    cols[3].metric("SOC Score", score.get("overall_soc_triage_score", 0))
    tabs = st.tabs(
        [
            "Telemetry Sources",
            "Detection Rules",
            "Alerts",
            "Correlated Incidents",
            "Analyst Queue",
            "MITRE Coverage",
            "Incident Timeline",
            "Blast Radius",
            "False Positive Review",
            "AI App Security Events",
            "Runbooks",
            "Scorecards",
        ]
    )
    with tabs[0]:
        st.dataframe(pd.DataFrame([{"source": path.stem, "rows": len(_csv(path))} for path in TELEMETRY.glob("*.csv")]), use_container_width=True)
    with tabs[1]:
        st.dataframe(_csv(RULES / "detection_rules_index.csv"), use_container_width=True)
    with tabs[2]:
        st.dataframe(_csv(ALERTS / "security_alerts.csv"), use_container_width=True)
    with tabs[3]:
        st.dataframe(_csv(INCIDENTS / "security_incidents.csv"), use_container_width=True)
    with tabs[4]:
        st.dataframe(_csv(TRIAGE / "analyst_queue.csv"), use_container_width=True)
    with tabs[5]:
        st.json(_json(SCORECARDS / "mitre_coverage_report.json"))
    with tabs[6]:
        st.dataframe(_csv(TIMELINES / "incident_timelines.csv"), use_container_width=True)
    with tabs[7]:
        st.dataframe(_csv(INCIDENTS / "blast_radius_report.csv"), use_container_width=True)
    with tabs[8]:
        st.dataframe(_csv(SCORECARDS / "false_positive_report.csv"), use_container_width=True)
    with tabs[9]:
        st.dataframe(_csv(TELEMETRY / "ai_app_security_logs.csv").head(200), use_container_width=True)
    with tabs[10]:
        for path in sorted(DOC_RUNBOOKS.glob("*.md")):
            st.subheader(path.stem)
            st.markdown(path.read_text(encoding="utf-8")[:1000])
    with tabs[11]:
        for path in sorted(SCORECARDS.glob("*.json")):
            st.subheader(path.stem)
            st.json(_json(path))


if __name__ == "__main__":
    main()
