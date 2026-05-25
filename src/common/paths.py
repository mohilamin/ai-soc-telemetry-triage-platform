"""Project path helpers."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "data"
RAW = DATA / "raw"
TELEMETRY = DATA / "telemetry"
DETECTIONS = DATA / "detections"
ALERTS = DATA / "alerts"
INCIDENTS = DATA / "incidents"
TRIAGE = DATA / "triage"
TIMELINES = DATA / "timelines"
RUNBOOKS = DATA / "runbooks"
RESPONSE = DATA / "response"
COVERAGE = DATA / "coverage"
WAREHOUSE = DATA / "warehouse"
SCORECARDS = DATA / "scorecards"
DOC_RUNBOOKS = ROOT / "docs" / "runbooks"
RULES = ROOT / "rules"


def ensure_dirs() -> None:
    """Create all runtime output directories."""
    for path in [
        RAW,
        TELEMETRY,
        DETECTIONS,
        ALERTS,
        INCIDENTS,
        TRIAGE,
        TIMELINES,
        RUNBOOKS,
        RESPONSE,
        COVERAGE,
        WAREHOUSE,
        SCORECARDS,
        DOC_RUNBOOKS,
    ]:
        path.mkdir(parents=True, exist_ok=True)

