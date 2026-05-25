"""FastAPI app for SOC telemetry triage."""

import json
from pathlib import Path
from typing import Any

import pandas as pd
from fastapi import FastAPI

from src.api.schemas import AttackScenarioRequest, FalsePositiveRequest, TriageIncidentRequest
from src.common.paths import ALERTS, DOC_RUNBOOKS, INCIDENTS, SCORECARDS, TELEMETRY, TIMELINES, TRIAGE
from src.soc_core import inject_attack_scenarios

app = FastAPI(title="AI SOC Telemetry Triage Platform")


def _records(path: Path, limit: int = 100) -> list[dict[str, Any]]:
    return pd.read_csv(path).head(limit).fillna("").to_dict(orient="records") if path.exists() else []


def _json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


@app.get("/health")
def health() -> dict[str, str]:
    """Health endpoint."""
    return {"status": "ok", "service": "ai-soc-telemetry-triage-platform"}


@app.get("/soc-summary")
def soc_summary() -> dict[str, Any]:
    """SOC summary."""
    return _json(SCORECARDS / "soc_performance_report.json")


@app.get("/telemetry-sources")
def telemetry_sources() -> dict[str, int]:
    """Telemetry source row counts."""
    return {path.stem: len(pd.read_csv(path)) for path in TELEMETRY.glob("*.csv")}


@app.get("/alerts")
def alerts() -> list[dict[str, Any]]:
    """Security alerts."""
    return _records(ALERTS / "security_alerts.csv")


@app.get("/alerts/{alert_id}")
def alert_detail(alert_id: str) -> dict[str, Any]:
    """Alert detail."""
    return next((row for row in _records(ALERTS / "security_alerts.csv", 10000) if row["alert_id"] == alert_id), {"found": False})


@app.get("/incidents")
def incidents() -> list[dict[str, Any]]:
    """Security incidents."""
    return _records(INCIDENTS / "security_incidents.csv")


@app.get("/incidents/{incident_id}")
def incident_detail(incident_id: str) -> dict[str, Any]:
    """Incident detail."""
    return next((row for row in _records(INCIDENTS / "security_incidents.csv", 10000) if row["incident_id"] == incident_id), {"found": False})


@app.get("/analyst-queue")
def analyst_queue() -> list[dict[str, Any]]:
    """Analyst queue."""
    return _records(TRIAGE / "analyst_queue.csv")


@app.get("/blast-radius/{incident_id}")
def blast_radius(incident_id: str) -> dict[str, Any]:
    """Blast radius for incident."""
    return next((row for row in _records(INCIDENTS / "blast_radius_report.csv", 10000) if row["incident_id"] == incident_id), {"found": False})


@app.get("/mitre-coverage")
def mitre_coverage() -> dict[str, Any]:
    """MITRE-style coverage."""
    return _json(SCORECARDS / "mitre_coverage_report.json")


@app.get("/scorecards")
def scorecards() -> dict[str, Any]:
    """Scorecards."""
    return {path.stem: _json(path) for path in SCORECARDS.glob("*.json")}


@app.get("/runbooks")
def runbooks() -> dict[str, str]:
    """Runbook list."""
    return {path.name: path.read_text(encoding="utf-8")[:500] for path in DOC_RUNBOOKS.glob("*.md")}


@app.get("/evidence/{incident_id}")
def evidence(incident_id: str) -> list[dict[str, Any]]:
    """Evidence for an incident."""
    return [row for row in _records(TIMELINES / "evidence_records.csv", 10000) if row["incident_id"] == incident_id]


@app.post("/simulate-attack-scenario")
def simulate_attack_scenario(request: AttackScenarioRequest) -> dict[str, Any]:
    """Simulate attack scenario."""
    manifest = inject_attack_scenarios()
    exists = request.scenario_type in set(manifest["scenario_type"])
    return {"scenario_type": request.scenario_type, "available": exists, "status": "simulated" if exists else "unknown_scenario"}


@app.post("/triage-incident")
def triage_incident(request: TriageIncidentRequest) -> dict[str, Any]:
    """Triage incident."""
    incident = incident_detail(request.incident_id)
    return {"incident_id": request.incident_id, "triage_status": "queued" if incident.get("found") is not False else "not_found", "incident": incident}


@app.post("/mark-false-positive")
def mark_false_positive(request: FalsePositiveRequest) -> dict[str, str]:
    """Mark an alert as false positive for demo purposes."""
    return {"alert_id": request.alert_id, "reviewer": request.reviewer, "status": "marked_false_positive"}
