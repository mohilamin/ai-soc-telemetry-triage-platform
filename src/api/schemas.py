"""API schemas."""

from pydantic import BaseModel


class AttackScenarioRequest(BaseModel):
    """Attack scenario simulation request."""

    scenario_type: str


class TriageIncidentRequest(BaseModel):
    """Incident triage request."""

    incident_id: str


class FalsePositiveRequest(BaseModel):
    """False-positive request."""

    alert_id: str
    reviewer: str = "demo_analyst"

