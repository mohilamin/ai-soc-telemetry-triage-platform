"""Runbook recommender."""


def recommend_runbook(incident_type: str) -> str:
    """Recommend runbook for incident type."""
    return incident_type.replace("_", "-") + ".md"

