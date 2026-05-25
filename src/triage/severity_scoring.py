"""Severity scoring."""


def score_severity(severity: str, asset_criticality: str = "medium") -> int:
    """Score severity with asset criticality."""
    base = {"critical": 95, "high": 80, "medium": 55, "low": 25}.get(severity, 40)
    return min(100, base + (10 if asset_criticality == "critical" else 0))

