"""Technique mapping helpers."""

from src.soc_core import SCENARIOS


def map_technique(scenario_type: str) -> str:
    """Map scenario to MITRE-style technique."""
    return next((technique for scenario, _tactic, technique, _severity, _response in SCENARIOS if scenario == scenario_type), "Unknown")

