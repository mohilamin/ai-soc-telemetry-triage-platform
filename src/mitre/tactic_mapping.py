"""Tactic mapping helpers."""

from src.soc_core import SCENARIOS


def map_tactic(scenario_type: str) -> str:
    """Map scenario to MITRE-style tactic."""
    return next((tactic for scenario, tactic, _technique, _severity, _response in SCENARIOS if scenario == scenario_type), "Unknown")

