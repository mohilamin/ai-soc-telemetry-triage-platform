"""Escalation helpers."""


def escalation_owner(severity: str) -> str:
    """Return escalation owner."""
    return "SOC Tier 2" if severity in {"critical", "high"} else "SOC Tier 1"

