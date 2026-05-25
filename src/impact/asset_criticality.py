"""Asset criticality helpers."""


def criticality_weight(criticality: str) -> int:
    """Return criticality weight."""
    return {"critical": 35, "high": 25, "medium": 15, "low": 5}.get(criticality, 10)

