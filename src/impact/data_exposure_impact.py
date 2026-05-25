"""Data exposure impact helpers."""


def data_exposure_score(records_at_risk: int) -> int:
    """Score data exposure impact."""
    return min(100, records_at_risk // 100)

