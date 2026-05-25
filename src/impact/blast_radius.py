"""Blast radius scoring."""


def calculate_blast_radius(affected_users: int, affected_assets: int, sensitive_data: bool) -> int:
    """Calculate blast radius score."""
    return min(100, affected_users * 5 + affected_assets * 8 + (35 if sensitive_data else 0))

