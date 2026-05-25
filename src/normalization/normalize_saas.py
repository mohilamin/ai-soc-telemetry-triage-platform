"""SaaS normalization."""


def normalize_saas_event(event: dict) -> dict:
    """Normalize SaaS event."""
    return {**event, "normalized_source": "saas"}

