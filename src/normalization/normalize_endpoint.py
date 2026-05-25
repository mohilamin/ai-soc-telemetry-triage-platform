"""Endpoint normalization."""


def normalize_endpoint_event(event: dict) -> dict:
    """Normalize endpoint event."""
    return {**event, "normalized_source": "endpoint"}

