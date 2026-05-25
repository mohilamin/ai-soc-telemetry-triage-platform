"""Network normalization."""


def normalize_network_event(event: dict) -> dict:
    """Normalize network event."""
    return {**event, "normalized_source": "network"}

