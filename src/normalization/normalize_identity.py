"""Identity normalization."""


def normalize_identity_event(event: dict) -> dict:
    """Normalize identity event."""
    return {**event, "normalized_source": "identity"}

