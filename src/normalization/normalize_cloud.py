"""Cloud normalization."""


def normalize_cloud_event(event: dict) -> dict:
    """Normalize cloud event."""
    return {**event, "normalized_source": "cloud"}

