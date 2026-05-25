"""AI app normalization."""


def normalize_ai_app_event(event: dict) -> dict:
    """Normalize AI app event."""
    return {**event, "normalized_source": "ai_app"}

