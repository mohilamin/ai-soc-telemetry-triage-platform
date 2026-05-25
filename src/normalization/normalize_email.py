"""Email normalization."""


def normalize_email_event(event: dict) -> dict:
    """Normalize email event."""
    return {**event, "normalized_source": "email"}

