"""Email detection helpers."""


def phishing_click(phishing_score: int, clicked: bool) -> bool:
    """Detect phishing click."""
    return phishing_score >= 80 and clicked

