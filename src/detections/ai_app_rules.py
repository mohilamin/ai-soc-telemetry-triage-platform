"""AI app detection helpers."""


def prompt_injection(score: int, policy_result: str) -> bool:
    """Detect AI prompt injection."""
    return score >= 80 or policy_result == "deny"

