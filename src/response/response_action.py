"""Response action helpers."""


def response_action(severity: str) -> str:
    """Return response action."""
    return "escalate_immediately" if severity in {"critical", "high"} else "review_queue"

