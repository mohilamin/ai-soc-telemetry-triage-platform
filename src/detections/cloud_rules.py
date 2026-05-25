"""Cloud detection helpers."""


def privileged_cloud_action(action: str) -> bool:
    """Detect privileged cloud action."""
    return action in {"UpdateRole", "AssumeRole", "CreateAccessKey"}

