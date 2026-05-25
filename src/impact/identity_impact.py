"""Identity impact helpers."""


def identity_impact(privilege_level: str) -> int:
    """Return identity impact score."""
    return {"admin": 35, "privileged": 25, "standard": 10}.get(privilege_level, 10)

