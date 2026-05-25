"""Identity detection helpers."""


def is_impossible_travel(countries: list[str]) -> bool:
    """Detect impossible travel signal."""
    return len(set(countries)) > 1

