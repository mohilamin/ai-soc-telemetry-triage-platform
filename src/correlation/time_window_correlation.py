"""Time-window correlation helpers."""


def within_window(minutes_between: int, window_minutes: int = 60) -> bool:
    """Return whether events are within a correlation window."""
    return minutes_between <= window_minutes

