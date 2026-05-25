"""Deterministic time helpers."""

from datetime import UTC, datetime, timedelta

BASE_TIME = datetime(2026, 1, 1, tzinfo=UTC)


def timestamp(minutes: int) -> str:
    """Return deterministic ISO timestamp."""
    return (BASE_TIME + timedelta(minutes=minutes)).isoformat()

