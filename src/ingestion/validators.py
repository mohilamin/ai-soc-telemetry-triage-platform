"""Telemetry validators."""

import pandas as pd


def validate_not_empty(frame: pd.DataFrame) -> bool:
    """Return whether a frame has rows."""
    return not frame.empty

