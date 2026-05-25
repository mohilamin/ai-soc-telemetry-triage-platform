"""Incident timeline loader."""

import pandas as pd

from src.common.paths import TIMELINES


def load_incident_timelines() -> pd.DataFrame:
    """Load incident timelines."""
    return pd.read_csv(TIMELINES / "incident_timelines.csv")

