"""Evidence loader."""

import pandas as pd

from src.common.paths import TIMELINES


def load_evidence_records() -> pd.DataFrame:
    """Load evidence records."""
    return pd.read_csv(TIMELINES / "evidence_records.csv")

