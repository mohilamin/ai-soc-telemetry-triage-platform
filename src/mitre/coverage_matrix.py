"""Coverage matrix helpers."""

import pandas as pd

from src.common.paths import DETECTIONS


def load_coverage_matrix() -> pd.DataFrame:
    """Load coverage matrix."""
    return pd.read_csv(DETECTIONS / "detection_rule_coverage.csv")

