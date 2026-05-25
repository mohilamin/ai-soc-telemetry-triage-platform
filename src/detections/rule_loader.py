"""Rule loader."""

import pandas as pd

from src.soc_core import create_detection_rules


def load_rules() -> pd.DataFrame:
    """Load detection rules."""
    return create_detection_rules()

