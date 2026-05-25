"""CSV loaders."""

import pandas as pd


def load_csv(path: str) -> pd.DataFrame:
    """Load a CSV file."""
    return pd.read_csv(path)

