"""Alert deduplication."""

import pandas as pd


def deduplicate_alerts(alerts: pd.DataFrame) -> pd.DataFrame:
    """Drop duplicate alerts by rule, entity, asset, and event."""
    return alerts.drop_duplicates(subset=["rule_id", "entity_id", "asset_id", "event_ids"])

