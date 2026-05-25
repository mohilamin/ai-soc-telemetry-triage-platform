"""Confidence scoring."""


def score_confidence(rule_confidence: float, scenario_match: bool = True) -> float:
    """Score alert confidence."""
    return round(min(1.0, rule_confidence + (0.05 if scenario_match else -0.1)), 3)

