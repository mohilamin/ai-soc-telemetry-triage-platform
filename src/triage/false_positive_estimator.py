"""False-positive estimator."""


def estimate_false_positive_probability(confidence: float) -> float:
    """Estimate false-positive probability."""
    return round(max(0.02, 0.35 - confidence * 0.25), 3)

