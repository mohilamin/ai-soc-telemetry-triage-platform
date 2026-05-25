"""Network detection helpers."""


def high_egress(bytes_out: int) -> bool:
    """Detect high egress."""
    return bytes_out > 1_000_000

