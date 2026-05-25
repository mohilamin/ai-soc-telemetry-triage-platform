"""Generate synthetic SOC telemetry."""

from src.soc_core import generate_telemetry


def main() -> dict[str, int]:
    """Generate telemetry."""
    result = generate_telemetry()
    print(result)
    return result


if __name__ == "__main__":
    main()

