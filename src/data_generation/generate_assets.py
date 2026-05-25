"""Generate synthetic SOC assets."""

from src.soc_core import generate_assets


def main() -> dict[str, int]:
    """Generate assets."""
    result = generate_assets()
    print(result)
    return result


if __name__ == "__main__":
    main()

