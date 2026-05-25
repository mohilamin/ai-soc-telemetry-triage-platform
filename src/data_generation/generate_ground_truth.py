"""Generate attack scenario ground truth."""

from src.soc_core import generate_ground_truth


def main() -> dict[str, int]:
    """Generate ground truth."""
    result = generate_ground_truth()
    print(result)
    return result


if __name__ == "__main__":
    main()

