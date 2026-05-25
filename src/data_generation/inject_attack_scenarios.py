"""Inject synthetic attack scenarios."""

from src.soc_core import inject_attack_scenarios


def main() -> int:
    """Inject scenarios."""
    frame = inject_attack_scenarios()
    print({"attack_scenarios": len(frame)})
    return len(frame)


if __name__ == "__main__":
    main()

