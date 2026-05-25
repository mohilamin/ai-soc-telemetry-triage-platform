"""Run full SOC triage pipeline."""

from src.soc_core import run_pipeline


def main() -> dict[str, object]:
    """Run pipeline."""
    return run_pipeline()


if __name__ == "__main__":
    main()

