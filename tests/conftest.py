"""Shared test fixtures."""

import pytest

from src.soc_core import run_pipeline


@pytest.fixture(scope="session", autouse=True)
def pipeline_outputs() -> dict[str, object]:
    """Run pipeline once for test session."""
    return run_pipeline()

