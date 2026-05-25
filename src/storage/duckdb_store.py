"""DuckDB store loader."""

from src.soc_core import load_duckdb_store as _load_duckdb_store


def load_store() -> str:
    """Load DuckDB warehouse."""
    return _load_duckdb_store()
