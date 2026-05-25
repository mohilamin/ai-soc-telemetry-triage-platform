"""Warehouse loading facade."""

from src.soc_core import load_duckdb_store


def load_warehouse() -> str:
    """Load DuckDB warehouse."""
    return load_duckdb_store()

