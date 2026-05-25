"""Configuration helpers."""

from pathlib import Path

import yaml

from src.common.paths import ROOT


def load_yaml(path: str | Path) -> dict:
    """Load a YAML file relative to the repository root."""
    full_path = ROOT / path
    return yaml.safe_load(full_path.read_text(encoding="utf-8")) or {}


def settings() -> dict:
    """Load project settings."""
    return load_yaml("config/settings.yaml")

