"""Load config.yaml and resolve paths relative to the ml/ directory."""

from pathlib import Path

import yaml

ML_DIR = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG = ML_DIR / "config.yaml"


def load_config(path=DEFAULT_CONFIG):
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def resolve(relative_path):
    """Turn a path from config.yaml into an absolute path under ml/."""
    return ML_DIR / relative_path
