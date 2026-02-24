"""CLI modules for BBAI."""

from bbai.cli.main import app
from bbai.cli.setup_wizard import run_setup_wizard

__all__ = [
    "app",
    "run_setup_wizard",
]
