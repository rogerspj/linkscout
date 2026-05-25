# Makes 'checker' a Python package and exports the one function callers need.
# Usage: from checker import check
from .core import check

__all__ = ["check"]
