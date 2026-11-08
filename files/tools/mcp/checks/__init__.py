"""6B-2 check family: check.run dispatcher generated from checks.json."""
from .policy import check_extra  # noqa: F401
from .handlers import execute  # noqa: F401

__all__ = ["check_extra", "execute"]
