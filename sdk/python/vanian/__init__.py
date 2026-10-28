"""Evidence reads and Admin configuration registration, separate from AIRI telemetry."""

from .client import ApiError, Page, VanianClient

__all__ = ["ApiError", "Page", "VanianClient"]
__version__ = "0.1.0"
