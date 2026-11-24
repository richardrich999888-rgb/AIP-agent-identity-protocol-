"""Read-only client for the AIP evidence service, independent of AIRI telemetry."""

from .client import ApiError, Page, VanianClient

__all__ = ["ApiError", "Page", "VanianClient"]
__version__ = "0.1.0"
