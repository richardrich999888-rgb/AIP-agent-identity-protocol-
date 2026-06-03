from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

from .client import AipClient


@dataclass(frozen=True)
class AIPConfig:
    """Runtime configuration for AIP service-backed SDK helpers."""

    base_url: str = "http://127.0.0.1:8081"
    aip_token: Optional[str] = None
    timeout: float = 5.0

    @classmethod
    def from_env(cls) -> "AIPConfig":
        return cls(
            base_url=os.getenv("AIP_BASE_URL")
            or os.getenv("AIP_SERVICE_URL")
            or "http://127.0.0.1:8081",
            aip_token=os.getenv("AIP_TOKEN"),
            timeout=float(os.getenv("AIP_TIMEOUT_SECONDS", "5.0")),
        )

    def client(self) -> AipClient:
        return AipClient(base_url=self.base_url, timeout=self.timeout)
