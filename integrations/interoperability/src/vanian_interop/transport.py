"""Institution-configured HTTPS, with no ambient credentials or redirects."""
from __future__ import annotations

import ssl
import hashlib
from pathlib import Path
from urllib.parse import urlsplit
import httpx


def endpoint_origin(url: str) -> tuple[str, str, int]:
    value = urlsplit(url)
    if value.scheme != "https" or not value.hostname or value.username or value.password or value.fragment:
        raise ValueError("configured HTTPS endpoint without credentials/fragment required")
    return value.scheme, value.hostname, value.port or 443


class PinnedHttps:
    def __init__(self, origin: str, *, ca_file: str, client_cert: str | None = None,
                 client_key: str | None = None, max_bytes: int = 1_048_576):
        self.origin = endpoint_origin(origin)
        self.ca_file = ca_file
        self.ca_sha256 = hashlib.sha256(Path(ca_file).read_bytes()).hexdigest()
        self.max_bytes = max_bytes
        if bool(client_cert) != bool(client_key):
            raise ValueError("both client certificate and key required")
        context = ssl.create_default_context(cafile=ca_file)
        if client_cert:
            context.load_cert_chain(client_cert, client_key)
        self.client = httpx.Client(verify=context, timeout=20, follow_redirects=False, trust_env=False)

    def request(self, method: str, url: str, *, body: dict | None = None,
                access_token: str | None = None) -> bytes:
        if endpoint_origin(url) != self.origin:
            raise ValueError("cross-origin credential forwarding refused")
        headers = {"Accept": "application/json"}
        if access_token is not None:
            if not access_token or any(c in access_token for c in "\r\n"):
                raise ValueError("invalid credential")
            headers["Authorization"] = "Bearer " + access_token
        with self.client.stream(method, url, json=body, headers=headers) as response:
            if 300 <= response.status_code < 400:
                raise ValueError("redirect refused")
            response.raise_for_status()
            content = bytearray()
            for chunk in response.iter_bytes():
                content.extend(chunk)
                if len(content) > self.max_bytes:
                    raise ValueError("response exceeds configured bound")
            return bytes(content)

    def close(self):
        self.client.close()
