from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class TlsMaterial:
    client_id: str
    server_name: str
    certificate_sha256: str
    certificate_path: Path
    private_key_path: Path
    reality_private_key: str | None = None
    reality_public_key: str | None = None
    reality_short_id: str | None = None
    reality_server_name: str = "www.microsoft.com"
    reality_dest: str = "www.microsoft.com:443"
