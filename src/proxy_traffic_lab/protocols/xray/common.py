from __future__ import annotations

import hashlib
import ipaddress
import re
import uuid
from typing import Any

from proxy_traffic_lab.common.errors import ConfigurationError
from proxy_traffic_lab.encryptions.material import TlsMaterial


def normalize_server_address(value: str) -> str:
    try:
        return ipaddress.ip_address(value).compressed
    except ValueError as exc:
        raise ConfigurationError(
            "server_address must be the VPS IPv4 or IPv6 address; "
            "placeholders and hostnames are rejected"
        ) from exc



def websocket_path(client_id: str) -> str:
    try:
        identifier = uuid.UUID(client_id)
    except (ValueError, TypeError) as exc:
        raise ConfigurationError("invalid VMess client UUID") from exc
    return f"/assets/{identifier.hex[:16]}"



def xhttp_path(client_id: str) -> str:
    try:
        identifier = uuid.UUID(client_id)
    except (ValueError, TypeError) as exc:
        raise ConfigurationError("invalid XHTTP client UUID") from exc
    return f"/xhttp/{identifier.hex[:16]}"



def trojan_password(material: TlsMaterial) -> str:
    return hashlib.sha256(f"trojan:{material.client_id}".encode()).hexdigest()



def reality_values(material: TlsMaterial) -> tuple[str, str, str]:
    if not material.reality_private_key or not material.reality_public_key:
        raise ConfigurationError(
            "REALITY keys are missing; render a configured REALITY target first"
        )
    short_id = material.reality_short_id or ""
    if not re.fullmatch(r"[0-9a-fA-F]{2,16}", short_id):
        raise ConfigurationError("REALITY shortId must be 1-8 bytes encoded as hex")
    return material.reality_private_key, material.reality_public_key, short_id.lower()



def server_routing() -> dict[str, Any]:
    return {
        "domainStrategy": "IPIfNonMatch",
        "rules": [
            {
                "type": "field",
                "ip": [
                    "geoip:private",
                    "100.64.0.0/10",
                    "100.100.100.200/32",
                    "169.254.0.0/16",
                    "224.0.0.0/4",
                    "240.0.0.0/4",
                    "::1/128",
                    "fe80::/10",
                    "fc00::/7",
                ],
                "outboundTag": "block",
            },
            {
                "type": "field",
                "protocol": ["bittorrent"],
                "outboundTag": "block",
            },
        ],
    }



def validate_port(port: int) -> None:
    if not 1 <= port <= 65535:
        raise ConfigurationError("port must be between 1 and 65535")
