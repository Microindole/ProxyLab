from __future__ import annotations

import base64
import hashlib
from typing import Any

from proxy_traffic_lab.providers.xray.runtime import (
    VlessTlsMaterial,
    _normalize_server_address,
    _server_routing,
    _validate_port,
)


SS2022_METHOD = "2022-blake3-aes-128-gcm"


def render_shadowsocks_2022_server(
    material: VlessTlsMaterial,
    *,
    port: int,
    network: str,
) -> dict[str, Any]:
    """Render native Xray-core Shadowsocks 2022 inbound configuration."""
    _validate_network(network)
    _validate_port(port)
    return {
        "log": {"loglevel": "warning", "access": "none"},
        "inbounds": [
            {
                "tag": f"shadowsocks-2022-{network}-in",
                "listen": "0.0.0.0",
                "port": port,
                "protocol": "shadowsocks",
                "settings": {
                    "network": network,
                    "method": SS2022_METHOD,
                    "password": _ss2022_key(material, network),
                },
            }
        ],
        "outbounds": [
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"},
        ],
        "routing": _server_routing(),
    }


def render_shadowsocks_2022_client(
    material: VlessTlsMaterial,
    *,
    server_address: str,
    server_port: int,
    socks_port: int = 10808,
    network: str,
) -> dict[str, Any]:
    """Render native Xray-core Shadowsocks 2022 outbound configuration."""
    _validate_network(network)
    _validate_port(server_port)
    _validate_port(socks_port)
    address = _normalize_server_address(server_address)
    return {
        "log": {"loglevel": "warning", "access": "none"},
        "inbounds": [
            {
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "socks",
                "settings": {"udp": network == "udp"},
            }
        ],
        "outbounds": [
            {
                "tag": "proxy",
                "protocol": "shadowsocks",
                "settings": {
                    "address": address,
                    "port": server_port,
                    "method": SS2022_METHOD,
                    "password": _ss2022_key(material, network),
                },
            },
            {"tag": "block", "protocol": "blackhole"},
        ],
    }


def _ss2022_key(material: VlessTlsMaterial, network: str) -> str:
    # AES-128 SS2022 uses exactly 16 random-looking key bytes, Base64 encoded.
    raw = hashlib.sha256(
        f"proxy-lab:ss2022:{network}:{material.client_id}".encode()
    ).digest()[:16]
    return base64.b64encode(raw).decode("ascii")


def _validate_network(network: str) -> None:
    if network not in {"tcp", "udp"}:
        raise ValueError("Shadowsocks network must be tcp or udp")
