"""Trojan composition renderers targeting Xray-core."""

from __future__ import annotations

from typing import Any

from proxy_traffic_lab.encryptions.material import TlsMaterial
from proxy_traffic_lab.protocols.xray.common import (
    normalize_server_address,
    server_routing,
    trojan_password,
    validate_port,
    websocket_path,
)

def render_trojan_raw_tls_server(
    material: TlsMaterial,
    *,
    port: int,
    certificate_container_path: str = "/run/secrets/xray/server.crt",
    private_key_container_path: str = "/run/secrets/xray/server.key",
) -> dict[str, Any]:
    """Render Trojan over RAW TCP with TLS using Xray-core."""
    validate_port(port)
    return {
        "log": {"loglevel": "warning", "access": "none"},
        "inbounds": [
            {
                "tag": "trojan-raw-tls-in",
                "listen": "0.0.0.0",
                "port": port,
                "protocol": "trojan",
                "settings": {
                    "clients": [
                        {
                            "password": trojan_password(material),
                            "email": "trojan-raw-collector",
                        }
                    ]
                },
                "streamSettings": {
                    "method": "raw",
                    "security": "tls",
                    "tlsSettings": {
                        "rejectUnknownSni": True,
                        "minVersion": "1.3",
                        "certificates": [
                            {
                                "certificateFile": certificate_container_path,
                                "keyFile": private_key_container_path,
                            }
                        ],
                    },
                },
            }
        ],
        "outbounds": [
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"},
        ],
        "routing": server_routing(),
    }


def render_trojan_raw_tls_client(
    material: TlsMaterial,
    *,
    server_address: str,
    server_port: int,
    socks_port: int = 10808,
) -> dict[str, Any]:
    validate_port(server_port)
    validate_port(socks_port)
    normalized_server_address = normalize_server_address(server_address)
    return {
        "log": {"loglevel": "warning", "access": "none"},
        "inbounds": [
            {
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "socks",
                "settings": {"udp": False},
            }
        ],
        "outbounds": [
            {
                "tag": "proxy",
                "protocol": "trojan",
                "settings": {
                    "servers": [
                        {
                            "address": normalized_server_address,
                            "port": server_port,
                            "password": trojan_password(material),
                        }
                    ]
                },
                "streamSettings": {
                    "method": "raw",
                    "security": "tls",
                    "tlsSettings": {
                        "serverName": material.server_name,
                        "fingerprint": "chrome",
                        "pinnedPeerCertSha256": material.certificate_sha256,
                    },
                },
            },
            {"tag": "block", "protocol": "blackhole"},
        ],
    }


def render_trojan_websocket_tls_server(
    material: TlsMaterial,
    *,
    port: int,
    certificate_container_path: str = "/run/secrets/xray/server.crt",
    private_key_container_path: str = "/run/secrets/xray/server.key",
) -> dict[str, Any]:
    """Render Trojan over WebSocket with TLS using Xray-core."""
    validate_port(port)
    return {
        "log": {"loglevel": "warning", "access": "none"},
        "inbounds": [
            {
                "tag": "trojan-websocket-tls-in",
                "listen": "0.0.0.0",
                "port": port,
                "protocol": "trojan",
                "settings": {
                    "clients": [
                        {
                            "password": trojan_password(material),
                            "email": "trojan-websocket-collector",
                        }
                    ]
                },
                "streamSettings": {
                    "method": "websocket",
                    "security": "tls",
                    "wsSettings": {
                        "path": websocket_path(material.client_id),
                        "host": material.server_name,
                    },
                    "tlsSettings": {
                        "rejectUnknownSni": True,
                        "minVersion": "1.3",
                        "alpn": ["http/1.1"],
                        "certificates": [
                            {
                                "certificateFile": certificate_container_path,
                                "keyFile": private_key_container_path,
                            }
                        ],
                    },
                },
            }
        ],
        "outbounds": [
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"},
        ],
        "routing": server_routing(),
    }


def render_trojan_websocket_tls_client(
    material: TlsMaterial,
    *,
    server_address: str,
    server_port: int,
    socks_port: int = 10808,
) -> dict[str, Any]:
    validate_port(server_port)
    validate_port(socks_port)
    normalized_server_address = normalize_server_address(server_address)
    return {
        "log": {"loglevel": "warning", "access": "none"},
        "inbounds": [
            {
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "socks",
                "settings": {"udp": False},
            }
        ],
        "outbounds": [
            {
                "tag": "proxy",
                "protocol": "trojan",
                "settings": {
                    "servers": [
                        {
                            "address": normalized_server_address,
                            "port": server_port,
                            "password": trojan_password(material),
                        }
                    ]
                },
                "streamSettings": {
                    "method": "websocket",
                    "security": "tls",
                    "wsSettings": {
                        "path": websocket_path(material.client_id),
                        "host": material.server_name,
                    },
                    "tlsSettings": {
                        "serverName": material.server_name,
                        "fingerprint": "chrome",
                        "alpn": ["http/1.1"],
                        "pinnedPeerCertSha256": material.certificate_sha256,
                    },
                },
            },
            {"tag": "block", "protocol": "blackhole"},
        ],
    }

