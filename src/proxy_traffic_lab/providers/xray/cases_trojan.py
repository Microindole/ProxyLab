from __future__ import annotations

from typing import Any

from proxy_traffic_lab.providers.xray.runtime import (
    VlessTlsMaterial,
    _normalize_server_address,
    _server_routing,
    _trojan_password,
    _validate_port,
    _websocket_path,
)

def render_trojan_raw_tls_server(
    material: VlessTlsMaterial,
    *,
    port: int,
    certificate_container_path: str = "/run/secrets/xray/server.crt",
    private_key_container_path: str = "/run/secrets/xray/server.key",
) -> dict[str, Any]:
    """Render class 9 using Xray's Trojan, RAW TCP and TLS implementations."""
    _validate_port(port)
    return {
        "log": {"loglevel": "warning", "access": "none"},
        "inbounds": [
            {
                "tag": "class-09-trojan-raw-tls-in",
                "listen": "0.0.0.0",
                "port": port,
                "protocol": "trojan",
                "settings": {
                    "clients": [
                        {
                            "password": _trojan_password(material),
                            "email": "class-09-collector",
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
        "routing": _server_routing(),
    }


def render_trojan_raw_tls_client(
    material: VlessTlsMaterial,
    *,
    server_address: str,
    server_port: int,
    socks_port: int = 10808,
) -> dict[str, Any]:
    _validate_port(server_port)
    _validate_port(socks_port)
    normalized_server_address = _normalize_server_address(server_address)
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
                            "password": _trojan_password(material),
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
    material: VlessTlsMaterial,
    *,
    port: int,
    certificate_container_path: str = "/run/secrets/xray/server.crt",
    private_key_container_path: str = "/run/secrets/xray/server.key",
) -> dict[str, Any]:
    """Render class 10 using Xray's Trojan, WebSocket and TLS implementations."""
    _validate_port(port)
    return {
        "log": {"loglevel": "warning", "access": "none"},
        "inbounds": [
            {
                "tag": "class-10-trojan-websocket-tls-in",
                "listen": "0.0.0.0",
                "port": port,
                "protocol": "trojan",
                "settings": {
                    "clients": [
                        {
                            "password": _trojan_password(material),
                            "email": "class-10-collector",
                        }
                    ]
                },
                "streamSettings": {
                    "method": "websocket",
                    "security": "tls",
                    "wsSettings": {
                        "path": _websocket_path(material.client_id),
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
        "routing": _server_routing(),
    }


def render_trojan_websocket_tls_client(
    material: VlessTlsMaterial,
    *,
    server_address: str,
    server_port: int,
    socks_port: int = 10808,
) -> dict[str, Any]:
    _validate_port(server_port)
    _validate_port(socks_port)
    normalized_server_address = _normalize_server_address(server_address)
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
                            "password": _trojan_password(material),
                        }
                    ]
                },
                "streamSettings": {
                    "method": "websocket",
                    "security": "tls",
                    "wsSettings": {
                        "path": _websocket_path(material.client_id),
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
