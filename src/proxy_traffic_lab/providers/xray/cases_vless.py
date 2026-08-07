from __future__ import annotations

import ipaddress
from typing import Any

from proxy_traffic_lab.controller.errors import ConfigurationError
from proxy_traffic_lab.providers.xray.runtime import (
    VlessTlsMaterial,
    _grpc_service_name,
    _normalize_server_address,
    _reality_values,
    _server_routing,
    _validate_port,
)

def render_vless_tls_server(
    material: VlessTlsMaterial,
    *,
    port: int,
    certificate_container_path: str = "/run/secrets/xray/server.crt",
    private_key_container_path: str = "/run/secrets/xray/server.key",
) -> dict[str, Any]:
    _validate_port(port)
    return {
        "log": {"loglevel": "warning", "access": "none"},
        "inbounds": [
            {
                "tag": "vless-tcp-tls-in",
                "listen": "0.0.0.0",
                "port": port,
                "protocol": "vless",
                "settings": {
                    "clients": [
                        {
                            "id": material.client_id,
                            "email": "mvp-collector",
                        }
                    ],
                    "decryption": "none",
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
        "routing": {
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
        },
    }


def render_vless_tls_client(
    material: VlessTlsMaterial,
    *,
    server_address: str,
    server_port: int,
    socks_port: int = 10808,
) -> dict[str, Any]:
    _validate_port(server_port)
    _validate_port(socks_port)
    try:
        normalized_server_address = ipaddress.ip_address(server_address).compressed
    except ValueError as exc:
        raise ConfigurationError(
            "server_address must be the VPS IPv4 or IPv6 address; placeholders and hostnames are rejected"
        ) from exc
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
                "protocol": "vless",
                "settings": {
                    "address": normalized_server_address,
                    "port": server_port,
                    "id": material.client_id,
                    "encryption": "none",
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


def render_vless_reality_vision_server(
    material: VlessTlsMaterial,
    *,
    port: int,
) -> dict[str, Any]:
    """Render class 7 using Xray's VLESS RAW, REALITY and Vision flow."""
    _validate_port(port)
    private_key, _, short_id = _reality_values(material)
    return {
        "log": {"loglevel": "warning", "access": "none"},
        "inbounds": [
            {
                "tag": "class-07-vless-raw-reality-vision-in",
                "listen": "0.0.0.0",
                "port": port,
                "protocol": "vless",
                "settings": {
                    "clients": [
                        {
                            "id": material.client_id,
                            "flow": "xtls-rprx-vision",
                            "email": "class-07-collector",
                        }
                    ],
                    "decryption": "none",
                },
                "streamSettings": {
                    "method": "raw",
                    "security": "reality",
                    "realitySettings": {
                        "show": False,
                        "dest": material.reality_dest,
                        "xver": 0,
                        "serverNames": [material.reality_server_name],
                        "privateKey": private_key,
                        "shortIds": [short_id],
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


def render_vless_reality_vision_client(
    material: VlessTlsMaterial,
    *,
    server_address: str,
    server_port: int,
    socks_port: int = 10808,
) -> dict[str, Any]:
    _validate_port(server_port)
    _validate_port(socks_port)
    normalized_server_address = _normalize_server_address(server_address)
    _, public_key, short_id = _reality_values(material)
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
                "protocol": "vless",
                "settings": {
                    "address": normalized_server_address,
                    "port": server_port,
                    "id": material.client_id,
                    "encryption": "none",
                    "flow": "xtls-rprx-vision",
                },
                "streamSettings": {
                    "method": "raw",
                    "security": "reality",
                    "realitySettings": {
                        "serverName": material.reality_server_name,
                        "fingerprint": "chrome",
                        "publicKey": public_key,
                        "shortId": short_id,
                        "spiderX": "/",
                    },
                },
            },
            {"tag": "block", "protocol": "blackhole"},
        ],
    }


def render_vless_grpc_tls_server(
    material: VlessTlsMaterial,
    *,
    port: int,
    certificate_container_path: str = "/run/secrets/xray/server.crt",
    private_key_container_path: str = "/run/secrets/xray/server.key",
) -> dict[str, Any]:
    """Render class 8 using Xray's VLESS, gRPC and TLS implementations."""
    _validate_port(port)
    service_name = _grpc_service_name(material.client_id)
    return {
        "log": {"loglevel": "warning", "access": "none"},
        "inbounds": [
            {
                "tag": "class-08-vless-grpc-tls-in",
                "listen": "0.0.0.0",
                "port": port,
                "protocol": "vless",
                "settings": {
                    "clients": [
                        {
                            "id": material.client_id,
                            "email": "class-08-collector",
                        }
                    ],
                    "decryption": "none",
                },
                "streamSettings": {
                    "method": "grpc",
                    "security": "tls",
                    "grpcSettings": {
                        "serviceName": service_name,
                        "multiMode": False,
                    },
                    "tlsSettings": {
                        "rejectUnknownSni": True,
                        "minVersion": "1.3",
                        "alpn": ["h2"],
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


def render_vless_grpc_tls_client(
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
                "protocol": "vless",
                "settings": {
                    "address": normalized_server_address,
                    "port": server_port,
                    "id": material.client_id,
                    "encryption": "none",
                },
                "streamSettings": {
                    "method": "grpc",
                    "security": "tls",
                    "grpcSettings": {
                        "serviceName": _grpc_service_name(material.client_id),
                        "multiMode": False,
                    },
                    "tlsSettings": {
                        "serverName": material.server_name,
                        "fingerprint": "chrome",
                        "alpn": ["h2"],
                        "pinnedPeerCertSha256": material.certificate_sha256,
                    },
                },
            },
            {"tag": "block", "protocol": "blackhole"},
        ],
    }
