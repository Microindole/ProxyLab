"""VMess composition renderers targeting Xray-core."""

from __future__ import annotations

from typing import Any

from proxy_traffic_lab.encryptions.material import TlsMaterial
from proxy_traffic_lab.protocols.xray.common import (
    normalize_server_address,
    server_routing,
    validate_port,
    websocket_path,
    xhttp_path,
)

def render_vmess_websocket_tls_server(
    material: TlsMaterial,
    *,
    port: int,
    certificate_container_path: str = "/run/secrets/xray/server.crt",
    private_key_container_path: str = "/run/secrets/xray/server.key",
) -> dict[str, Any]:
    """Render VMess over WebSocket with TLS using Xray-core."""
    validate_port(port)
    path = websocket_path(material.client_id)
    return {
        "log": {"loglevel": "warning", "access": "none"},
        "inbounds": [
            {
                "tag": "vmess-websocket-tls-in",
                "listen": "0.0.0.0",
                "port": port,
                "protocol": "vmess",
                "settings": {
                    "clients": [
                        {
                            "id": material.client_id,
                            "level": 0,
                            "email": "vmess-websocket-collector",
                        }
                    ]
                },
                "streamSettings": {
                    "method": "websocket",
                    "security": "tls",
                    "wsSettings": {
                        "path": path,
                        "host": material.server_name,
                        "acceptProxyProtocol": False,
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


def render_vmess_websocket_tls_client(
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
                "protocol": "vmess",
                "settings": {
                    "address": normalized_server_address,
                    "port": server_port,
                    "id": material.client_id,
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


def render_vmess_xhttp_h2_tls_server(
    material: TlsMaterial,
    *,
    port: int,
    xhttp_mode: str = "stream-up",
    http_version: str = "h2",
    certificate_container_path: str = "/run/secrets/xray/server.crt",
    private_key_container_path: str = "/run/secrets/xray/server.key",
) -> dict[str, Any]:
    """Render VMess over XHTTP/HTTP2 with TLS using Xray-core."""
    validate_port(port)
    _validate_xhttp_h2(xhttp_mode=xhttp_mode, http_version=http_version)
    return {
        "log": {"loglevel": "warning", "access": "none"},
        "inbounds": [
            {
                "tag": "vmess-xhttp-h2-tls-in",
                "listen": "0.0.0.0",
                "port": port,
                "protocol": "vmess",
                "settings": {
                    "clients": [
                        {
                            "id": material.client_id,
                            "level": 0,
                            "email": "vmess-xhttp-collector",
                        }
                    ]
                },
                "streamSettings": {
                    "method": "xhttp",
                    "security": "tls",
                    "xhttpSettings": {
                        "path": xhttp_path(material.client_id),
                        "host": material.server_name,
                        "mode": xhttp_mode,
                    },
                    "tlsSettings": {
                        "rejectUnknownSni": True,
                        "minVersion": "1.3",
                        "alpn": [http_version],
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


def render_vmess_xhttp_h2_tls_client(
    material: TlsMaterial,
    *,
    server_address: str,
    server_port: int,
    socks_port: int = 10808,
    xhttp_mode: str = "stream-up",
    http_version: str = "h2",
) -> dict[str, Any]:
    validate_port(server_port)
    validate_port(socks_port)
    _validate_xhttp_h2(xhttp_mode=xhttp_mode, http_version=http_version)
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
                "protocol": "vmess",
                "settings": {
                    "address": normalized_server_address,
                    "port": server_port,
                    "id": material.client_id,
                },
                "streamSettings": {
                    "method": "xhttp",
                    "security": "tls",
                    "xhttpSettings": {
                        "path": xhttp_path(material.client_id),
                        "host": material.server_name,
                        "mode": xhttp_mode,
                    },
                    "tlsSettings": {
                        "serverName": material.server_name,
                        "fingerprint": "chrome",
                        "alpn": [http_version],
                        "pinnedPeerCertSha256": material.certificate_sha256,
                    },
                },
            },
            {"tag": "block", "protocol": "blackhole"},
        ],
    }


def _validate_xhttp_h2(*, xhttp_mode: str, http_version: str) -> None:
    if xhttp_mode != "stream-up":
        raise ValueError("this target requires XHTTP mode stream-up")
    if http_version != "h2":
        raise ValueError("this target requires HTTP/2 TLS ALPN h2")
