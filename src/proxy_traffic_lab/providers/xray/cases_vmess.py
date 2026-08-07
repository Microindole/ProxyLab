from __future__ import annotations

from typing import Any

from proxy_traffic_lab.providers.xray.runtime import (
    VlessTlsMaterial,
    _normalize_server_address,
    _server_routing,
    _validate_port,
    _websocket_path,
    _xhttp_path,
)

def render_vmess_websocket_tls_server(
    material: VlessTlsMaterial,
    *,
    port: int,
    certificate_container_path: str = "/run/secrets/xray/server.crt",
    private_key_container_path: str = "/run/secrets/xray/server.key",
) -> dict[str, Any]:
    """Render class 5 using Xray's VMess, WebSocket and TLS implementations."""
    _validate_port(port)
    websocket_path = _websocket_path(material.client_id)
    return {
        "log": {"loglevel": "warning", "access": "none"},
        "inbounds": [
            {
                "tag": "class-05-vmess-websocket-tls-in",
                "listen": "0.0.0.0",
                "port": port,
                "protocol": "vmess",
                "settings": {
                    "clients": [
                        {
                            "id": material.client_id,
                            "level": 0,
                            "email": "class-05-collector",
                        }
                    ]
                },
                "streamSettings": {
                    "method": "websocket",
                    "security": "tls",
                    "wsSettings": {
                        "path": websocket_path,
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
        "routing": _server_routing(),
    }


def render_vmess_websocket_tls_client(
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


def render_vmess_xhttp_h2_tls_server(
    material: VlessTlsMaterial,
    *,
    port: int,
    certificate_container_path: str = "/run/secrets/xray/server.crt",
    private_key_container_path: str = "/run/secrets/xray/server.key",
) -> dict[str, Any]:
    """Render class 6 using Xray's VMess, XHTTP over HTTP/2 and TLS."""
    _validate_port(port)
    return {
        "log": {"loglevel": "warning", "access": "none"},
        "inbounds": [
            {
                "tag": "class-06-vmess-xhttp-h2-tls-in",
                "listen": "0.0.0.0",
                "port": port,
                "protocol": "vmess",
                "settings": {
                    "clients": [
                        {
                            "id": material.client_id,
                            "level": 0,
                            "email": "class-06-collector",
                        }
                    ]
                },
                "streamSettings": {
                    "method": "xhttp",
                    "security": "tls",
                    "xhttpSettings": {
                        "path": _xhttp_path(material.client_id),
                        "host": material.server_name,
                        "mode": "stream-up",
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


def render_vmess_xhttp_h2_tls_client(
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
                        "path": _xhttp_path(material.client_id),
                        "host": material.server_name,
                        "mode": "stream-up",
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
