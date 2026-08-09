"""Pure ShadowsocksR configuration rendering and validation."""

from __future__ import annotations

import ipaddress
from typing import Any

from proxy_traffic_lab.common.errors import ConfigurationError
from proxy_traffic_lab.configuration.models import ProtocolCase

SSR_METHOD = "aes-256-cfb"
SSR_OBFS = "tls1.2_ticket_auth"


def render_case(
    case: ProtocolCase,
    *,
    password: str,
    server_address: str,
    server_port: int,
    socks_port: int = 10808,
) -> dict[str, dict[str, Any]]:
    if (
        case.client_core != "shadowsocksr-native"
        or case.server_core != "shadowsocksr-native"
    ):
        raise ConfigurationError(f"{case.id} is not implemented by ShadowsocksR-native")
    protocol = case.parameter("protocol_plugin")
    if not isinstance(protocol, str):
        raise ConfigurationError(f"{case.id} is missing a protocol_plugin parameter")
    _validate_port(server_port)
    _validate_port(socks_port)
    try:
        address = ipaddress.ip_address(server_address).compressed
    except ValueError as exc:
        raise ConfigurationError("server_address must be the VPS IPv4 or IPv6 address") from exc
    common: dict[str, Any] = {
        "password": password,
        "method": SSR_METHOD,
        "protocol": protocol,
        "protocol_param": "",
        "obfs": SSR_OBFS,
        "obfs_param": "",
        "udp": False,
        "idle_timeout": 300,
        "connect_timeout": 10,
        "udp_timeout": 10,
    }
    server = {
        **common,
        "server_settings": {
            "listen_address": "0.0.0.0",
            "listen_port": server_port,
        },
    }
    client = {
        **common,
        "client_settings": {
            "server": address,
            "server_port": server_port,
            "listen_address": "127.0.0.1",
            "listen_port": socks_port,
        },
    }
    return {"server": server, "client": client}



def validate_documents(server: dict[str, Any], client: dict[str, Any]) -> None:
    required = ("password", "method", "protocol", "obfs")
    if any(not server.get(key) or server.get(key) != client.get(key) for key in required):
        raise ConfigurationError("ShadowsocksR server/client protocol settings differ")
    if server["protocol"] not in {"auth_aes128_md5", "auth_aes128_sha1"}:
        raise ConfigurationError("unsupported ShadowsocksR protocol plugin")
    if server["method"] != SSR_METHOD or server["obfs"] != SSR_OBFS:
        raise ConfigurationError("unexpected ShadowsocksR cipher or obfuscator")
    try:
        server_port = int(server["server_settings"]["listen_port"])
        client_server_port = int(client["client_settings"]["server_port"])
        _validate_port(server_port)
        _validate_port(client_server_port)
        _validate_port(int(client["client_settings"]["listen_port"]))
    except (KeyError, TypeError, ValueError) as exc:
        raise ConfigurationError("invalid ShadowsocksR listener configuration") from exc
    if server_port != client_server_port:
        raise ConfigurationError("ShadowsocksR client/server ports differ")
    try:
        ipaddress.ip_address(client["client_settings"]["server"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ConfigurationError("ShadowsocksR client server address must be an IP") from exc



def _validate_port(port: int) -> None:
    if not 1 <= port <= 65535:
        raise ConfigurationError("port must be between 1 and 65535")
