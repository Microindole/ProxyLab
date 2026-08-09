"""Pure Hysteria 2 protocol configuration rendering and validation."""

from __future__ import annotations

import hashlib
import ipaddress
from typing import Any

from proxy_traffic_lab.common.errors import ConfigurationError
from proxy_traffic_lab.configuration.models import ProtocolCase
from proxy_traffic_lab.encryptions.material import TlsMaterial


def render_hysteria2_case(
    case: ProtocolCase,
    material: TlsMaterial,
    *,
    server_address: str,
    server_port: int,
    socks_port: int = 10808,
    bandwidth_mbps: int = 10,
) -> dict[str, dict[str, Any]]:
    if case.client_core != "hysteria2" or case.server_core != "hysteria2":
        raise ConfigurationError(f"{case.id} is not implemented by Hysteria2")
    address = _normalize_server_address(server_address)
    _validate_port(server_port)
    _validate_port(socks_port)
    if not 1 <= bandwidth_mbps <= 1000:
        raise ConfigurationError("bandwidth_mbps must be between 1 and 1000")

    auth_password = _derived_secret("auth", material.client_id)
    server: dict[str, Any] = {
        "listen": f":{server_port}",
        "tls": {
            "cert": "/run/secrets/hysteria2/server.crt",
            "key": "/run/secrets/hysteria2/server.key",
        },
        "auth": {"type": "password", "password": auth_password},
        "bandwidth": {
            "up": f"{bandwidth_mbps} mbps",
            "down": f"{bandwidth_mbps} mbps",
        },
        "ignoreClientBandwidth": False,
    }
    client: dict[str, Any] = {
        "server": _host_port(address, server_port),
        "auth": auth_password,
        "tls": {
            "sni": material.server_name,
            "insecure": True,
            "pinSHA256": _colon_fingerprint(material.certificate_sha256),
        },
        "bandwidth": {
            "up": f"{bandwidth_mbps} mbps",
            "down": f"{bandwidth_mbps} mbps",
        },
        "lazy": True,
        "socks5": {"listen": f"127.0.0.1:{socks_port}"},
    }
    if case.parameter("obfs") == "salamander":
        obfs = {
            "type": "salamander",
            "salamander": {
                "password": _derived_secret("salamander", material.client_id)
            },
        }
        server["obfs"] = obfs
        client["obfs"] = obfs
    return {"server": server, "client": client}



def validate_hysteria2_documents(
    server: dict[str, Any], client: dict[str, Any]
) -> None:
    try:
        listen = str(server["listen"])
        cert = str(server["tls"]["cert"])
        key = str(server["tls"]["key"])
        auth_type = str(server["auth"]["type"])
        auth_password = str(server["auth"]["password"])
        client_server = str(client["server"])
        client_auth = str(client["auth"])
        socks_listen = str(client["socks5"]["listen"])
        pin = str(client["tls"]["pinSHA256"])
    except (KeyError, TypeError) as exc:
        raise ConfigurationError(f"Hysteria2 config is missing a required field: {exc}") from exc
    if not listen.startswith(":") or not listen[1:].isdigit():
        raise ConfigurationError("Hysteria2 server listen must be :PORT")
    _validate_port(int(listen[1:]))
    if not cert or not key or auth_type != "password" or not auth_password:
        raise ConfigurationError("Hysteria2 TLS/auth configuration is invalid")
    if client_auth != auth_password:
        raise ConfigurationError("Hysteria2 client/server auth passwords differ")
    if not client_server or not socks_listen.startswith("127.0.0.1:"):
        raise ConfigurationError("Hysteria2 client endpoint/listener is invalid")
    if len(pin.replace(":", "")) != 64:
        raise ConfigurationError("Hysteria2 certificate pin is invalid")
    server_obfs = server.get("obfs")
    client_obfs = client.get("obfs")
    if server_obfs != client_obfs:
        raise ConfigurationError("Hysteria2 client/server obfuscation differs")



def _normalize_server_address(value: str) -> str:
    try:
        return ipaddress.ip_address(value).compressed
    except ValueError as exc:
        raise ConfigurationError(
            "server_address must be the VPS IPv4 or IPv6 address"
        ) from exc



def _host_port(address: str, port: int) -> str:
    return f"[{address}]:{port}" if ":" in address else f"{address}:{port}"



def _derived_secret(purpose: str, seed: str) -> str:
    return hashlib.sha256(f"hysteria2:{purpose}:{seed}".encode()).hexdigest()



def _colon_fingerprint(value: str) -> str:
    compact = value.replace(":", "").upper()
    if len(compact) != 64 or any(ch not in "0123456789ABCDEF" for ch in compact):
        raise ConfigurationError("certificate SHA-256 fingerprint is invalid")
    return ":".join(compact[index : index + 2] for index in range(0, 64, 2))



def _validate_port(port: int) -> None:
    if not 1 <= port <= 65535:
        raise ConfigurationError("port must be between 1 and 65535")
