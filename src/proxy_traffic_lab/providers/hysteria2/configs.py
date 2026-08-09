"""Native Hysteria 2 configuration rendering.

ProxyLab does not implement Hysteria, QUIC, TLS, or Salamander.  These
documents are consumed by the pinned upstream Hysteria executable.
"""

from __future__ import annotations

import hashlib
import ipaddress
from pathlib import Path
from typing import Any

import yaml

from proxy_traffic_lab.controller.errors import ConfigurationError
from proxy_traffic_lab.providers.xray.runtime import VlessTlsMaterial


HYSTERIA2_CASES = {
    "class-11-hysteria2-quic-tls",
    "class-12-hysteria2-quic-salamander-tls",
}


def render_hysteria2_case(
    case_id: str,
    material: VlessTlsMaterial,
    *,
    server_address: str,
    server_port: int,
    socks_port: int = 10808,
    bandwidth_mbps: int = 10,
) -> dict[str, dict[str, Any]]:
    if case_id not in HYSTERIA2_CASES:
        raise ConfigurationError(f"Hysteria2 case is not implemented: {case_id}")
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
    if case_id == "class-12-hysteria2-quic-salamander-tls":
        obfs = {
            "type": "salamander",
            "salamander": {
                "password": _derived_secret("salamander", material.client_id)
            },
        }
        server["obfs"] = obfs
        client["obfs"] = obfs
    return {"server": server, "client": client}


def write_hysteria2_case(
    output_dir: Path,
    case_id: str,
    material: VlessTlsMaterial,
    *,
    server_address: str,
    server_port: int,
    socks_port: int = 10808,
    bandwidth_mbps: int = 10,
) -> tuple[Path, Path]:
    rendered = render_hysteria2_case(
        case_id,
        material,
        server_address=server_address,
        server_port=server_port,
        socks_port=socks_port,
        bandwidth_mbps=bandwidth_mbps,
    )
    output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    server_path = output_dir / "hysteria2-server.yaml"
    client_path = output_dir / "hysteria2-client.yaml"
    for path, document in (
        (server_path, rendered["server"]),
        (client_path, rendered["client"]),
    ):
        path.write_text(
            yaml.safe_dump(document, sort_keys=False, allow_unicode=True),
            encoding="utf-8",
        )
        path.chmod(0o600)
    return server_path, client_path


def load_hysteria2_yaml(path: Path) -> dict[str, Any]:
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigurationError(f"cannot load Hysteria2 config {path}: {exc}") from exc
    if not isinstance(document, dict):
        raise ConfigurationError(f"Hysteria2 config is not a mapping: {path}")
    return document


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
