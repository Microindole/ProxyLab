"""Native configuration adapter for the upstream ShadowsocksR-native core."""

from __future__ import annotations

import ipaddress
import json
import secrets
from pathlib import Path
from typing import Any

from proxy_traffic_lab.controller.errors import ConfigurationError


SSR_CASES = {
    "class-03-ssr-auth-aes128-md5": "auth_aes128_md5",
    "class-04-ssr-auth-aes128-sha1": "auth_aes128_sha1",
}
SSR_METHOD = "aes-256-cfb"
SSR_OBFS = "tls1.2_ticket_auth"


def create_identity(secrets_dir: Path) -> str:
    secrets_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = secrets_dir / "identity.json"
    if path.exists():
        raise ConfigurationError(f"refusing to overwrite existing secret: {path}")
    password = secrets.token_urlsafe(24)
    path.write_text(json.dumps({"password": password}, indent=2) + "\n", encoding="utf-8")
    path.chmod(0o600)
    return password


def load_identity(secrets_dir: Path) -> str:
    path = secrets_dir / "identity.json"
    try:
        password = json.loads(path.read_text(encoding="utf-8"))["password"]
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise ConfigurationError(f"cannot load ShadowsocksR identity {path}: {exc}") from exc
    if not isinstance(password, str) or len(password) < 16:
        raise ConfigurationError("ShadowsocksR password must contain at least 16 characters")
    return password


def render_case(
    case_id: str,
    *,
    password: str,
    server_address: str,
    server_port: int,
    socks_port: int = 10808,
) -> dict[str, dict[str, Any]]:
    try:
        protocol = SSR_CASES[case_id]
    except KeyError as exc:
        raise ConfigurationError(f"ShadowsocksR case is not implemented: {case_id}") from exc
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


def write_case(
    output_dir: Path,
    case_id: str,
    *,
    password: str,
    server_address: str,
    server_port: int,
    socks_port: int = 10808,
) -> tuple[Path, Path]:
    documents = render_case(
        case_id,
        password=password,
        server_address=server_address,
        server_port=server_port,
        socks_port=socks_port,
    )
    output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    server_path = output_dir / "shadowsocksr-server.json"
    client_path = output_dir / "shadowsocksr-client.json"
    for path, document in ((server_path, documents["server"]), (client_path, documents["client"])):
        path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
        path.chmod(0o600)
    return server_path, client_path


def load_document(path: Path) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigurationError(f"cannot load ShadowsocksR config {path}: {exc}") from exc
    if not isinstance(document, dict):
        raise ConfigurationError(f"ShadowsocksR config must be an object: {path}")
    return document


def validate_documents(server: dict[str, Any], client: dict[str, Any]) -> None:
    required = ("password", "method", "protocol", "obfs")
    if any(not server.get(key) or server.get(key) != client.get(key) for key in required):
        raise ConfigurationError("ShadowsocksR server/client protocol settings differ")
    if server["protocol"] not in set(SSR_CASES.values()):
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
