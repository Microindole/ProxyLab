"""ShadowsocksR credentials and generated configuration persistence."""

from __future__ import annotations

import json
import secrets
from pathlib import Path
from typing import Any

from proxy_traffic_lab.common.errors import ConfigurationError
from proxy_traffic_lab.configuration.models import ProtocolCase
from proxy_traffic_lab.protocols.shadowsocksr import render_case


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



def write_case(
    output_dir: Path,
    case: ProtocolCase,
    *,
    password: str,
    server_address: str,
    server_port: int,
    socks_port: int = 10808,
) -> tuple[Path, Path]:
    documents = render_case(
        case,
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
