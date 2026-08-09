"""Hysteria 2 generated configuration persistence."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from proxy_traffic_lab.common.errors import ConfigurationError
from proxy_traffic_lab.configuration.models import ProtocolCase
from proxy_traffic_lab.encryptions.material import TlsMaterial
from proxy_traffic_lab.protocols.hysteria2 import render_hysteria2_case


def write_hysteria2_case(
    output_dir: Path,
    case: ProtocolCase,
    material: TlsMaterial,
    *,
    server_address: str,
    server_port: int,
    socks_port: int = 10808,
    bandwidth_mbps: int = 10,
) -> tuple[Path, Path]:
    rendered = render_hysteria2_case(
        case,
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
