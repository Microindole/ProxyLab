"""Orchestrate Xray configuration material and endpoint rendering."""

from __future__ import annotations

from pathlib import Path

from proxy_traffic_lab.common.errors import ConfigurationError
from proxy_traffic_lab.configuration.models import ProtocolCase
from proxy_traffic_lab.encryptions.credentials import load_tls_material
from proxy_traffic_lab.lifecycle.xray.credentials import (
    ensure_reality_material,
    ensure_vless_encryption_material,
)
from proxy_traffic_lab.lifecycle.xray.documents import write_private_json
from proxy_traffic_lab.lifecycle.xray.rendering import (
    render_xray_case_client,
    render_xray_case_server,
)


def render_endpoints(
    project_root: Path,
    case: ProtocolCase,
    *,
    server_address: str,
    server_port: int,
    socks_port: int,
) -> tuple[Path, Path]:
    if case.client_core != "xray-core" or case.server_core != "xray-core":
        raise ConfigurationError(f"{case.id} is not an Xray-core target")
    secrets_dir = project_root / "secrets" / "xray"
    material = load_tls_material(secrets_dir)
    if case.encryption == "reality":
        material = ensure_reality_material(secrets_dir, material)
    if case.parameter("vless_encryption") is True:
        material = ensure_vless_encryption_material(secrets_dir, material)
    generated = project_root / "secrets" / "generated"
    server_path = generated / "server.json"
    client_path = generated / "client.json"
    write_private_json(
        server_path,
        render_xray_case_server(case, material, port=server_port),
    )
    write_private_json(
        client_path,
        render_xray_case_client(
            case,
            material,
            server_address=server_address,
            server_port=server_port,
            socks_port=socks_port,
        ),
    )
    return server_path, client_path
