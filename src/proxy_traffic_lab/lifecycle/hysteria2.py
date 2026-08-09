"""Render, validate, and manage Hysteria 2 endpoints."""

from __future__ import annotations

import socket
from pathlib import Path
from typing import Any

from proxy_traffic_lab.common.errors import ConfigurationError
from proxy_traffic_lab.common.process import run_command
from proxy_traffic_lab.kernels.hysteria2 import load_image_lock
from proxy_traffic_lab.lifecycle.docker import container_id, container_image, container_label, container_logs, container_state, file_sha256, prepare_read_permissions, stop_container
from proxy_traffic_lab.lifecycle.hysteria2_documents import load_hysteria2_yaml
from proxy_traffic_lab.lifecycle.hysteria2_documents import write_hysteria2_case
from proxy_traffic_lab.configuration.models import ProtocolCase
from proxy_traffic_lab.encryptions.credentials import load_tls_material
from proxy_traffic_lab.protocols.hysteria2 import validate_hysteria2_documents

HYSTERIA2_SERVER_CONTAINER = "proxy-traffic-lab-hysteria2-server"
HYSTERIA2_CLIENT_CONTAINER = "proxy-traffic-lab-hysteria2-client"


def render_endpoints(
    project_root: Path,
    case: ProtocolCase,
    *,
    server_address: str,
    server_port: int,
    socks_port: int,
    bandwidth_mbps: int,
) -> tuple[Path, Path]:
    if case.client_core != "hysteria2" or case.server_core != "hysteria2":
        raise ConfigurationError(f"{case.id} is not a Hysteria 2 target")
    material = load_tls_material(project_root / "secrets" / "hysteria2")
    return write_hysteria2_case(
        project_root / "secrets" / "generated",
        case,
        material,
        server_address=server_address,
        server_port=server_port,
        socks_port=socks_port,
        bandwidth_mbps=bandwidth_mbps,
    )


def validate_generated_configs(project_root: Path) -> str:
    image = load_image_lock(project_root / "configs" / "locks" / "hysteria2.json")
    server_path, client_path = _config_paths(project_root)
    server = load_hysteria2_yaml(server_path)
    client = load_hysteria2_yaml(client_path)
    validate_hysteria2_documents(server, client)
    cert, key = _certificate_paths(project_root)
    for path in (cert, key):
        if not path.is_file():
            raise ConfigurationError(f"required Hysteria2 TLS file is missing: {path}")
    version = run_command(["docker", "run", "--rm", image, "version"], timeout_seconds=30)
    if version.returncode != 0:
        raise ConfigurationError(f"cannot execute pinned Hysteria2 image: {version.stderr}")
    return version.stdout or version.stderr or "Hysteria2 configuration structure valid"



def start_server_container(project_root: Path) -> str:
    image = load_image_lock(project_root / "configs" / "locks" / "hysteria2.json")
    validate_generated_configs(project_root)
    server_path, _ = _config_paths(project_root)
    cert, key = _certificate_paths(project_root)
    return _start_container(
        name=HYSTERIA2_SERVER_CONTAINER,
        image=image,
        config_path=server_path,
        config_target="/run/lab/server.yaml",
        command=("server", "-c", "/run/lab/server.yaml"),
        extra_mounts=(
            (cert, "/run/secrets/hysteria2/server.crt"),
            (key, "/run/secrets/hysteria2/server.key"),
        ),
        restart="no",
    )



def start_client_container(project_root: Path, config_path: Path | None = None) -> str:
    image = load_image_lock(project_root / "configs" / "locks" / "hysteria2.json")
    _, default_client = _config_paths(project_root)
    resolved = (config_path or default_client).expanduser().resolve()
    client = load_hysteria2_yaml(resolved)
    if "server" not in client or "socks5" not in client:
        raise ConfigurationError("Hysteria2 client config lacks server or socks5")
    return _start_container(
        name=HYSTERIA2_CLIENT_CONTAINER,
        image=image,
        config_path=resolved,
        config_target="/run/lab/client.yaml",
        command=("client", "-c", "/run/lab/client.yaml"),
        extra_mounts=(),
        restart="unless-stopped",
    )



def server_status(project_root: Path) -> dict[str, Any]:
    state = container_state(HYSTERIA2_SERVER_CONTAINER)
    result: dict[str, Any] = {
        "core": "hysteria2",
        "container": HYSTERIA2_SERVER_CONTAINER,
        "state": state,
        "healthy": state == "running",
        "transport": "udp",
    }
    try:
        server_path, _ = _config_paths(project_root)
        result["port"] = int(str(load_hysteria2_yaml(server_path)["listen"])[1:])
    except (ConfigurationError, KeyError, TypeError, ValueError):
        result["detail"] = "cannot read generated Hysteria2 server port"
    else:
        result["detail"] = (
            "Hysteria2 process running" if state == "running" else "container not running"
        )
    return result



def client_status(*, socks_port: int = 10808) -> dict[str, Any]:
    _validate_port(socks_port)
    state = container_state(HYSTERIA2_CLIENT_CONTAINER)
    result: dict[str, Any] = {
        "core": "hysteria2",
        "container": HYSTERIA2_CLIENT_CONTAINER,
        "state": state,
        "healthy": False,
        "socks_port": socks_port,
    }
    if state != "running":
        return result
    try:
        with socket.create_connection(("127.0.0.1", socks_port), timeout=2):
            pass
    except OSError as exc:
        result["detail"] = f"SOCKS listener unavailable: {type(exc).__name__}"
        return result
    result.update({"healthy": True, "detail": "SOCKS listener reachable"})
    return result



def server_logs(*, tail: int = 100) -> str:
    return container_logs(HYSTERIA2_SERVER_CONTAINER, tail=tail)



def client_logs(*, tail: int = 100) -> str:
    return container_logs(HYSTERIA2_CLIENT_CONTAINER, tail=tail)



def stop_server_container() -> str:
    return stop_container(HYSTERIA2_SERVER_CONTAINER)



def stop_client_container() -> str:
    return stop_container(HYSTERIA2_CLIENT_CONTAINER)



def _start_container(
    *,
    name: str,
    image: str,
    config_path: Path,
    config_target: str,
    command: tuple[str, ...],
    extra_mounts: tuple[tuple[Path, str], ...],
    restart: str,
) -> str:
    paths = (config_path, *(source for source, _ in extra_mounts))
    prepare_read_permissions(*paths)
    config_sha256 = file_sha256(config_path)
    state = container_state(name)
    if (
        state == "running"
        and container_label(name, "proxy-traffic-lab.config-sha256") == config_sha256
        and container_image(name) == image
    ):
        return container_id(name)
    if state != "absent":
        stop_container(name)
    args = [
        "docker", "run", "--detach", "--name", name,
        "--label", f"proxy-traffic-lab.config-sha256={config_sha256}",
        "--restart", restart,
        "--network", "host",
        "--read-only",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--pids-limit", "128",
        "--memory", "512m",
        "--cpus", "1.0",
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
        "--mount", f"type=bind,src={config_path},dst={config_target},readonly",
    ]
    for source, target in extra_mounts:
        args.extend(["--mount", f"type=bind,src={source},dst={target},readonly"])
    args.extend([image, *command])
    result = run_command(args, timeout_seconds=30)
    if result.returncode != 0:
        raise ConfigurationError(f"cannot start Hysteria2 container {name}: {result.stderr}")
    return result.stdout.strip()



def _config_paths(project_root: Path) -> tuple[Path, Path]:
    generated = project_root / "secrets" / "generated"
    return generated / "hysteria2-server.yaml", generated / "hysteria2-client.yaml"



def _certificate_paths(project_root: Path) -> tuple[Path, Path]:
    secrets_dir = project_root / "secrets" / "hysteria2"
    return secrets_dir / "server.crt", secrets_dir / "server.key"



def _validate_port(port: int) -> None:
    if not 1 <= port <= 65535:
        raise ConfigurationError("port must be between 1 and 65535")
