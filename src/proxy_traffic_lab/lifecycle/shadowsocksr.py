"""Render, validate, and manage ShadowsocksR-native endpoints."""

from __future__ import annotations

import socket
from pathlib import Path
from typing import Any

from proxy_traffic_lab.common.errors import ConfigurationError
from proxy_traffic_lab.common.process import run_command
from proxy_traffic_lab.kernels.shadowsocksr import load_image_lock
from proxy_traffic_lab.lifecycle.docker import container_id, container_image, container_label, container_logs, container_state, file_sha256, prepare_read_permissions, stop_container
from proxy_traffic_lab.lifecycle.shadowsocksr_documents import load_document
from proxy_traffic_lab.lifecycle.shadowsocksr_documents import load_identity, write_case
from proxy_traffic_lab.configuration.models import ProtocolCase
from proxy_traffic_lab.protocols.shadowsocksr import validate_documents

SSR_SERVER_CONTAINER = "proxy-traffic-lab-shadowsocksr-server"
SSR_CLIENT_CONTAINER = "proxy-traffic-lab-shadowsocksr-client"


def render_endpoints(
    project_root: Path,
    case: ProtocolCase,
    *,
    server_address: str,
    server_port: int,
    socks_port: int,
) -> tuple[Path, Path]:
    if (
        case.client_core != "shadowsocksr-native"
        or case.server_core != "shadowsocksr-native"
    ):
        raise ConfigurationError(f"{case.id} is not a ShadowsocksR-native target")
    password = load_identity(project_root / "secrets" / "shadowsocksr-native")
    return write_case(
        project_root / "secrets" / "generated",
        case,
        password=password,
        server_address=server_address,
        server_port=server_port,
        socks_port=socks_port,
    )


def validate_generated_configs(project_root: Path) -> str:
    image = load_image_lock(project_root)
    server_path, client_path = _config_paths(project_root)
    validate_documents(load_document(server_path), load_document(client_path))
    details: list[str] = []
    for binary in ("ssr-server", "ssr-client"):
        result = run_command(
            ["docker", "run", "--rm", "--network", "none", image, binary, "-h"],
            timeout_seconds=30,
        )
        if result.returncode != 0:
            raise ConfigurationError(
                f"cannot execute upstream {binary}: {result.stderr or result.stdout}"
            )
        detail = result.stdout or result.stderr or f"{binary} executable valid"
        details.append(detail.splitlines()[0])
    return "\n".join(details)



def start_server_container(project_root: Path) -> str:
    image = load_image_lock(project_root)
    server_path, _ = _config_paths(project_root)
    document = load_document(server_path)
    return _start_container(
        name=SSR_SERVER_CONTAINER,
        image=image,
        config_path=server_path,
        command=("ssr-server", "-c", "/run/lab/config.json"),
        restart="no",
        expected_port=int(document["server_settings"]["listen_port"]),
    )



def start_client_container(project_root: Path, config_path: Path | None = None) -> str:
    image = load_image_lock(project_root)
    _, default_client = _config_paths(project_root)
    resolved = (config_path or default_client).expanduser().resolve()
    document = load_document(resolved)
    try:
        socks_port = int(document["client_settings"]["listen_port"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ConfigurationError("ShadowsocksR client config lacks a SOCKS listener") from exc
    return _start_container(
        name=SSR_CLIENT_CONTAINER,
        image=image,
        config_path=resolved,
        command=("ssr-client", "-c", "/run/lab/config.json"),
        restart="unless-stopped",
        expected_port=socks_port,
    )



def server_status(project_root: Path) -> dict[str, Any]:
    server_path, _ = _config_paths(project_root)
    try:
        port = int(load_document(server_path)["server_settings"]["listen_port"])
    except (ConfigurationError, KeyError, TypeError, ValueError):
        port = 0
    return _listener_status(SSR_SERVER_CONTAINER, port=port, kind="server")



def client_status(*, socks_port: int = 10808) -> dict[str, Any]:
    return _listener_status(SSR_CLIENT_CONTAINER, port=socks_port, kind="client")



def server_logs(*, tail: int = 100) -> str:
    return container_logs(SSR_SERVER_CONTAINER, tail=tail)



def client_logs(*, tail: int = 100) -> str:
    return container_logs(SSR_CLIENT_CONTAINER, tail=tail)



def stop_server_container() -> str:
    return stop_container(SSR_SERVER_CONTAINER)



def stop_client_container() -> str:
    return stop_container(SSR_CLIENT_CONTAINER)



def _start_container(
    *,
    name: str,
    image: str,
    config_path: Path,
    command: tuple[str, ...],
    restart: str,
    expected_port: int,
) -> str:
    if not 1 <= expected_port <= 65535:
        raise ConfigurationError("ShadowsocksR listener port is invalid")
    prepare_read_permissions(config_path)
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
        "docker",
        "run",
        "--detach",
        "--name",
        name,
        "--label",
        f"proxy-traffic-lab.config-sha256={config_sha256}",
        "--restart",
        restart,
        "--network",
        "host",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "128",
        "--memory",
        "256m",
        "--cpus",
        "1.0",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=16m",
        "--mount",
        f"type=bind,src={config_path},dst=/run/lab/config.json,readonly",
        image,
        *command,
    ]
    result = run_command(args, timeout_seconds=30)
    if result.returncode != 0:
        raise ConfigurationError(f"cannot start ShadowsocksR container: {result.stderr}")
    return result.stdout.strip()



def _listener_status(name: str, *, port: int, kind: str) -> dict[str, Any]:
    state = container_state(name)
    result: dict[str, Any] = {
        "core": "shadowsocksr-native",
        "container": name,
        "state": state,
        "healthy": False,
        "port": port or None,
    }
    if state != "running" or not 1 <= port <= 65535:
        return result
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2):
            pass
    except OSError as exc:
        result["detail"] = f"{kind} listener unavailable: {type(exc).__name__}"
        return result
    result.update({"healthy": True, "detail": f"{kind} listener reachable"})
    return result



def _config_paths(project_root: Path) -> tuple[Path, Path]:
    generated = project_root / "secrets" / "generated"
    return generated / "shadowsocksr-server.json", generated / "shadowsocksr-client.json"
