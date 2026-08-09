from __future__ import annotations

import os
import socket
from pathlib import Path
from typing import Any

from proxy_traffic_lab.common.errors import ConfigurationError
from proxy_traffic_lab.common.process import run_command
from proxy_traffic_lab.protocols.xray.common import validate_port
from proxy_traffic_lab.lifecycle.docker import container_id, container_label, container_logs, container_state, file_sha256, stop_container
from proxy_traffic_lab.lifecycle.xray.documents import validate_generated_client_address
from proxy_traffic_lab.kernels.xray import local_official_image_id

XRAY_CLIENT_CONTAINER = "proxy-traffic-lab-client"


def start_client_container(config_path: Path) -> str:
    """Start the local Xray client from an explicitly supplied generated config."""
    resolved = config_path.expanduser().resolve()
    if not resolved.is_file():
        raise ConfigurationError(f"Xray client config is missing: {resolved}")
    validate_generated_client_address(resolved)
    image = local_official_image_id()
    config_sha256 = file_sha256(resolved)
    state = container_state(XRAY_CLIENT_CONTAINER)
    if state == "running" and container_label(
        XRAY_CLIENT_CONTAINER, "proxy-traffic-lab.config-sha256"
    ) == config_sha256:
        return container_id(XRAY_CLIENT_CONTAINER)
    if state == "running":
        stopped = run_command(
            ["docker", "stop", "--time", "10", XRAY_CLIENT_CONTAINER],
            timeout_seconds=20,
        )
        if stopped.returncode != 0:
            raise ConfigurationError(f"cannot stop stale Xray client: {stopped.stderr}")
        state = "stopped"
    if state == "stopped":
        removed = run_command(
            ["docker", "rm", XRAY_CLIENT_CONTAINER], timeout_seconds=15
        )
        if removed.returncode != 0:
            raise ConfigurationError(f"cannot remove stale Xray client: {removed.stderr}")

    result = run_command(
        [
            "docker",
            "run",
            "--detach",
            "--name",
            XRAY_CLIENT_CONTAINER,
            "--label",
            f"proxy-traffic-lab.config-sha256={config_sha256}",
            "--restart",
            "unless-stopped",
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
            "512m",
            "--cpus",
            "1.0",
            "--user",
            f"{os.getuid()}:{os.getgid()}",
            "--mount",
            f"type=bind,src={resolved},dst=/run/lab/client.json,readonly",
            image,
            "run",
            "-config",
            "/run/lab/client.json",
        ],
        timeout_seconds=30,
    )
    if result.returncode != 0:
        raise ConfigurationError(f"cannot start Xray client: {result.stderr}")
    return result.stdout.strip()



def client_status(*, socks_port: int = 10808) -> dict[str, Any]:
    validate_port(socks_port)
    state = container_state(XRAY_CLIENT_CONTAINER)
    status: dict[str, Any] = {
        "container": XRAY_CLIENT_CONTAINER,
        "state": state,
        "healthy": False,
        "socks_port": socks_port,
    }
    if state != "running":
        return status
    try:
        with socket.create_connection(("127.0.0.1", socks_port), timeout=2):
            pass
    except OSError as exc:
        status["detail"] = f"SOCKS listener unavailable: {type(exc).__name__}"
        return status
    status.update({"healthy": True, "detail": "SOCKS listener reachable"})
    return status



def client_logs(*, tail: int = 100) -> str:
    return container_logs(XRAY_CLIENT_CONTAINER, tail=tail)



def stop_client_container() -> str:
    return stop_container(XRAY_CLIENT_CONTAINER)



