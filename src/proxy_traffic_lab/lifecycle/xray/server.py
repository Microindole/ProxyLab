from __future__ import annotations

import json
import socket
from pathlib import Path
from typing import Any

from proxy_traffic_lab.common.errors import ConfigurationError
from proxy_traffic_lab.common.process import run_command
from proxy_traffic_lab.lifecycle.docker import container_id, container_label, container_state, file_sha256, prepare_read_permissions
from proxy_traffic_lab.kernels.xray import load_image_lock
from proxy_traffic_lab.lifecycle.xray.validation import validate_server_config_with_container

XRAY_SERVER_CONTAINER = "proxy-traffic-lab-xray"


def start_server_container(project_root: Path) -> str:
    """Start the constrained Xray server container, or return its running ID."""
    image = load_image_lock(project_root / "configs" / "locks" / "xray.json")
    validate_server_config_with_container(project_root)
    config_path = project_root / "secrets" / "generated" / "server.json"
    config_sha256 = file_sha256(config_path)
    existing = container_state(XRAY_SERVER_CONTAINER)
    if existing == "running" and container_label(
        XRAY_SERVER_CONTAINER, "proxy-traffic-lab.config-sha256"
    ) == config_sha256:
        return container_id(XRAY_SERVER_CONTAINER)
    if existing == "running":
        stop = run_command(
            ["docker", "stop", "--time", "10", XRAY_SERVER_CONTAINER],
            timeout_seconds=20,
        )
        if stop.returncode != 0:
            raise ConfigurationError(f"cannot stop stale Xray container: {stop.stderr}")
        existing = "stopped"
    if existing == "stopped":
        remove = run_command(
            ["docker", "rm", XRAY_SERVER_CONTAINER], timeout_seconds=15
        )
        if remove.returncode != 0:
            raise ConfigurationError(f"cannot remove stopped Xray container: {remove.stderr}")

    certificate_path = project_root / "secrets" / "xray" / "server.crt"
    private_key_path = project_root / "secrets" / "xray" / "server.key"
    prepare_read_permissions(config_path, certificate_path, private_key_path)
    result = run_command(
        [
            "docker",
            "run",
            "--detach",
            "--name",
            XRAY_SERVER_CONTAINER,
            "--label",
            f"proxy-traffic-lab.config-sha256={config_sha256}",
            "--restart",
            "no",
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
            "--network",
            "host",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=16m",
            "--mount",
            f"type=bind,src={config_path},dst=/run/lab/server.json,readonly",
            "--mount",
            f"type=bind,src={certificate_path},dst=/run/secrets/xray/server.crt,readonly",
            "--mount",
            f"type=bind,src={private_key_path},dst=/run/secrets/xray/server.key,readonly",
            image,
            "run",
            "-config",
            "/run/lab/server.json",
        ],
        timeout_seconds=30,
    )
    if result.returncode != 0:
        raise ConfigurationError(f"cannot start Xray server: {result.stderr}")
    return result.stdout.strip()



def server_status(project_root: Path) -> dict[str, Any]:
    state = container_state(XRAY_SERVER_CONTAINER)
    result: dict[str, Any] = {
        "container": XRAY_SERVER_CONTAINER,
        "state": state,
        "healthy": False,
    }
    if state != "running":
        return result
    config_path = project_root / "secrets" / "generated" / "server.json"
    try:
        document = json.loads(config_path.read_text(encoding="utf-8"))
        inbound = document["inbounds"][0]
        port = int(inbound["port"])
        transport = str(inbound.get("settings", {}).get("network", "tcp"))
    except (OSError, json.JSONDecodeError, KeyError, IndexError, TypeError, ValueError):
        result["detail"] = "cannot read generated server port"
        return result
    if transport == "udp":
        result.update(
            {
                "healthy": True,
                "port": port,
                "transport": "udp",
                "detail": "Xray process running; UDP has no connect-style health probe",
            }
        )
        return result
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2):
            pass
    except OSError as exc:
        result["port"] = port
        result["detail"] = f"TCP listener unavailable: {type(exc).__name__}"
        return result
    result.update(
        {
            "healthy": True,
            "port": port,
            "transport": "tcp",
            "detail": "TCP listener reachable",
        }
    )
    return result



def server_logs(*, tail: int = 100) -> str:
    if not 1 <= tail <= 10_000:
        raise ConfigurationError("tail must be between 1 and 10000")
    if container_state(XRAY_SERVER_CONTAINER) == "absent":
        return "Xray server container is absent"
    result = run_command(
        ["docker", "logs", "--tail", str(tail), XRAY_SERVER_CONTAINER],
        timeout_seconds=15,
    )
    if result.returncode != 0:
        raise ConfigurationError(f"cannot read Xray logs: {result.stderr}")
    return "\n".join(part for part in (result.stdout, result.stderr) if part)



def stop_server_container() -> str:
    state = container_state(XRAY_SERVER_CONTAINER)
    if state == "absent":
        return "already absent"
    if state == "running":
        stop = run_command(
            ["docker", "stop", "--time", "10", XRAY_SERVER_CONTAINER],
            timeout_seconds=20,
        )
        if stop.returncode != 0:
            raise ConfigurationError(f"cannot stop Xray server: {stop.stderr}")
    remove = run_command(
        ["docker", "rm", XRAY_SERVER_CONTAINER], timeout_seconds=15
    )
    if remove.returncode != 0:
        raise ConfigurationError(f"cannot remove Xray server: {remove.stderr}")
    return "stopped and removed"



