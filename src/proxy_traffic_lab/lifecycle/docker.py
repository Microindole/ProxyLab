"""Shared Docker lifecycle primitives."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from proxy_traffic_lab.common.errors import ConfigurationError
from proxy_traffic_lab.common.process import run_command


def container_state(name: str) -> str:
    result = run_command(
        [
            "docker",
            "inspect",
            "--format",
            "{{.State.Status}}",
            name,
        ],
        timeout_seconds=10,
    )
    if result.returncode != 0:
        return "absent"
    return "running" if result.stdout.strip() == "running" else "stopped"



def container_id(name: str) -> str:
    result = run_command(
        ["docker", "inspect", "--format", "{{.Id}}", name],
        timeout_seconds=10,
    )
    if result.returncode != 0:
        raise ConfigurationError(f"cannot inspect container {name}: {result.stderr}")
    return result.stdout.strip()



def container_label(name: str, label: str) -> str:
    result = run_command(
        [
            "docker",
            "inspect",
            "--format",
            f"{{{{index .Config.Labels \"{label}\"}}}}",
            name,
        ],
        timeout_seconds=10,
    )
    return result.stdout.strip() if result.returncode == 0 else ""


def container_image(name: str) -> str:
    result = run_command(
        ["docker", "inspect", "--format", "{{.Config.Image}}", name],
        timeout_seconds=10,
    )
    return result.stdout.strip() if result.returncode == 0 else ""



def container_logs(name: str, *, tail: int) -> str:
    if not 1 <= tail <= 10_000:
        raise ConfigurationError("tail must be between 1 and 10000")
    if container_state(name) == "absent":
        return f"{name} is absent"
    result = run_command(
        ["docker", "logs", "--tail", str(tail), name], timeout_seconds=15
    )
    if result.returncode != 0:
        raise ConfigurationError(f"cannot read {name} logs: {result.stderr}")
    return "\n".join(part for part in (result.stdout, result.stderr) if part)



def stop_container(name: str) -> str:
    state = container_state(name)
    if state == "absent":
        return "already absent"
    if state == "running":
        stop = run_command(
            ["docker", "stop", "--time", "10", name], timeout_seconds=20
        )
        if stop.returncode != 0:
            raise ConfigurationError(f"cannot stop {name}: {stop.stderr}")
    remove = run_command(["docker", "rm", name], timeout_seconds=15)
    if remove.returncode != 0:
        raise ConfigurationError(f"cannot remove {name}: {remove.stderr}")
    return "stopped and removed"



def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()



def prepare_read_permissions(*paths: Path) -> None:
    for path in paths:
        if not path.is_file():
            raise ConfigurationError(f"required container file is missing: {path}")
        os.chmod(path, 0o640)
        if getattr(os, "geteuid", lambda: 1)() == 0:
            os.chown(path, 0, 65532)



