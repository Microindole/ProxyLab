"""Container adapter for the pinned upstream Hysteria 2 executable."""

from __future__ import annotations

import hashlib
import json
import os
import re
import socket
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from proxy_traffic_lab.controller.errors import ConfigurationError
from proxy_traffic_lab.controller.subprocesses import run_command
from proxy_traffic_lab.providers.hysteria2.configs import (
    load_hysteria2_yaml,
    validate_hysteria2_documents,
)


HYSTERIA2_OFFICIAL_IMAGE_TAG = "tobyxdd/hysteria:v2.10.0"
HYSTERIA2_SERVER_CONTAINER = "proxy-traffic-lab-hysteria2-server"
HYSTERIA2_CLIENT_CONTAINER = "proxy-traffic-lab-hysteria2-client"
IMAGE_DIGEST_PATTERN = re.compile(
    r"^tobyxdd/hysteria@sha256:[0-9a-f]{64}$"
)


def lock_official_image(lock_path: Path) -> str:
    pull = run_command(["docker", "pull", HYSTERIA2_OFFICIAL_IMAGE_TAG], timeout_seconds=180)
    if pull.returncode != 0:
        raise ConfigurationError(f"cannot pull official Hysteria2 image: {pull.stderr}")
    inspect = run_command(
        [
            "docker",
            "image",
            "inspect",
            HYSTERIA2_OFFICIAL_IMAGE_TAG,
            "--format",
            "{{index .RepoDigests 0}}",
        ],
        timeout_seconds=15,
    )
    if inspect.returncode != 0:
        raise ConfigurationError(f"cannot inspect Hysteria2 image: {inspect.stderr}")
    image = _validate_image_digest(inspect.stdout.strip())
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.write_text(
        json.dumps(
            {
                "source_tag": HYSTERIA2_OFFICIAL_IMAGE_TAG,
                "image": image,
                "locked_at_utc": datetime.now(UTC).isoformat(),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return image


def load_image_lock(lock_path: Path) -> str:
    try:
        value = json.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigurationError(f"cannot load image lock {lock_path}: {exc}") from exc
    return _validate_image_digest(value.get("image", ""))


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
    state = _container_state(HYSTERIA2_SERVER_CONTAINER)
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
    state = _container_state(HYSTERIA2_CLIENT_CONTAINER)
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
    return _container_logs(HYSTERIA2_SERVER_CONTAINER, tail=tail)


def client_logs(*, tail: int = 100) -> str:
    return _container_logs(HYSTERIA2_CLIENT_CONTAINER, tail=tail)


def stop_server_container() -> str:
    return _stop_container(HYSTERIA2_SERVER_CONTAINER)


def stop_client_container() -> str:
    return _stop_container(HYSTERIA2_CLIENT_CONTAINER)


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
    _prepare_read_permissions(*paths)
    config_sha256 = _file_sha256(config_path)
    state = _container_state(name)
    if (
        state == "running"
        and _container_label(name, "proxy-traffic-lab.config-sha256") == config_sha256
        and _container_image(name) == image
    ):
        return _container_id(name)
    if state != "absent":
        _stop_container(name)
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


def _validate_image_digest(value: str) -> str:
    if not IMAGE_DIGEST_PATTERN.fullmatch(value):
        raise ConfigurationError("Hysteria2 image lock is missing or not digest-pinned")
    return value


def _container_state(name: str) -> str:
    result = run_command(["docker", "inspect", "--format", "{{.State.Status}}", name])
    if result.returncode != 0:
        return "absent"
    return "running" if result.stdout.strip() == "running" else "stopped"


def _container_id(name: str) -> str:
    result = run_command(["docker", "inspect", "--format", "{{.Id}}", name])
    if result.returncode != 0:
        raise ConfigurationError(f"cannot inspect {name}: {result.stderr}")
    return result.stdout.strip()


def _container_label(name: str, label: str) -> str:
    result = run_command(
        ["docker", "inspect", "--format", f'{{{{index .Config.Labels "{label}"}}}}', name]
    )
    return result.stdout.strip() if result.returncode == 0 else ""


def _container_image(name: str) -> str:
    result = run_command(["docker", "inspect", "--format", "{{.Config.Image}}", name])
    return result.stdout.strip() if result.returncode == 0 else ""


def _container_logs(name: str, *, tail: int) -> str:
    if not 1 <= tail <= 10_000:
        raise ConfigurationError("tail must be between 1 and 10000")
    if _container_state(name) == "absent":
        return f"{name} is absent"
    result = run_command(["docker", "logs", "--tail", str(tail), name], timeout_seconds=15)
    if result.returncode != 0:
        raise ConfigurationError(f"cannot read {name} logs: {result.stderr}")
    return "\n".join(part for part in (result.stdout, result.stderr) if part)


def _stop_container(name: str) -> str:
    state = _container_state(name)
    if state == "absent":
        return "already absent"
    if state == "running":
        stopped = run_command(["docker", "stop", "--time", "10", name], timeout_seconds=20)
        if stopped.returncode != 0:
            raise ConfigurationError(f"cannot stop {name}: {stopped.stderr}")
    removed = run_command(["docker", "rm", name], timeout_seconds=15)
    if removed.returncode != 0:
        raise ConfigurationError(f"cannot remove {name}: {removed.stderr}")
    return "stopped and removed"


def _prepare_read_permissions(*paths: Path) -> None:
    for path in paths:
        if not path.is_file():
            raise ConfigurationError(f"required Hysteria2 file is missing: {path}")
        path.chmod(0o640)
        if getattr(os, "geteuid", lambda: 1)() == 0:
            os.chown(path, 0, 65532)


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_port(port: int) -> None:
    if not 1 <= port <= 65535:
        raise ConfigurationError("port must be between 1 and 65535")
