"""Container adapter for a source-pinned upstream ShadowsocksR-native build."""

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
from proxy_traffic_lab.providers.shadowsocksr_native.configs import (
    load_document,
    validate_documents,
)


SSR_SOURCE_REPOSITORY = "https://github.com/ShadowsocksR-Live/shadowsocksr-native.git"
SSR_SOURCE_COMMIT = "17677abc3c3c0992244b732c7b62397022dbbe79"
SSR_LOCAL_TAG = f"proxy-traffic-lab/shadowsocksr-native:{SSR_SOURCE_COMMIT[:12]}"
SSR_SERVER_CONTAINER = "proxy-traffic-lab-shadowsocksr-server"
SSR_CLIENT_CONTAINER = "proxy-traffic-lab-shadowsocksr-client"
IMAGE_ID_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")


def build_pinned_image(project_root: Path) -> str:
    context = project_root / "containers" / "shadowsocksr-native"
    dockerfile = context / "Dockerfile"
    if not dockerfile.is_file():
        raise ConfigurationError(f"ShadowsocksR Dockerfile is missing: {dockerfile}")
    build = run_command(
        [
            "docker",
            "build",
            "--pull",
            "--tag",
            SSR_LOCAL_TAG,
            "--build-arg",
            f"SSR_COMMIT={SSR_SOURCE_COMMIT}",
            str(context),
        ],
        timeout_seconds=1200,
    )
    if build.returncode != 0:
        raise ConfigurationError(
            "cannot build pinned ShadowsocksR-native image: "
            + (build.stderr or build.stdout)
        )
    inspect = run_command(
        ["docker", "image", "inspect", SSR_LOCAL_TAG, "--format", "{{.Id}}"],
        timeout_seconds=15,
    )
    if inspect.returncode != 0:
        raise ConfigurationError(f"cannot inspect ShadowsocksR image: {inspect.stderr}")
    image_id = _validate_image_id(inspect.stdout.strip())
    lock_path = project_root / "configs" / "locks" / "shadowsocksr-native.json"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.write_text(
        json.dumps(
            {
                "source_repository": SSR_SOURCE_REPOSITORY,
                "source_commit": SSR_SOURCE_COMMIT,
                "local_tag": SSR_LOCAL_TAG,
                "image": image_id,
                "built_at_utc": datetime.now(UTC).isoformat(),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return image_id


def load_image_lock(project_root: Path) -> str:
    path = project_root / "configs" / "locks" / "shadowsocksr-native.json"
    try:
        lock = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigurationError(f"cannot load ShadowsocksR image lock {path}: {exc}") from exc
    if lock.get("source_commit") != SSR_SOURCE_COMMIT:
        raise ConfigurationError("ShadowsocksR image lock uses an unexpected source commit")
    return _validate_image_id(str(lock.get("image", "")))


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
    return _container_logs(SSR_SERVER_CONTAINER, tail=tail)


def client_logs(*, tail: int = 100) -> str:
    return _container_logs(SSR_CLIENT_CONTAINER, tail=tail)


def stop_server_container() -> str:
    return _stop_container(SSR_SERVER_CONTAINER)


def stop_client_container() -> str:
    return _stop_container(SSR_CLIENT_CONTAINER)


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
    _prepare_read_permission(config_path)
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
    state = _container_state(name)
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


def _validate_image_id(value: str) -> str:
    if not IMAGE_ID_PATTERN.fullmatch(value):
        raise ConfigurationError("ShadowsocksR image must be pinned by local sha256 image ID")
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


def _container_image(name: str) -> str:
    result = run_command(["docker", "inspect", "--format", "{{.Image}}", name])
    return result.stdout.strip() if result.returncode == 0 else ""


def _container_label(name: str, label: str) -> str:
    result = run_command(
        ["docker", "inspect", "--format", f'{{{{index .Config.Labels "{label}"}}}}', name]
    )
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


def _prepare_read_permission(path: Path) -> None:
    if not path.is_file():
        raise ConfigurationError(f"required ShadowsocksR config is missing: {path}")
    path.chmod(0o640)
    if getattr(os, "geteuid", lambda: 1)() == 0:
        os.chown(path, 0, 65532)


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
