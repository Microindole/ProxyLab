"""Shared official Xray image, configuration, and container runtime adapter."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import socket
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from proxy_traffic_lab.controller.errors import ConfigurationError
from proxy_traffic_lab.controller.subprocesses import run_command

# GitHub release tags include a leading "v", while GHCR image tags do not.
XRAY_OFFICIAL_IMAGE_TAG = "ghcr.io/xtls/xray-core:26.2.6"
XRAY_SERVER_CONTAINER = "proxy-traffic-lab-xray"
XRAY_CLIENT_CONTAINER = "proxy-traffic-lab-client"
IMAGE_DIGEST_PATTERN = re.compile(
    r"^ghcr\.io/xtls/xray-core@sha256:[0-9a-f]{64}$"
)


@dataclass(frozen=True)
class VlessTlsMaterial:
    client_id: str
    server_name: str
    certificate_sha256: str
    certificate_path: Path
    private_key_path: Path


def create_vless_tls_material(
    secrets_dir: Path,
    *,
    server_name: str = "lab.invalid",
    validity_days: int = 30,
) -> VlessTlsMaterial:
    """Create short-lived lab TLS material. Existing secrets are never overwritten."""
    if not server_name or len(server_name) > 253:
        raise ConfigurationError("server_name must be a non-empty DNS name or IP")
    if not 1 <= validity_days <= 397:
        raise ConfigurationError("validity_days must be between 1 and 397")

    secrets_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    certificate_path = secrets_dir / "server.crt"
    private_key_path = secrets_dir / "server.key"
    identity_path = secrets_dir / "identity.json"
    for path in (certificate_path, private_key_path, identity_path):
        if path.exists():
            raise ConfigurationError(f"refusing to overwrite existing secret: {path}")

    san_kind = "IP" if _looks_like_ip(server_name) else "DNS"
    result = run_command(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-sha256",
            "-nodes",
            "-days",
            str(validity_days),
            "-subj",
            f"/CN={server_name}",
            "-addext",
            f"subjectAltName={san_kind}:{server_name}",
            "-keyout",
            str(private_key_path),
            "-out",
            str(certificate_path),
        ],
        timeout_seconds=30,
    )
    if result.returncode != 0:
        private_key_path.unlink(missing_ok=True)
        certificate_path.unlink(missing_ok=True)
        raise ConfigurationError(f"openssl certificate generation failed: {result.stderr}")

    fingerprint = _certificate_fingerprint(certificate_path)
    client_id = str(uuid.uuid4())
    identity_path.write_text(
        json.dumps(
            {
                "client_id": client_id,
                "server_name": server_name,
                "certificate_sha256": fingerprint,
                "websocket_path": f"/assets/{uuid.UUID(client_id).hex[:16]}",
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    os.chmod(private_key_path, 0o600)
    os.chmod(certificate_path, 0o600)
    os.chmod(identity_path, 0o600)
    return VlessTlsMaterial(
        client_id=client_id,
        server_name=server_name,
        certificate_sha256=fingerprint,
        certificate_path=certificate_path,
        private_key_path=private_key_path,
    )


def load_vless_tls_material(secrets_dir: Path) -> VlessTlsMaterial:
    identity_path = secrets_dir / "identity.json"
    try:
        identity = json.loads(identity_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigurationError(f"cannot load {identity_path}: {exc}") from exc
    required = {"client_id", "server_name", "certificate_sha256"}
    if not required.issubset(identity):
        raise ConfigurationError(f"missing fields in {identity_path}")
    try:
        uuid.UUID(identity["client_id"])
    except (ValueError, TypeError) as exc:
        raise ConfigurationError("invalid VLESS client UUID") from exc
    return VlessTlsMaterial(
        client_id=identity["client_id"],
        server_name=identity["server_name"],
        certificate_sha256=identity["certificate_sha256"],
        certificate_path=secrets_dir / "server.crt",
        private_key_path=secrets_dir / "server.key",
    )


def render_vless_tls_server(
    material: VlessTlsMaterial,
    *,
    port: int,
    certificate_container_path: str = "/run/secrets/xray/server.crt",
    private_key_container_path: str = "/run/secrets/xray/server.key",
) -> dict[str, Any]:
    _validate_port(port)
    return {
        "log": {"loglevel": "warning", "access": "none"},
        "inbounds": [
            {
                "tag": "vless-tcp-tls-in",
                "listen": "0.0.0.0",
                "port": port,
                "protocol": "vless",
                "settings": {
                    "clients": [
                        {
                            "id": material.client_id,
                            "email": "mvp-collector",
                        }
                    ],
                    "decryption": "none",
                },
                "streamSettings": {
                    "method": "raw",
                    "security": "tls",
                    "tlsSettings": {
                        "rejectUnknownSni": True,
                        "minVersion": "1.3",
                        "certificates": [
                            {
                                "certificateFile": certificate_container_path,
                                "keyFile": private_key_container_path,
                            }
                        ],
                    },
                },
            }
        ],
        "outbounds": [
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"},
        ],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {
                    "type": "field",
                    "ip": [
                        "geoip:private",
                        "100.64.0.0/10",
                        "100.100.100.200/32",
                        "169.254.0.0/16",
                        "224.0.0.0/4",
                        "240.0.0.0/4",
                        "::1/128",
                        "fe80::/10",
                        "fc00::/7",
                    ],
                    "outboundTag": "block",
                },
                {
                    "type": "field",
                    "protocol": ["bittorrent"],
                    "outboundTag": "block",
                },
            ],
        },
    }


def render_vless_tls_client(
    material: VlessTlsMaterial,
    *,
    server_address: str,
    server_port: int,
    socks_port: int = 10808,
) -> dict[str, Any]:
    _validate_port(server_port)
    _validate_port(socks_port)
    try:
        normalized_server_address = ipaddress.ip_address(server_address).compressed
    except ValueError as exc:
        raise ConfigurationError(
            "server_address must be the VPS IPv4 or IPv6 address; placeholders and hostnames are rejected"
        ) from exc
    return {
        "log": {"loglevel": "warning", "access": "none"},
        "inbounds": [
            {
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "socks",
                "settings": {"udp": False},
            }
        ],
        "outbounds": [
            {
                "tag": "proxy",
                "protocol": "vless",
                "settings": {
                    "address": normalized_server_address,
                    "port": server_port,
                    "id": material.client_id,
                    "encryption": "none",
                },
                "streamSettings": {
                    "method": "raw",
                    "security": "tls",
                    "tlsSettings": {
                        "serverName": material.server_name,
                        "fingerprint": "chrome",
                        "pinnedPeerCertSha256": material.certificate_sha256,
                    },
                },
            },
            {"tag": "block", "protocol": "blackhole"},
        ],
    }


def render_vmess_websocket_tls_server(
    material: VlessTlsMaterial,
    *,
    port: int,
    certificate_container_path: str = "/run/secrets/xray/server.crt",
    private_key_container_path: str = "/run/secrets/xray/server.key",
) -> dict[str, Any]:
    """Render class 5 using Xray's VMess, WebSocket and TLS implementations."""
    _validate_port(port)
    websocket_path = _websocket_path(material.client_id)
    return {
        "log": {"loglevel": "warning", "access": "none"},
        "inbounds": [
            {
                "tag": "class-05-vmess-websocket-tls-in",
                "listen": "0.0.0.0",
                "port": port,
                "protocol": "vmess",
                "settings": {
                    "users": [
                        {
                            "id": material.client_id,
                            "level": 0,
                            "email": "class-05-collector",
                        }
                    ]
                },
                "streamSettings": {
                    "method": "websocket",
                    "security": "tls",
                    "wsSettings": {
                        "path": websocket_path,
                        "host": material.server_name,
                        "acceptProxyProtocol": False,
                    },
                    "tlsSettings": {
                        "rejectUnknownSni": True,
                        "minVersion": "1.3",
                        "alpn": ["http/1.1"],
                        "certificates": [
                            {
                                "certificateFile": certificate_container_path,
                                "keyFile": private_key_container_path,
                            }
                        ],
                    },
                },
            }
        ],
        "outbounds": [
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"},
        ],
        "routing": _server_routing(),
    }


def render_vmess_websocket_tls_client(
    material: VlessTlsMaterial,
    *,
    server_address: str,
    server_port: int,
    socks_port: int = 10808,
) -> dict[str, Any]:
    _validate_port(server_port)
    _validate_port(socks_port)
    normalized_server_address = _normalize_server_address(server_address)
    return {
        "log": {"loglevel": "warning", "access": "none"},
        "inbounds": [
            {
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "socks",
                "settings": {"udp": False},
            }
        ],
        "outbounds": [
            {
                "tag": "proxy",
                "protocol": "vmess",
                "settings": {
                    "address": normalized_server_address,
                    "port": server_port,
                    "id": material.client_id,
                },
                "streamSettings": {
                    "method": "websocket",
                    "security": "tls",
                    "wsSettings": {
                        "path": _websocket_path(material.client_id),
                        "host": material.server_name,
                    },
                    "tlsSettings": {
                        "serverName": material.server_name,
                        "fingerprint": "chrome",
                        "alpn": ["http/1.1"],
                        "pinnedPeerCertSha256": material.certificate_sha256,
                    },
                },
            },
            {"tag": "block", "protocol": "blackhole"},
        ],
    }


def render_xray_case_server(
    case_id: str,
    material: VlessTlsMaterial,
    *,
    port: int,
) -> dict[str, Any]:
    if case_id == "vless-tcp-tls":
        return render_vless_tls_server(material, port=port)
    if case_id == "class-05-vmess-websocket-tls":
        return render_vmess_websocket_tls_server(material, port=port)
    raise ConfigurationError(f"Xray case is not implemented yet: {case_id}")


def render_xray_case_client(
    case_id: str,
    material: VlessTlsMaterial,
    *,
    server_address: str,
    server_port: int,
    socks_port: int = 10808,
) -> dict[str, Any]:
    if case_id == "vless-tcp-tls":
        return render_vless_tls_client(
            material,
            server_address=server_address,
            server_port=server_port,
            socks_port=socks_port,
        )
    if case_id == "class-05-vmess-websocket-tls":
        return render_vmess_websocket_tls_client(
            material,
            server_address=server_address,
            server_port=server_port,
            socks_port=socks_port,
        )
    raise ConfigurationError(f"Xray case is not implemented yet: {case_id}")


def write_private_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    os.chmod(path, 0o600)


def validate_official_image_digest(image: str) -> str:
    if not IMAGE_DIGEST_PATTERN.fullmatch(image):
        raise ConfigurationError(
            "Xray image must be the official GHCR image pinned by sha256 digest"
        )
    return image


def lock_official_image(lock_path: Path) -> str:
    pull = run_command(["docker", "pull", XRAY_OFFICIAL_IMAGE_TAG], timeout_seconds=180)
    if pull.returncode != 0:
        raise ConfigurationError(f"cannot pull official Xray image: {pull.stderr}")
    inspect = run_command(
        [
            "docker",
            "image",
            "inspect",
            XRAY_OFFICIAL_IMAGE_TAG,
            "--format",
            "{{index .RepoDigests 0}}",
        ],
        timeout_seconds=15,
    )
    if inspect.returncode != 0:
        raise ConfigurationError(f"cannot inspect Xray image: {inspect.stderr}")
    image = validate_official_image_digest(inspect.stdout.strip())
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.write_text(
        json.dumps(
            {
                "source_tag": XRAY_OFFICIAL_IMAGE_TAG,
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
    return validate_official_image_digest(value.get("image", ""))


def validate_server_config_with_container(project_root: Path) -> str:
    image = load_image_lock(project_root / "configs" / "locks" / "xray.json")
    config_path = project_root / "secrets" / "generated" / "server.json"
    certificate_path = project_root / "secrets" / "xray" / "server.crt"
    private_key_path = project_root / "secrets" / "xray" / "server.key"
    for path in (config_path, certificate_path, private_key_path):
        if not path.is_file():
            raise ConfigurationError(f"required generated file is missing: {path}")
    server_result = run_command(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--user",
            "0:0",
            "--mount",
            f"type=bind,src={config_path},dst=/run/lab/server.json,readonly",
            "--mount",
            f"type=bind,src={certificate_path},dst=/run/secrets/xray/server.crt,readonly",
            "--mount",
            f"type=bind,src={private_key_path},dst=/run/secrets/xray/server.key,readonly",
            image,
            "run",
            "-test",
            "-config",
            "/run/lab/server.json",
        ],
        timeout_seconds=30,
    )
    if server_result.returncode != 0:
        raise ConfigurationError(
            "Xray rejected generated server configuration: "
            + (server_result.stderr or server_result.stdout)
        )

    client_path = project_root / "secrets" / "generated" / "client.json"
    if not client_path.is_file():
        raise ConfigurationError(f"required generated file is missing: {client_path}")
    validate_generated_client_address(client_path)
    client_result = run_command(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--user",
            "0:0",
            "--mount",
            f"type=bind,src={client_path},dst=/run/lab/client.json,readonly",
            image,
            "run",
            "-test",
            "-config",
            "/run/lab/client.json",
        ],
        timeout_seconds=30,
    )
    if client_result.returncode != 0:
        raise ConfigurationError(
            "Xray rejected generated client configuration: "
            + (client_result.stderr or client_result.stdout)
        )
    server_detail = server_result.stdout or server_result.stderr
    client_detail = client_result.stdout or client_result.stderr
    return f"SERVER\n{server_detail}\nCLIENT\n{client_detail}"


def validate_generated_client_address(client_path: Path) -> str:
    try:
        document = json.loads(client_path.read_text(encoding="utf-8"))
        value = document["outbounds"][0]["settings"]["address"]
    except (OSError, json.JSONDecodeError, KeyError, IndexError, TypeError) as exc:
        raise ConfigurationError(
            f"cannot read generated client server address from {client_path}"
        ) from exc
    try:
        return ipaddress.ip_address(value).compressed
    except (ValueError, TypeError) as exc:
        raise ConfigurationError(
            "generated client server address is not an IP; rerun `lab xray render` with the VPS public IP"
        ) from exc


def start_server_container(project_root: Path) -> str:
    """Start the constrained Xray server container, or return its running ID."""
    image = load_image_lock(project_root / "configs" / "locks" / "xray.json")
    validate_server_config_with_container(project_root)
    config_path = project_root / "secrets" / "generated" / "server.json"
    config_sha256 = _file_sha256(config_path)
    existing = _container_state()
    if existing == "running" and _container_label(
        XRAY_SERVER_CONTAINER, "proxy-traffic-lab.config-sha256"
    ) == config_sha256:
        return _container_id()
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
    _prepare_container_read_permissions(config_path, certificate_path, private_key_path)
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


def start_client_container(config_path: Path) -> str:
    """Start the local Xray client from an explicitly supplied generated config."""
    resolved = config_path.expanduser().resolve()
    if not resolved.is_file():
        raise ConfigurationError(f"Xray client config is missing: {resolved}")
    validate_generated_client_address(resolved)
    image = _local_official_image_id()
    config_sha256 = _file_sha256(resolved)
    state = _named_container_state(XRAY_CLIENT_CONTAINER)
    if state == "running" and _container_label(
        XRAY_CLIENT_CONTAINER, "proxy-traffic-lab.config-sha256"
    ) == config_sha256:
        return _named_container_id(XRAY_CLIENT_CONTAINER)
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
    _validate_port(socks_port)
    state = _named_container_state(XRAY_CLIENT_CONTAINER)
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
    return _named_container_logs(XRAY_CLIENT_CONTAINER, tail=tail)


def stop_client_container() -> str:
    return _stop_named_container(XRAY_CLIENT_CONTAINER)


def server_status(project_root: Path) -> dict[str, Any]:
    state = _container_state()
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
        port = int(document["inbounds"][0]["port"])
    except (OSError, json.JSONDecodeError, KeyError, IndexError, TypeError, ValueError):
        result["detail"] = "cannot read generated server port"
        return result
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2):
            pass
    except OSError as exc:
        result["port"] = port
        result["detail"] = f"TCP listener unavailable: {type(exc).__name__}"
        return result
    result.update({"healthy": True, "port": port, "detail": "TCP listener reachable"})
    return result


def server_logs(*, tail: int = 100) -> str:
    if not 1 <= tail <= 10_000:
        raise ConfigurationError("tail must be between 1 and 10000")
    if _container_state() == "absent":
        return "Xray server container is absent"
    result = run_command(
        ["docker", "logs", "--tail", str(tail), XRAY_SERVER_CONTAINER],
        timeout_seconds=15,
    )
    if result.returncode != 0:
        raise ConfigurationError(f"cannot read Xray logs: {result.stderr}")
    return "\n".join(part for part in (result.stdout, result.stderr) if part)


def stop_server_container() -> str:
    state = _container_state()
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


def _container_state() -> str:
    return _named_container_state(XRAY_SERVER_CONTAINER)


def _named_container_state(name: str) -> str:
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


def _container_id() -> str:
    return _named_container_id(XRAY_SERVER_CONTAINER)


def _named_container_id(name: str) -> str:
    result = run_command(
        ["docker", "inspect", "--format", "{{.Id}}", name],
        timeout_seconds=10,
    )
    if result.returncode != 0:
        raise ConfigurationError(f"cannot inspect Xray server: {result.stderr}")
    return result.stdout.strip()


def _container_label(name: str, label: str) -> str:
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


def _named_container_logs(name: str, *, tail: int) -> str:
    if not 1 <= tail <= 10_000:
        raise ConfigurationError("tail must be between 1 and 10000")
    if _named_container_state(name) == "absent":
        return f"{name} is absent"
    result = run_command(
        ["docker", "logs", "--tail", str(tail), name], timeout_seconds=15
    )
    if result.returncode != 0:
        raise ConfigurationError(f"cannot read {name} logs: {result.stderr}")
    return "\n".join(part for part in (result.stdout, result.stderr) if part)


def _stop_named_container(name: str) -> str:
    state = _named_container_state(name)
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


def _local_official_image_id() -> str:
    result = run_command(
        ["docker", "image", "inspect", XRAY_OFFICIAL_IMAGE_TAG, "--format", "{{.Id}}"],
        timeout_seconds=15,
    )
    if result.returncode != 0 or not re.fullmatch(r"sha256:[0-9a-f]{64}", result.stdout):
        raise ConfigurationError(
            f"local official Xray image is missing: {XRAY_OFFICIAL_IMAGE_TAG}"
        )
    return result.stdout


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _prepare_container_read_permissions(*paths: Path) -> None:
    for path in paths:
        if not path.is_file():
            raise ConfigurationError(f"required Xray file is missing: {path}")
        os.chmod(path, 0o640)
        if os.geteuid() == 0:
            os.chown(path, 0, 65532)


def _certificate_fingerprint(path: Path) -> str:
    result = run_command(
        ["openssl", "x509", "-in", str(path), "-noout", "-fingerprint", "-sha256"],
        timeout_seconds=10,
    )
    if result.returncode != 0 or "=" not in result.stdout:
        raise ConfigurationError(f"cannot fingerprint certificate: {result.stderr}")
    return result.stdout.split("=", 1)[1].replace(":", "").lower()


def _looks_like_ip(value: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _normalize_server_address(value: str) -> str:
    try:
        return ipaddress.ip_address(value).compressed
    except ValueError as exc:
        raise ConfigurationError(
            "server_address must be the VPS IPv4 or IPv6 address; "
            "placeholders and hostnames are rejected"
        ) from exc


def _websocket_path(client_id: str) -> str:
    try:
        identifier = uuid.UUID(client_id)
    except (ValueError, TypeError) as exc:
        raise ConfigurationError("invalid VMess client UUID") from exc
    return f"/assets/{identifier.hex[:16]}"


def _server_routing() -> dict[str, Any]:
    return {
        "domainStrategy": "IPIfNonMatch",
        "rules": [
            {
                "type": "field",
                "ip": [
                    "geoip:private",
                    "100.64.0.0/10",
                    "100.100.100.200/32",
                    "169.254.0.0/16",
                    "224.0.0.0/4",
                    "240.0.0.0/4",
                    "::1/128",
                    "fe80::/10",
                    "fc00::/7",
                ],
                "outboundTag": "block",
            },
            {
                "type": "field",
                "protocol": ["bittorrent"],
                "outboundTag": "block",
            },
        ],
    }


def _validate_port(port: int) -> None:
    if not 1 <= port <= 65535:
        raise ConfigurationError("port must be between 1 and 65535")
