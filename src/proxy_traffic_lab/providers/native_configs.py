from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from proxy_traffic_lab.controller.errors import ConfigurationError

SS2022_METHOD = "2022-blake3-aes-128-gcm"
SSR_METHOD = "aes-256-cfb"
SSR_OBFS = "tls1.2_ticket_auth"


def render_native_case(
    case_id: str,
    *,
    server_address: str,
    server_port: int,
    socks_port: int = 10808,
    seed: str,
) -> dict[str, dict[str, Any]]:
    _validate_port(server_port)
    _validate_port(socks_port)
    if case_id == "class-01-shadowsocks-2022-tcp":
        return _render_shadowsocks_2022(
            server_address=server_address,
            server_port=server_port,
            socks_port=socks_port,
            seed=seed,
            network="tcp",
        )
    if case_id == "class-02-shadowsocks-2022-udp":
        return _render_shadowsocks_2022(
            server_address=server_address,
            server_port=server_port,
            socks_port=socks_port,
            seed=seed,
            network="udp",
        )
    if case_id == "class-03-ssr-auth-aes128-md5":
        return _render_shadowsocksr(
            server_address=server_address,
            server_port=server_port,
            socks_port=socks_port,
            seed=seed,
            protocol="auth_aes128_md5",
        )
    if case_id == "class-04-ssr-auth-aes128-sha1":
        return _render_shadowsocksr(
            server_address=server_address,
            server_port=server_port,
            socks_port=socks_port,
            seed=seed,
            protocol="auth_aes128_sha1",
        )
    raise ConfigurationError(f"native case is not implemented: {case_id}")


def write_native_case(
    output_dir: Path,
    case_id: str,
    *,
    server_address: str,
    server_port: int,
    socks_port: int = 10808,
    seed: str,
) -> tuple[Path, Path]:
    rendered = render_native_case(
        case_id,
        server_address=server_address,
        server_port=server_port,
        socks_port=socks_port,
        seed=seed,
    )
    output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    server_path = output_dir / "server.json"
    client_path = output_dir / "client.json"
    _write_private_json(server_path, rendered["server"])
    _write_private_json(client_path, rendered["client"])
    return server_path, client_path


def _render_shadowsocks_2022(
    *,
    server_address: str,
    server_port: int,
    socks_port: int,
    seed: str,
    network: str,
) -> dict[str, dict[str, Any]]:
    password = _secret(seed, f"ss2022:{network}", length=32)
    server = {
        "implementation": "shadowsocks-rust",
        "binary": "ssserver",
        "server": "0.0.0.0",
        "server_port": server_port,
        "method": SS2022_METHOD,
        "password": password,
        "mode": "tcp_only" if network == "tcp" else "udp_only",
        "timeout": 300,
    }
    client = {
        "implementation": "sing-box",
        "log": {"level": "warn"},
        "inbounds": [
            {
                "type": "socks",
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "listen_port": socks_port,
                "udp": network == "udp",
            }
        ],
        "outbounds": [
            {
                "type": "shadowsocks",
                "tag": "proxy",
                "server": server_address,
                "server_port": server_port,
                "method": SS2022_METHOD,
                "password": password,
                "network": network,
            },
            {"type": "block", "tag": "block"},
        ],
    }
    return {"server": server, "client": client}


def _render_shadowsocksr(
    *,
    server_address: str,
    server_port: int,
    socks_port: int,
    seed: str,
    protocol: str,
) -> dict[str, dict[str, Any]]:
    password = _secret(seed, f"ssr:{protocol}", length=24)
    common = {
        "server_port": server_port,
        "password": password,
        "method": SSR_METHOD,
        "protocol": protocol,
        "protocol_param": "",
        "obfs": SSR_OBFS,
        "obfs_param": "",
        "timeout": 300,
    }
    server = {
        "implementation": "shadowsocksr-libev",
        "binary": "ssr-server",
        "server": "0.0.0.0",
        **common,
    }
    client = {
        "implementation": "shadowsocksr-libev",
        "binary": "ssr-local",
        "server": server_address,
        "local_address": "127.0.0.1",
        "local_port": socks_port,
        **common,
    }
    return {"server": server, "client": client}


def _secret(seed: str, label: str, *, length: int) -> str:
    digest = hashlib.sha256(f"{label}:{seed}".encode()).hexdigest()
    return digest[:length]


def _validate_port(port: int) -> None:
    if not 1 <= port <= 65535:
        raise ConfigurationError("port must be between 1 and 65535")


def _write_private_json(path: Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass
