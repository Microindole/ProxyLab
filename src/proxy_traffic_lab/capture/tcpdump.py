"""Own the Linux tcpdump process and capture-host preflight checks."""

from __future__ import annotations

import os
import re
import signal
import socket
import subprocess
from pathlib import Path
from urllib.parse import urlparse

from proxy_traffic_lab.common.errors import ConfigurationError
from proxy_traffic_lab.common.process import run_command


def start_tcpdump(
    *, interface: str, capture_filter: str, output_path: Path
) -> subprocess.Popen[str]:
    prefix: list[str] = [] if os.geteuid() == 0 else ["sudo", "-n"]
    args = prefix + [
        "tcpdump",
        "-i",
        interface,
        "-nn",
        "-s",
        "0",
        "-U",
        "-w",
        str(output_path),
        capture_filter,
    ]
    try:
        return subprocess.Popen(
            args,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
    except OSError as exc:
        raise ConfigurationError(f"cannot start tcpdump: {exc}") from exc


def ensure_sudo_credentials() -> None:
    if os.geteuid() == 0:
        return
    try:
        result = subprocess.run(
            ["sudo", "-n", "-v"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ConfigurationError(
            "cannot refresh sudo credentials; run 'sudo -v' before capture"
        ) from exc
    if result.returncode != 0:
        detail = result.stderr.strip() or "sudo authorization is unavailable"
        raise ConfigurationError(
            f"cannot refresh sudo credentials: {detail}; run 'sudo -v' before capture"
        )


def stop_tcpdump(process: subprocess.Popen[str]) -> str:
    if process.poll() is None:
        process.send_signal(signal.SIGINT)
    try:
        _, stderr = process.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        process.terminate()
        try:
            _, stderr = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            _, stderr = process.communicate(timeout=2)
    return stderr.strip()


def route_interface(server_ip: str) -> str:
    result = run_command(["ip", "route", "get", server_ip], timeout_seconds=10)
    if result.returncode != 0:
        raise ConfigurationError(f"cannot determine capture interface: {result.stderr}")
    match = re.search(r"(?:^|\s)dev\s+(\S+)", result.stdout)
    if not match:
        raise ConfigurationError("route lookup did not return an interface")
    return match.group(1)


def require_proxy_listener(proxy_server: str) -> None:
    parsed = urlparse(proxy_server)
    if parsed.scheme not in {"socks5", "http"} or not parsed.hostname or not parsed.port:
        raise ConfigurationError("proxy must look like socks5://127.0.0.1:10808")
    try:
        with socket.create_connection((parsed.hostname, parsed.port), timeout=2):
            pass
    except OSError as exc:
        raise ConfigurationError(
            f"proxy listener is unavailable at {parsed.hostname}:{parsed.port}"
        ) from exc

