from __future__ import annotations

import csv
import hashlib
import io
import os
import re
import signal
import subprocess
from dataclasses import dataclass
from pathlib import Path

from proxy_traffic_lab.common.errors import ConfigurationError
from proxy_traffic_lab.common.process import run_command


@dataclass(frozen=True)
class CaptureStats:
    packet_count: int
    captured_bytes: int
    file_bytes: int
    duration_seconds: float
    link_type: str
    dropped_packets: int
    sha256: str


def build_dumpcap_command(
    *,
    interface: str,
    capture_filter: str,
    output_path: Path,
    use_sudo: bool,
) -> list[str]:
    if not interface or any(character.isspace() for character in interface):
        raise ConfigurationError("capture interface is invalid")
    if not capture_filter:
        raise ConfigurationError("capture filter cannot be empty")
    prefix = ["sudo", "-n"] if use_sudo else []
    return prefix + [
        "dumpcap",
        "-F",
        "pcap",
        "-i",
        interface,
        "-f",
        capture_filter,
        "-s",
        "0",
        "-w",
        str(output_path),
    ]


class DumpcapCapture:
    """One standardized libpcap capture process for all dataset classes."""

    def __init__(self, *, interface: str, capture_filter: str, output_path: Path):
        self.interface = interface
        self.capture_filter = capture_filter
        self.output_path = output_path
        self._process: subprocess.Popen[str] | None = None

    def start(self) -> None:
        if self._process is not None:
            raise ConfigurationError("capture has already started")
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        command = build_dumpcap_command(
            interface=self.interface,
            capture_filter=self.capture_filter,
            output_path=self.output_path,
            use_sudo=os.geteuid() != 0,
        )
        try:
            self._process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
            )
        except OSError as exc:
            raise ConfigurationError(f"cannot start dumpcap: {exc}") from exc

    def assert_running(self) -> None:
        if self._process is None:
            raise ConfigurationError("capture has not started")
        if self._process.poll() is not None:
            _, stderr = self._process.communicate(timeout=2)
            raise ConfigurationError(f"dumpcap exited before traffic: {stderr.strip()}")

    def stop(self) -> str:
        if self._process is None:
            return ""
        if self._process.poll() is None:
            self._process.send_signal(signal.SIGINT)
        try:
            _, stderr = self._process.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            self._process.terminate()
            try:
                _, stderr = self._process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
                _, stderr = self._process.communicate(timeout=2)
        return stderr.strip()


def inspect_pcap(path: Path) -> CaptureStats:
    if not path.is_file() or path.stat().st_size <= 24:
        raise ConfigurationError(f"capture is missing or empty: {path}")
    result = run_command(
        ["capinfos", "-T", "-m", "-c", "-d", "-s", "-u", "-E", str(path)],
        timeout_seconds=60,
    )
    if result.returncode != 0:
        raise ConfigurationError(f"capinfos rejected capture: {result.stderr}")
    values = parse_capinfos_table(result.stdout)
    return CaptureStats(
        packet_count=_integer_field(values, "Number of packets"),
        captured_bytes=_integer_field(values, "Data size"),
        file_bytes=_integer_field(values, "File size"),
        duration_seconds=_float_field(values, "Capture duration"),
        link_type=values.get("File encapsulation", "unknown"),
        dropped_packets=parse_dumpcap_drops(path),
        sha256=file_sha256(path),
    )


def parse_capinfos_table(output: str) -> dict[str, str]:
    rows = list(csv.reader(io.StringIO(output)))
    if len(rows) < 2:
        raise ConfigurationError("capinfos table output is incomplete")
    headers = [header.strip() for header in rows[0]]
    values = [value.strip() for value in rows[1]]
    if len(headers) != len(values):
        raise ConfigurationError("capinfos table columns do not match")
    return dict(zip(headers, values, strict=True))


def validate_tunnel_packets(
    path: Path, *, server_ip: str, server_port: int, transport: str
) -> bool:
    address_field = "ipv6.addr" if ":" in server_ip else "ip.addr"
    port_field = "tcp.port" if transport == "tcp" else "udp.port"
    display_filter = (
        f"not (({address_field} == {server_ip}) and ({port_field} == {server_port}))"
    )
    result = run_command(
        [
            "tshark",
            "-r",
            str(path),
            "-Y",
            display_filter,
            "-T",
            "fields",
            "-e",
            "frame.number",
            "-c",
            "1",
        ],
        timeout_seconds=60,
    )
    if result.returncode != 0:
        raise ConfigurationError(f"tshark could not audit capture: {result.stderr}")
    return not result.stdout.strip()


def parse_dumpcap_drops(path: Path) -> int:
    # Classic pcap does not store interface drop counters. The process log is
    # authoritative; zero is used until the orchestrator supplies that value.
    del path
    return 0


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _integer_field(values: dict[str, str], name: str) -> int:
    value = _text_field(values, name)
    match = re.search(r"[0-9]+", value.replace(",", ""))
    if not match:
        raise ConfigurationError(f"capinfos field is not an integer: {name}={value}")
    return int(match.group(0))


def _float_field(values: dict[str, str], name: str) -> float:
    value = _text_field(values, name)
    match = re.search(r"[0-9]+(?:\.[0-9]+)?", value.replace(",", ""))
    if not match:
        raise ConfigurationError(f"capinfos field is not numeric: {name}={value}")
    return float(match.group(0))


def _text_field(
    values: dict[str, str], name: str, *, fallback: str | None = None
) -> str:
    if values.get(name):
        return values[name]
    if fallback is not None:
        return fallback
    raise ConfigurationError(f"capinfos output is missing field: {name}")
