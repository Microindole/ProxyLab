from __future__ import annotations

import json
import os
import platform
import shutil
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

from proxy_traffic_lab.controller.models import HostRole, LabConfig
from proxy_traffic_lab.controller.subprocesses import run_command
from proxy_traffic_lab.security.redaction import stable_hash


@dataclass(frozen=True)
class Check:
    name: str
    status: str
    detail: str
    required: bool
    remediation: str | None = None

    @property
    def passed(self) -> bool:
        return self.status in {"pass", "skip"}


@dataclass(frozen=True)
class DoctorReport:
    role: str
    checks: tuple[Check, ...]

    @property
    def healthy(self) -> bool:
        return all(check.passed for check in self.checks if check.required)

    def to_json(self) -> str:
        return json.dumps(
            {
                "role": self.role,
                "healthy": self.healthy,
                "checks": [asdict(check) for check in self.checks],
            },
            ensure_ascii=False,
            indent=2,
        )


def run_doctor(config: LabConfig, *, network_checks: bool = True) -> DoctorReport:
    checks: list[Check] = []
    is_client = config.role in {HostRole.CLIENT, HostRole.COMBINED_DEV}
    is_server = config.role in {HostRole.SERVER, HostRole.COMBINED_DEV}

    checks.append(_linux_check())
    checks.append(_privilege_check())
    checks.append(_python_check())

    for command, package, required in (
        ("ip", "iproute2", True),
        ("tc", "iproute2", is_client),
        ("nft", "nftables", True),
        ("iptables", "iptables", False),
        ("docker", "docker.io or Docker CE", is_server),
        ("tcpdump", "tcpdump", is_client),
        ("dumpcap", "tshark", False),
        ("tshark", "tshark", is_client),
        ("git", "git", False),
        ("make", "make", False),
    ):
        checks.append(_command_check(command, package, required=required))

    if shutil.which("docker"):
        checks.append(_docker_daemon_check(required=is_server))

    checks.append(_playwright_check(required=is_client))
    checks.append(_disk_check(config))
    checks.append(_memory_check())
    checks.append(_cpu_check())

    if network_checks:
        checks.append(_public_ip_check())
    else:
        checks.append(Check("public_ip", "skip", "network checks disabled", False))

    checks.append(_vps_ssh_check(config, enabled=network_checks))
    checks.append(
        Check(
            "cloud_security_group",
            "manual",
            "verify SSH and proxy ports allow only the capture client's CIDR",
            False,
            "Check the cloud console; never expose the proxy port to 0.0.0.0/0.",
        )
    )
    return DoctorReport(role=config.role.value, checks=tuple(checks))


def render_report(report: DoctorReport) -> str:
    labels = {
        "pass": "PASS",
        "fail": "FAIL",
        "warn": "WARN",
        "skip": "SKIP",
        "manual": "MANUAL",
    }
    lines = [f"Proxy Traffic Lab doctor (role={report.role})"]
    for check in report.checks:
        required = " required" if check.required else ""
        lines.append(
            f"[{labels.get(check.status, check.status.upper()):6}] "
            f"{check.name}{required}: {check.detail}"
        )
        if check.status in {"fail", "warn"} and check.remediation:
            lines.append(f"         fix: {check.remediation}")
    lines.append(f"Overall: {'HEALTHY' if report.healthy else 'NOT READY'}")
    return "\n".join(lines)


def _linux_check() -> Check:
    if sys.platform.startswith("linux"):
        detail = platform.platform()
        os_release = _read_os_release()
        if os_release:
            detail = f"{os_release}; kernel={platform.release()}"
        return Check("linux", "pass", detail, True)
    return Check(
        "linux",
        "fail",
        f"detected {sys.platform}",
        True,
        "Run lab inside the Ubuntu host, not from the Windows-mounted drive.",
    )


def _privilege_check() -> Check:
    if not hasattr(os, "geteuid"):
        return Check("privileges", "fail", "POSIX effective UID unavailable", True)
    if os.geteuid() == 0:
        return Check("privileges", "pass", "running as root", True)
    return Check(
        "privileges",
        "warn",
        f"effective uid={os.geteuid()}; capture and namespaces need capabilities",
        True,
        "Run with sudo or grant only the required capabilities to capture tools.",
    )


def _python_check() -> Check:
    version = platform.python_version()
    supported = sys.version_info >= (3, 12)
    return Check(
        "python",
        "pass" if supported else "fail",
        version,
        True,
        None if supported else "Install Python 3.12 or newer.",
    )


def _command_check(
    command: str,
    package: str,
    *,
    required: bool,
) -> Check:
    path = shutil.which(command)
    if path:
        return Check(f"command:{command}", "pass", path, required)
    status = "fail" if required else "warn"
    return Check(
        f"command:{command}",
        status,
        "not found",
        required,
        f"Install the Ubuntu package: {package}",
    )


def _docker_daemon_check(*, required: bool) -> Check:
    result = run_command(
        ["docker", "version", "--format", "{{.Server.Version}}"],
        timeout_seconds=8,
    )
    if result.returncode == 0 and result.stdout:
        return Check("docker_daemon", "pass", f"server={result.stdout}", required)
    return Check(
        "docker_daemon",
        "fail" if required else "warn",
        result.stderr or "Docker daemon unavailable",
        required,
        "Start Docker and verify this user can access its socket.",
    )


def _playwright_check(*, required: bool) -> Check:
    result = run_command(
        [sys.executable, "-c", "import playwright; print('installed')"],
        timeout_seconds=5,
    )
    if result.returncode == 0:
        return Check("playwright", "pass", "Python package installed", required)
    return Check(
        "playwright",
        "fail" if required else "skip",
        "not required on server role" if not required else "Python package missing",
        required,
        "Install the traffic extra and Chromium on the capture client.",
    )


def _disk_check(config: LabConfig) -> Check:
    target = _existing_ancestor(config.data_root)
    usage = shutil.disk_usage(target)
    free_gib = usage.free / (1024**3)
    required = float(config.limits.min_free_disk_gib)
    passed = free_gib >= required
    return Check(
        "disk",
        "pass" if passed else "fail",
        f"path={target}; free={free_gib:.1f} GiB; required={required:.0f} GiB",
        True,
        None if passed else "Free disk space or choose a larger LAB_DATA_ROOT.",
    )


def _memory_check() -> Check:
    meminfo = _parse_key_value_file(Path("/proc/meminfo"))
    total_kib = int(meminfo.get("MemTotal", "0 kB").split()[0])
    total_gib = total_kib / (1024**2)
    status = "pass" if total_gib >= 3.5 else "warn"
    return Check(
        "memory",
        status,
        f"total={total_gib:.1f} GiB",
        False,
        None if status == "pass" else "Use one experiment at a time and lower capture limits.",
    )


def _cpu_check() -> Check:
    count = os.cpu_count() or 0
    return Check(
        "cpu",
        "pass" if count >= 2 else "warn",
        f"logical_cpus={count}",
        False,
        None if count >= 2 else "Use one experiment at a time.",
    )


def _public_ip_check() -> Check:
    configured = os.environ.get("LAB_PUBLIC_IP", "").strip()
    if configured:
        try:
            socket.inet_pton(
                socket.AF_INET6 if ":" in configured else socket.AF_INET,
                configured,
            )
        except OSError:
            return Check(
                "public_ip",
                "warn",
                "LAB_PUBLIC_IP is not a valid IP address",
                False,
                "Correct LAB_PUBLIC_IP in the ignored .env file.",
            )
        return Check(
            "public_ip",
            "pass",
            f"configured; {stable_hash(configured)}",
            False,
        )

    endpoints = (
        "https://api.ipify.org",
        "https://checkip.amazonaws.com",
    )
    failures: list[str] = []
    for endpoint in endpoints:
        request = urllib.request.Request(
            endpoint,
            headers={"User-Agent": "proxy-traffic-lab-doctor/0.1"},
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                value = response.read(128).decode("ascii").strip()
            socket.inet_pton(
                socket.AF_INET6 if ":" in value else socket.AF_INET,
                value,
            )
        except (OSError, ValueError, urllib.error.URLError) as exc:
            failures.append(f"{urllib.parse.urlparse(endpoint).hostname}:{type(exc).__name__}")
            continue
        source = urllib.parse.urlparse(endpoint).hostname
        return Check(
            "public_ip",
            "pass",
            f"source={source}; {stable_hash(value)}",
            False,
        )
    return Check(
        "public_ip",
        "warn",
        "lookup failed: " + ", ".join(failures),
        False,
        "Set LAB_PUBLIC_IP in .env from the cloud console, or confirm outbound HTTPS.",
    )


def _vps_ssh_check(config: LabConfig, *, enabled: bool) -> Check:
    if not config.vps.host:
        return Check(
            "vps_ssh",
            "skip",
            "vps.host is not configured",
            False,
            "Set vps.host when running doctor on the capture client.",
        )
    if not enabled:
        return Check("vps_ssh", "skip", "network checks disabled", False)

    args = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=5",
        "-o",
        "StrictHostKeyChecking=yes",
        "-p",
        str(config.vps.ssh_port),
    ]
    if config.vps.identity_file:
        args.extend(["-i", str(config.vps.identity_file)])
    args.extend(
        [
            f"{config.vps.ssh_user}@{config.vps.host}",
            "uname -s; printf '\\n'; free -m; df -P /",
        ]
    )
    result = run_command(args, timeout_seconds=10)
    if result.returncode == 0:
        summary = "SSH connected; remote OS/memory/disk query succeeded"
        return Check("vps_ssh", "pass", summary, False)
    return Check(
        "vps_ssh",
        "warn",
        f"SSH check failed (exit={result.returncode})",
        False,
        "Verify the host key, SSH key, user, port, and security-group source CIDR.",
    )


def _read_os_release() -> str:
    values = _parse_key_value_file(Path("/etc/os-release"))
    return values.get("PRETTY_NAME", "").strip('"')


def _parse_key_value_file(path: Path) -> dict[str, str]:
    try:
        lines: Iterable[str] = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return {}
    result: dict[str, str] = {}
    for line in lines:
        if "=" in line:
            key, value = line.split("=", 1)
            result[key] = value
        elif ":" in line:
            key, value = line.split(":", 1)
            result[key] = value.strip()
    return result


def _existing_ancestor(path: Path) -> Path:
    candidate = path.expanduser()
    while not candidate.exists() and candidate != candidate.parent:
        candidate = candidate.parent
    return candidate
