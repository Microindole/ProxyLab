"""Windows dumpcap execution and IPv6 flow capture."""

from __future__ import annotations

import os
import subprocess
import sys
import time
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from proxy_traffic_lab.capture.experiment import _format_bytes
from proxy_traffic_lab.capture.flow_tracker import PcapIpPacketTracker, PcapL4ConversationTracker, PcapTcpFlowTracker
from proxy_traffic_lab.common.errors import LabError
from proxy_traffic_lab.configuration.loader import load_plain_capture_config, project_root


@dataclass(frozen=True, slots=True)
class WindowsCaptureRequest:
    """Capture-layer input, independent from argparse and the CLI command tree."""

    list_interfaces: bool
    interface: str | None
    output: Path | None
    profiles: list[str] | None
    output_root: Path
    ip_version: str
    target_flows: int | None
    flow_count_mode: str
    progress_interval: float
    idle_seconds: float
    idle_kib_per_second: float
    finish_timeout: float
    duration_seconds: int
    start_url: str
    start_chrome: bool
    disable_quic: bool
    isolate_chrome_network: bool
    case_id: str | None


def execute_windows_capture(request: WindowsCaptureRequest) -> int:
    root = project_root()
    script = _windows_helper_script("capture.ps1")
    if not request.list_interfaces and not request.interface:
        raise LabError(
            "missing --interface; first run: lab capture windows-ipv6 --list-interfaces"
        )
    if request.target_flows is not None and request.target_flows <= 0:
        raise LabError("--target-flows must be positive")
    if request.progress_interval <= 0:
        raise LabError("--progress-interval must be positive")
    if request.idle_seconds < 0 or request.idle_kib_per_second < 0:
        raise LabError("idle thresholds cannot be negative")
    command = [
        "powershell.exe",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        _wslpath_to_windows(script),
    ]
    if request.list_interfaces:
        if os.name == "nt":
            completed = subprocess.run(
                [str(_find_windows_dumpcap_for_wsl()), "-D"],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            stdout_text = completed.stdout.decode("mbcs", errors="replace")
            stderr_text = completed.stderr.decode("mbcs", errors="replace")
            sys.stdout.write(
                stdout_text.encode(
                    sys.stdout.encoding or "utf-8", errors="replace"
                ).decode(sys.stdout.encoding or "utf-8")
            )
            sys.stderr.write(
                stderr_text.encode(
                    sys.stderr.encoding or "utf-8", errors="replace"
                ).decode(sys.stderr.encoding or "utf-8")
            )
            return completed.returncode
        command.append("-ListInterfaces")
    elif request.target_flows is not None:
        plain_config = load_plain_capture_config(root / "configs" / "plain_capture.yaml")
        case_id = request.case_id or getattr(plain_config.case_ids, request.ip_version)
        session_dirs = _run_windows_ipv6_flow_capture(
            interface=request.interface,
            ip_version=request.ip_version,
            flow_count_mode=request.flow_count_mode,
            target_flows=request.target_flows,
            output_root=request.output_root,
            profiles=request.profiles or ["mixed"],
            start_chrome=request.start_chrome,
            start_url=request.start_url,
            disable_quic=request.disable_quic,
            isolate_chrome_network=request.isolate_chrome_network,
            progress_interval_seconds=request.progress_interval,
            idle_seconds=request.idle_seconds,
            idle_bytes_per_second=request.idle_kib_per_second * 1024,
            finish_timeout_seconds=request.finish_timeout,
            case_id=case_id,
        )
        print("Capture sessions written:")
        for session_dir in session_dirs:
            print(f"  {session_dir}")
        return 0
    else:
        command.extend(["-Interface", request.interface])
        command.extend(["-IpVersion", request.ip_version])
        if request.output is not None:
            command.extend(["-Output", _wslpath_to_windows(request.output)])
        if request.duration_seconds:
            command.extend(["-DurationSeconds", str(request.duration_seconds)])
        command.extend(["-StartUrl", request.start_url])
        if request.start_chrome:
            command.append("-StartChrome")
        if request.disable_quic:
            command.append("-DisableQuic")
    completed = subprocess.run(command, check=False)
    return completed.returncode


def _wslpath_to_windows(path: Path) -> str:
    expanded = path.expanduser()
    if os.name == "nt":
        return str(expanded.resolve())
    result = subprocess.run(
        ["wslpath", "-w", str(expanded)],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode != 0:
        raise LabError(f"cannot convert path for PowerShell: {result.stderr.strip()}")
    return result.stdout.strip()


class TerminalDashboard:
    """Small alternate-screen dashboard for live capture progress only."""

    def __init__(self) -> None:
        self._active = False

    def __enter__(self) -> TerminalDashboard:
        if sys.stdout.isatty():
            sys.stdout.write("\x1b[?1049h\x1b[?25l\x1b[H\x1b[2J")
            sys.stdout.flush()
            self._active = True
        return self

    def render(self, text: str) -> None:
        if self._active:
            sys.stdout.write("\x1b[H\x1b[2J")
            sys.stdout.write(text)
            sys.stdout.flush()
        else:
            print(text, flush=True)

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        if self._active:
            sys.stdout.write("\x1b[?25h\x1b[?1049l")
            sys.stdout.flush()
            self._active = False


def _run_windows_ipv6_flow_capture(
    *,
    interface: str,
    ip_version: str,
    flow_count_mode: str,
    target_flows: int,
    output_root: Path,
    profiles: Sequence[str],
    start_chrome: bool,
    start_url: str,
    disable_quic: bool,
    isolate_chrome_network: bool,
    progress_interval_seconds: float,
    idle_seconds: float,
    idle_bytes_per_second: float,
    finish_timeout_seconds: float,
    case_id: str,
) -> tuple[Path, ...]:
    dumpcap = _find_windows_dumpcap_for_wsl()
    series_started_at = datetime.now(UTC)
    series_id = (
        f"{series_started_at.strftime('%Y%m%dT%H%M%SZ')}-"
        f"{uuid.uuid4().hex[:10]}"
    )
    sessions: list[Path] = []
    segment_count = len(profiles)
    isolation_enabled = False
    try:
        if isolate_chrome_network:
            _set_windows_chrome_network_isolation(enable=True)
            isolation_enabled = True
        if start_chrome:
            _start_windows_no_proxy_browser(
                start_url=start_url, disable_quic=disable_quic
            )

        for segment_index, profile in enumerate(profiles, start=1):
            segment_flow_count_mode = _resolve_windows_plain_flow_count_mode(
                profile=profile,
                requested_mode=flow_count_mode,
            )
            if segment_index > 1:
                print(
                    f"Starting segment {segment_index}/{segment_count}: {profile}. "
                    "Wait for READY before beginning the next workload.",
                    flush=True,
                )
            session_dir, stop_reason = _capture_windows_ipv6_flow_segment(
                dumpcap=dumpcap,
                interface=interface,
                ip_version=ip_version,
                flow_count_mode=segment_flow_count_mode,
                requested_flow_count_mode=flow_count_mode,
                target_flows=target_flows,
                output_root=output_root,
                profile=profile,
                series_id=series_id,
                segment_index=segment_index,
                segment_count=segment_count,
                progress_interval_seconds=progress_interval_seconds,
                idle_seconds=idle_seconds,
                idle_bytes_per_second=idle_bytes_per_second,
                finish_timeout_seconds=finish_timeout_seconds,
                case_id=case_id,
            )
            sessions.append(session_dir)
            if segment_index == segment_count:
                break
            if stop_reason != "target_flows_reached_and_traffic_idle":
                print(
                    f"Series stopped after segment {segment_index}: {stop_reason}.",
                    flush=True,
                )
                break
    finally:
        if isolation_enabled:
            _set_windows_chrome_network_isolation(enable=False)
    return tuple(sessions)


def _resolve_windows_plain_flow_count_mode(
    *,
    profile: str,
    requested_mode: str,
) -> str:
    if requested_mode != "auto":
        return requested_mode
    normalized = profile.lower().replace("_", "-")
    if normalized.startswith("video"):
        return "conversation-5tuple"
    return "established"


def _progress_bar(
    *,
    value: float,
    total: float,
    width: int = 28,
) -> str:
    if total <= 0:
        total = 1
    ratio = max(0.0, min(value / total, 1.0))
    filled = int(round(ratio * width))
    return "█" * filled + "░" * (width - filled)


def _render_windows_capture_progress(
    *,
    segment_index: int,
    segment_count: int,
    phase: str,
    profile: str,
    pcap_path: Path,
    stats: object,
    ip_stats: object,
    target_flows: int,
    size: int,
    rate: float,
    status: str,
) -> str:
    flow_total_for_bar = max(target_flows, stats.total_flows, 1)
    l4_total_for_bar = max(stats.tcp_conversations + stats.udp_conversations, 1)
    ip_flow_total_for_bar = max(stats.ipv4_flows + stats.ipv6_flows, 1)
    packet_total_for_bar = max(ip_stats.ipv4_packets + ip_stats.ipv6_packets, 1)
    percent = min(stats.total_flows / target_flows * 100, 100.0)

    def metric_line(label: str, value: int, total: int, suffix: str = "") -> str:
        return (
            f"{label:<12} "
            f"[{_progress_bar(value=value, total=total)}] "
            f"{value:>8} / {total:<8} {suffix}"
        )

    return "\n".join(
        [
            f"segment {segment_index}/{segment_count}  {phase}  "
            f"{datetime.now(UTC).strftime('%H:%M:%S')}Z",
            f"profile     {profile}",
            f"pcap        {pcap_path}",
            f"status      {status}",
            metric_line(
                "flows",
                stats.total_flows,
                target_flows,
                f"{percent:5.1f}%",
            ),
            metric_line("completed", stats.completed_flows, flow_total_for_bar),
            metric_line("active", stats.active_flows, flow_total_for_bar),
            metric_line("l4 tcp", stats.tcp_conversations, l4_total_for_bar),
            metric_line("l4 udp", stats.udp_conversations, l4_total_for_bar),
            metric_line("flow ipv6", stats.ipv6_flows, ip_flow_total_for_bar),
            metric_line("flow ipv4", stats.ipv4_flows, ip_flow_total_for_bar),
            metric_line("pkt ipv6", ip_stats.ipv6_packets, packet_total_for_bar),
            metric_line("pkt ipv4", ip_stats.ipv4_packets, packet_total_for_bar),
            f"udp443 conv {ip_stats.udp_443_conversations}",
            f"pcap size   {_format_bytes(size)}",
            f"write rate  {_format_bytes(int(rate))}/s",
        ]
    )


def _capture_windows_ipv6_flow_segment(
    *,
    dumpcap: Path,
    interface: str,
    ip_version: str,
    flow_count_mode: str,
    requested_flow_count_mode: str,
    target_flows: int,
    output_root: Path,
    profile: str,
    series_id: str,
    segment_index: int,
    segment_count: int,
    progress_interval_seconds: float,
    idle_seconds: float,
    idle_bytes_per_second: float,
    finish_timeout_seconds: float,
    case_id: str,
) -> tuple[Path, str]:
    started_at = datetime.now(UTC)
    sample_id = f"{started_at.strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:10]}"
    session_dir = (
        output_root.expanduser().resolve()
        / "formal"
        / case_id
        / profile
        / sample_id
    )
    session_dir.mkdir(parents=True, exist_ok=False)
    pcap_path = session_dir / "capture.pcap"
    dumpcap_log_path = session_dir / "dumpcap.log"
    capture_filter = (
        "ip6 and (tcp port 80 or tcp port 443 or udp port 443)"
        if ip_version == "ipv6"
        else "(ip or ip6) and (tcp port 80 or tcp port 443 or udp port 443)"
    )
    windows_output = _wslpath_to_windows(pcap_path)
    dumpcap_log = dumpcap_log_path.open("wb")
    process = subprocess.Popen(
        [
            str(dumpcap),
            "-q",
            "-F",
            "pcap",
            "-i",
            interface,
            "-f",
            capture_filter,
            "-s",
            "0",
            "-w",
            windows_output,
        ],
        stdin=subprocess.DEVNULL,
        stdout=dumpcap_log,
        stderr=subprocess.STDOUT,
    )
    tracker = (
        PcapL4ConversationTracker(pcap_path)
        if flow_count_mode == "conversation-5tuple"
        else PcapTcpFlowTracker(pcap_path, count_mode=flow_count_mode)
    )
    ip_tracker = PcapIpPacketTracker(pcap_path)
    stop_reason = "interrupted"
    target_reached_at: float | None = None
    quiet_started_at: float | None = None
    flow_timeout_warning_at: float | None = None
    previous_time = time.monotonic()
    previous_size = 0
    target_label = (
        "TCP+UDP 5-tuple conversations"
        if flow_count_mode == "conversation-5tuple"
        else f"TCP flows ({flow_count_mode})"
    )
    print(
        f"READY segment {segment_index}/{segment_count}: {profile}\n"
        f"Capturing plain {ip_version} on Windows interface {interface} to {pcap_path}\n"
        f"Filter: {capture_filter}\n"
        f"Target: {target_flows} {target_label}; after target, stop opening new pages "
        "and wait for PCAP write rate to become idle. Active TCP flows are reported "
        "but do not block plain website rotation. Press Ctrl+C to stop early.",
        flush=True,
    )
    status_message = "capturing; open/use only the intended browser workload"
    try:
        with TerminalDashboard() as dashboard:
            try:
                time.sleep(1)
                if process.poll() is not None:
                    dumpcap_log.close()
                    stderr = dumpcap_log_path.read_text(errors="replace")
                    raise LabError(
                        f"dumpcap exited before traffic started: {stderr.strip()}"
                    )
                while True:
                    time.sleep(progress_interval_seconds)
                    now = time.monotonic()
                    size = pcap_path.stat().st_size if pcap_path.is_file() else 0
                    interval = max(now - previous_time, 0.001)
                    rate = max(size - previous_size, 0) / interval
                    stats = tracker.poll()
                    ip_stats = ip_tracker.poll()
                    phase = (
                        "DRAINING"
                        if stats.total_flows >= target_flows
                        else "CAPTURING"
                    )
                    dashboard.render(
                        _render_windows_capture_progress(
                            segment_index=segment_index,
                            segment_count=segment_count,
                            phase=phase,
                            profile=profile,
                            pcap_path=pcap_path,
                            stats=stats,
                            ip_stats=ip_stats,
                            target_flows=target_flows,
                            size=size,
                            rate=rate,
                            status=status_message,
                        )
                    )
                    if process.poll() is not None:
                        dumpcap_log.close()
                        stderr = dumpcap_log_path.read_text(errors="replace")
                        raise LabError(f"dumpcap stopped unexpectedly: {stderr.strip()}")
                    if stats.total_flows >= target_flows:
                        if target_reached_at is None:
                            target_reached_at = now
                            flow_timeout_warning_at = now + finish_timeout_seconds
                            status_message = (
                                "target reached; stop new browsing and wait for idle"
                            )
                        if rate <= idle_bytes_per_second:
                            quiet_started_at = quiet_started_at or now
                        else:
                            quiet_started_at = None
                        if (
                            quiet_started_at is not None
                            and now - quiet_started_at >= idle_seconds
                        ):
                            stop_reason = "target_flows_reached_and_traffic_idle"
                            break
                        if (
                            flow_timeout_warning_at is not None
                            and now >= flow_timeout_warning_at
                        ):
                            status_message = (
                                "still waiting for traffic idle; active TCP flows "
                                f"{stats.active_flows}"
                            )
                            flow_timeout_warning_at = now + finish_timeout_seconds
                    previous_time = now
                    previous_size = size
            except KeyboardInterrupt:
                stop_reason = "interrupted"
                size = pcap_path.stat().st_size if pcap_path.is_file() else 0
                stats = tracker.poll()
                ip_stats = ip_tracker.poll()
                phase = (
                    "DRAINING" if stats.total_flows >= target_flows else "CAPTURING"
                )
                dashboard.render(
                    _render_windows_capture_progress(
                        segment_index=segment_index,
                        segment_count=segment_count,
                        phase=phase,
                        profile=profile,
                        pcap_path=pcap_path,
                        stats=stats,
                        ip_stats=ip_stats,
                        target_flows=target_flows,
                        size=size,
                        rate=0,
                        status=(
                            "Ctrl+C received; stopping dumpcap and writing metadata..."
                        ),
                    )
                )
    finally:
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        if not dumpcap_log.closed:
            dumpcap_log.close()
        dumpcap_log_text = dumpcap_log_path.read_text(errors="replace")

    ended_at = datetime.now(UTC)
    final_stats = tracker.poll()
    final_ip_stats = ip_tracker.poll()
    final_size = pcap_path.stat().st_size if pcap_path.is_file() else 0
    metadata = {
        "schema_version": "1.0.0",
        "sample_id": sample_id,
        "series_id": series_id,
        "segment_index": segment_index,
        "segment_count": segment_count,
        "case_id": case_id,
        "profile": profile,
        "capture": {
            "pcap": pcap_path.name,
            "interface": interface,
            "bpf": capture_filter,
            "start_time_utc": started_at.isoformat(),
            "end_time_utc": ended_at.isoformat(),
            "target_flows": target_flows,
            "requested_flow_count_mode": requested_flow_count_mode,
            "flow_count_mode": flow_count_mode,
            "flow_count_definition": (
                "bidirectional TCP plus UDP L4 5-tuple conversations, matching "
                "Wireshark Conversations TCP+UDP counts"
                if flow_count_mode == "conversation-5tuple"
                else "TCP flows tracked from SYN/SYN-ACK/FIN/RST packets"
            ),
            "file_bytes": final_size,
            "target_met": final_stats.total_flows >= target_flows,
            "flow_count": final_stats.total_flows,
            "tcp_conversation_count": final_stats.tcp_conversations,
            "udp_conversation_count": final_stats.udp_conversations,
            "completed_flow_count": final_stats.completed_flows,
            "active_flow_count": final_stats.active_flows,
            "ipv4_flow_count": final_stats.ipv4_flows,
            "ipv6_flow_count": final_stats.ipv6_flows,
            "completed_ipv4_flow_count": final_stats.completed_ipv4_flows,
            "completed_ipv6_flow_count": final_stats.completed_ipv6_flows,
            "active_ipv4_flow_count": final_stats.active_ipv4_flows,
            "active_ipv6_flow_count": final_stats.active_ipv6_flows,
            "ipv4_packets": final_ip_stats.ipv4_packets,
            "ipv6_packets": final_ip_stats.ipv6_packets,
            "tcp_packets": final_ip_stats.tcp_packets,
            "udp_packets": final_ip_stats.udp_packets,
            "udp_443_conversations": final_ip_stats.udp_443_conversations,
            "stop_reason": stop_reason,
            "dumpcap_log": dumpcap_log_text.strip(),
        },
    }
    (session_dir / "capture.json").write_text(
        json_dumps(metadata),
        encoding="utf-8",
    )
    print(
        f"Segment {segment_index}/{segment_count} stopped: {stop_reason}; "
        f"final size {_format_bytes(final_size)}, flows {final_stats.total_flows}, "
        f"active {final_stats.active_flows}\n"
        f"PCAP: {pcap_path}",
        flush=True,
    )
    return session_dir, stop_reason


def json_dumps(value: object) -> str:
    import json

    return json.dumps(value, indent=2, ensure_ascii=False) + "\n"


def _find_windows_dumpcap_for_wsl() -> Path:
    if os.name == "nt":
        where_result = subprocess.run(
            ["where.exe", "dumpcap.exe"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        for line in where_result.stdout.splitlines():
            candidate = Path(line.strip())
            if candidate.is_file():
                return candidate
        candidates = [
            Path("C:/Program Files/Wireshark/dumpcap.exe"),
            Path("C:/Program Files (x86)/Wireshark/dumpcap.exe"),
            Path("D:/Wireshark/dumpcap.exe"),
        ]
        for candidate in candidates:
            if candidate.is_file():
                return candidate
        raise LabError(
            "Windows dumpcap.exe was not found; install Wireshark with Npcap"
        )
    where_result = subprocess.run(
        ["cmd.exe", "/c", "where", "dumpcap.exe"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    for line in where_result.stdout.splitlines():
        candidate_text = line.strip()
        if not candidate_text:
            continue
        converted = subprocess.run(
            ["wslpath", "-u", candidate_text],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        if converted.returncode == 0:
            candidate = Path(converted.stdout.strip())
            if candidate.is_file():
                return candidate
    candidates = [
        Path("/mnt/c/Program Files/Wireshark/dumpcap.exe"),
        Path("/mnt/c/Program Files (x86)/Wireshark/dumpcap.exe"),
        Path("/mnt/d/Wireshark/dumpcap.exe"),
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise LabError("Windows dumpcap.exe was not found; install Wireshark with Npcap")


def _start_windows_no_proxy_browser(*, start_url: str, disable_quic: bool) -> None:
    script = _windows_helper_script("browser.ps1")
    command = [
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        _wslpath_to_windows(script),
        "-StartUrl",
        start_url,
    ]
    if disable_quic:
        command.append("-DisableQuic")
    result = subprocess.run(
        command,
        check=False,
        text=True,
    )
    if result.returncode != 0:
        raise LabError("failed to start Windows no-proxy browser")


def _windows_helper_script(name: str) -> Path:
    script = project_root() / "scripts" / "windows" / name
    if not script.is_file():
        raise LabError(f"missing helper script: {script}")
    return script


def _set_windows_chrome_network_isolation(*, enable: bool) -> None:
    script = _windows_helper_script("isolate.ps1")
    action = "Enable" if enable else "Disable"
    script_for_display = _wslpath_to_windows(script)
    command = [
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        script_for_display,
        "-Action",
        action,
    ]
    result = subprocess.run(command, check=False, text=True)
    if result.returncode != 0:
        if enable:
            raise LabError(
                "failed to enable Chrome network isolation; rerun from an elevated "
                "PowerShell or omit --isolate-chrome-network"
            )
        raise LabError(
            "failed to disable Chrome network isolation; run "
            f"`powershell -ExecutionPolicy Bypass -File {script_for_display} "
            "-Action Disable` from an elevated PowerShell"
        )
