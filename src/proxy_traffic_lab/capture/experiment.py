from __future__ import annotations

import hashlib
import json
import os
import re
import signal
import socket
import subprocess
import time
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from proxy_traffic_lab.capture.filters import tunnel_bpf
from proxy_traffic_lab.capture.flow_tracker import (
    PcapL4ConversationTracker,
    PcapTcpFlowTracker,
)
from proxy_traffic_lab.controller.errors import ConfigurationError
from proxy_traffic_lab.controller.models import ProtocolCase
from proxy_traffic_lab.controller.subprocesses import run_command
from proxy_traffic_lab.traffic.playwright_web import generate_web_traffic


_SUDO_REFRESH_INTERVAL_SECONDS = 60.0


def run_size_limited_capture(
    *,
    case: ProtocolCase,
    server_ip: str,
    server_port: int,
    target_bytes: int,
    output_root: Path,
    profile: str = "mixed",
    interface: str | None = None,
    progress_interval_seconds: float = 5.0,
    idle_seconds: float = 15.0,
    idle_bytes_per_second: float = 32 * 1024,
    finish_timeout_seconds: float = 300.0,
) -> Path:
    """Capture one size-limited PCAP (backward-compatible single segment)."""
    sessions = run_segmented_capture(
        case=case,
        server_ip=server_ip,
        server_port=server_port,
        target_bytes=target_bytes,
        target_flows=None,
        output_root=output_root,
        profiles=(profile,),
        interface=interface,
        progress_interval_seconds=progress_interval_seconds,
        idle_seconds=idle_seconds,
        idle_bytes_per_second=idle_bytes_per_second,
        finish_timeout_seconds=finish_timeout_seconds,
    )
    return sessions[0]


def run_segmented_capture(
    *,
    case: ProtocolCase,
    server_ip: str,
    server_port: int,
    target_bytes: int | None,
    output_root: Path,
    profiles: Sequence[str],
    interface: str | None = None,
    progress_interval_seconds: float = 5.0,
    idle_seconds: float = 15.0,
    idle_bytes_per_second: float = 32 * 1024,
    finish_timeout_seconds: float = 300.0,
    target_flows: int | None = None,
) -> tuple[Path, ...]:
    """Capture multiple PCAPs, rotating only after a post-target quiet period."""
    if not case.enabled:
        raise ConfigurationError(f"protocol case is disabled: {case.id}")
    if target_flows is None:
        if target_bytes is None or target_bytes <= 24:
            raise ConfigurationError("target capture size must be greater than 24 bytes")
    else:
        if target_flows <= 0:
            raise ConfigurationError("target flow count must be positive")
        if case.outer_transport not in {"tcp", "udp"}:
            raise ConfigurationError(
                "live flow-limited capture requires outer TCP or UDP"
            )
    if progress_interval_seconds <= 0:
        raise ConfigurationError("progress interval must be positive")
    if idle_seconds < 0 or idle_bytes_per_second < 0:
        raise ConfigurationError("idle thresholds cannot be negative")
    if finish_timeout_seconds <= 0:
        raise ConfigurationError("finish timeout must be positive")
    if not profiles:
        raise ConfigurationError("at least one capture profile is required")
    for profile in profiles:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", profile):
            raise ConfigurationError(
                f"profile contains unsupported characters: {profile}"
            )

    selected_interface = interface or _route_interface(server_ip)
    capture_filter = tunnel_bpf(server_ip, server_port, case.outer_transport)
    series_started_at = datetime.now(UTC)
    series_id = (
        f"{series_started_at.strftime('%Y%m%dT%H%M%SZ')}-"
        f"{uuid.uuid4().hex[:10]}"
    )
    sessions: list[Path] = []
    segment_count = len(profiles)

    for segment_index, profile in enumerate(profiles, start=1):
        _ensure_sudo_credentials()
        if segment_index > 1:
            print(
                f"Starting segment {segment_index}/{segment_count}: {profile}. "
                "Wait for the READY message before beginning the next workload.",
                flush=True,
            )
        session_dir, stop_reason = _capture_size_segment(
            case=case,
            server_ip=server_ip,
            server_port=server_port,
            target_bytes=target_bytes,
            target_flows=target_flows,
            output_root=output_root,
            profile=profile,
            selected_interface=selected_interface,
            capture_filter=capture_filter,
            progress_interval_seconds=progress_interval_seconds,
            idle_seconds=idle_seconds,
            idle_bytes_per_second=idle_bytes_per_second,
            finish_timeout_seconds=finish_timeout_seconds,
            series_id=series_id,
            segment_index=segment_index,
            segment_count=segment_count,
        )
        sessions.append(session_dir)
        if segment_index == segment_count:
            break
        if stop_reason not in {
            "target_reached_and_traffic_idle",
            "target_flows_reached_and_all_flows_closed",
            "target_udp_conversations_reached_and_traffic_idle",
        }:
            print(
                f"Series stopped after segment {segment_index}: {stop_reason}. "
                "No new PCAP was started because the previous flow boundary was not idle.",
                flush=True,
            )
            break

    return tuple(sessions)


def _capture_size_segment(
    *,
    case: ProtocolCase,
    server_ip: str,
    server_port: int,
    target_bytes: int | None,
    target_flows: int | None,
    output_root: Path,
    profile: str,
    selected_interface: str,
    capture_filter: str,
    progress_interval_seconds: float,
    idle_seconds: float,
    idle_bytes_per_second: float,
    finish_timeout_seconds: float,
    series_id: str,
    segment_index: int,
    segment_count: int,
) -> tuple[Path, str]:
    started_at = datetime.now(UTC)
    sample_id = f"{started_at.strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:10]}"
    session_dir = (
        output_root.expanduser().resolve() / "formal" / case.id / profile / sample_id
    )
    session_dir.mkdir(parents=True, exist_ok=False)
    pcap_path = session_dir / "capture.pcap"
    flow_tracker = None
    if target_flows is not None:
        flow_tracker = (
            PcapTcpFlowTracker(pcap_path)
            if case.outer_transport == "tcp"
            else PcapL4ConversationTracker(pcap_path)
        )

    process = _start_tcpdump(
        interface=selected_interface,
        capture_filter=capture_filter,
        output_path=pcap_path,
    )
    stop_reason = "interrupted"
    target_reached_at: float | None = None
    quiet_started_at: float | None = None
    previous_time = time.monotonic()
    previous_size = 0
    next_sudo_refresh = previous_time + _SUDO_REFRESH_INTERVAL_SECONDS
    flow_timeout_warning_at: float | None = None
    target_text = (
        (
            f"{target_flows} outer TCP flows"
            if case.outer_transport == "tcp"
            else f"{target_flows} outer UDP 5-tuple conversations"
        )
        if target_flows is not None
        else _format_bytes(target_bytes or 0)
    )
    print(
        f"READY segment {segment_index}/{segment_count}: {profile}\n"
        f"Capturing {case.id} on {selected_interface} to {pcap_path}\n"
        f"Target: {target_text}; after target, do not start new work. "
        "The capture will wait for active flows to close and traffic to stay at or below "
        f"{_format_bytes(int(idle_bytes_per_second))}/s for {idle_seconds:g}s. "
        "Press Ctrl+C to stop the whole series early.",
        flush=True,
    )
    try:
        time.sleep(1)
        if process.poll() is not None:
            _, stderr = process.communicate(timeout=2)
            raise ConfigurationError(f"tcpdump exited before traffic started: {stderr}")

        while True:
            time.sleep(progress_interval_seconds)
            now = time.monotonic()
            if now >= next_sudo_refresh:
                try:
                    _ensure_sudo_credentials()
                except ConfigurationError as exc:
                    print(
                        f"warning: {exc} The current tcpdump will continue, but the "
                        "next segment cannot start until sudo is authorized again.",
                        flush=True,
                    )
                next_sudo_refresh = now + _SUDO_REFRESH_INTERVAL_SECONDS
            size = pcap_path.stat().st_size if pcap_path.is_file() else 0
            interval = max(now - previous_time, 0.001)
            rate = max(size - previous_size, 0) / interval
            flow_stats = flow_tracker.poll() if flow_tracker is not None else None
            if flow_stats is not None and target_flows is not None:
                percent = min(flow_stats.total_flows / target_flows * 100, 100.0)
                phase = (
                    "DRAINING"
                    if flow_stats.total_flows >= target_flows
                    else "CAPTURING"
                )
                overshoot = max(flow_stats.total_flows - target_flows, 0)
                print(
                    f"[segment {segment_index}/{segment_count} {phase} "
                    f"{datetime.now(UTC).strftime('%H:%M:%S')}Z] "
                    f"flows {flow_stats.total_flows} / {target_flows} "
                    f"({percent:5.1f}%), active {flow_stats.active_flows}, "
                    f"completed {flow_stats.completed_flows}, overshoot {overshoot}, "
                    f"pcap {_format_bytes(size)}, rate {_format_bytes(int(rate))}/s",
                    flush=True,
                )
            else:
                assert target_bytes is not None
                percent = min(size / target_bytes * 100, 100.0)
                phase = "WAITING_FOR_IDLE" if size >= target_bytes else "CAPTURING"
                overshoot = max(size - target_bytes, 0)
                overshoot_text = (
                    f", overshoot {_format_bytes(overshoot)}" if overshoot else ""
                )
                print(
                    f"[segment {segment_index}/{segment_count} {phase} "
                    f"{datetime.now(UTC).strftime('%H:%M:%S')}Z] "
                    f"{_format_bytes(size)} / {_format_bytes(target_bytes)} "
                    f"({percent:5.1f}%){overshoot_text}, "
                    f"current rate {_format_bytes(int(rate))}/s",
                    flush=True,
                )
            if process.poll() is not None:
                _, stderr = process.communicate(timeout=2)
                raise ConfigurationError(f"tcpdump stopped unexpectedly: {stderr}")

            if flow_stats is not None and target_flows is not None:
                if flow_stats.total_flows >= target_flows:
                    if target_reached_at is None:
                        target_reached_at = now
                        flow_timeout_warning_at = now + finish_timeout_seconds
                        if case.outer_transport == "tcp":
                            print(
                                f"Segment {segment_index}/{segment_count} flow target reached. "
                                "Stop creating new sessions and let every active flow close; "
                                "the PCAP will not be cut at the threshold.",
                                flush=True,
                            )
                        else:
                            print(
                                f"Segment {segment_index}/{segment_count} UDP conversation "
                                "target reached. Stop creating new workloads and wait for "
                                "outer QUIC traffic to become idle.",
                                flush=True,
                            )
                    if flow_stats.active_flows == 0 and rate <= idle_bytes_per_second:
                        quiet_started_at = quiet_started_at or now
                    else:
                        quiet_started_at = None
                    if (
                        quiet_started_at is not None
                        and now - quiet_started_at >= idle_seconds
                    ):
                        stop_reason = (
                            "target_flows_reached_and_all_flows_closed"
                            if case.outer_transport == "tcp"
                            else "target_udp_conversations_reached_and_traffic_idle"
                        )
                        break
                    if (
                        flow_timeout_warning_at is not None
                        and now >= flow_timeout_warning_at
                    ):
                        print(
                            f"warning: still waiting for {flow_stats.active_flows} active "
                            "flow(s); capture continues because active flows are never "
                            "truncated by the finish timeout.",
                            flush=True,
                        )
                        flow_timeout_warning_at = now + finish_timeout_seconds
            elif target_bytes is not None and size >= target_bytes:
                if target_reached_at is None:
                    target_reached_at = now
                    print(
                        f"Segment {segment_index}/{segment_count} target reached. "
                        "Finish the current workload; do not start the next workload yet.",
                        flush=True,
                    )
                if rate <= idle_bytes_per_second:
                    quiet_started_at = quiet_started_at or now
                else:
                    quiet_started_at = None
                if quiet_started_at is not None and now - quiet_started_at >= idle_seconds:
                    stop_reason = "target_reached_and_traffic_idle"
                    break
                if now - target_reached_at >= finish_timeout_seconds:
                    stop_reason = "target_reached_finish_timeout"
                    break

            previous_time = now
            previous_size = size
    except KeyboardInterrupt:
        print("\nStopping capture on user request...", flush=True)
    finally:
        capture_stderr = _stop_tcpdump(process)

    ended_at = datetime.now(UTC)
    final_size = pcap_path.stat().st_size if pcap_path.is_file() else 0
    final_flow_stats = flow_tracker.poll() if flow_tracker is not None else None
    target_met = (
        final_flow_stats.total_flows >= target_flows
        if final_flow_stats is not None and target_flows is not None
        else target_bytes is not None and final_size >= target_bytes
    )
    metadata = {
        "schema_version": "1.0.0",
        "sample_id": sample_id,
        "series_id": series_id,
        "segment_index": segment_index,
        "segment_count": segment_count,
        "case_id": case.id,
        "profile": profile,
        "capture": {
            "pcap": pcap_path.name,
            "interface": selected_interface,
            "bpf": capture_filter,
            "server_port": server_port,
            "start_time_utc": started_at.isoformat(),
            "end_time_utc": ended_at.isoformat(),
            "target_bytes": target_bytes,
            "target_flows": target_flows,
            "flow_count_definition": (
                "outer TCP connections beginning with SYN"
                if target_flows is not None and case.outer_transport == "tcp"
                else (
                    "bidirectionally normalized outer UDP 5-tuple conversations; "
                    "one multiplexed Hysteria2 QUIC connection may carry many inner flows"
                    if target_flows is not None
                    else None
                )
            ),
            "file_bytes": final_size,
            "target_met": target_met,
            "flow_count": (
                final_flow_stats.total_flows if final_flow_stats is not None else None
            ),
            "completed_flow_count": (
                final_flow_stats.completed_flows if final_flow_stats is not None else None
            ),
            "active_flow_count": (
                final_flow_stats.active_flows if final_flow_stats is not None else None
            ),
            "tcp_conversation_count": (
                final_flow_stats.tcp_conversations if final_flow_stats is not None else None
            ),
            "udp_conversation_count": (
                final_flow_stats.udp_conversations if final_flow_stats is not None else None
            ),
            "stop_reason": stop_reason,
            "tcpdump_log": capture_stderr[-2000:],
        },
    }
    (session_dir / "capture.json").write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(
        f"Segment {segment_index}/{segment_count} stopped: {stop_reason}; "
        f"final size {_format_bytes(final_size)}"
        + (
            f", flows {final_flow_stats.total_flows}, "
            f"active {final_flow_stats.active_flows}"
            if final_flow_stats is not None
            else ""
        )
        + "\n"
        f"PCAP: {pcap_path}",
        flush=True,
    )
    return session_dir, stop_reason


def _format_bytes(value: int) -> str:
    size = float(value)
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    for unit in units:
        if size < 1024 or unit == units[-1]:
            return f"{size:.2f} {unit}"
        size /= 1024
    raise AssertionError("unreachable")


def run_web_capture(
    *,
    case: ProtocolCase,
    server_ip: str,
    server_port: int,
    proxy_server: str,
    urls: Sequence[str],
    seed: int,
    max_duration_seconds: int,
    max_pages: int,
    output_root: Path,
    interface: str | None = None,
) -> Path:
    if not case.enabled:
        raise ConfigurationError(f"protocol case is disabled: {case.id}")
    if "tcp" not in case.inner_networks:
        raise ConfigurationError(f"web profile is not valid for {case.id}")
    _require_proxy_listener(proxy_server)
    selected_interface = interface or _route_interface(server_ip)
    capture_filter = tunnel_bpf(server_ip, server_port, case.outer_transport)

    started_at = datetime.now(UTC)
    sample_id = f"{started_at.strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:10]}"
    session_dir = output_root.expanduser().resolve() / "pilot" / case.id / sample_id
    session_dir.mkdir(parents=True, exist_ok=False)
    pcap_path = session_dir / "capture.pcap"
    traffic_log = session_dir / "traffic.jsonl"

    capture_process = _start_tcpdump(
        interface=selected_interface,
        capture_filter=capture_filter,
        output_path=pcap_path,
    )
    traffic_error: str | None = None
    result = None
    try:
        time.sleep(1)
        if capture_process.poll() is not None:
            _, stderr = capture_process.communicate(timeout=2)
            raise ConfigurationError(f"tcpdump exited before traffic started: {stderr}")
        result = generate_web_traffic(
            proxy_server=proxy_server,
            urls=urls,
            seed=seed,
            max_duration_seconds=max_duration_seconds,
            max_pages=max_pages,
        )
    except Exception as exc:
        traffic_error = f"{type(exc).__name__}: {exc}"
        raise
    finally:
        capture_stderr = _stop_tcpdump(capture_process)
        ended_at = datetime.now(UTC)
        if result is not None:
            with traffic_log.open("w", encoding="utf-8") as stream:
                for event in result.events:
                    stream.write(json.dumps(event, ensure_ascii=False) + "\n")
        _write_metadata(
            session_dir=session_dir,
            pcap_path=pcap_path,
            case=case,
            sample_id=sample_id,
            server_ip=server_ip,
            server_port=server_port,
            interface=selected_interface,
            capture_filter=capture_filter,
            started_at=started_at,
            ended_at=ended_at,
            seed=seed,
            urls=urls,
            result=result,
            capture_stderr=capture_stderr,
            traffic_error=traffic_error,
        )
    return session_dir


def _start_tcpdump(
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


def _ensure_sudo_credentials() -> None:
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


def _stop_tcpdump(process: subprocess.Popen[str]) -> str:
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


def _route_interface(server_ip: str) -> str:
    result = run_command(["ip", "route", "get", server_ip], timeout_seconds=10)
    if result.returncode != 0:
        raise ConfigurationError(f"cannot determine capture interface: {result.stderr}")
    match = re.search(r"(?:^|\s)dev\s+(\S+)", result.stdout)
    if not match:
        raise ConfigurationError("route lookup did not return an interface")
    return match.group(1)


def _require_proxy_listener(proxy_server: str) -> None:
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


def _write_metadata(
    *,
    session_dir: Path,
    pcap_path: Path,
    case: ProtocolCase,
    sample_id: str,
    server_ip: str,
    server_port: int,
    interface: str,
    capture_filter: str,
    started_at: datetime,
    ended_at: datetime,
    seed: int,
    urls: Sequence[str],
    result: Any,
    capture_stderr: str,
    traffic_error: str | None,
) -> None:
    pcap_size = pcap_path.stat().st_size if pcap_path.is_file() else 0
    packet_count = _packet_count(pcap_path) if pcap_size else 0
    pcap_sha256 = _sha256(pcap_path) if pcap_size else None
    successful_pages = result.successful_pages if result is not None else 0
    validation_status = (
        "passed" if pcap_size > 24 and packet_count > 0 and successful_pages > 0 else "failed"
    )
    metadata = {
        "schema_version": "1.0.0",
        "sample_id": sample_id,
        "label": {
            "dataset_class": case.dataset_class,
            "case_id": case.id,
            "proxy_protocol": case.protocol,
            "outer_transport": case.outer_transport,
            "transport_wrapper": case.wrapper,
            "security": case.security,
            "flow": case.flow,
            "inner_network": "tcp",
            "application_profile": "web",
        },
        "capture": {
            "side": "client",
            "interface": interface,
            "bpf": capture_filter,
            "server_ip_sha256": hashlib.sha256(server_ip.encode()).hexdigest(),
            "server_port": server_port,
            "format": "pcap",
            "snaplen": 0,
            "start_time_utc": started_at.isoformat(),
            "end_time_utc": ended_at.isoformat(),
            "packet_count": packet_count,
            "file_bytes": pcap_size,
            "pcap_sha256": pcap_sha256,
        },
        "traffic": {
            "generator": "playwright",
            "browser": "chromium",
            "profile": "web",
            "seed": seed,
            "urls": list(urls),
            "attempted_pages": result.attempted_pages if result is not None else 0,
            "successful_pages": successful_pages,
        },
        "validation": {
            "status": validation_status,
            "proxy_connectivity": traffic_error is None,
            "traffic_error": traffic_error,
            "capture_log": capture_stderr[-2000:],
            "notes": [
                "pilot capture; full unexpected-destination audit is not implemented yet"
            ],
        },
    }
    metadata_path = session_dir / "metadata.json"
    metadata_path.write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    manifest_path = session_dir / "manifest.sha256"
    lines = []
    for path in (pcap_path, metadata_path, session_dir / "traffic.jsonl"):
        if path.is_file():
            lines.append(f"{_sha256(path)}  {path.name}")
    manifest_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _packet_count(path: Path) -> int:
    result = run_command(["capinfos", "-c", str(path)], timeout_seconds=30)
    if result.returncode != 0:
        return 0
    match = re.search(r"Number of packets:\s+([0-9,]+)", result.stdout)
    return int(match.group(1).replace(",", "")) if match else 0


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
