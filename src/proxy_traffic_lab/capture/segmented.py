"""Rotate formal proxy-tunnel capture segments at clean flow boundaries."""

from __future__ import annotations

import re
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from proxy_traffic_lab.capture.filters import tunnel_bpf
from proxy_traffic_lab.capture.segment import capture_segment
from proxy_traffic_lab.capture.tcpdump import (
    ensure_sudo_credentials,
    route_interface,
)
from proxy_traffic_lab.common.errors import ConfigurationError
from proxy_traffic_lab.configuration.models import ProtocolCase


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

    selected_interface = interface or route_interface(server_ip)
    capture_filter = tunnel_bpf(server_ip, server_port, case.outer_transport)
    series_started_at = datetime.now(UTC)
    series_id = (
        f"{series_started_at.strftime('%Y%m%dT%H%M%SZ')}-"
        f"{uuid.uuid4().hex[:10]}"
    )
    sessions: list[Path] = []
    segment_count = len(profiles)

    for segment_index, profile in enumerate(profiles, start=1):
        ensure_sudo_credentials()
        if segment_index > 1:
            print(
                f"Starting segment {segment_index}/{segment_count}: {profile}. "
                "Wait for the READY message before beginning the next workload.",
                flush=True,
            )
        session_dir, stop_reason = capture_segment(
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
