"""Capture and drain one formal proxy-tunnel PCAP segment."""

from __future__ import annotations

import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

from proxy_traffic_lab.capture.flow_tracker import PcapL4ConversationTracker, PcapTcpFlowTracker
from proxy_traffic_lab.capture.formatting import format_bytes
from proxy_traffic_lab.capture.tcpdump import ensure_sudo_credentials, start_tcpdump, stop_tcpdump
from proxy_traffic_lab.common.errors import ConfigurationError
from proxy_traffic_lab.configuration.models import ProtocolCase
from proxy_traffic_lab.dataset.records import write_segment_record

_SUDO_REFRESH_INTERVAL_SECONDS = 60.0


def capture_segment(
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

    process = start_tcpdump(
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
        else format_bytes(target_bytes or 0)
    )
    print(
        f"READY segment {segment_index}/{segment_count}: {profile}\n"
        f"Capturing {case.id} on {selected_interface} to {pcap_path}\n"
        f"Target: {target_text}; after target, do not start new work. "
        "The capture will wait for active flows to close and traffic to stay at or below "
        f"{format_bytes(int(idle_bytes_per_second))}/s for {idle_seconds:g}s. "
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
                    ensure_sudo_credentials()
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
                    f"pcap {format_bytes(size)}, rate {format_bytes(int(rate))}/s",
                    flush=True,
                )
            else:
                assert target_bytes is not None
                percent = min(size / target_bytes * 100, 100.0)
                phase = "WAITING_FOR_IDLE" if size >= target_bytes else "CAPTURING"
                overshoot = max(size - target_bytes, 0)
                overshoot_text = (
                    f", overshoot {format_bytes(overshoot)}" if overshoot else ""
                )
                print(
                    f"[segment {segment_index}/{segment_count} {phase} "
                    f"{datetime.now(UTC).strftime('%H:%M:%S')}Z] "
                    f"{format_bytes(size)} / {format_bytes(target_bytes)} "
                    f"({percent:5.1f}%){overshoot_text}, "
                    f"current rate {format_bytes(int(rate))}/s",
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
        capture_stderr = stop_tcpdump(process)

    ended_at = datetime.now(UTC)
    final_size = pcap_path.stat().st_size if pcap_path.is_file() else 0
    final_flow_stats = flow_tracker.poll() if flow_tracker is not None else None
    target_met = (
        final_flow_stats.total_flows >= target_flows
        if final_flow_stats is not None and target_flows is not None
        else target_bytes is not None and final_size >= target_bytes
    )
    write_segment_record(
        session_dir=session_dir,
        pcap_path=pcap_path,
        case=case,
        sample_id=sample_id,
        series_id=series_id,
        segment_index=segment_index,
        segment_count=segment_count,
        profile=profile,
        interface=selected_interface,
        capture_filter=capture_filter,
        server_port=server_port,
        started_at=started_at,
        ended_at=ended_at,
        target_bytes=target_bytes,
        target_flows=target_flows,
        final_size=final_size,
        target_met=target_met,
        flow_stats=final_flow_stats,
        stop_reason=stop_reason,
        capture_stderr=capture_stderr,
    )
    print(
        f"Segment {segment_index}/{segment_count} stopped: {stop_reason}; "
        f"final size {format_bytes(final_size)}"
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
