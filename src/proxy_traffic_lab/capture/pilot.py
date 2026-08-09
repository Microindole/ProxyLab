"""Orchestrate one small workload capture used for connectivity and purity pilots."""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from proxy_traffic_lab.capture.filters import tunnel_bpf
from proxy_traffic_lab.capture.tcpdump import (
    require_proxy_listener,
    route_interface,
    start_tcpdump,
    stop_tcpdump,
)
from proxy_traffic_lab.common.errors import ConfigurationError
from proxy_traffic_lab.configuration.models import ProtocolCase
from proxy_traffic_lab.dataset.records import write_pilot_record, write_traffic_events
from proxy_traffic_lab.traffic.models import WorkloadResult
from proxy_traffic_lab.traffic.registry import resolve_workload


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
    _require_enabled(case)
    workload = resolve_workload("web", case)
    return _run_workload_capture(
        case=case,
        server_ip=server_ip,
        server_port=server_port,
        proxy_server=proxy_server,
        seed=seed,
        output_root=output_root,
        interface=interface,
        workload_name=workload.name,
        inner_network=workload.inner_network,
        traffic_details={"browser": "chromium", "urls": list(urls)},
        run=lambda: workload.runner(
            proxy_server=proxy_server,
            urls=urls,
            seed=seed,
            max_duration_seconds=max_duration_seconds,
            max_pages=max_pages,
        ),
    )


def run_udp_capture(
    *,
    case: ProtocolCase,
    server_ip: str,
    server_port: int,
    proxy_server: str,
    target_host: str,
    target_port: int,
    seed: int,
    count: int,
    payload_bytes: int,
    timeout_seconds: float,
    interval_seconds: float,
    output_root: Path,
    interface: str | None = None,
) -> Path:
    _require_enabled(case)
    workload = resolve_workload("udp", case)
    return _run_workload_capture(
        case=case,
        server_ip=server_ip,
        server_port=server_port,
        proxy_server=proxy_server,
        seed=seed,
        output_root=output_root,
        interface=interface,
        workload_name=workload.name,
        inner_network=workload.inner_network,
        traffic_details={
            "target_host": target_host,
            "target_port": target_port,
            "payload_bytes": payload_bytes,
        },
        run=lambda: workload.runner(
            proxy_server=proxy_server,
            target_host=target_host,
            target_port=target_port,
            seed=seed,
            count=count,
            payload_bytes=payload_bytes,
            timeout_seconds=timeout_seconds,
            interval_seconds=interval_seconds,
        ),
    )


def _run_workload_capture(
    *,
    case: ProtocolCase,
    server_ip: str,
    server_port: int,
    proxy_server: str,
    seed: int,
    output_root: Path,
    interface: str | None,
    workload_name: str,
    inner_network: str,
    traffic_details: dict[str, Any],
    run: Callable[[], WorkloadResult],
) -> Path:
    require_proxy_listener(proxy_server)
    selected_interface = interface or route_interface(server_ip)
    capture_filter = tunnel_bpf(server_ip, server_port, case.outer_transport)
    started_at = datetime.now(UTC)
    sample_id = f"{started_at.strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:10]}"
    session_dir = output_root.expanduser().resolve() / "pilot" / case.id / sample_id
    session_dir.mkdir(parents=True, exist_ok=False)
    pcap_path = session_dir / "capture.pcap"
    traffic_log = session_dir / "traffic.jsonl"
    capture_process = start_tcpdump(
        interface=selected_interface,
        capture_filter=capture_filter,
        output_path=pcap_path,
    )
    traffic_error: str | None = None
    result: WorkloadResult | None = None
    try:
        time.sleep(1)
        if capture_process.poll() is not None:
            _, stderr = capture_process.communicate(timeout=2)
            raise ConfigurationError(f"tcpdump exited before traffic started: {stderr}")
        result = run()
        if result.successful == 0:
            raise ConfigurationError(f"{workload_name} workload produced no successful events")
    except Exception as exc:
        traffic_error = f"{type(exc).__name__}: {exc}"
        raise
    finally:
        capture_stderr = stop_tcpdump(capture_process)
        ended_at = datetime.now(UTC)
        if result is not None:
            write_traffic_events(traffic_log, result)
        write_pilot_record(
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
            workload_name=workload_name,
            inner_network=inner_network,
            traffic_details=traffic_details,
            result=result,
            capture_stderr=capture_stderr,
            traffic_error=traffic_error,
        )
    return session_dir


def _require_enabled(case: ProtocolCase) -> None:
    if not case.enabled:
        raise ConfigurationError(f"protocol case is disabled: {case.id}")
