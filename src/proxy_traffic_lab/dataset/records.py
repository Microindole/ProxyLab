"""Serialize capture metadata, traffic events, and integrity manifests."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

from proxy_traffic_lab.common.process import run_command
from proxy_traffic_lab.configuration.models import ProtocolCase
from proxy_traffic_lab.traffic.models import WorkloadResult


class FlowStatsView(Protocol):
    total_flows: int
    completed_flows: int
    active_flows: int
    tcp_conversations: int
    udp_conversations: int


def write_segment_record(
    *,
    session_dir: Path,
    pcap_path: Path,
    case: ProtocolCase,
    sample_id: str,
    series_id: str,
    segment_index: int,
    segment_count: int,
    profile: str,
    interface: str,
    capture_filter: str,
    server_port: int,
    started_at: datetime,
    ended_at: datetime,
    target_bytes: int | None,
    target_flows: int | None,
    final_size: int,
    target_met: bool,
    flow_stats: FlowStatsView | None,
    stop_reason: str,
    capture_stderr: str,
) -> None:
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
            "interface": interface,
            "bpf": capture_filter,
            "server_port": server_port,
            "start_time_utc": started_at.isoformat(),
            "end_time_utc": ended_at.isoformat(),
            "target_bytes": target_bytes,
            "target_flows": target_flows,
            "flow_count_definition": _flow_count_definition(case, target_flows),
            "file_bytes": final_size,
            "target_met": target_met,
            "flow_count": flow_stats.total_flows if flow_stats else None,
            "completed_flow_count": flow_stats.completed_flows if flow_stats else None,
            "active_flow_count": flow_stats.active_flows if flow_stats else None,
            "tcp_conversation_count": flow_stats.tcp_conversations if flow_stats else None,
            "udp_conversation_count": flow_stats.udp_conversations if flow_stats else None,
            "stop_reason": stop_reason,
            "tcpdump_log": capture_stderr[-2000:],
        },
    }
    (session_dir / "capture.json").write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def _flow_count_definition(case: ProtocolCase, target_flows: int | None) -> str | None:
    if target_flows is None:
        return None
    if case.outer_transport == "tcp":
        return "outer TCP connections beginning with SYN"
    return (
        "bidirectionally normalized outer UDP 5-tuple conversations; "
        "one multiplexed Hysteria2 QUIC connection may carry many inner flows"
    )


def write_pilot_record(
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
    workload_name: str,
    inner_network: str,
    traffic_details: dict[str, Any],
    result: WorkloadResult | None,
    capture_stderr: str,
    traffic_error: str | None,
) -> None:
    pcap_size = pcap_path.stat().st_size if pcap_path.is_file() else 0
    packets = packet_count(pcap_path) if pcap_size else 0
    pcap_sha256 = sha256_file(pcap_path) if pcap_size else None
    successful = result.successful if result is not None else 0
    validation_status = (
        "passed" if pcap_size > 24 and packets > 0 and successful > 0 else "failed"
    )
    metadata = {
        "schema_version": "1.0.0",
        "sample_id": sample_id,
        "label": {
            "dataset_class": case.dataset_class,
            "case_id": case.id,
            "proxy_protocol": case.protocol,
            "outer_transport": case.outer_transport,
            "transport_wrapper": case.transport,
            "security": case.encryption,
            "flow": case.parameter("flow"),
            "inner_network": inner_network,
            "application_profile": workload_name,
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
            "packet_count": packets,
            "file_bytes": pcap_size,
            "pcap_sha256": pcap_sha256,
        },
        "traffic": {
            "generator": workload_name,
            "profile": workload_name,
            "seed": seed,
            **traffic_details,
            "attempted": result.attempted if result is not None else 0,
            "successful": successful,
        },
        "validation": {
            "status": validation_status,
            "proxy_connectivity": traffic_error is None,
            "traffic_error": traffic_error,
            "capture_log": capture_stderr[-2000:],
            "notes": ["pilot capture; run `lab dataset audit` before accepting it"],
        },
    }
    metadata_path = session_dir / "metadata.json"
    metadata_path.write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    manifest_path = session_dir / "manifest.sha256"
    paths = (pcap_path, metadata_path, session_dir / "traffic.jsonl")
    lines = [f"{sha256_file(path)}  {path.name}" for path in paths if path.is_file()]
    manifest_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_traffic_events(path: Path, result: WorkloadResult) -> None:
    with path.open("w", encoding="utf-8") as stream:
        for event in result.events:
            stream.write(json.dumps(event, ensure_ascii=False) + "\n")


def packet_count(path: Path) -> int:
    result = run_command(["capinfos", "-c", str(path)], timeout_seconds=30)
    if result.returncode != 0:
        return 0
    match = re.search(r"Number of packets:\s+([0-9,]+)", result.stdout)
    return int(match.group(1).replace(",", "")) if match else 0


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
