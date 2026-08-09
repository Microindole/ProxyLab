from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from proxy_traffic_lab.common.errors import ConfigurationError
from proxy_traffic_lab.common.process import run_command
from proxy_traffic_lab.capture.filters import tunnel_bpf
from proxy_traffic_lab.configuration.loader import find_protocol_case


@dataclass
class AuditReport:
    session: str
    pcap: str
    case_id: str
    passed: bool = True
    checks: dict[str, bool] = field(default_factory=dict)
    metrics: dict[str, int | str | bool | None] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def check(self, name: str, passed: bool, error: str) -> None:
        self.checks[name] = passed
        if not passed:
            self.passed = False
            self.errors.append(error)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def audit_session(
    session_dir: Path,
    *,
    server_ip: str,
    matrix_path: Path | None = None,
) -> AuditReport:
    session = session_dir.expanduser().resolve()
    if not session.is_dir():
        raise ConfigurationError(f"dataset session directory does not exist: {session}")
    supplied_address = server_ip.strip()
    address = ipaddress.ip_address(supplied_address).compressed
    metadata_path, metadata = _load_metadata(session)
    case_id = _case_id(metadata)
    case = find_protocol_case(case_id, matrix_path)
    capture = _capture_section(metadata)
    pcap_name = str(capture.get("pcap") or "capture.pcap")
    pcap_path = (session / pcap_name).resolve()
    if pcap_path.parent != session:
        raise ConfigurationError("capture metadata points outside the session directory")
    report = AuditReport(
        session=str(session),
        pcap=str(pcap_path),
        case_id=case_id,
    )

    report.check("pcap_exists", pcap_path.is_file(), f"PCAP is missing: {pcap_path}")
    if not pcap_path.is_file():
        return report
    size = pcap_path.stat().st_size
    report.metrics["file_bytes"] = size
    report.check("pcap_nonempty", size > 24, "PCAP contains no packet records")

    metadata_size = capture.get("file_bytes")
    if isinstance(metadata_size, int):
        report.check(
            "metadata_file_size",
            metadata_size == size,
            f"metadata file_bytes={metadata_size}, actual={size}",
        )

    digest = _sha256(pcap_path)
    report.metrics["sha256"] = digest
    expected_digest = capture.get("pcap_sha256") or capture.get("sha256")
    if isinstance(expected_digest, str):
        report.check(
            "metadata_sha256",
            expected_digest == digest,
            "PCAP SHA-256 does not match metadata",
        )
    _audit_manifest(session, report)
    if size <= 24:
        return report

    expected_hash = capture.get("server_ip_sha256")
    if isinstance(expected_hash, str):
        report.check(
            "server_ip_hash",
            expected_hash
            in {
                hashlib.sha256(supplied_address.encode()).hexdigest(),
                hashlib.sha256(address.encode()).hexdigest(),
            },
            "supplied server IP does not match the hashed metadata value",
        )

    server_port = capture.get("server_port")
    if not isinstance(server_port, int) or not 1 <= server_port <= 65535:
        report.check("server_port", False, "metadata has no valid server_port")
        return report
    report.metrics["server_port"] = server_port
    report.metrics["outer_transport"] = case.outer_transport
    report.check(
        "capture_filter",
        _bpf_matches(capture.get("bpf"), address, server_port, case.outer_transport),
        "capture BPF does not match the selected server, port and outer transport",
    )

    packet_count = _capinfos_packet_count(pcap_path)
    report.metrics["packet_count"] = packet_count
    report.check("pcap_readable", packet_count > 0, "capinfos could not read packets from PCAP")
    unexpected = _unexpected_packet_count(
        pcap_path,
        server_ip=address,
        server_port=server_port,
        transport=case.outer_transport,
    )
    report.metrics["unexpected_packet_count"] = unexpected
    report.check(
        "expected_tunnel_only",
        unexpected == 0,
        f"PCAP contains {unexpected} packet(s) outside the expected tunnel tuple",
    )
    _audit_capture_completion(capture, case.outer_transport, report)
    validation = metadata.get("validation")
    capture_log = validation.get("capture_log") if isinstance(validation, dict) else None
    _audit_drop_log(capture, report, fallback_log=capture_log)
    _audit_workload(metadata, report)
    report.metrics["metadata_file"] = metadata_path.name
    return report


def _load_metadata(session: Path) -> tuple[Path, dict[str, Any]]:
    for name in ("capture.json", "metadata.json"):
        path = session / name
        if path.is_file():
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise ConfigurationError(f"cannot read dataset metadata {path}: {exc}") from exc
            if not isinstance(value, dict):
                raise ConfigurationError(f"dataset metadata must be an object: {path}")
            return path, value
    raise ConfigurationError(f"capture.json or metadata.json is required in {session}")


def _case_id(metadata: dict[str, Any]) -> str:
    value = metadata.get("case_id")
    if not isinstance(value, str):
        label = metadata.get("label")
        value = label.get("case_id") if isinstance(label, dict) else None
    if not isinstance(value, str) or not value:
        raise ConfigurationError("dataset metadata has no case_id")
    return value


def _capture_section(metadata: dict[str, Any]) -> dict[str, Any]:
    value = metadata.get("capture")
    if not isinstance(value, dict):
        raise ConfigurationError("dataset metadata has no capture object")
    return value


def _audit_manifest(session: Path, report: AuditReport) -> None:
    manifest = session / "manifest.sha256"
    if not manifest.is_file():
        report.warnings.append("manifest.sha256 is absent")
        return
    valid = True
    for line in manifest.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([^/\\]+)", line)
        if not match:
            valid = False
            continue
        expected, name = match.groups()
        path = session / name
        if not path.is_file() or _sha256(path) != expected:
            valid = False
    report.check("manifest_sha256", valid, "manifest.sha256 is invalid or stale")


def _capinfos_packet_count(path: Path) -> int:
    result = run_command(["capinfos", "-c", str(path)], timeout_seconds=120)
    if result.returncode != 0:
        return 0
    match = re.search(r"Number of packets:\s+([0-9,]+)", result.stdout)
    return int(match.group(1).replace(",", "")) if match else 0


def _unexpected_packet_count(
    path: Path,
    *,
    server_ip: str,
    server_port: int,
    transport: str,
) -> int:
    address_field = "ipv6.addr" if ipaddress.ip_address(server_ip).version == 6 else "ip.addr"
    display_filter = (
        f"not ({address_field} == {server_ip} and {transport}.port == {server_port})"
    )
    result = run_command(
        [
            "tshark",
            "-r",
            str(path),
            "-n",
            "-Y",
            display_filter,
            "-T",
            "fields",
            "-e",
            "frame.number",
        ],
        timeout_seconds=600,
    )
    if result.returncode != 0:
        raise ConfigurationError(f"tshark audit failed: {result.stderr or result.stdout}")
    return len(result.stdout.splitlines()) if result.stdout else 0


def _bpf_matches(value: object, server_ip: str, port: int, transport: str) -> bool:
    if not isinstance(value, str):
        return False
    normalized = " ".join(value.lower().split())
    expected = " ".join(tunnel_bpf(server_ip, port, transport).lower().split())
    return normalized == expected


def _audit_capture_completion(
    capture: dict[str, Any], transport: str, report: AuditReport
) -> None:
    target_flows = capture.get("target_flows")
    if not isinstance(target_flows, int):
        target_met = capture.get("target_met")
        if isinstance(target_met, bool):
            report.check("capture_target_met", target_met, "capture target was not met")
        return
    flow_count = capture.get("flow_count")
    report.check(
        "flow_target",
        isinstance(flow_count, int) and flow_count >= target_flows,
        f"flow_count={flow_count} is below target_flows={target_flows}",
    )
    if transport == "tcp":
        active = capture.get("active_flow_count")
        completed = capture.get("completed_flow_count")
        report.check(
            "tcp_flows_closed",
            active == 0 and completed == flow_count,
            f"TCP boundary incomplete: active={active}, completed={completed}, total={flow_count}",
        )
        report.check(
            "stop_reason",
            capture.get("stop_reason") == "target_flows_reached_and_all_flows_closed",
            f"unexpected TCP stop reason: {capture.get('stop_reason')}",
        )
    else:
        report.check(
            "stop_reason",
            capture.get("stop_reason")
            == "target_udp_conversations_reached_and_traffic_idle",
            f"unexpected UDP stop reason: {capture.get('stop_reason')}",
        )


def _audit_drop_log(
    capture: dict[str, Any], report: AuditReport, *, fallback_log: object = None
) -> None:
    log = capture.get("tcpdump_log") or capture.get("capture_log") or fallback_log
    if not isinstance(log, str):
        report.warnings.append("capture log is absent; packet drops cannot be verified")
        return
    match = re.search(r"(\d+) packets dropped by kernel", log)
    if not match:
        report.warnings.append("capture log has no kernel drop counter")
        return
    dropped = int(match.group(1))
    report.metrics["dropped_packets"] = dropped
    report.check("no_kernel_drops", dropped == 0, f"capture dropped {dropped} packet(s)")


def _audit_workload(metadata: dict[str, Any], report: AuditReport) -> None:
    validation = metadata.get("validation")
    if isinstance(validation, dict) and "status" in validation:
        report.check(
            "pilot_validation",
            validation.get("status") == "passed",
            f"pilot metadata validation status is {validation.get('status')}",
        )
    traffic = metadata.get("traffic")
    if not isinstance(traffic, dict):
        return
    successful = traffic.get("successful", traffic.get("successful_pages"))
    if isinstance(successful, int):
        report.metrics["successful_workload_events"] = successful
        report.check(
            "workload_success",
            successful > 0,
            "workload produced no successful events",
        )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
