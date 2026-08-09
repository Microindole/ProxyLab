from __future__ import annotations

import json
from pathlib import Path

from proxy_traffic_lab.common.process import CommandResult
from proxy_traffic_lab.dataset import audit


def _session(tmp_path: Path) -> Path:
    session = tmp_path / "sample"
    session.mkdir()
    (session / "capture.pcap").write_bytes(b"pcap" + b"\x00" * 64)
    (session / "capture.json").write_text(
        json.dumps(
            {
                "case_id": "class-01-shadowsocks-2022-tcp",
                "capture": {
                    "pcap": "capture.pcap",
                    "bpf": "host 203.0.113.10 and tcp port 24443",
                    "server_port": 24443,
                    "file_bytes": 68,
                    "target_flows": 2,
                    "flow_count": 2,
                    "completed_flow_count": 2,
                    "active_flow_count": 0,
                    "stop_reason": "target_flows_reached_and_all_flows_closed",
                    "tcpdump_log": "2 packets captured\n0 packets dropped by kernel",
                },
            }
        ),
        encoding="utf-8",
    )
    return session


def test_audit_accepts_expected_complete_tunnel(tmp_path: Path, monkeypatch) -> None:
    session = _session(tmp_path)

    def fake_run(args, **_kwargs):
        stdout = "Number of packets: 2" if args[0] == "capinfos" else ""
        return CommandResult(tuple(args), 0, stdout, "")

    monkeypatch.setattr(audit, "run_command", fake_run)
    report = audit.audit_session(session, server_ip="203.0.113.10")

    assert report.passed is True
    assert report.metrics["unexpected_packet_count"] == 0
    assert report.checks["tcp_flows_closed"] is True
    assert report.checks["no_kernel_drops"] is True


def test_audit_rejects_unexpected_packets(tmp_path: Path, monkeypatch) -> None:
    session = _session(tmp_path)

    def fake_run(args, **_kwargs):
        stdout = "Number of packets: 2" if args[0] == "capinfos" else "9\n12"
        return CommandResult(tuple(args), 0, stdout, "")

    monkeypatch.setattr(audit, "run_command", fake_run)
    report = audit.audit_session(session, server_ip="203.0.113.10")

    assert report.passed is False
    assert report.metrics["unexpected_packet_count"] == 2
    assert report.checks["expected_tunnel_only"] is False

