from pathlib import Path
from types import SimpleNamespace

from proxy_traffic_lab.capture import experiment
from proxy_traffic_lab.capture.experiment import _format_bytes
from proxy_traffic_lab.controller.cli import build_parser


def test_format_bytes_uses_binary_units() -> None:
    assert _format_bytes(1024**3) == "1.00 GiB"
    assert _format_bytes(32 * 1024) == "32.00 KiB"


def test_capture_run_defaults_to_one_gib() -> None:
    args = build_parser().parse_args(
        [
            "capture",
            "run",
            "--case",
            "class-05-vmess-websocket-tls",
            "--server-ip",
            "203.0.113.10",
            "--server-port",
            "24443",
        ]
    )
    assert args.target_gib == 1.0
    assert args.idle_seconds == 15.0
    assert args.idle_kib_per_second == 32.0


def test_capture_run_accepts_repeated_profiles() -> None:
    args = build_parser().parse_args(
        [
            "capture",
            "run",
            "--case",
            "class-05-vmess-websocket-tls",
            "--server-ip",
            "203.0.113.10",
            "--server-port",
            "24443",
            "--profile",
            "large-download",
            "--profile",
            "video",
        ]
    )
    assert args.profiles == ["large-download", "video"]


def test_capture_run_accepts_flow_limits() -> None:
    args = build_parser().parse_args(
        [
            "capture",
            "run",
            "--case",
            "class-05-vmess-websocket-tls",
            "--server-ip",
            "203.0.113.10",
            "--server-port",
            "24443",
            "--target-flows",
            "3000",
        ]
    )
    assert args.target_flows == 3000


def test_segmented_capture_rotates_only_after_idle(monkeypatch) -> None:
    calls: list[str] = []
    sudo_refreshes: list[None] = []

    def fake_segment(**kwargs):
        calls.append(kwargs["profile"])
        return Path(f"/{kwargs['profile']}"), "target_reached_and_traffic_idle"

    monkeypatch.setattr(experiment, "_capture_size_segment", fake_segment)
    monkeypatch.setattr(
        experiment,
        "_ensure_sudo_credentials",
        lambda: sudo_refreshes.append(None),
    )
    case = SimpleNamespace(enabled=True, id="case-05", outer_transport="tcp")
    sessions = experiment.run_segmented_capture(
        case=case,
        server_ip="203.0.113.10",
        server_port=24443,
        target_bytes=1024,
        output_root=Path("/data"),
        profiles=("download", "video"),
        interface="eth0",
    )
    assert calls == ["download", "video"]
    assert len(sudo_refreshes) == 2
    assert sessions == (Path("/download"), Path("/video"))


def test_segmented_capture_does_not_split_an_active_flow(monkeypatch) -> None:
    calls: list[str] = []

    def fake_segment(**kwargs):
        calls.append(kwargs["profile"])
        return Path(f"/{kwargs['profile']}"), "target_reached_finish_timeout"

    monkeypatch.setattr(experiment, "_capture_size_segment", fake_segment)
    monkeypatch.setattr(experiment, "_ensure_sudo_credentials", lambda: None)
    case = SimpleNamespace(enabled=True, id="case-05", outer_transport="tcp")
    sessions = experiment.run_segmented_capture(
        case=case,
        server_ip="203.0.113.10",
        server_port=24443,
        target_bytes=1024,
        output_root=Path("/data"),
        profiles=("download", "video"),
        interface="eth0",
    )
    assert calls == ["download"]
    assert sessions == (Path("/download"),)
