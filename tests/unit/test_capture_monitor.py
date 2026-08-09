import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from proxy_traffic_lab.capture import experiment
from proxy_traffic_lab.capture import windows as capture_windows
from proxy_traffic_lab.capture.experiment import _format_bytes
from proxy_traffic_lab.cli.app import build_parser


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


def test_capture_windows_ipv6_parser() -> None:
    args = build_parser().parse_args(
        [
            "capture",
            "windows-ipv6",
            "--interface",
            "5",
            "--target-flows",
            "3000",
            "--ip-version",
            "mixed",
            "--profile",
            "text-01",
            "--profile",
            "text-02",
            "--start-chrome",
        ]
    )
    assert args.capture_command == "windows-ipv6"
    assert args.interface == "5"
    assert args.target_flows == 3000
    assert args.ip_version == "mixed"
    assert args.flow_count_mode == "auto"
    assert args.profiles == ["text-01", "text-02"]
    assert args.start_chrome is True


def test_windows_plain_auto_uses_conversations_for_video_only() -> None:
    assert (
        capture_windows._resolve_windows_plain_flow_count_mode(
            profile="video-bilibili-01",
            requested_mode="auto",
        )
        == "conversation-5tuple"
    )
    assert (
        capture_windows._resolve_windows_plain_flow_count_mode(
            profile="text-ai-kimi-01",
            requested_mode="auto",
        )
        == "established"
    )
    assert (
        capture_windows._resolve_windows_plain_flow_count_mode(
            profile="video-bilibili-01",
            requested_mode="syn",
        )
        == "syn"
    )


def test_windows_capture_helper_paths_follow_project_root() -> None:
    root = Path(__file__).resolve().parents[2]
    assert capture_windows._windows_helper_script("capture.ps1") == (
        root / "scripts" / "windows" / "capture.ps1"
    )
    assert capture_windows._windows_helper_script("browser.ps1") == (
        root / "scripts" / "windows" / "browser.ps1"
    )
    assert capture_windows._windows_helper_script("isolate.ps1") == (
        root / "scripts" / "windows" / "isolate.ps1"
    )


def test_windows_progress_bar_uses_unicode_blocks() -> None:
    assert capture_windows._progress_bar(value=1, total=2, width=4) == "██░░"


def test_windows_isolation_enable_registers_capture_owner(monkeypatch) -> None:
    commands: list[list[str]] = []

    monkeypatch.setattr(
        capture_windows,
        "_windows_helper_script",
        lambda _name: Path("E:/works/ProxyLab/scripts/windows/isolate.ps1"),
    )
    monkeypatch.setattr(capture_windows, "_wslpath_to_windows", str)
    monkeypatch.setattr(capture_windows.os, "getpid", lambda: 4242)
    monkeypatch.setattr(
        capture_windows.subprocess,
        "run",
        lambda command, **_kwargs: (
            commands.append(command) or subprocess.CompletedProcess(command, 0)
        ),
    )

    capture_windows._set_windows_chrome_network_isolation(enable=True)

    assert commands[0][-4:] == ["-Action", "Enable", "-OwnerProcessId", "4242"]


def test_windows_isolation_disable_does_not_claim_a_new_owner(monkeypatch) -> None:
    commands: list[list[str]] = []

    monkeypatch.setattr(
        capture_windows,
        "_windows_helper_script",
        lambda _name: Path("E:/works/ProxyLab/scripts/windows/isolate.ps1"),
    )
    monkeypatch.setattr(capture_windows, "_wslpath_to_windows", str)
    monkeypatch.setattr(
        capture_windows.subprocess,
        "run",
        lambda command, **_kwargs: (
            commands.append(command) or subprocess.CompletedProcess(command, 0)
        ),
    )

    capture_windows._set_windows_chrome_network_isolation(enable=False)

    assert commands[0][-2:] == ["-Action", "Disable"]


def test_windows_capture_restores_isolation_after_capture_failure(monkeypatch) -> None:
    isolation_calls: list[bool] = []

    monkeypatch.setattr(
        capture_windows,
        "_find_windows_dumpcap_for_wsl",
        lambda: Path("dumpcap.exe"),
    )
    monkeypatch.setattr(
        capture_windows,
        "_set_windows_chrome_network_isolation",
        lambda *, enable: isolation_calls.append(enable),
    )
    monkeypatch.setattr(
        capture_windows,
        "_capture_windows_ipv6_flow_segment",
        lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("capture failed")),
    )

    with pytest.raises(RuntimeError, match="capture failed"):
        capture_windows._run_windows_ipv6_flow_capture(
            interface="4",
            ip_version="mixed",
            flow_count_mode="established",
            target_flows=1500,
            output_root=Path("/data"),
            profiles=("one",),
            start_chrome=False,
            start_url="about:blank",
            disable_quic=True,
            isolate_chrome_network=True,
            progress_interval_seconds=2,
            idle_seconds=15,
            idle_bytes_per_second=32 * 1024,
            finish_timeout_seconds=300,
            case_id="plain-mixed-test",
        )

    assert isolation_calls == [True, False]


def test_windows_plain_capture_continues_after_traffic_idle(monkeypatch) -> None:
    calls: list[str] = []

    def fake_segment(**kwargs):
        calls.append(kwargs["profile"])
        return Path(f"/{kwargs['profile']}"), "target_flows_reached_and_traffic_idle"

    monkeypatch.setattr(
        capture_windows,
        "_find_windows_dumpcap_for_wsl",
        lambda: Path("dumpcap.exe"),
    )
    monkeypatch.setattr(
        capture_windows,
        "_capture_windows_ipv6_flow_segment",
        fake_segment,
    )
    sessions = capture_windows._run_windows_ipv6_flow_capture(
        interface="4",
        ip_version="mixed",
        flow_count_mode="established",
        target_flows=1500,
        output_root=Path("/data"),
        profiles=("one", "two"),
        start_chrome=False,
        start_url="about:blank",
        disable_quic=True,
        isolate_chrome_network=False,
        progress_interval_seconds=2,
        idle_seconds=15,
        idle_bytes_per_second=32 * 1024,
        finish_timeout_seconds=300,
        case_id="plain-mixed-test",
    )

    assert calls == ["one", "two"]
    assert sessions == (Path("/one"), Path("/two"))


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


def test_segmented_capture_accepts_udp_conversation_targets(monkeypatch) -> None:
    calls: list[str] = []

    def fake_segment(**kwargs):
        calls.append(kwargs["profile"])
        return Path(f"/{kwargs['profile']}"), "target_udp_conversations_reached_and_traffic_idle"

    monkeypatch.setattr(experiment, "_capture_size_segment", fake_segment)
    monkeypatch.setattr(experiment, "_ensure_sudo_credentials", lambda: None)
    case = SimpleNamespace(enabled=True, id="class-11", outer_transport="udp")
    sessions = experiment.run_segmented_capture(
        case=case,
        server_ip="203.0.113.10",
        server_port=24443,
        target_bytes=None,
        target_flows=5,
        output_root=Path("/data"),
        profiles=("udp-one", "udp-two"),
        interface="eth0",
    )
    assert calls == ["udp-one", "udp-two"]
    assert sessions == (Path("/udp-one"), Path("/udp-two"))
