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
