"""Windows capture CLI declaration and feedback."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from proxy_traffic_lab.capture.windows import WindowsCaptureRequest, execute_windows_capture
from proxy_traffic_lab.cli.commands.common import add_command
from proxy_traffic_lab.cli.commands.registry import COMMANDS


def register_parser(capture_subcommands: Any) -> None:
    windows_ipv6 = add_command(
        capture_subcommands,
        "windows-ipv6",
        aliases=("win6",),
        dest="capture_command",
        help="capture plain Win11 IPv6 browser traffic with Windows dumpcap",
    )
    windows_ipv6.add_argument(
        "-l",
        "--list-interfaces",
        action="store_true",
        help="list Windows dumpcap interfaces and exit",
    )
    windows_ipv6.add_argument(
        "-i",
        "--interface",
        help="Windows dumpcap interface number or name, from --list-interfaces",
    )
    windows_ipv6.add_argument(
        "-o",
        "--output",
        type=Path,
        help="single output PCAP path; omit when using repeated --profile",
    )
    windows_ipv6.add_argument(
        "-P",
        "--profile",
        action="append",
        dest="profiles",
        help="profile for one PCAP; repeat to capture multiple PCAPs in sequence",
    )
    windows_ipv6.add_argument(
        "-O",
        "--output-root",
        type=Path,
        default=Path("~/proxy-lab-data/plain"),
        help="root used with --profile; default: ~/proxy-lab-data/plain",
    )
    windows_ipv6.add_argument(
        "-c",
        "--case-id",
        help="override the plain capture case id from configs/plain_capture.yaml",
    )
    windows_ipv6.add_argument(
        "-6",
        "--ip-version",
        choices=("ipv6", "mixed"),
        default="mixed",
        help="capture only IPv6, or mixed IPv4+IPv6; default: mixed",
    )
    windows_ipv6.add_argument("-n", "--target-flows", type=int)
    windows_ipv6.add_argument(
        "--flow-count-mode",
        choices=("auto", "established", "syn", "conversation-5tuple"),
        default="auto",
        help=(
            "flow counting mode for plain Windows capture; auto uses "
            "conversation-5tuple for video-* profiles and established TCP for "
            "other profiles"
        ),
    )
    windows_ipv6.add_argument("--progress-interval", type=float, default=5.0)
    windows_ipv6.add_argument("--idle-seconds", type=float, default=15.0)
    windows_ipv6.add_argument("--idle-kib-per-second", type=float, default=32.0)
    windows_ipv6.add_argument("--finish-timeout", type=float, default=300.0)
    windows_ipv6.add_argument("-d", "--duration-seconds", type=int, default=0)
    windows_ipv6.add_argument(
        "--start-url",
        default="https://test-ipv6.com/",
        help="initial URL for the no-proxy capture browser",
    )
    windows_ipv6.add_argument(
        "--start-chrome",
        action="store_true",
        help="start a dedicated no-proxy Chrome/Edge profile",
    )
    windows_ipv6.add_argument(
        "--disable-quic",
        action="store_true",
        help="disable QUIC in the launched browser; leave off for realistic video",
    )
    windows_ipv6.add_argument(
        "--isolate-chrome-network",
        action="store_true",
        help=(
            "temporarily block non-browser outbound traffic with Windows Firewall "
            "during capture; requires an elevated Windows session"
        ),
    )


@COMMANDS.handler("capture", "windows-ipv6")
def handle_windows_ipv6(args: Any) -> int:
    return execute_windows_capture(
        WindowsCaptureRequest(
            list_interfaces=args.list_interfaces,
            interface=args.interface,
            output=args.output,
            profiles=args.profiles,
            output_root=args.output_root,
            ip_version=args.ip_version,
            target_flows=args.target_flows,
            flow_count_mode=args.flow_count_mode,
            progress_interval=args.progress_interval,
            idle_seconds=args.idle_seconds,
            idle_kib_per_second=args.idle_kib_per_second,
            finish_timeout=args.finish_timeout,
            duration_seconds=args.duration_seconds,
            start_url=args.start_url,
            start_chrome=args.start_chrome,
            disable_quic=args.disable_quic,
            isolate_chrome_network=args.isolate_chrome_network,
            case_id=args.case_id,
        )
    )
