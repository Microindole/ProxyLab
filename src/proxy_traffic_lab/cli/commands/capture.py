from __future__ import annotations

from pathlib import Path

from proxy_traffic_lab.capture.segmented import run_segmented_capture
from proxy_traffic_lab.cli.commands.common import add_command, case_from_args
from proxy_traffic_lab.cli.commands.registry import COMMANDS
from proxy_traffic_lab.common.errors import LabError
from proxy_traffic_lab.cli.commands import capture_windows


def register_parser(subcommands) -> None:
    capture = add_command(subcommands, "capture", aliases=("cap",), help="traffic capture operations")
    nested = capture.add_subparsers(dest="capture_command", required=True)
    run = add_command(nested, "run", aliases=("r",), dest="capture_command", help="capture an outer proxy tunnel")
    run.add_argument("-c", "--case", required=True)
    run.add_argument("-a", "--server-ip", required=True)
    run.add_argument("-p", "--server-port", required=True, type=int)
    run.add_argument("-g", "--target-gib", type=float, default=1.0)
    run.add_argument("-n", "--target-flows", type=int)
    run.add_argument("-P", "--profile", action="append", dest="profiles")
    run.add_argument("-i", "--interface")
    run.add_argument("-I", "--progress-interval", type=float, default=5.0)
    run.add_argument("--idle-seconds", type=float, default=15.0)
    run.add_argument("--idle-kib-per-second", type=float, default=32.0)
    run.add_argument("--finish-timeout", type=float, default=300.0)
    run.add_argument("-o", "--output-root", type=Path, default=Path("~/proxy-lab-data"))
    capture_windows.register_parser(nested)


@COMMANDS.handler("capture", "run")
def capture_run(args) -> int:
    case = case_from_args(args)
    if args.target_gib <= 0:
        raise LabError("--target-gib must be positive")
    if args.target_flows is not None and args.target_flows <= 0:
        raise LabError("--target-flows must be positive")
    sessions = run_segmented_capture(
        case=case,
        server_ip=args.server_ip,
        server_port=args.server_port,
        target_bytes=None if args.target_flows is not None else round(args.target_gib * 1024**3),
        target_flows=args.target_flows,
        output_root=args.output_root,
        profiles=args.profiles or ["mixed"],
        interface=args.interface,
        progress_interval_seconds=args.progress_interval,
        idle_seconds=args.idle_seconds,
        idle_bytes_per_second=args.idle_kib_per_second * 1024,
        finish_timeout_seconds=args.finish_timeout,
    )
    print("Capture sessions written:")
    for session in sessions:
        print(f"  {session}")
    return 0


