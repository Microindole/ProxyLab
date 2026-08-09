from __future__ import annotations

import random
from pathlib import Path

from proxy_traffic_lab.capture.pilot import run_udp_capture, run_web_capture
from proxy_traffic_lab.cli.commands.common import add_command, case_from_args
from proxy_traffic_lab.cli.commands.registry import COMMANDS


def register_parser(subcommands) -> None:
    experiment = add_command(subcommands, "experiment", aliases=("exp",), help="client-side experiments")
    nested = experiment.add_subparsers(dest="experiment_command", required=True)
    web = add_command(nested, "web", aliases=("w",), dest="experiment_command")
    web.add_argument("-c", "--case", required=True)
    web.add_argument("-a", "--server-ip", required=True)
    web.add_argument("-p", "--server-port", required=True, type=int)
    web.add_argument("-x", "--proxy", default="socks5://127.0.0.1:10808")
    web.add_argument("-u", "--url", action="append", dest="urls")
    web.add_argument("-d", "--duration", type=int, default=120)
    web.add_argument("-m", "--max-pages", type=int, default=12)
    web.add_argument("--seed", type=int)
    web.add_argument("-i", "--interface")
    web.add_argument("-o", "--output-root", type=Path, default=Path("~/proxy-lab-data"))
    udp = add_command(
        nested,
        "udp",
        aliases=("u",),
        dest="experiment_command",
        help="capture an authorized UDP echo workload through SOCKS5",
    )
    udp.add_argument("-c", "--case", required=True)
    udp.add_argument("-a", "--server-ip", required=True)
    udp.add_argument("-p", "--server-port", required=True, type=int)
    udp.add_argument("-x", "--proxy", default="socks5://127.0.0.1:10808")
    udp.add_argument("-H", "--target-host", required=True)
    udp.add_argument("-P", "--target-port", required=True, type=int)
    udp.add_argument("-n", "--count", type=int, default=20)
    udp.add_argument("-b", "--payload-bytes", type=int, default=256)
    udp.add_argument("-t", "--timeout", type=float, default=5.0)
    udp.add_argument("--interval", type=float, default=0.1)
    udp.add_argument("--seed", type=int)
    udp.add_argument("-i", "--interface")
    udp.add_argument("-o", "--output-root", type=Path, default=Path("~/proxy-lab-data"))


@COMMANDS.handler("experiment", "web")
def web(args) -> int:
    case = case_from_args(args)
    seed = args.seed if args.seed is not None else random.SystemRandom().randrange(2**31)
    session = run_web_capture(
        case=case,
        server_ip=args.server_ip,
        server_port=args.server_port,
        proxy_server=args.proxy,
        urls=args.urls or ["https://example.com/"],
        seed=seed,
        max_duration_seconds=args.duration,
        max_pages=args.max_pages,
        output_root=args.output_root,
        interface=args.interface,
    )
    print(f"Pilot session written: {session}")
    return 0


@COMMANDS.handler("experiment", "udp")
def udp(args) -> int:
    case = case_from_args(args)
    seed = args.seed if args.seed is not None else random.SystemRandom().randrange(2**31)
    session = run_udp_capture(
        case=case,
        server_ip=args.server_ip,
        server_port=args.server_port,
        proxy_server=args.proxy,
        target_host=args.target_host,
        target_port=args.target_port,
        seed=seed,
        count=args.count,
        payload_bytes=args.payload_bytes,
        timeout_seconds=args.timeout,
        interval_seconds=args.interval,
        output_root=args.output_root,
        interface=args.interface,
    )
    print(f"UDP pilot session written: {session}")
    return 0

