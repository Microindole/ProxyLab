from __future__ import annotations

import random
from pathlib import Path

from proxy_traffic_lab.capture.experiment import run_web_capture
from proxy_traffic_lab.cli.commands.common import case_from_args
from proxy_traffic_lab.cli.commands.registry import COMMANDS


def register_parser(subcommands) -> None:
    experiment = subcommands.add_parser("experiment", help="client-side experiments")
    nested = experiment.add_subparsers(dest="experiment_command", required=True)
    web = nested.add_parser("web")
    web.add_argument("--case", required=True)
    web.add_argument("--server-ip", required=True)
    web.add_argument("--server-port", required=True, type=int)
    web.add_argument("--proxy", default="socks5://127.0.0.1:10808")
    web.add_argument("--url", action="append", dest="urls")
    web.add_argument("--duration", type=int, default=120)
    web.add_argument("--max-pages", type=int, default=12)
    web.add_argument("--seed", type=int)
    web.add_argument("--interface")
    web.add_argument("--output-root", type=Path, default=Path("~/proxy-lab-data"))


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



