from __future__ import annotations

import json
from pathlib import Path

from proxy_traffic_lab.cli.commands.common import (
    add_runtime_selector,
    runtime_core_for_args,
)
from proxy_traffic_lab.cli.commands.registry import COMMANDS
from proxy_traffic_lab.configuration.loader import project_root
from proxy_traffic_lab.lifecycle import registry as runtime


def register_parser(subcommands) -> None:
    server = subcommands.add_parser("server", help="proxy server lifecycle")
    server_sub = server.add_subparsers(dest="server_command", required=True)
    for name in ("start", "status", "stop"):
        add_runtime_selector(server_sub.add_parser(name))
    logs = server_sub.add_parser("logs")
    logs.add_argument("--tail", type=int, default=100)
    add_runtime_selector(logs)

    client = subcommands.add_parser("client", help="local proxy client lifecycle")
    client_sub = client.add_subparsers(dest="client_command", required=True)
    start = client_sub.add_parser("start")
    start.add_argument("--config", type=Path)
    add_runtime_selector(start)
    status = client_sub.add_parser("status")
    status.add_argument("--socks-port", type=int, default=10808)
    add_runtime_selector(status)
    logs = client_sub.add_parser("logs")
    logs.add_argument("--tail", type=int, default=100)
    add_runtime_selector(logs)
    add_runtime_selector(client_sub.add_parser("stop"))


@COMMANDS.handler("server", "start")
def server_start(args) -> int:
    core = runtime_core_for_args(args, side="server")
    container = runtime.start_server(core, project_root())
    print(f"{core.value} server running: {container[:12]}")
    return 0


@COMMANDS.handler("server", "status")
def server_status(args) -> int:
    core = runtime_core_for_args(args, side="server")
    status = runtime.server_status(core, project_root())
    print(json.dumps(status, ensure_ascii=False, indent=2))
    return 0 if status["healthy"] else 2


@COMMANDS.handler("server", "logs")
def server_logs(args) -> int:
    core = runtime_core_for_args(args, side="server")
    print(runtime.server_logs(core, tail=args.tail))
    return 0


@COMMANDS.handler("server", "stop")
def server_stop(args) -> int:
    core = runtime_core_for_args(args, side="server")
    print(runtime.stop_server(core))
    return 0


@COMMANDS.handler("client", "start")
def client_start(args) -> int:
    core = runtime_core_for_args(args, side="client")
    container = runtime.start_client(core, project_root(), args.config)
    print(f"{core.value} client running: {container[:12]}")
    return 0


@COMMANDS.handler("client", "status")
def client_status(args) -> int:
    core = runtime_core_for_args(args, side="client")
    status = runtime.client_status(core, socks_port=args.socks_port)
    print(json.dumps(status, ensure_ascii=False, indent=2))
    return 0 if status["healthy"] else 2


@COMMANDS.handler("client", "logs")
def client_logs(args) -> int:
    core = runtime_core_for_args(args, side="client")
    print(runtime.client_logs(core, tail=args.tail))
    return 0


@COMMANDS.handler("client", "stop")
def client_stop(args) -> int:
    core = runtime_core_for_args(args, side="client")
    print(runtime.stop_client(core))
    return 0



