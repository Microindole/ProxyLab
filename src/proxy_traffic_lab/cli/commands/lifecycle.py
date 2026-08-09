from __future__ import annotations

import json
from pathlib import Path

from proxy_traffic_lab.cli.commands.common import (
    add_command,
    add_runtime_selector,
    runtime_core_for_args,
)
from proxy_traffic_lab.cli.commands.registry import COMMANDS
from proxy_traffic_lab.configuration.loader import project_root
from proxy_traffic_lab.lifecycle import registry as runtime


def register_parser(subcommands) -> None:
    server = add_command(subcommands, "server", aliases=("srv",), help="proxy server lifecycle")
    server_sub = server.add_subparsers(dest="server_command", required=True)
    for name, alias in (("start", "up"), ("status", "st"), ("stop", "down")):
        add_runtime_selector(add_command(server_sub, name, aliases=(alias,), dest="server_command"))
    logs = add_command(server_sub, "logs", aliases=("log",), dest="server_command")
    logs.add_argument("-n", "--tail", type=int, default=100)
    add_runtime_selector(logs)

    client = add_command(subcommands, "client", aliases=("cli",), help="local proxy client lifecycle")
    client_sub = client.add_subparsers(dest="client_command", required=True)
    start = add_command(client_sub, "start", aliases=("up",), dest="client_command")
    start.add_argument("-f", "--config", type=Path)
    add_runtime_selector(start)
    status = add_command(client_sub, "status", aliases=("st",), dest="client_command")
    status.add_argument("-s", "--socks-port", type=int, default=10808)
    add_runtime_selector(status)
    logs = add_command(client_sub, "logs", aliases=("log",), dest="client_command")
    logs.add_argument("-n", "--tail", type=int, default=100)
    add_runtime_selector(logs)
    add_runtime_selector(add_command(client_sub, "stop", aliases=("down",), dest="client_command"))


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



