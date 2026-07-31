from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from proxy_traffic_lab.controller.config import (
    load_dotenv,
    load_lab_config,
    load_protocol_matrix,
)
from proxy_traffic_lab.controller.doctor import render_report, run_doctor
from proxy_traffic_lab.controller.errors import LabError
from proxy_traffic_lab.providers.xray import (
    create_vless_tls_material,
    load_vless_tls_material,
    lock_official_image,
    render_vless_tls_client,
    render_vless_tls_server,
    server_logs,
    server_status,
    start_server_container,
    stop_server_container,
    validate_server_config_with_container,
    write_private_json,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="lab")
    parser.add_argument(
        "--lab-config",
        type=Path,
        help="path to lab.yaml (default: configs/lab.yaml)",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    doctor = subcommands.add_parser("doctor", help="diagnose the current host")
    doctor.add_argument("--json", action="store_true", help="emit JSON")
    doctor.add_argument(
        "--no-network",
        action="store_true",
        help="skip public-IP and SSH checks",
    )

    config = subcommands.add_parser("config", help="configuration operations")
    config_subcommands = config.add_subparsers(dest="config_command", required=True)
    config_subcommands.add_parser("validate", help="validate checked-in YAML")

    matrix = subcommands.add_parser("matrix", help="protocol-matrix operations")
    matrix_subcommands = matrix.add_subparsers(dest="matrix_command", required=True)
    matrix_subcommands.add_parser("list", help="list configured protocol cases")

    xray = subcommands.add_parser("xray", help="Xray MVP operations")
    xray_subcommands = xray.add_subparsers(dest="xray_command", required=True)
    xray_subcommands.add_parser(
        "lock-image", help="pull and lock the official Xray image digest"
    )
    init_secrets = xray_subcommands.add_parser(
        "init-secrets", help="create short-lived TLS and VLESS credentials"
    )
    init_secrets.add_argument("--server-name", default="lab.invalid")
    init_secrets.add_argument("--validity-days", type=int, default=30)
    render = xray_subcommands.add_parser(
        "render", help="render secret server/client configurations"
    )
    render.add_argument("--server-address", required=True)
    render.add_argument("--server-port", type=int, required=True)
    render.add_argument("--socks-port", type=int, default=10808)
    xray_subcommands.add_parser(
        "validate", help="validate generated server config in the locked image"
    )

    server = subcommands.add_parser("server", help="proxy server lifecycle")
    server_subcommands = server.add_subparsers(dest="server_command", required=True)
    server_subcommands.add_parser("start", help="start the constrained Xray server")
    server_subcommands.add_parser("status", help="show Xray container and listener state")
    logs = server_subcommands.add_parser("logs", help="show Xray container logs")
    logs.add_argument("--tail", type=int, default=100)
    server_subcommands.add_parser("stop", help="stop and remove the Xray server")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        load_dotenv()
        if args.command == "doctor":
            config = load_lab_config(args.lab_config)
            report = run_doctor(config, network_checks=not args.no_network)
            print(report.to_json() if args.json else render_report(report))
            return 0 if report.healthy else 2

        if args.command == "config" and args.config_command == "validate":
            lab_config = load_lab_config(args.lab_config)
            matrix = load_protocol_matrix()
            print(
                "Configuration valid: "
                f"role={lab_config.role.value}, cases={len(matrix.cases)}"
            )
            return 0

        if args.command == "matrix" and args.matrix_command == "list":
            matrix = load_protocol_matrix()
            for case in matrix.cases:
                enabled = "enabled" if case.enabled else "disabled"
                inner = ",".join(case.inner_networks)
                print(
                    f"{case.id}\t{enabled}\t"
                    f"{case.protocol}/{case.outer_transport}/"
                    f"{case.wrapper}/{case.security}\tinner={inner}"
                )
            return 0

        if args.command == "xray" and args.xray_command == "lock-image":
            root = Path(__file__).resolve().parents[3]
            image = lock_official_image(root / "configs" / "locks" / "xray.json")
            print(f"Locked official image: {image}")
            return 0

        if args.command == "xray" and args.xray_command == "init-secrets":
            root = Path(__file__).resolve().parents[3]
            material = create_vless_tls_material(
                root / "secrets" / "xray",
                server_name=args.server_name,
                validity_days=args.validity_days,
            )
            print(
                "Created ignored credentials under secrets/xray; "
                f"certificate_sha256={material.certificate_sha256}"
            )
            return 0

        if args.command == "xray" and args.xray_command == "render":
            root = Path(__file__).resolve().parents[3]
            material = load_vless_tls_material(root / "secrets" / "xray")
            generated = root / "secrets" / "generated"
            write_private_json(
                generated / "server.json",
                render_vless_tls_server(material, port=args.server_port),
            )
            write_private_json(
                generated / "client.json",
                render_vless_tls_client(
                    material,
                    server_address=args.server_address,
                    server_port=args.server_port,
                    socks_port=args.socks_port,
                ),
            )
            print("Rendered ignored configs under secrets/generated")
            return 0

        if args.command == "xray" and args.xray_command == "validate":
            root = Path(__file__).resolve().parents[3]
            detail = validate_server_config_with_container(root)
            print(detail)
            return 0

        if args.command == "server" and args.server_command == "start":
            root = Path(__file__).resolve().parents[3]
            container_id = start_server_container(root)
            print(f"Xray server running: {container_id[:12]}")
            return 0

        if args.command == "server" and args.server_command == "status":
            root = Path(__file__).resolve().parents[3]
            status = server_status(root)
            print(json.dumps(status, ensure_ascii=False, indent=2))
            return 0 if status["healthy"] else 2

        if args.command == "server" and args.server_command == "logs":
            print(server_logs(tail=args.tail))
            return 0

        if args.command == "server" and args.server_command == "stop":
            print(stop_server_container())
            return 0
    except LabError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    parser.error("unsupported command")
    return 2
