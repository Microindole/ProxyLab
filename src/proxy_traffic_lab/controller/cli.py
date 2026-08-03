from __future__ import annotations

import argparse
import json
import random
import sys
from collections.abc import Sequence
from pathlib import Path

from proxy_traffic_lab.capture.experiment import (
    run_segmented_capture,
    run_web_capture,
)
from proxy_traffic_lab.controller.config import (
    load_dotenv,
    load_lab_config,
    load_protocol_matrix,
)
from proxy_traffic_lab.controller.doctor import render_report, run_doctor
from proxy_traffic_lab.controller.errors import LabError
from proxy_traffic_lab.providers.xray import (
    client_logs,
    client_status,
    create_vless_tls_material,
    load_vless_tls_material,
    lock_official_image,
    render_xray_case_client,
    render_xray_case_server,
    server_logs,
    server_status,
    start_client_container,
    start_server_container,
    stop_client_container,
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
    render.add_argument(
        "--case",
        default="vless-tcp-tls",
        choices=[
            "vless-tcp-tls",
            "class-05-vmess-websocket-tls",
            "class-06-vmess-xhttp-h2-tls",
        ],
        help="protocol case to render (default keeps the original smoke case)",
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

    client = subcommands.add_parser("client", help="local Xray client lifecycle")
    client_subcommands = client.add_subparsers(dest="client_command", required=True)
    client_start = client_subcommands.add_parser(
        "start", help="start the constrained local Xray client"
    )
    client_start.add_argument(
        "--config",
        type=Path,
        default=Path("~/proxy-lab-client/client.json"),
    )
    client_status_parser = client_subcommands.add_parser(
        "status", help="show local Xray client and SOCKS listener status"
    )
    client_status_parser.add_argument("--socks-port", type=int, default=10808)
    client_logs_parser = client_subcommands.add_parser(
        "logs", help="show local Xray client logs"
    )
    client_logs_parser.add_argument("--tail", type=int, default=100)
    client_subcommands.add_parser("stop", help="stop and remove the local Xray client")

    capture = subcommands.add_parser(
        "capture", help="capture existing real traffic to a size-limited PCAP"
    )
    capture_subcommands = capture.add_subparsers(
        dest="capture_command", required=True
    )
    capture_run = capture_subcommands.add_parser(
        "run", help="monitor PCAP size and stop after post-target traffic becomes idle"
    )
    capture_run.add_argument("--case", required=True, help="enabled protocol case id")
    capture_run.add_argument("--server-ip", required=True)
    capture_run.add_argument("--server-port", required=True, type=int)
    capture_run.add_argument(
        "--target-gib",
        type=float,
        default=1.0,
        help="size target used only when --target-flows is omitted",
    )
    capture_run.add_argument(
        "--target-flows",
        type=int,
        help=(
            "outer TCP connection target; after reaching it, wait for all active "
            "flows to close instead of cutting the PCAP"
        ),
    )
    capture_run.add_argument(
        "--profile",
        action="append",
        dest="profiles",
        help=(
            "profile for one PCAP; repeat to capture multiple PCAPs in sequence "
            "without restarting the command"
        ),
    )
    capture_run.add_argument("--interface")
    capture_run.add_argument("--progress-interval", type=float, default=5.0)
    capture_run.add_argument("--idle-seconds", type=float, default=15.0)
    capture_run.add_argument("--idle-kib-per-second", type=float, default=32.0)
    capture_run.add_argument("--finish-timeout", type=float, default=300.0)
    capture_run.add_argument(
        "--output-root", type=Path, default=Path("~/proxy-lab-data")
    )

    experiment = subcommands.add_parser(
        "experiment", help="run a client-side capture experiment"
    )
    experiment_subcommands = experiment.add_subparsers(
        dest="experiment_command", required=True
    )
    web = experiment_subcommands.add_parser(
        "web", help="capture a Playwright web-browsing pilot"
    )
    web.add_argument("--case", required=True, help="enabled protocol case id")
    web.add_argument("--server-ip", required=True)
    web.add_argument("--server-port", required=True, type=int)
    web.add_argument("--proxy", default="socks5://127.0.0.1:10808")
    web.add_argument(
        "--url",
        action="append",
        dest="urls",
        help="authorized URL to visit; repeat for multiple sites",
    )
    web.add_argument("--duration", type=int, default=120)
    web.add_argument("--max-pages", type=int, default=12)
    web.add_argument("--seed", type=int)
    web.add_argument("--interface")
    web.add_argument(
        "--output-root",
        type=Path,
        default=Path("~/proxy-lab-data"),
    )
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
                render_xray_case_server(
                    args.case,
                    material,
                    port=args.server_port,
                ),
            )
            write_private_json(
                generated / "client.json",
                render_xray_case_client(
                    args.case,
                    material,
                    server_address=args.server_address,
                    server_port=args.server_port,
                    socks_port=args.socks_port,
                ),
            )
            print(
                "Rendered ignored configs under secrets/generated; "
                f"case={args.case}"
            )
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

        if args.command == "client" and args.client_command == "start":
            container_id = start_client_container(args.config)
            print(f"Xray client running: {container_id[:12]}")
            return 0

        if args.command == "client" and args.client_command == "status":
            status = client_status(socks_port=args.socks_port)
            print(json.dumps(status, ensure_ascii=False, indent=2))
            return 0 if status["healthy"] else 2

        if args.command == "client" and args.client_command == "logs":
            print(client_logs(tail=args.tail))
            return 0

        if args.command == "client" and args.client_command == "stop":
            print(stop_client_container())
            return 0

        if args.command == "capture" and args.capture_command == "run":
            matrix = load_protocol_matrix()
            case = next((item for item in matrix.cases if item.id == args.case), None)
            if case is None:
                raise LabError(f"unknown protocol case: {args.case}")
            if args.target_gib <= 0:
                raise LabError("--target-gib must be positive")
            if args.target_flows is not None and args.target_flows <= 0:
                raise LabError("--target-flows must be positive")
            session_dirs = run_segmented_capture(
                case=case,
                server_ip=args.server_ip,
                server_port=args.server_port,
                target_bytes=(
                    None
                    if args.target_flows is not None
                    else round(args.target_gib * 1024**3)
                ),
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
            for session_dir in session_dirs:
                print(f"  {session_dir}")
            return 0

        if args.command == "experiment" and args.experiment_command == "web":
            matrix = load_protocol_matrix()
            case = next((item for item in matrix.cases if item.id == args.case), None)
            if case is None:
                raise LabError(f"unknown protocol case: {args.case}")
            seed = args.seed if args.seed is not None else random.SystemRandom().randrange(2**31)
            session_dir = run_web_capture(
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
            print(f"Pilot session written: {session_dir}")
            return 0
    except LabError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    parser.error("unsupported command")
    return 2
