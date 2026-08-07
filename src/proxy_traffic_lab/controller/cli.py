from __future__ import annotations

import argparse
import json
import os
import random
import subprocess
import sys
import time
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from proxy_traffic_lab.capture.experiment import _format_bytes
from proxy_traffic_lab.capture.flow_tracker import (
    PcapIpPacketTracker,
    PcapL4ConversationTracker,
    PcapTcpFlowTracker,
)
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
    ensure_reality_material,
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
            "class-07-vless-raw-reality-vision",
            "class-08-vless-grpc-tls",
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
    capture_win_ipv6 = capture_subcommands.add_parser(
        "windows-ipv6",
        help="capture plain Win11 IPv6 browser traffic with Windows dumpcap",
    )
    capture_win_ipv6.add_argument(
        "--list-interfaces",
        action="store_true",
        help="list Windows dumpcap interfaces and exit",
    )
    capture_win_ipv6.add_argument(
        "--interface",
        help="Windows dumpcap interface number or name, from --list-interfaces",
    )
    capture_win_ipv6.add_argument(
        "--output",
        type=Path,
        help="single output PCAP path; omit when using repeated --profile",
    )
    capture_win_ipv6.add_argument(
        "--profile",
        action="append",
        dest="profiles",
        help="profile for one PCAP; repeat to capture multiple PCAPs in sequence",
    )
    capture_win_ipv6.add_argument(
        "--output-root",
        type=Path,
        default=Path("~/proxy-lab-data/plain"),
        help="root used with --profile; default: ~/proxy-lab-data/plain",
    )
    capture_win_ipv6.add_argument(
        "--ip-version",
        choices=("ipv6", "mixed"),
        default="mixed",
        help="capture only IPv6, or mixed IPv4+IPv6; default: mixed",
    )
    capture_win_ipv6.add_argument("--target-flows", type=int)
    capture_win_ipv6.add_argument(
        "--flow-count-mode",
        choices=("auto", "established", "syn", "conversation-5tuple"),
        default="auto",
        help=(
            "flow counting mode for plain Windows capture; auto uses "
            "conversation-5tuple for video-* profiles and established TCP for "
            "other profiles"
        ),
    )
    capture_win_ipv6.add_argument("--progress-interval", type=float, default=5.0)
    capture_win_ipv6.add_argument("--idle-seconds", type=float, default=15.0)
    capture_win_ipv6.add_argument("--idle-kib-per-second", type=float, default=32.0)
    capture_win_ipv6.add_argument("--finish-timeout", type=float, default=300.0)
    capture_win_ipv6.add_argument("--duration-seconds", type=int, default=0)
    capture_win_ipv6.add_argument(
        "--start-url",
        default="https://test-ipv6.com/",
        help="initial URL for the no-proxy capture browser",
    )
    capture_win_ipv6.add_argument(
        "--start-chrome",
        action="store_true",
        help="start a dedicated no-proxy Chrome/Edge profile",
    )
    capture_win_ipv6.add_argument(
        "--disable-quic",
        action="store_true",
        help="disable QUIC in the launched browser; leave off for realistic video",
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
            if args.case == "class-07-vless-raw-reality-vision":
                material = ensure_reality_material(root / "secrets" / "xray", material)
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

        if args.command == "capture" and args.capture_command == "windows-ipv6":
            root = Path(__file__).resolve().parents[3]
            script = root / "scripts" / "capture_win_ipv6.ps1"
            if not script.is_file():
                raise LabError(f"missing helper script: {script}")
            if not args.list_interfaces and not args.interface:
                raise LabError(
                    "missing --interface; first run: lab capture windows-ipv6 --list-interfaces"
                )
            if args.target_flows is not None and args.target_flows <= 0:
                raise LabError("--target-flows must be positive")
            if args.progress_interval <= 0:
                raise LabError("--progress-interval must be positive")
            if args.idle_seconds < 0 or args.idle_kib_per_second < 0:
                raise LabError("idle thresholds cannot be negative")
            command = [
                "powershell.exe",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                _wslpath_to_windows(script),
            ]
            if args.list_interfaces:
                if os.name == "nt":
                    completed = subprocess.run(
                        [str(_find_windows_dumpcap_for_wsl()), "-D"],
                        check=False,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                    stdout_text = completed.stdout.decode("mbcs", errors="replace")
                    stderr_text = completed.stderr.decode("mbcs", errors="replace")
                    sys.stdout.write(
                        stdout_text.encode(
                            sys.stdout.encoding or "utf-8", errors="replace"
                        ).decode(sys.stdout.encoding or "utf-8")
                    )
                    sys.stderr.write(
                        stderr_text.encode(
                            sys.stderr.encoding or "utf-8", errors="replace"
                        ).decode(sys.stderr.encoding or "utf-8")
                    )
                    return completed.returncode
                command.append("-ListInterfaces")
            elif args.target_flows is not None:
                session_dirs = _run_windows_ipv6_flow_capture(
                    interface=args.interface,
                    ip_version=args.ip_version,
                    flow_count_mode=args.flow_count_mode,
                    target_flows=args.target_flows,
                    output_root=args.output_root,
                    profiles=args.profiles or ["mixed"],
                    start_chrome=args.start_chrome,
                    start_url=args.start_url,
                    disable_quic=args.disable_quic,
                    progress_interval_seconds=args.progress_interval,
                    idle_seconds=args.idle_seconds,
                    idle_bytes_per_second=args.idle_kib_per_second * 1024,
                    finish_timeout_seconds=args.finish_timeout,
                )
                print("Capture sessions written:")
                for session_dir in session_dirs:
                    print(f"  {session_dir}")
                return 0
            else:
                command.extend(["-Interface", args.interface])
                command.extend(["-IpVersion", args.ip_version])
                if args.output is not None:
                    command.extend(["-Output", _wslpath_to_windows(args.output)])
                if args.duration_seconds:
                    command.extend(["-DurationSeconds", str(args.duration_seconds)])
                command.extend(["-StartUrl", args.start_url])
                if args.start_chrome:
                    command.append("-StartChrome")
                if args.disable_quic:
                    command.append("-DisableQuic")
            completed = subprocess.run(command, check=False)
            return completed.returncode

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


def _wslpath_to_windows(path: Path) -> str:
    expanded = path.expanduser()
    if os.name == "nt":
        return str(expanded.resolve())
    result = subprocess.run(
        ["wslpath", "-w", str(expanded)],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode != 0:
        raise LabError(f"cannot convert path for PowerShell: {result.stderr.strip()}")
    return result.stdout.strip()


def _run_windows_ipv6_flow_capture(
    *,
    interface: str,
    ip_version: str,
    flow_count_mode: str,
    target_flows: int,
    output_root: Path,
    profiles: Sequence[str],
    start_chrome: bool,
    start_url: str,
    disable_quic: bool,
    progress_interval_seconds: float,
    idle_seconds: float,
    idle_bytes_per_second: float,
    finish_timeout_seconds: float,
) -> tuple[Path, ...]:
    dumpcap = _find_windows_dumpcap_for_wsl()
    series_started_at = datetime.now(UTC)
    series_id = (
        f"{series_started_at.strftime('%Y%m%dT%H%M%SZ')}-"
        f"{uuid.uuid4().hex[:10]}"
    )
    sessions: list[Path] = []
    segment_count = len(profiles)
    if start_chrome:
        _start_windows_no_proxy_browser(start_url=start_url, disable_quic=disable_quic)

    for segment_index, profile in enumerate(profiles, start=1):
        segment_flow_count_mode = _resolve_windows_plain_flow_count_mode(
            profile=profile,
            requested_mode=flow_count_mode,
        )
        if segment_index > 1:
            print(
                f"Starting segment {segment_index}/{segment_count}: {profile}. "
                "Wait for READY before beginning the next workload.",
                flush=True,
            )
        session_dir, stop_reason = _capture_windows_ipv6_flow_segment(
            dumpcap=dumpcap,
            interface=interface,
            ip_version=ip_version,
            flow_count_mode=segment_flow_count_mode,
            requested_flow_count_mode=flow_count_mode,
            target_flows=target_flows,
            output_root=output_root,
            profile=profile,
            series_id=series_id,
            segment_index=segment_index,
            segment_count=segment_count,
            progress_interval_seconds=progress_interval_seconds,
            idle_seconds=idle_seconds,
            idle_bytes_per_second=idle_bytes_per_second,
            finish_timeout_seconds=finish_timeout_seconds,
        )
        sessions.append(session_dir)
        if segment_index == segment_count:
            break
        if stop_reason != "target_flows_reached_and_traffic_idle":
            print(
                f"Series stopped after segment {segment_index}: {stop_reason}.",
                flush=True,
            )
            break
    return tuple(sessions)


def _resolve_windows_plain_flow_count_mode(
    *,
    profile: str,
    requested_mode: str,
) -> str:
    if requested_mode != "auto":
        return requested_mode
    normalized = profile.lower().replace("_", "-")
    if normalized.startswith("video"):
        return "conversation-5tuple"
    return "established"


def _capture_windows_ipv6_flow_segment(
    *,
    dumpcap: Path,
    interface: str,
    ip_version: str,
    flow_count_mode: str,
    requested_flow_count_mode: str,
    target_flows: int,
    output_root: Path,
    profile: str,
    series_id: str,
    segment_index: int,
    segment_count: int,
    progress_interval_seconds: float,
    idle_seconds: float,
    idle_bytes_per_second: float,
    finish_timeout_seconds: float,
) -> tuple[Path, str]:
    started_at = datetime.now(UTC)
    sample_id = f"{started_at.strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:10]}"
    case_id = (
        "class-00-plain-ipv6"
        if ip_version == "ipv6"
        else "class-00-plain-ipv4-ipv6"
    )
    session_dir = (
        output_root.expanduser().resolve()
        / "formal"
        / case_id
        / profile
        / sample_id
    )
    session_dir.mkdir(parents=True, exist_ok=False)
    pcap_path = session_dir / "capture.pcap"
    dumpcap_log_path = session_dir / "dumpcap.log"
    capture_filter = (
        "ip6 and (tcp port 80 or tcp port 443 or udp port 443)"
        if ip_version == "ipv6"
        else "(ip or ip6) and (tcp port 80 or tcp port 443 or udp port 443)"
    )
    windows_output = _wslpath_to_windows(pcap_path)
    dumpcap_log = dumpcap_log_path.open("wb")
    process = subprocess.Popen(
        [
            str(dumpcap),
            "-q",
            "-F",
            "pcap",
            "-i",
            interface,
            "-f",
            capture_filter,
            "-s",
            "0",
            "-w",
            windows_output,
        ],
        stdin=subprocess.DEVNULL,
        stdout=dumpcap_log,
        stderr=subprocess.STDOUT,
    )
    tracker = (
        PcapL4ConversationTracker(pcap_path)
        if flow_count_mode == "conversation-5tuple"
        else PcapTcpFlowTracker(pcap_path, count_mode=flow_count_mode)
    )
    ip_tracker = PcapIpPacketTracker(pcap_path)
    stop_reason = "interrupted"
    target_reached_at: float | None = None
    quiet_started_at: float | None = None
    flow_timeout_warning_at: float | None = None
    previous_time = time.monotonic()
    previous_size = 0
    target_label = (
        "TCP+UDP 5-tuple conversations"
        if flow_count_mode == "conversation-5tuple"
        else f"TCP flows ({flow_count_mode})"
    )
    print(
        f"READY segment {segment_index}/{segment_count}: {profile}\n"
        f"Capturing plain {ip_version} on Windows interface {interface} to {pcap_path}\n"
        f"Filter: {capture_filter}\n"
        f"Target: {target_flows} {target_label}; after target, stop opening new pages "
        "and wait for PCAP write rate to become idle. Active TCP flows are reported "
        "but do not block plain website rotation. Press Ctrl+C to stop early.",
        flush=True,
    )
    try:
        time.sleep(1)
        if process.poll() is not None:
            dumpcap_log.close()
            stderr = dumpcap_log_path.read_text(errors="replace")
            raise LabError(f"dumpcap exited before traffic started: {stderr.strip()}")
        while True:
            time.sleep(progress_interval_seconds)
            now = time.monotonic()
            size = pcap_path.stat().st_size if pcap_path.is_file() else 0
            interval = max(now - previous_time, 0.001)
            rate = max(size - previous_size, 0) / interval
            stats = tracker.poll()
            ip_stats = ip_tracker.poll()
            phase = "DRAINING" if stats.total_flows >= target_flows else "CAPTURING"
            percent = min(stats.total_flows / target_flows * 100, 100.0)
            print(
                f"[segment {segment_index}/{segment_count} {phase} "
                f"{datetime.now(UTC).strftime('%H:%M:%S')}Z] "
                f"flows {stats.total_flows} / {target_flows} ({percent:5.1f}%), "
                f"active {stats.active_flows}, completed {stats.completed_flows}, "
                f"l4tcp {stats.tcp_conversations}, l4udp {stats.udp_conversations}, "
                f"flow6 {stats.ipv6_flows}, flow4 {stats.ipv4_flows}, "
                f"ip6 {ip_stats.ipv6_packets}, ip4 {ip_stats.ipv4_packets}, "
                f"udp443-conv {ip_stats.udp_443_conversations}, "
                f"pcap {_format_bytes(size)}, rate {_format_bytes(int(rate))}/s",
                flush=True,
            )
            if process.poll() is not None:
                dumpcap_log.close()
                stderr = dumpcap_log_path.read_text(errors="replace")
                raise LabError(f"dumpcap stopped unexpectedly: {stderr.strip()}")
            if stats.total_flows >= target_flows:
                if target_reached_at is None:
                    target_reached_at = now
                    flow_timeout_warning_at = now + finish_timeout_seconds
                    print(
                        f"Segment {segment_index}/{segment_count} flow target reached. "
                        "Do not start new browsing work; waiting for traffic idle.",
                        flush=True,
                    )
                if rate <= idle_bytes_per_second:
                    quiet_started_at = quiet_started_at or now
                else:
                    quiet_started_at = None
                if (
                    quiet_started_at is not None
                    and now - quiet_started_at >= idle_seconds
                ):
                    stop_reason = "target_flows_reached_and_traffic_idle"
                    break
                if (
                    flow_timeout_warning_at is not None
                    and now >= flow_timeout_warning_at
                ):
                    print(
                        f"warning: still waiting for traffic idle; active TCP flows "
                        f"currently {stats.active_flows}.",
                        flush=True,
                    )
                    flow_timeout_warning_at = now + finish_timeout_seconds
            previous_time = now
            previous_size = size
    except KeyboardInterrupt:
        print("\nStopping capture on user request...", flush=True)
    finally:
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        if not dumpcap_log.closed:
            dumpcap_log.close()
        dumpcap_log_text = dumpcap_log_path.read_text(errors="replace")

    ended_at = datetime.now(UTC)
    final_stats = tracker.poll()
    final_ip_stats = ip_tracker.poll()
    final_size = pcap_path.stat().st_size if pcap_path.is_file() else 0
    metadata = {
        "schema_version": "1.0.0",
        "sample_id": sample_id,
        "series_id": series_id,
        "segment_index": segment_index,
        "segment_count": segment_count,
        "case_id": case_id,
        "profile": profile,
        "capture": {
            "pcap": pcap_path.name,
            "interface": interface,
            "bpf": capture_filter,
            "start_time_utc": started_at.isoformat(),
            "end_time_utc": ended_at.isoformat(),
            "target_flows": target_flows,
            "requested_flow_count_mode": requested_flow_count_mode,
            "flow_count_mode": flow_count_mode,
            "flow_count_definition": (
                "bidirectional TCP plus UDP L4 5-tuple conversations, matching "
                "Wireshark Conversations TCP+UDP counts"
                if flow_count_mode == "conversation-5tuple"
                else (
                    "TCP connections with observed SYN-ACK"
                    if flow_count_mode == "established"
                    else "TCP SYN starts"
                )
            ),
            "file_bytes": final_size,
            "target_met": final_stats.total_flows >= target_flows,
            "flow_count": final_stats.total_flows,
            "tcp_conversation_count": final_stats.tcp_conversations,
            "udp_conversation_count": final_stats.udp_conversations,
            "completed_flow_count": final_stats.completed_flows,
            "active_flow_count": final_stats.active_flows,
            "ipv4_flow_count": final_stats.ipv4_flows,
            "ipv6_flow_count": final_stats.ipv6_flows,
            "completed_ipv4_flow_count": final_stats.completed_ipv4_flows,
            "completed_ipv6_flow_count": final_stats.completed_ipv6_flows,
            "active_ipv4_flow_count": final_stats.active_ipv4_flows,
            "active_ipv6_flow_count": final_stats.active_ipv6_flows,
            "ipv4_packets": final_ip_stats.ipv4_packets,
            "ipv6_packets": final_ip_stats.ipv6_packets,
            "tcp_packets": final_ip_stats.tcp_packets,
            "udp_packets": final_ip_stats.udp_packets,
            "udp_443_conversations": final_ip_stats.udp_443_conversations,
            "stop_reason": stop_reason,
            "dumpcap_log": dumpcap_log_text[-2000:],
        },
    }
    (session_dir / "capture.json").write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(
        f"Segment {segment_index}/{segment_count} stopped: {stop_reason}; "
        f"final size {_format_bytes(final_size)}, flows {final_stats.total_flows}, "
        f"active {final_stats.active_flows}\n"
        f"PCAP: {pcap_path}",
        flush=True,
    )
    return session_dir, stop_reason


def _find_windows_dumpcap_for_wsl() -> Path:
    if os.name == "nt":
        where_result = subprocess.run(
            ["where.exe", "dumpcap.exe"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        for line in where_result.stdout.splitlines():
            candidate = Path(line.strip())
            if candidate.is_file():
                return candidate
        candidates = [
            Path("C:/Program Files/Wireshark/dumpcap.exe"),
            Path("C:/Program Files (x86)/Wireshark/dumpcap.exe"),
            Path("D:/Wireshark/dumpcap.exe"),
        ]
        for candidate in candidates:
            if candidate.is_file():
                return candidate
        raise LabError(
            "Windows dumpcap.exe was not found; install Wireshark with Npcap"
        )
    where_result = subprocess.run(
        ["cmd.exe", "/c", "where", "dumpcap.exe"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    for line in where_result.stdout.splitlines():
        candidate_text = line.strip()
        if not candidate_text:
            continue
        converted = subprocess.run(
            ["wslpath", "-u", candidate_text],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        if converted.returncode == 0:
            candidate = Path(converted.stdout.strip())
            if candidate.is_file():
                return candidate
    candidates = [
        Path("/mnt/c/Program Files/Wireshark/dumpcap.exe"),
        Path("/mnt/c/Program Files (x86)/Wireshark/dumpcap.exe"),
        Path("/mnt/d/Wireshark/dumpcap.exe"),
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise LabError("Windows dumpcap.exe was not found; install Wireshark with Npcap")


def _start_windows_no_proxy_browser(*, start_url: str, disable_quic: bool) -> None:
    root = Path(__file__).resolve().parents[3]
    script = root / "scripts" / "launch_win_capture_browser.ps1"
    if not script.is_file():
        raise LabError(f"missing helper script: {script}")
    command = [
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        _wslpath_to_windows(script),
        "-StartUrl",
        start_url,
    ]
    if disable_quic:
        command.append("-DisableQuic")
    result = subprocess.run(
        command,
        check=False,
        text=True,
    )
    if result.returncode != 0:
        raise LabError("failed to start Windows no-proxy browser")
