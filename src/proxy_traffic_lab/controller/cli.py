from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from proxy_traffic_lab.controller.config import (
    load_lab_config,
    load_protocol_matrix,
)
from proxy_traffic_lab.controller.doctor import render_report, run_doctor
from proxy_traffic_lab.controller.errors import LabError


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
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
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
    except LabError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    parser.error("unsupported command")
    return 2

