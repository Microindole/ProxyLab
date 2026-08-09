from __future__ import annotations

import argparse
import json

from proxy_traffic_lab.configuration.composition import validate_case_composition
from proxy_traffic_lab.cli.commands.registry import COMMANDS
from proxy_traffic_lab.cli.commands.common import add_command
from proxy_traffic_lab.configuration.loader import (
    load_component_catalogs,
    load_lab_config,
    load_protocol_matrix,
)
from proxy_traffic_lab.diagnostics.doctor import render_report, run_doctor
from proxy_traffic_lab.configuration.models import ProtocolCase
from proxy_traffic_lab.common.errors import LabError


def register_parser(subcommands) -> None:
    doctor = add_command(subcommands, "doctor", aliases=("d",), help="diagnose the current host")
    doctor.add_argument("-j", "--json", action="store_true")
    doctor.add_argument("-N", "--no-network", action="store_true")

    config = add_command(subcommands, "config", aliases=("cfg",), help="configuration operations")
    config_sub = config.add_subparsers(dest="config_command", required=True)
    add_command(config_sub, "validate", aliases=("v",), dest="config_command", help="validate lab, layers and target matrix")

    matrix = add_command(subcommands, "matrix", aliases=("mx",), help="dataset target/composition operations")
    matrix_sub = matrix.add_subparsers(dest="matrix_command", required=True)
    add_command(matrix_sub, "list", aliases=("ls",), dest="matrix_command", help="list configured target cases")
    compose = add_command(matrix_sub, "compose", aliases=("cmp",), dest="matrix_command", help="validate a custom layer composition")
    compose.add_argument("-p", "--protocol", required=True)
    compose.add_argument("-t", "--transport", required=True)
    compose.add_argument("-e", "--encryption", required=True)
    compose.add_argument("-o", "--outer-transport", required=True)
    compose.add_argument("-C", "--client-core", required=True)
    compose.add_argument("-S", "--server-core", required=True)
    compose.add_argument("-P", "--parameter", action="append", default=[], metavar="KEY=VALUE")
    compose.add_argument("-n", "--inner-network", action="append", default=["tcp"])


@COMMANDS.handler("doctor")
def doctor(args) -> int:
    config = load_lab_config(args.lab_config)
    report = run_doctor(config, network_checks=not args.no_network)
    print(report.to_json() if args.json else render_report(report))
    return 0 if report.healthy else 2


@COMMANDS.handler("config", "validate")
def validate_config(args) -> int:
    config = load_lab_config(args.lab_config)
    matrix = load_protocol_matrix(args.matrix_config)
    print(
        "Configuration valid: "
        f"role={config.role.value}, targets={len(matrix.cases)}, "
        f"required={len(matrix.required_dataset_classes)}"
    )
    return 0


@COMMANDS.handler("matrix", "list")
def list_matrix(args) -> int:
    matrix = load_protocol_matrix(args.matrix_config)
    for case in matrix.cases:
        print(
            f"{case.id}\tclass={case.dataset_class}\t"
            f"{case.protocol}+{case.transport}+{case.encryption}/"
            f"{case.outer_transport}\tcore={case.client_core}/{case.server_core}"
        )
    return 0


@COMMANDS.handler("matrix", "compose")
def compose(args) -> int:
    parameters: dict[str, str] = {}
    for item in args.parameter:
        if "=" not in item:
            raise LabError("--parameter must use KEY=VALUE")
        key, value = item.split("=", 1)
        parameters[key] = value
    case = ProtocolCase(
        id="ad-hoc-composition",
        dataset_class=0,
        protocol=args.protocol,
        client_core=args.client_core,
        server_core=args.server_core,
        outer_transport=args.outer_transport,
        transport=args.transport,
        encryption=args.encryption,
        parameters=parameters,
        inner_networks=args.inner_network,
    )
    catalogs = load_component_catalogs()
    validate_case_composition(
        case,
        protocols=catalogs[0],
        transports=catalogs[1],
        encryptions=catalogs[2],
        compatibility=catalogs[3],
    )
    print(json.dumps(case.model_dump(mode="json"), ensure_ascii=False, indent=2))
    return 0



