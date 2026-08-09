from __future__ import annotations

import json
from pathlib import Path

from proxy_traffic_lab.cli.commands.common import add_command
from proxy_traffic_lab.cli.commands.registry import COMMANDS
from proxy_traffic_lab.dataset.audit import audit_session


def register_parser(subcommands) -> None:
    dataset = add_command(
        subcommands,
        "dataset",
        aliases=("ds",),
        help="dataset validation operations",
    )
    nested = dataset.add_subparsers(dest="dataset_command", required=True)
    audit = add_command(
        nested,
        "audit",
        aliases=("a",),
        dest="dataset_command",
        help="audit one captured session",
    )
    audit.add_argument("session", type=Path)
    audit.add_argument("-a", "--server-ip", required=True)
    audit.add_argument("-o", "--output", type=Path)


@COMMANDS.handler("dataset", "audit")
def audit(args) -> int:
    report = audit_session(
        args.session,
        server_ip=args.server_ip,
        matrix_path=args.matrix_config,
    )
    rendered = json.dumps(report.to_dict(), ensure_ascii=False, indent=2) + "\n"
    if args.output:
        output = args.output.expanduser().resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
        print(f"Audit report written: {output}")
    else:
        print(rendered, end="")
    return 0 if report.passed else 1

