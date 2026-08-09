"""CLI composition root; command behavior lives in cli.commands."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from proxy_traffic_lab.cli.commands import (
    load_command_modules,
    register_command_parsers,
)
from proxy_traffic_lab.configuration.loader import load_dotenv
from proxy_traffic_lab.common.errors import LabError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="lab")
    parser.add_argument(
        "-L",
        "--lab-config",
        type=Path,
        help="path to lab.yaml (default: configs/lab.yaml)",
    )
    parser.add_argument(
        "-M",
        "--matrix-config",
        type=Path,
        help="path to protocol target YAML (default: configs/protocol_matrix.yaml)",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)
    register_command_parsers(subcommands)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        load_dotenv()
        result = load_command_modules().dispatch(args)
        if result is not None:
            return result
    except LabError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    parser.error("unsupported command")
    return 2



