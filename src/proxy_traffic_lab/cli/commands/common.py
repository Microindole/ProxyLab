from __future__ import annotations

import argparse

from proxy_traffic_lab.configuration.loader import find_protocol_case, load_lab_config
from proxy_traffic_lab.common.errors import LabError
from proxy_traffic_lab.lifecycle import registry as managed_runtime


def case_from_args(args):
    return find_protocol_case(args.case, getattr(args, "matrix_config", None))


def add_runtime_selector(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--core",
        help="upstream core; default comes from --case or configs/lab.yaml",
    )
    parser.add_argument("--case", help="target case used to select its declared core")


def runtime_core_for_args(args, *, side: str):
    config = load_lab_config(args.lab_config)
    case = case_from_args(args) if getattr(args, "case", None) else None
    try:
        return managed_runtime.resolve_runtime_core(
            config,
            explicit=getattr(args, "core", None),
            case=case,
            side=side,
        )
    except ValueError as exc:
        raise LabError(str(exc)) from exc



