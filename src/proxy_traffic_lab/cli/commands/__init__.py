from __future__ import annotations

from typing import Any

from proxy_traffic_lab.cli.commands.registry import COMMANDS, CommandRegistry


def _modules():
    from proxy_traffic_lab.cli.commands import (
        capture,
        dataset,
        kernel,
        diagnostics,
        experiment,
        lifecycle,
    )

    return diagnostics, kernel, lifecycle, capture, experiment, dataset


def register_command_parsers(subcommands: Any) -> None:
    for module in _modules():
        module.register_parser(subcommands)


def load_command_modules() -> CommandRegistry:
    _modules()  # Imports apply handler decorators exactly once.
    return COMMANDS


__all__ = [
    "COMMANDS",
    "CommandRegistry",
    "load_command_modules",
    "register_command_parsers",
]


