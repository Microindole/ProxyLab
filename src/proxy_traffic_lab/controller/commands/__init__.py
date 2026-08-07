from __future__ import annotations

from proxy_traffic_lab.controller.commands.registry import COMMANDS, CommandRegistry


def load_command_modules() -> CommandRegistry:
    # Importing command modules registers their handlers in COMMANDS.
    from proxy_traffic_lab.controller.commands import capture_windows as _capture_windows

    return COMMANDS


__all__ = ["COMMANDS", "CommandRegistry", "load_command_modules"]
