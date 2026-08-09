from __future__ import annotations

import random
import sys
import time
from importlib.resources import files
from typing import Any

from proxy_traffic_lab.cli.commands.registry import COMMANDS

ACCENT_COLOR = "\x1b[38;2;102;204;255m"
RESET_COLOR = "\x1b[0m"
ENTER_FULLSCREEN = "\x1b[?1049h\x1b[?25l\x1b[2J\x1b[H"
LEAVE_FULLSCREEN = "\x1b[0m\x1b[?25h\x1b[?1049l"


class _HiddenCommandMap(dict[str, Any]):
    def __iter__(self):
        return (name for name in super().__iter__() if name != "lty")


def register_parser(subcommands: Any) -> None:
    parser = subcommands.add_parser("lty", add_help=False)
    parser.set_defaults(command="lty")
    subcommands._choices_actions = [
        action for action in subcommands._choices_actions if action.dest != "lty"
    ]
    visible_choices = _HiddenCommandMap(subcommands._name_parser_map)
    subcommands._name_parser_map = visible_choices
    subcommands.choices = visible_choices


@COMMANDS.handler("lty")
def print_terminal_banner(_args: Any) -> int:
    art = (
        files("proxy_traffic_lab.cli")
        .joinpath("assets", "terminal-banner.txt")
        .read_text(encoding="utf-8")
    )
    duration = random.SystemRandom().uniform(1.0, 2.0)
    interrupted = False
    try:
        sys.stdout.write(ENTER_FULLSCREEN)
        sys.stdout.write(ACCENT_COLOR)
        sys.stdout.write(art)
        if not art.endswith("\n"):
            sys.stdout.write("\n")
        sys.stdout.flush()
        time.sleep(duration)
    except KeyboardInterrupt:
        interrupted = True
    finally:
        sys.stdout.write(LEAVE_FULLSCREEN)
        sys.stdout.flush()
    return 130 if interrupted else 0
