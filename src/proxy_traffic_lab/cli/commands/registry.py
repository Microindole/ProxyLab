from __future__ import annotations

from collections.abc import Callable
from typing import Any

CommandHandler = Callable[[Any], int]


class CommandRegistry:
    def __init__(self) -> None:
        self._handlers: dict[tuple[str, ...], CommandHandler] = {}

    def register(self, path: tuple[str, ...], handler: CommandHandler) -> None:
        if path in self._handlers:
            raise ValueError(f"duplicate command handler: {' '.join(path)}")
        self._handlers[path] = handler

    def handler(self, *path: str) -> Callable[[CommandHandler], CommandHandler]:
        def decorator(func: CommandHandler) -> CommandHandler:
            self.register(tuple(path), func)
            return func

        return decorator

    def dispatch(self, args: Any) -> int | None:
        path = _command_path(args)
        for length in range(len(path), 0, -1):
            handler = self._handlers.get(path[:length])
            if handler is not None:
                return handler(args)
        return None


def _command_path(args: Any) -> tuple[str, ...]:
    command = getattr(args, "command", None)
    if not command:
        return ()
    parts = [command]
    nested_attr = f"{command}_command"
    nested = getattr(args, nested_attr, None)
    if nested:
        parts.append(nested)
    return tuple(parts)


COMMANDS = CommandRegistry()



