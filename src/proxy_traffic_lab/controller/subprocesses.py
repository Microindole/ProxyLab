from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


@dataclass(frozen=True)
class CommandResult:
    args: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False


def run_command(
    args: Sequence[str],
    *,
    timeout_seconds: float = 10,
    cwd: Path | None = None,
) -> CommandResult:
    """Run an external command without invoking a shell."""
    safe_args = tuple(str(part) for part in args)
    try:
        completed = subprocess.run(
            safe_args,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return CommandResult(
            args=safe_args,
            returncode=124,
            stdout=_as_text(exc.stdout),
            stderr=_as_text(exc.stderr),
            timed_out=True,
        )
    except OSError as exc:
        return CommandResult(
            args=safe_args,
            returncode=127,
            stdout="",
            stderr=str(exc),
        )

    return CommandResult(
        args=safe_args,
        returncode=completed.returncode,
        stdout=completed.stdout.strip(),
        stderr=completed.stderr.strip(),
    )


def _as_text(value: bytes | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode(errors="replace").strip()
    return value.strip()

