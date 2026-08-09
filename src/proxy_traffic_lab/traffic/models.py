from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class WorkloadResult:
    attempted: int
    successful: int
    events: tuple[dict[str, Any], ...]

