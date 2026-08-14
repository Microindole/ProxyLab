from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
from typing import Any

from proxy_traffic_lab.common.errors import ConfigurationError


def write_private_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    os.chmod(path, 0o600)



def validate_generated_client_address(client_path: Path) -> str:
    try:
        document = json.loads(client_path.read_text(encoding="utf-8"))
        settings = document["outbounds"][0]["settings"]
        if "address" in settings:
            value = settings["address"]
        else:
            value = settings["servers"][0]["address"]
    except (OSError, json.JSONDecodeError, KeyError, IndexError, TypeError) as exc:
        raise ConfigurationError(
            f"cannot read generated client server address from {client_path}"
        ) from exc
    try:
        return ipaddress.ip_address(value).compressed
    except (ValueError, TypeError) as exc:
        raise ConfigurationError(
            "generated client server address is not an IP; rerun `lab xray render` with the VPS public IP"
        ) from exc


