from __future__ import annotations

import json
import os
import secrets
from pathlib import Path

from proxy_traffic_lab.common.errors import ConfigurationError
from proxy_traffic_lab.common.process import run_command
from proxy_traffic_lab.encryptions.material import TlsMaterial
from proxy_traffic_lab.kernels.xray import XRAY_OFFICIAL_IMAGE_TAG


def ensure_reality_material(
    secrets_dir: Path,
    material: TlsMaterial,
) -> TlsMaterial:
    """Ensure Xray REALITY x25519 keys exist in identity.json."""
    if material.reality_private_key and material.reality_public_key:
        return material

    identity_path = secrets_dir / "identity.json"
    try:
        identity = json.loads(identity_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigurationError(f"cannot update {identity_path}: {exc}") from exc

    key_pair = generate_reality_key_pair()
    identity["reality_private_key"] = key_pair["private_key"]
    identity["reality_public_key"] = key_pair["public_key"]
    identity.setdefault("reality_short_id", material.reality_short_id or secrets.token_hex(8))
    identity.setdefault("reality_server_name", material.reality_server_name)
    identity.setdefault("reality_dest", material.reality_dest)
    identity_path.write_text(
        json.dumps(identity, indent=2) + "\n",
        encoding="utf-8",
    )
    os.chmod(identity_path, 0o600)
    return TlsMaterial(
        client_id=material.client_id,
        server_name=material.server_name,
        certificate_sha256=material.certificate_sha256,
        certificate_path=material.certificate_path,
        private_key_path=material.private_key_path,
        reality_private_key=identity["reality_private_key"],
        reality_public_key=identity["reality_public_key"],
        reality_short_id=identity["reality_short_id"],
        reality_server_name=identity["reality_server_name"],
        reality_dest=identity["reality_dest"],
    )


def generate_reality_key_pair() -> dict[str, str]:
    result = run_command(
        ["docker", "run", "--rm", XRAY_OFFICIAL_IMAGE_TAG, "x25519"],
        timeout_seconds=30,
    )
    if result.returncode != 0:
        raise ConfigurationError(
            "cannot generate Xray REALITY x25519 key pair: " + result.stderr
        )
    private_key: str | None = None
    public_key: str | None = None
    for line in result.stdout.splitlines():
        lowered = line.lower()
        if "private" in lowered and ":" in line:
            private_key = line.split(":", 1)[1].strip()
        if "public" in lowered and ":" in line:
            public_key = line.split(":", 1)[1].strip()
    if not private_key or not public_key:
        raise ConfigurationError("cannot parse Xray x25519 key output")
    return {"private_key": private_key, "public_key": public_key}



