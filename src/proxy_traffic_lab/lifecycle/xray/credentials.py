from __future__ import annotations

import json
import os
import re
import secrets
from dataclasses import replace
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
    return replace(
        material,
        reality_private_key=identity["reality_private_key"],
        reality_public_key=identity["reality_public_key"],
        reality_short_id=identity["reality_short_id"],
        reality_server_name=identity["reality_server_name"],
        reality_dest=identity["reality_dest"],
    )


def ensure_vless_encryption_material(
    secrets_dir: Path,
    material: TlsMaterial,
) -> TlsMaterial:
    """Ensure one persistent X25519-authenticated VLESS Encryption pair exists."""
    if material.vless_decryption and material.vless_encryption:
        return material

    identity_path = secrets_dir / "identity.json"
    try:
        identity = json.loads(identity_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigurationError(f"cannot update {identity_path}: {exc}") from exc

    key_pair = generate_vless_encryption_pair()
    identity["vless_decryption"] = key_pair["decryption"]
    identity["vless_encryption"] = key_pair["encryption"]
    identity_path.write_text(
        json.dumps(identity, indent=2) + "\n",
        encoding="utf-8",
    )
    os.chmod(identity_path, 0o600)
    return replace(
        material,
        vless_decryption=identity["vless_decryption"],
        vless_encryption=identity["vless_encryption"],
    )


def generate_vless_encryption_pair() -> dict[str, str]:
    result = run_command(
        ["docker", "run", "--rm", XRAY_OFFICIAL_IMAGE_TAG, "vlessenc"],
        timeout_seconds=30,
    )
    if result.returncode != 0:
        raise ConfigurationError(
            "cannot generate Xray VLESS Encryption pair: " + result.stderr
        )
    output = "\n".join(part for part in (result.stdout, result.stderr) if part)
    decryption_match = re.search(r'"decryption"\s*:\s*"(?P<value>[^"]+)"', output)
    encryption_match = re.search(r'"encryption"\s*:\s*"(?P<value>[^"]+)"', output)
    if not decryption_match or not encryption_match:
        detail = output.strip() or "<empty output>"
        raise ConfigurationError(f"cannot parse Xray vlessenc output: {detail}")
    return {
        "decryption": decryption_match.group("value"),
        "encryption": encryption_match.group("value"),
    }


def generate_reality_key_pair() -> dict[str, str]:
    result = run_command(
        ["docker", "run", "--rm", XRAY_OFFICIAL_IMAGE_TAG, "x25519"],
        timeout_seconds=30,
    )
    if result.returncode != 0:
        raise ConfigurationError(
            "cannot generate Xray REALITY x25519 key pair: " + result.stderr
        )
    output = "\n".join(part for part in (result.stdout, result.stderr) if part)
    private_key: str | None = None
    public_key: str | None = None
    for line in output.splitlines():
        private_match = re.search(
            r"\bprivate\s*key\b\s*[:=]\s*(?P<value>\S+)",
            line,
            flags=re.IGNORECASE,
        ) or re.search(
            r"\bprivateKey\b\s*[:=]\s*(?P<value>\S+)",
            line,
            flags=re.IGNORECASE,
        )
        public_match = re.search(
            r"\bpublic\s*key\b\s*[:=]\s*(?P<value>\S+)",
            line,
            flags=re.IGNORECASE,
        ) or re.search(
            r"\bpublicKey\b\s*[:=]\s*(?P<value>\S+)",
            line,
            flags=re.IGNORECASE,
        ) or re.search(
            r"\bpassword\b\s*[:=]\s*(?P<value>\S+)",
            line,
            flags=re.IGNORECASE,
        )
        if private_match:
            private_key = private_match.group("value").strip()
        if public_match:
            public_key = public_match.group("value").strip()
    if not private_key or not public_key:
        detail = output.strip() or "<empty output>"
        raise ConfigurationError(f"cannot parse Xray x25519 key output: {detail}")
    return {"private_key": private_key, "public_key": public_key}
