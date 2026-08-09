from __future__ import annotations

import ipaddress
import json
import os
import uuid
from pathlib import Path

from proxy_traffic_lab.common.errors import ConfigurationError
from proxy_traffic_lab.common.process import run_command
from proxy_traffic_lab.encryptions.material import TlsMaterial


def create_tls_material(
    secrets_dir: Path,
    *,
    server_name: str = "lab.invalid",
    validity_days: int = 30,
) -> TlsMaterial:
    """Create short-lived lab TLS material. Existing secrets are never overwritten."""
    if not server_name or len(server_name) > 253:
        raise ConfigurationError("server_name must be a non-empty DNS name or IP")
    if not 1 <= validity_days <= 397:
        raise ConfigurationError("validity_days must be between 1 and 397")

    secrets_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    certificate_path = secrets_dir / "server.crt"
    private_key_path = secrets_dir / "server.key"
    identity_path = secrets_dir / "identity.json"
    for path in (certificate_path, private_key_path, identity_path):
        if path.exists():
            raise ConfigurationError(f"refusing to overwrite existing secret: {path}")

    san_kind = "IP" if looks_like_ip(server_name) else "DNS"
    result = run_command(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-sha256",
            "-nodes",
            "-days",
            str(validity_days),
            "-subj",
            f"/CN={server_name}",
            "-addext",
            f"subjectAltName={san_kind}:{server_name}",
            "-keyout",
            str(private_key_path),
            "-out",
            str(certificate_path),
        ],
        timeout_seconds=30,
    )
    if result.returncode != 0:
        private_key_path.unlink(missing_ok=True)
        certificate_path.unlink(missing_ok=True)
        raise ConfigurationError(f"openssl certificate generation failed: {result.stderr}")

    fingerprint = certificate_fingerprint(certificate_path)
    client_id = str(uuid.uuid4())
    identity_path.write_text(
        json.dumps(
            {
                "client_id": client_id,
                "server_name": server_name,
                "certificate_sha256": fingerprint,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    os.chmod(private_key_path, 0o600)
    os.chmod(certificate_path, 0o600)
    os.chmod(identity_path, 0o600)
    return TlsMaterial(
        client_id=client_id,
        server_name=server_name,
        certificate_sha256=fingerprint,
        certificate_path=certificate_path,
        private_key_path=private_key_path,
    )

def load_tls_material(secrets_dir: Path) -> TlsMaterial:
    identity_path = secrets_dir / "identity.json"
    try:
        identity = json.loads(identity_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigurationError(f"cannot load {identity_path}: {exc}") from exc
    required = {"client_id", "server_name", "certificate_sha256"}
    if not required.issubset(identity):
        raise ConfigurationError(f"missing fields in {identity_path}")
    try:
        uuid.UUID(identity["client_id"])
    except (ValueError, TypeError) as exc:
        raise ConfigurationError("invalid client UUID") from exc
    return TlsMaterial(
        client_id=identity["client_id"],
        server_name=identity["server_name"],
        certificate_sha256=identity["certificate_sha256"],
        certificate_path=secrets_dir / "server.crt",
        private_key_path=secrets_dir / "server.key",
        reality_private_key=identity.get("reality_private_key"),
        reality_public_key=identity.get("reality_public_key"),
        reality_short_id=identity.get("reality_short_id"),
        reality_server_name=identity.get("reality_server_name", "www.microsoft.com"),
        reality_dest=identity.get("reality_dest", "www.microsoft.com:443"),
    )


def certificate_fingerprint(path: Path) -> str:
    result = run_command(
        ["openssl", "x509", "-in", str(path), "-noout", "-fingerprint", "-sha256"],
        timeout_seconds=10,
    )
    if result.returncode != 0 or "=" not in result.stdout:
        raise ConfigurationError(f"cannot fingerprint certificate: {result.stderr}")
    return result.stdout.split("=", 1)[1].replace(":", "").lower()


def looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True
