"""Pinned Xray-core reference and image acquisition."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path

from proxy_traffic_lab.common.errors import ConfigurationError
from proxy_traffic_lab.common.process import run_command

XRAY_OFFICIAL_IMAGE_TAG = "ghcr.io/xtls/xray-core:26.2.6"
IMAGE_DIGEST_PATTERN = re.compile(r"^ghcr\.io/xtls/xray-core@sha256:[0-9a-f]{64}$")


def validate_official_image_digest(image: str) -> str:
    if not IMAGE_DIGEST_PATTERN.fullmatch(image):
        raise ConfigurationError(
            "Xray image must be the official GHCR image pinned by sha256 digest"
        )
    return image



def lock_official_image(lock_path: Path) -> str:
    pull = run_command(["docker", "pull", XRAY_OFFICIAL_IMAGE_TAG], timeout_seconds=180)
    if pull.returncode != 0:
        raise ConfigurationError(f"cannot pull official Xray image: {pull.stderr}")
    inspect = run_command(
        [
            "docker",
            "image",
            "inspect",
            XRAY_OFFICIAL_IMAGE_TAG,
            "--format",
            "{{index .RepoDigests 0}}",
        ],
        timeout_seconds=15,
    )
    if inspect.returncode != 0:
        raise ConfigurationError(f"cannot inspect Xray image: {inspect.stderr}")
    image = validate_official_image_digest(inspect.stdout.strip())
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.write_text(
        json.dumps(
            {
                "source_tag": XRAY_OFFICIAL_IMAGE_TAG,
                "image": image,
                "locked_at_utc": datetime.now(UTC).isoformat(),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return image



def load_image_lock(lock_path: Path) -> str:
    try:
        value = json.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigurationError(f"cannot load image lock {lock_path}: {exc}") from exc
    return validate_official_image_digest(value.get("image", ""))



def local_official_image_id() -> str:
    result = run_command(
        ["docker", "image", "inspect", XRAY_OFFICIAL_IMAGE_TAG, "--format", "{{.Id}}"],
        timeout_seconds=15,
    )
    if result.returncode != 0 or not re.fullmatch(r"sha256:[0-9a-f]{64}", result.stdout):
        raise ConfigurationError(
            f"local official Xray image is missing: {XRAY_OFFICIAL_IMAGE_TAG}"
        )
    return result.stdout



