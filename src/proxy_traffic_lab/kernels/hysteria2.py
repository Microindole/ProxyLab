"""Pinned Hysteria 2 kernel reference and image acquisition."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path

from proxy_traffic_lab.common.errors import ConfigurationError
from proxy_traffic_lab.common.process import run_command

HYSTERIA2_OFFICIAL_IMAGE_TAG = "tobyxdd/hysteria:v2.10.0"
IMAGE_DIGEST_PATTERN = re.compile(r"^tobyxdd/hysteria@sha256:[0-9a-f]{64}$")


def lock_official_image(lock_path: Path) -> str:
    pull = run_command(["docker", "pull", HYSTERIA2_OFFICIAL_IMAGE_TAG], timeout_seconds=180)
    if pull.returncode != 0:
        raise ConfigurationError(f"cannot pull official Hysteria2 image: {pull.stderr}")
    inspect = run_command(
        [
            "docker",
            "image",
            "inspect",
            HYSTERIA2_OFFICIAL_IMAGE_TAG,
            "--format",
            "{{index .RepoDigests 0}}",
        ],
        timeout_seconds=15,
    )
    if inspect.returncode != 0:
        raise ConfigurationError(f"cannot inspect Hysteria2 image: {inspect.stderr}")
    image = validate_image_digest(inspect.stdout.strip())
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.write_text(
        json.dumps(
            {
                "source_tag": HYSTERIA2_OFFICIAL_IMAGE_TAG,
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
    return validate_image_digest(value.get("image", ""))



def validate_image_digest(value: str) -> str:
    if not IMAGE_DIGEST_PATTERN.fullmatch(value):
        raise ConfigurationError("Hysteria2 image lock is missing or not digest-pinned")
    return value
