"""Pinned ShadowsocksR-native source reference and image build."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path

from proxy_traffic_lab.common.errors import ConfigurationError
from proxy_traffic_lab.common.process import run_command

SSR_SOURCE_REPOSITORY = "https://github.com/ShadowsocksR-Live/shadowsocksr-native.git"
SSR_SOURCE_COMMIT = "17677abc3c3c0992244b732c7b62397022dbbe79"
SSR_LOCAL_TAG = f"proxy-traffic-lab/shadowsocksr-native:{SSR_SOURCE_COMMIT[:12]}"
IMAGE_ID_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")


def build_pinned_image(project_root: Path) -> str:
    context = project_root / "containers" / "shadowsocksr-native"
    dockerfile = context / "Dockerfile"
    if not dockerfile.is_file():
        raise ConfigurationError(f"ShadowsocksR Dockerfile is missing: {dockerfile}")
    build = run_command(
        [
            "docker",
            "build",
            "--pull",
            "--tag",
            SSR_LOCAL_TAG,
            "--build-arg",
            f"SSR_COMMIT={SSR_SOURCE_COMMIT}",
            str(context),
        ],
        timeout_seconds=1200,
    )
    if build.returncode != 0:
        raise ConfigurationError(
            "cannot build pinned ShadowsocksR-native image: "
            + (build.stderr or build.stdout)
        )
    inspect = run_command(
        ["docker", "image", "inspect", SSR_LOCAL_TAG, "--format", "{{.Id}}"],
        timeout_seconds=15,
    )
    if inspect.returncode != 0:
        raise ConfigurationError(f"cannot inspect ShadowsocksR image: {inspect.stderr}")
    image_id = validate_image_id(inspect.stdout.strip())
    lock_path = project_root / "configs" / "locks" / "shadowsocksr-native.json"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.write_text(
        json.dumps(
            {
                "source_repository": SSR_SOURCE_REPOSITORY,
                "source_commit": SSR_SOURCE_COMMIT,
                "local_tag": SSR_LOCAL_TAG,
                "image": image_id,
                "built_at_utc": datetime.now(UTC).isoformat(),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return image_id



def load_image_lock(project_root: Path) -> str:
    path = project_root / "configs" / "locks" / "shadowsocksr-native.json"
    try:
        lock = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigurationError(f"cannot load ShadowsocksR image lock {path}: {exc}") from exc
    if lock.get("source_commit") != SSR_SOURCE_COMMIT:
        raise ConfigurationError("ShadowsocksR image lock uses an unexpected source commit")
    return validate_image_id(str(lock.get("image", "")))



def validate_image_id(value: str) -> str:
    if not IMAGE_ID_PATTERN.fullmatch(value):
        raise ConfigurationError("ShadowsocksR image must be pinned by local sha256 image ID")
    return value
