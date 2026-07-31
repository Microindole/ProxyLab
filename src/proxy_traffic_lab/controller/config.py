from __future__ import annotations

import os
from pathlib import Path
from typing import TypeVar

import yaml
from pydantic import BaseModel, ValidationError

from proxy_traffic_lab.controller.errors import ConfigurationError
from proxy_traffic_lab.controller.models import LabConfig, ProtocolMatrix

ModelT = TypeVar("ModelT", bound=BaseModel)


def project_root() -> Path:
    return Path(__file__).resolve().parents[3]


def load_dotenv(path: Path | None = None) -> None:
    """Load simple KEY=VALUE entries without overriding the process environment."""
    env_path = path or project_root() / ".env"
    try:
        lines = env_path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise ConfigurationError(f"cannot read {env_path}: {exc}") from exc
    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ConfigurationError(
                f"invalid .env entry at {env_path}:{line_number}"
            )
        key, value = line.split("=", 1)
        key = key.strip()
        if not key or not key.replace("_", "").isalnum():
            raise ConfigurationError(
                f"invalid .env key at {env_path}:{line_number}"
            )
        os.environ.setdefault(key, value.strip().strip("\"'"))


def load_yaml(path: Path, model: type[ModelT]) -> ModelT:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigurationError(f"cannot read {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise ConfigurationError(f"invalid YAML in {path}: {exc}") from exc

    try:
        return model.model_validate(raw)
    except ValidationError as exc:
        raise ConfigurationError(f"invalid configuration in {path}:\n{exc}") from exc


def load_lab_config(path: Path | None = None) -> LabConfig:
    return load_yaml(path or project_root() / "configs" / "lab.yaml", LabConfig)


def load_protocol_matrix(path: Path | None = None) -> ProtocolMatrix:
    return load_yaml(
        path or project_root() / "configs" / "protocol_matrix.yaml",
        ProtocolMatrix,
    )
