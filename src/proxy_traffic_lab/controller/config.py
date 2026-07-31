from __future__ import annotations

from pathlib import Path
from typing import TypeVar

import yaml
from pydantic import BaseModel, ValidationError

from proxy_traffic_lab.controller.errors import ConfigurationError
from proxy_traffic_lab.controller.models import LabConfig, ProtocolMatrix

ModelT = TypeVar("ModelT", bound=BaseModel)


def project_root() -> Path:
    return Path(__file__).resolve().parents[3]


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

