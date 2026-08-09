from __future__ import annotations

import os
from pathlib import Path
from typing import TypeVar

import yaml
from pydantic import BaseModel, ValidationError

from proxy_traffic_lab.common.errors import ConfigurationError
from proxy_traffic_lab.configuration.composition import (
    CompatibilityCatalog,
    validate_case_composition,
)
from proxy_traffic_lab.configuration.models import (
    LabConfig,
    PlainCaptureConfig,
    ProtocolMatrix,
)
from proxy_traffic_lab.encryptions import EncryptionCatalog
from proxy_traffic_lab.protocols import ProtocolCatalog
from proxy_traffic_lab.transports import TransportCatalog

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


def load_plain_capture_config(path: Path | None = None) -> PlainCaptureConfig:
    return load_yaml(
        path or project_root() / "configs" / "plain_capture.yaml",
        PlainCaptureConfig,
    )


def load_protocol_matrix(path: Path | None = None) -> ProtocolMatrix:
    matrix = load_yaml(
        path or project_root() / "configs" / "protocol_matrix.yaml",
        ProtocolMatrix,
    )
    protocols, transports, encryptions, compatibility = load_component_catalogs()
    for case in matrix.cases:
        validate_case_composition(
            case,
            protocols=protocols,
            transports=transports,
            encryptions=encryptions,
            compatibility=compatibility,
        )
    return matrix


def load_component_catalogs():
    root = project_root() / "configs"
    catalogs = (
        load_yaml(root / "protocols.yaml", ProtocolCatalog),
        load_yaml(root / "transports.yaml", TransportCatalog),
        load_yaml(root / "encryptions.yaml", EncryptionCatalog),
        load_yaml(root / "compatibility.yaml", CompatibilityCatalog),
    )
    protocols, transports, encryptions, compatibility = catalogs
    for index, rule in enumerate(compatibility.rules, start=1):
        unknown: list[str] = []
        if rule.protocol not in protocols.ids():
            unknown.append(f"protocol={rule.protocol}")
        if rule.transport not in transports.ids():
            unknown.append(f"transport={rule.transport}")
        if rule.encryption not in encryptions.ids():
            unknown.append(f"encryption={rule.encryption}")
        unknown.extend(
            f"core={core}" for core in rule.cores if core not in compatibility.cores
        )
        if unknown:
            raise ConfigurationError(
                f"compatibility rule {index} references unknown components: "
                + ", ".join(unknown)
            )
    return catalogs


def find_protocol_case(case_id: str, path: Path | None = None):
    matrix = load_protocol_matrix(path)
    case = next((item for item in matrix.cases if item.id == case_id), None)
    if case is None:
        raise ConfigurationError(f"unknown protocol case: {case_id}")
    return case



