from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class HostRole(StrEnum):
    CLIENT = "client"
    SERVER = "server"
    COMBINED_DEV = "combined-dev"


class RuntimeCore(StrEnum):
    XRAY_CORE = "xray-core"
    HYSTERIA2 = "hysteria2"
    SHADOWSOCKSR_NATIVE = "shadowsocksr-native"


class Limits(StrictModel):
    max_experiment_seconds: int = Field(default=300, ge=10, le=3600)
    max_capture_bytes: int = Field(
        default=512 * 1024 * 1024,
        ge=1024 * 1024,
        le=20 * 1024 * 1024 * 1024,
    )
    max_connections: int = Field(default=32, ge=1, le=1024)
    max_bandwidth_mbps: int = Field(default=10, ge=1, le=1000)
    min_free_disk_gib: int = Field(default=10, ge=1, le=10_000)


class VpsConfig(StrictModel):
    host: str | None = None
    ssh_user: str = "root"
    ssh_port: int = Field(default=22, ge=1, le=65535)
    identity_file: Path | None = None


class RuntimeConfig(StrictModel):
    default_core: RuntimeCore = RuntimeCore.XRAY_CORE


class LabConfig(StrictModel):
    schema_version: Literal[1]
    role: HostRole
    data_root: Path
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    limits: Limits = Field(default_factory=Limits)
    vps: VpsConfig = Field(default_factory=VpsConfig)
    runtime: RuntimeConfig = Field(default_factory=RuntimeConfig)


class PlainCaptureCases(StrictModel):
    ipv6: str = Field(pattern=r"^[a-z0-9][a-z0-9-]*$")
    mixed: str = Field(pattern=r"^[a-z0-9][a-z0-9-]*$")


class PlainCaptureConfig(StrictModel):
    schema_version: Literal[1]
    case_ids: PlainCaptureCases


ParameterValue = str | int | float | bool | None


class ProtocolCase(StrictModel):
    """One dataset target assembled from independently declared layers."""

    id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]*$")
    dataset_class: int = Field(ge=0)
    enabled: bool = True
    protocol: str = Field(pattern=r"^[a-z0-9][a-z0-9-]*$")
    client_core: str = Field(pattern=r"^[a-z0-9][a-z0-9-]*$")
    server_core: str = Field(pattern=r"^[a-z0-9][a-z0-9-]*$")
    outer_transport: str = Field(pattern=r"^[a-z0-9][a-z0-9-]*$")
    transport: str = Field(pattern=r"^[a-z0-9][a-z0-9-]*$")
    encryption: str = Field(pattern=r"^[a-z0-9][a-z0-9-]*$")
    parameters: dict[str, ParameterValue] = Field(default_factory=dict)
    inner_networks: list[str] = Field(min_length=1)

    def parameter(self, name: str) -> ParameterValue:
        return self.parameters.get(name)


class ProtocolMatrix(StrictModel):
    schema_version: Literal[1]
    required_dataset_classes: list[int] = Field(min_length=1)
    cases: list[ProtocolCase] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_targets(self) -> ProtocolMatrix:
        required = self.required_dataset_classes
        if len(required) != len(set(required)):
            raise ValueError("required dataset class numbers must be unique")
        ids = [case.id for case in self.cases]
        if len(ids) != len(set(ids)):
            raise ValueError("protocol case ids must be unique")
        classes = [case.dataset_class for case in self.cases]
        if len(classes) != len(set(classes)):
            raise ValueError("dataset class numbers must be unique")
        if set(classes) != set(required):
            missing = sorted(set(required) - set(classes))
            unexpected = sorted(set(classes) - set(required))
            raise ValueError(
                "protocol matrix does not match required_dataset_classes; "
                f"missing={missing}, unexpected={unexpected}"
            )
        disabled = [
            case.dataset_class
            for case in self.cases
            if case.dataset_class in required and not case.enabled
        ]
        if disabled:
            raise ValueError(f"required dataset classes cannot be disabled: {disabled}")
        return self



