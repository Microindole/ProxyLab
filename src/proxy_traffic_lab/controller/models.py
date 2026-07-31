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


class LabConfig(StrictModel):
    schema_version: Literal[1]
    role: HostRole
    data_root: Path
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    limits: Limits = Field(default_factory=Limits)
    vps: VpsConfig = Field(default_factory=VpsConfig)


class ProtocolCase(StrictModel):
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]*$")
    enabled: bool = True
    protocol: Literal["vless", "vmess", "trojan", "shadowsocks", "hysteria2"]
    client: Literal["xray", "sing-box", "shadowsocks-rust", "hysteria2"]
    server: Literal["xray", "sing-box", "shadowsocks-rust", "hysteria2"]
    outer_transport: Literal["tcp", "udp"]
    wrapper: Literal["raw", "websocket", "grpc", "quic"]
    security: Literal["none", "tls", "reality", "shadowsocks-2022"]
    flow: str | None = None
    inner_networks: list[Literal["tcp", "udp"]] = Field(min_length=1)

    @model_validator(mode="after")
    def supported_combination(self) -> "ProtocolCase":
        if self.id == "vless-tcp-tls":
            expected = (
                self.protocol == "vless"
                and self.client == "xray"
                and self.server == "xray"
                and self.outer_transport == "tcp"
                and self.wrapper == "raw"
                and self.security == "tls"
                and self.flow is None
            )
            if not expected:
                raise ValueError("vless-tcp-tls does not match the supported MVP stack")
        return self


class ProtocolMatrix(StrictModel):
    schema_version: Literal[1]
    cases: list[ProtocolCase] = Field(min_length=1)

    @model_validator(mode="after")
    def unique_case_ids(self) -> "ProtocolMatrix":
        ids = [case.id for case in self.cases]
        if len(ids) != len(set(ids)):
            raise ValueError("protocol case ids must be unique")
        return self

