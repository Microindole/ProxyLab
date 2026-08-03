from __future__ import annotations

import ipaddress
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class TrafficProfile(StrEnum):
    WEB = "web"
    DOWNLOAD = "download"
    UPLOAD = "upload"
    VIDEO = "video"
    WEBSOCKET = "websocket"
    UDP = "udp"
    MIXED = "mixed"


class CapturePolicy(StrictModel):
    """Immutable capture settings shared by every formal protocol class."""

    file_format: Literal["pcap"] = "pcap"
    backend: Literal["dumpcap"] = "dumpcap"
    snaplen: Literal[0] = 0
    name_resolution: Literal[False] = False
    full_packets: Literal[True] = True


class ExperimentSpec(StrictModel):
    schema_version: Literal[1] = 1
    case_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]*$")
    dataset_class: int = Field(ge=1, le=12)
    profile: TrafficProfile
    inner_network: Literal["tcp", "udp"]
    outer_transport: Literal["tcp", "udp"]
    server_ip: str
    server_port: int = Field(ge=1, le=65535)
    proxy_url: str | None = None
    duration_seconds: int = Field(ge=10, le=3600)
    seed: int = Field(ge=0, le=2**63 - 1)
    output_root: Path
    capture: CapturePolicy = Field(default_factory=CapturePolicy)

    @field_validator("server_ip")
    @classmethod
    def normalize_server_ip(cls, value: str) -> str:
        return ipaddress.ip_address(value).compressed

    @model_validator(mode="after")
    def profile_matches_inner_network(self) -> ExperimentSpec:
        if self.profile == TrafficProfile.UDP and self.inner_network != "udp":
            raise ValueError("udp profile requires inner_network=udp")
        if self.profile != TrafficProfile.UDP and self.inner_network != "tcp":
            raise ValueError(
                "web/download/upload/video/websocket/mixed profiles require inner_network=tcp"
            )
        return self


class CaptureMetadata(StrictModel):
    side: Literal["client"] = "client"
    backend: Literal["dumpcap"] = "dumpcap"
    interface: str
    bpf: str
    format: Literal["pcap"] = "pcap"
    snaplen: Literal[0] = 0
    link_type: str
    started_at_utc: datetime
    ended_at_utc: datetime
    packet_count: int = Field(ge=0)
    captured_bytes: int = Field(ge=0)
    file_bytes: int = Field(ge=0)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    dropped_packets: int = Field(ge=0)


class ValidationMetadata(StrictModel):
    status: Literal["passed", "failed"]
    pcap_readable: bool
    expected_tunnel_only: bool
    traffic_success: bool
    errors: list[str] = Field(default_factory=list)


class SessionMetadata(StrictModel):
    schema_version: Literal["1.0.0"] = "1.0.0"
    sample_id: str
    experiment: ExperimentSpec
    protocol: dict[str, object]
    capture: CaptureMetadata
    traffic: dict[str, object]
    validation: ValidationMetadata
