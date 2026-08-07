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
    dataset_class: int = Field(ge=1, le=12)
    enabled: bool = True
    protocol: Literal[
        "vless", "vmess", "trojan", "shadowsocks", "shadowsocksr", "hysteria2"
    ]
    client: Literal[
        "xray", "sing-box", "shadowsocks-rust", "shadowsocksr-libev", "hysteria2"
    ]
    server: Literal[
        "xray", "sing-box", "shadowsocks-rust", "shadowsocksr-libev", "hysteria2"
    ]
    outer_transport: Literal["tcp", "udp"]
    wrapper: Literal["raw", "websocket", "xhttp", "grpc", "quic"]
    security: Literal["none", "tls", "reality", "shadowsocks-2022"]
    flow: str | None = None
    cipher: str | None = None
    protocol_plugin: str | None = None
    obfs: str | None = None
    obfs_mode: str | None = None
    inner_networks: list[Literal["tcp", "udp"]] = Field(min_length=1)

    @model_validator(mode="after")
    def supported_combination(self) -> ProtocolCase:
        expected_ids = {
            1: "class-01-shadowsocks-2022-tcp",
            2: "class-02-shadowsocks-2022-udp",
            3: "class-03-ssr-auth-aes128-md5",
            4: "class-04-ssr-auth-aes128-sha1",
            5: "class-05-vmess-websocket-tls",
            6: "class-06-vmess-xhttp-h2-tls",
            7: "class-07-vless-raw-reality-vision",
            8: "class-08-vless-grpc-tls",
            9: "class-09-trojan-raw-tls",
            10: "class-10-trojan-websocket-tls",
            11: "class-11-hysteria2-quic-tls",
            12: "class-12-hysteria2-quic-salamander-tls",
        }
        if self.id != expected_ids[self.dataset_class]:
            raise ValueError(
                f"dataset class {self.dataset_class} must use id "
                f"{expected_ids[self.dataset_class]}"
            )

        if self.dataset_class == 5:
            expected = (
                self.protocol == "vmess"
                and self.client == "xray"
                and self.server == "xray"
                and self.outer_transport == "tcp"
                and self.wrapper == "websocket"
                and self.security == "tls"
            )
            if not expected:
                raise ValueError("class 5 must be VMess + WebSocket + TLS on Xray")
        if self.dataset_class == 6:
            expected = (
                self.protocol == "vmess"
                and self.client == "xray"
                and self.server == "xray"
                and self.outer_transport == "tcp"
                and self.wrapper == "xhttp"
                and self.security == "tls"
                and self.obfs_mode == "h2"
            )
            if not expected:
                raise ValueError("class 6 must be VMess + XHTTP + H2 + TLS on Xray")
        if self.dataset_class == 7:
            expected = (
                self.protocol == "vless"
                and self.client == "xray"
                and self.server == "xray"
                and self.outer_transport == "tcp"
                and self.wrapper == "raw"
                and self.security == "reality"
                and self.flow == "xtls-rprx-vision"
            )
            if not expected:
                raise ValueError("class 7 must be VLESS + RAW + REALITY + Vision on Xray")
        if self.dataset_class == 8:
            expected = (
                self.protocol == "vless"
                and self.client == "xray"
                and self.server == "xray"
                and self.outer_transport == "tcp"
                and self.wrapper == "grpc"
                and self.security == "tls"
            )
            if not expected:
                raise ValueError("class 8 must be VLESS + gRPC + TLS on Xray")
        return self


class ProtocolMatrix(StrictModel):
    schema_version: Literal[1]
    cases: list[ProtocolCase] = Field(min_length=1)

    @model_validator(mode="after")
    def unique_case_ids(self) -> ProtocolMatrix:
        ids = [case.id for case in self.cases]
        if len(ids) != len(set(ids)):
            raise ValueError("protocol case ids must be unique")
        classes = [case.dataset_class for case in self.cases]
        if len(classes) != len(set(classes)):
            raise ValueError("dataset class numbers must be unique")
        if set(classes) != set(range(1, 13)):
            raise ValueError("protocol matrix must define dataset classes 1 through 12")
        return self
