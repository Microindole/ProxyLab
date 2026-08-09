from __future__ import annotations

import socket
import struct

import pytest

from proxy_traffic_lab.common.errors import ConfigurationError
from proxy_traffic_lab.configuration.loader import find_protocol_case
from proxy_traffic_lab.traffic.registry import resolve_workload
from proxy_traffic_lab.traffic import socks5_udp


class _Control:
    def __init__(self) -> None:
        self.sent: list[bytes] = []
        self.response = bytearray(
            b"\x05\x00"
            + b"\x05\x00\x00\x01"
            + socket.inet_aton("127.0.0.1")
            + struct.pack("!H", 53000)
        )

    def __enter__(self):
        return self

    def __exit__(self, *_args) -> None:
        return None

    def settimeout(self, _timeout: float) -> None:
        return None

    def sendall(self, value: bytes) -> None:
        self.sent.append(value)

    def recv(self, size: int) -> bytes:
        value = bytes(self.response[:size])
        del self.response[:size]
        return value


class _UdpSocket:
    def __init__(self) -> None:
        self.request = b""

    def __enter__(self):
        return self

    def __exit__(self, *_args) -> None:
        return None

    def settimeout(self, _timeout: float) -> None:
        return None

    def sendto(self, value: bytes, address: tuple[str, int]) -> None:
        assert address == ("127.0.0.1", 53000)
        self.request = value

    def recvfrom(self, _size: int) -> tuple[bytes, tuple[str, int]]:
        payload = self.request[10:]
        response = (
            b"\x00\x00\x00\x01"
            + socket.inet_aton("192.0.2.20")
            + struct.pack("!H", 9000)
            + payload
        )
        return response, ("127.0.0.1", 53000)


def test_class_02_accepts_udp_workload_and_class_01_rejects_it() -> None:
    assert resolve_workload("udp", find_protocol_case("class-02-shadowsocks-2022-udp")).inner_network == "udp"
    with pytest.raises(ConfigurationError, match="inner udp"):
        resolve_workload("udp", find_protocol_case("class-01-shadowsocks-2022-tcp"))


def test_udp_workload_uses_socks5_udp_associate(monkeypatch: pytest.MonkeyPatch) -> None:
    control = _Control()
    udp_socket = _UdpSocket()
    monkeypatch.setattr(socks5_udp.socket, "create_connection", lambda *_args, **_kwargs: control)
    monkeypatch.setattr(socks5_udp.socket, "socket", lambda *_args, **_kwargs: udp_socket)

    result = socks5_udp.generate_socks5_udp_traffic(
        proxy_server="socks5://127.0.0.1:10808",
        target_host="192.0.2.20",
        target_port=9000,
        seed=7,
        count=2,
        payload_bytes=64,
        timeout_seconds=1,
        interval_seconds=0,
    )

    assert control.sent[0] == b"\x05\x01\x00"
    assert control.sent[1][1] == 3
    assert result.attempted == 2
    assert result.successful == 2


def test_udp_workload_requires_explicit_valid_target() -> None:
    with pytest.raises(ConfigurationError, match="target host"):
        socks5_udp.generate_socks5_udp_traffic(
            proxy_server="socks5://127.0.0.1:10808",
            target_host="",
            target_port=9000,
            seed=1,
            count=1,
            payload_bytes=64,
            timeout_seconds=1,
            interval_seconds=0,
        )
