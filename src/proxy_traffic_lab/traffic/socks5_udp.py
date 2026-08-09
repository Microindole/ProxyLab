"""Generate authorized UDP echo traffic through a standard SOCKS5 proxy."""

from __future__ import annotations

import ipaddress
import random
import socket
import struct
import time
from urllib.parse import urlparse

from proxy_traffic_lab.common.errors import ConfigurationError
from proxy_traffic_lab.traffic.models import WorkloadResult


def generate_socks5_udp_traffic(
    *,
    proxy_server: str,
    target_host: str,
    target_port: int,
    seed: int,
    count: int,
    payload_bytes: int,
    timeout_seconds: float,
    interval_seconds: float,
) -> WorkloadResult:
    """Send deterministic datagrams to an explicit UDP echo target."""
    proxy_host, proxy_port = _parse_proxy(proxy_server)
    _validate_inputs(
        target_host=target_host,
        target_port=target_port,
        count=count,
        payload_bytes=payload_bytes,
        timeout_seconds=timeout_seconds,
        interval_seconds=interval_seconds,
    )
    rng = random.Random(seed)
    events: list[dict[str, object]] = []
    successful = 0

    try:
        control = socket.create_connection((proxy_host, proxy_port), timeout=timeout_seconds)
    except OSError as exc:
        raise ConfigurationError(
            f"SOCKS5 control connection failed at {proxy_host}:{proxy_port}: {exc}"
        ) from exc

    with control:
        control.settimeout(timeout_seconds)
        _negotiate_no_auth(control)
        relay_host, relay_port = _request_udp_associate(control, proxy_host)
        family = socket.AF_INET6 if _is_ipv6(relay_host) else socket.AF_INET
        with socket.socket(family, socket.SOCK_DGRAM) as udp_socket:
            udp_socket.settimeout(timeout_seconds)
            for index in range(count):
                payload = _payload(rng, index=index, size=payload_bytes)
                packet = _udp_request(target_host, target_port, payload)
                started = time.monotonic()
                event: dict[str, object] = {
                    "index": index + 1,
                    "payload_bytes": len(payload),
                }
                try:
                    udp_socket.sendto(packet, (relay_host, relay_port))
                    response, _ = udp_socket.recvfrom(max(65535, payload_bytes + 512))
                    response_payload = _udp_response_payload(response)
                    if response_payload != payload:
                        raise ConfigurationError("UDP echo response payload did not match request")
                    successful += 1
                    event["status"] = "ok"
                except (OSError, ConfigurationError) as exc:
                    event.update(
                        {
                            "status": "error",
                            "error": f"{type(exc).__name__}: {str(exc)[:300]}",
                        }
                    )
                event["duration_seconds"] = round(time.monotonic() - started, 3)
                events.append(event)
                if interval_seconds and index + 1 < count:
                    time.sleep(interval_seconds)

    return WorkloadResult(
        attempted=len(events),
        successful=successful,
        events=tuple(events),
    )


def _parse_proxy(proxy_server: str) -> tuple[str, int]:
    parsed = urlparse(proxy_server)
    if (
        parsed.scheme != "socks5"
        or not parsed.hostname
        or not parsed.port
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ConfigurationError(
            "UDP workload requires an unauthenticated proxy URL like "
            "socks5://127.0.0.1:10808"
        )
    return parsed.hostname, parsed.port


def _validate_inputs(
    *,
    target_host: str,
    target_port: int,
    count: int,
    payload_bytes: int,
    timeout_seconds: float,
    interval_seconds: float,
) -> None:
    if not target_host.strip():
        raise ConfigurationError("UDP target host is required")
    if not 1 <= target_port <= 65535:
        raise ConfigurationError("UDP target port must be between 1 and 65535")
    if not 1 <= count <= 100_000:
        raise ConfigurationError("UDP datagram count must be between 1 and 100000")
    if not 32 <= payload_bytes <= 60_000:
        raise ConfigurationError("UDP payload size must be between 32 and 60000 bytes")
    if timeout_seconds <= 0 or interval_seconds < 0:
        raise ConfigurationError("UDP timeout must be positive and interval cannot be negative")


def _negotiate_no_auth(control: socket.socket) -> None:
    control.sendall(b"\x05\x01\x00")
    response = _recv_exact(control, 2)
    if response != b"\x05\x00":
        raise ConfigurationError("SOCKS5 proxy rejected no-authentication negotiation")


def _request_udp_associate(control: socket.socket, proxy_host: str) -> tuple[str, int]:
    control.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
    version, reply, reserved, address_type = _recv_exact(control, 4)
    if version != 5 or reserved != 0 or reply != 0:
        raise ConfigurationError(f"SOCKS5 UDP ASSOCIATE failed with reply {reply}")
    relay_host = _recv_address(control, address_type)
    relay_port = struct.unpack("!H", _recv_exact(control, 2))[0]
    if relay_host in {"0.0.0.0", "::"}:
        relay_host = proxy_host
    if relay_port == 0:
        raise ConfigurationError("SOCKS5 proxy returned an invalid UDP relay port")
    return relay_host, relay_port


def _udp_request(host: str, port: int, payload: bytes) -> bytes:
    address_type, encoded = _encode_address(host)
    return b"\x00\x00\x00" + bytes([address_type]) + encoded + struct.pack("!H", port) + payload


def _udp_response_payload(packet: bytes) -> bytes:
    if len(packet) < 4 or packet[:2] != b"\x00\x00" or packet[2] != 0:
        raise ConfigurationError("invalid or fragmented SOCKS5 UDP response")
    address_type = packet[3]
    offset = 4
    if address_type == 1:
        offset += 4
    elif address_type == 4:
        offset += 16
    elif address_type == 3:
        if len(packet) <= offset:
            raise ConfigurationError("truncated SOCKS5 UDP domain response")
        offset += 1 + packet[offset]
    else:
        raise ConfigurationError("SOCKS5 UDP response used an unknown address type")
    if len(packet) < offset + 2:
        raise ConfigurationError("truncated SOCKS5 UDP response")
    return packet[offset + 2 :]


def _encode_address(host: str) -> tuple[int, bytes]:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        encoded = host.encode("idna")
        if not encoded or len(encoded) > 255:
            raise ConfigurationError("UDP target hostname is invalid")
        return 3, bytes([len(encoded)]) + encoded
    return (1, address.packed) if address.version == 4 else (4, address.packed)


def _recv_address(control: socket.socket, address_type: int) -> str:
    if address_type == 1:
        return socket.inet_ntop(socket.AF_INET, _recv_exact(control, 4))
    if address_type == 4:
        return socket.inet_ntop(socket.AF_INET6, _recv_exact(control, 16))
    if address_type == 3:
        size = _recv_exact(control, 1)[0]
        return _recv_exact(control, size).decode("idna")
    raise ConfigurationError("SOCKS5 proxy returned an unknown relay address type")


def _recv_exact(control: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = control.recv(size - len(chunks))
        if not chunk:
            raise ConfigurationError("SOCKS5 control connection closed unexpectedly")
        chunks.extend(chunk)
    return bytes(chunks)


def _payload(rng: random.Random, *, index: int, size: int) -> bytes:
    prefix = f"proxy-lab-udp-{index:08d}:".encode()
    return prefix + rng.randbytes(size - len(prefix))


def _is_ipv6(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).version == 6
    except ValueError:
        return False

