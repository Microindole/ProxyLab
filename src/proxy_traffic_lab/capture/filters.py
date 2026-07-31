from __future__ import annotations

import ipaddress


def tunnel_bpf(server_ip: str, port: int, transport: str) -> str:
    address = ipaddress.ip_address(server_ip)
    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    if transport not in {"tcp", "udp"}:
        raise ValueError("transport must be tcp or udp")
    host = f"host {address.compressed}"
    return f"{host} and {transport} port {port}"

