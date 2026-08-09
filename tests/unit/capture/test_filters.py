import pytest

from proxy_traffic_lab.capture.filters import tunnel_bpf


def test_tcp_tunnel_filter() -> None:
    assert (
        tunnel_bpf("203.0.113.10", 24443, "tcp")
        == "host 203.0.113.10 and tcp port 24443"
    )


def test_udp_tunnel_filter() -> None:
    assert (
        tunnel_bpf("2001:db8::10", 24443, "udp")
        == "host 2001:db8::10 and udp port 24443"
    )


@pytest.mark.parametrize(
    ("ip", "port", "transport"),
    [
        ("not-an-ip", 443, "tcp"),
        ("203.0.113.10", 0, "tcp"),
        ("203.0.113.10", 443, "quic"),
    ],
)
def test_rejects_invalid_filters(ip: str, port: int, transport: str) -> None:
    with pytest.raises(ValueError):
        tunnel_bpf(ip, port, transport)
