import ipaddress
import struct
from pathlib import Path

from proxy_traffic_lab.capture.flow_tracker import (
    PcapIpPacketTracker,
    PcapL4ConversationTracker,
    PcapTcpFlowTracker,
)


def _tcp_frame(
    *,
    source: str,
    destination: str,
    source_port: int,
    destination_port: int,
    sequence: int,
    flags: int,
) -> bytes:
    ethernet = b"\x00" * 12 + b"\x08\x00"
    source_ip = ipaddress.ip_address(source).packed
    destination_ip = ipaddress.ip_address(destination).packed
    ipv4 = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        40,
        0,
        0,
        64,
        6,
        0,
        source_ip,
        destination_ip,
    )
    tcp = struct.pack(
        "!HHIIBBHHH",
        source_port,
        destination_port,
        sequence,
        0,
        0x50,
        flags,
        65535,
        0,
        0,
    )
    return ethernet + ipv4 + tcp


def _tcp6_frame(
    *,
    source: str,
    destination: str,
    source_port: int,
    destination_port: int,
    sequence: int,
    flags: int,
) -> bytes:
    ethernet = b"\x00" * 12 + b"\x86\xdd"
    source_ip = ipaddress.ip_address(source).packed
    destination_ip = ipaddress.ip_address(destination).packed
    payload_length = 20
    ipv6 = (
        (6 << 28).to_bytes(4, "big")
        + payload_length.to_bytes(2, "big")
        + bytes([6, 64])
        + source_ip
        + destination_ip
    )
    tcp = struct.pack(
        "!HHIIBBHHH",
        source_port,
        destination_port,
        sequence,
        0,
        0x50,
        flags,
        65535,
        0,
        0,
    )
    return ethernet + ipv6 + tcp


def _pcap(packets: list[bytes]) -> bytes:
    value = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
    for index, packet in enumerate(packets, start=1):
        value.extend(struct.pack("<IIII", index, 0, len(packet), len(packet)))
        value.extend(packet)
    return bytes(value)


def _udp6_frame(
    *,
    source: str,
    destination: str,
    source_port: int,
    destination_port: int,
) -> bytes:
    ethernet = b"\x00" * 12 + b"\x86\xdd"
    source_ip = ipaddress.ip_address(source).packed
    destination_ip = ipaddress.ip_address(destination).packed
    payload_length = 8
    ipv6 = (
        (6 << 28).to_bytes(4, "big")
        + payload_length.to_bytes(2, "big")
        + bytes([17, 64])
        + source_ip
        + destination_ip
    )
    udp = struct.pack("!HHHH", source_port, destination_port, payload_length, 0)
    return ethernet + ipv6 + udp


def test_tracker_counts_syn_once_and_waits_for_both_fins(tmp_path: Path) -> None:
    client = "192.0.2.10"
    server = "203.0.113.20"
    packets = [
        _tcp_frame(
            source=client,
            destination=server,
            source_port=50000,
            destination_port=24443,
            sequence=100,
            flags=0x02,
        ),
        # Retransmitted SYN is the same flow.
        _tcp_frame(
            source=client,
            destination=server,
            source_port=50000,
            destination_port=24443,
            sequence=100,
            flags=0x02,
        ),
        _tcp_frame(
            source=server,
            destination=client,
            source_port=24443,
            destination_port=50000,
            sequence=200,
            flags=0x12,
        ),
        _tcp_frame(
            source=client,
            destination=server,
            source_port=50000,
            destination_port=24443,
            sequence=101,
            flags=0x11,
        ),
        _tcp_frame(
            source=server,
            destination=client,
            source_port=24443,
            destination_port=50000,
            sequence=201,
            flags=0x11,
        ),
        _tcp_frame(
            source=client,
            destination=server,
            source_port=50001,
            destination_port=24443,
            sequence=300,
            flags=0x02,
        ),
        _tcp_frame(
            source=server,
            destination=client,
            source_port=24443,
            destination_port=50001,
            sequence=400,
            flags=0x14,
        ),
        # Mid-stream traffic without an observed SYN is not a complete flow.
        _tcp_frame(
            source=client,
            destination=server,
            source_port=50002,
            destination_port=24443,
            sequence=500,
            flags=0x18,
        ),
    ]
    path = tmp_path / "capture.pcap"
    path.write_bytes(_pcap(packets))

    stats = PcapTcpFlowTracker(path).poll()

    assert stats.total_flows == 2
    assert stats.active_flows == 0
    assert stats.completed_flows == 2


def test_tracker_reads_only_new_packets_from_growing_pcap(tmp_path: Path) -> None:
    path = tmp_path / "capture.pcap"
    syn = _tcp_frame(
        source="192.0.2.10",
        destination="203.0.113.20",
        source_port=51000,
        destination_port=24443,
        sequence=10,
        flags=0x02,
    )
    path.write_bytes(_pcap([syn]))
    tracker = PcapTcpFlowTracker(path)
    assert tracker.poll().total_flows == 1
    assert tracker.poll().total_flows == 1

    rst = _tcp_frame(
        source="203.0.113.20",
        destination="192.0.2.10",
        source_port=24443,
        destination_port=51000,
        sequence=20,
        flags=0x14,
    )
    with path.open("ab") as stream:
        stream.write(struct.pack("<IIII", 2, 0, len(rst), len(rst)))
        stream.write(rst)

    stats = tracker.poll()
    assert stats.total_flows == 1
    assert stats.active_flows == 0


def test_tracker_reports_ipv4_and_ipv6_flow_counts(tmp_path: Path) -> None:
    path = tmp_path / "capture.pcap"
    path.write_bytes(
        _pcap(
            [
                _tcp_frame(
                    source="192.0.2.10",
                    destination="203.0.113.20",
                    source_port=51000,
                    destination_port=443,
                    sequence=10,
                    flags=0x02,
                ),
                _tcp6_frame(
                    source="2001:db8::10",
                    destination="2001:db8::20",
                    source_port=52000,
                    destination_port=443,
                    sequence=20,
                    flags=0x02,
                ),
                _tcp6_frame(
                    source="2001:db8::20",
                    destination="2001:db8::10",
                    source_port=443,
                    destination_port=52000,
                    sequence=30,
                    flags=0x14,
                ),
            ]
        )
    )

    stats = PcapTcpFlowTracker(path).poll()

    assert stats.total_flows == 2
    assert stats.ipv4_flows == 1
    assert stats.ipv6_flows == 1
    assert stats.active_ipv4_flows == 1
    assert stats.active_ipv6_flows == 0
    assert stats.completed_ipv6_flows == 1


def test_tracker_established_mode_ignores_unanswered_syn(tmp_path: Path) -> None:
    path = tmp_path / "capture.pcap"
    path.write_bytes(
        _pcap(
            [
                _tcp_frame(
                    source="192.0.2.10",
                    destination="203.0.113.20",
                    source_port=51000,
                    destination_port=443,
                    sequence=10,
                    flags=0x02,
                ),
                _tcp_frame(
                    source="192.0.2.10",
                    destination="203.0.113.20",
                    source_port=51000,
                    destination_port=443,
                    sequence=10,
                    flags=0x02,
                ),
                _tcp_frame(
                    source="203.0.113.20",
                    destination="192.0.2.10",
                    source_port=443,
                    destination_port=51000,
                    sequence=20,
                    flags=0x12,
                ),
                _tcp_frame(
                    source="192.0.2.10",
                    destination="203.0.113.20",
                    source_port=51001,
                    destination_port=443,
                    sequence=30,
                    flags=0x02,
                ),
            ]
        )
    )

    syn_stats = PcapTcpFlowTracker(path).poll()
    established_stats = PcapTcpFlowTracker(path, count_mode="established").poll()

    assert syn_stats.total_flows == 2
    assert established_stats.total_flows == 1
    assert established_stats.ipv4_flows == 1


def test_l4_conversation_tracker_counts_tcp_and_udp_5tuples(tmp_path: Path) -> None:
    path = tmp_path / "capture.pcap"
    path.write_bytes(
        _pcap(
            [
                # Mid-stream TCP still counts as a Wireshark-style conversation.
                _tcp_frame(
                    source="192.0.2.10",
                    destination="203.0.113.20",
                    source_port=51000,
                    destination_port=443,
                    sequence=10,
                    flags=0x18,
                ),
                # Reverse direction is the same bidirectional 5-tuple.
                _tcp_frame(
                    source="203.0.113.20",
                    destination="192.0.2.10",
                    source_port=443,
                    destination_port=51000,
                    sequence=20,
                    flags=0x18,
                ),
                _tcp6_frame(
                    source="2001:db8::10",
                    destination="2001:db8::20",
                    source_port=52000,
                    destination_port=443,
                    sequence=30,
                    flags=0x02,
                ),
                _udp6_frame(
                    source="2001:db8::10",
                    destination="2001:db8::20",
                    source_port=53000,
                    destination_port=443,
                ),
                _udp6_frame(
                    source="2001:db8::20",
                    destination="2001:db8::10",
                    source_port=443,
                    destination_port=53000,
                ),
            ]
        )
    )

    stats = PcapL4ConversationTracker(path).poll()

    assert stats.total_flows == 3
    assert stats.tcp_conversations == 2
    assert stats.udp_conversations == 1
    assert stats.ipv4_flows == 1
    assert stats.ipv6_flows == 2
    assert stats.active_flows == 0


def test_l4_conversation_tracker_counts_reused_tcp_5tuple_streams(
    tmp_path: Path,
) -> None:
    path = tmp_path / "capture.pcap"
    path.write_bytes(
        _pcap(
            [
                _tcp_frame(
                    source="192.0.2.10",
                    destination="203.0.113.20",
                    source_port=51000,
                    destination_port=443,
                    sequence=10,
                    flags=0x02,
                ),
                # Same 5-tuple reused later with a different ISN is a second
                # Wireshark-style TCP stream.
                _tcp_frame(
                    source="192.0.2.10",
                    destination="203.0.113.20",
                    source_port=51000,
                    destination_port=443,
                    sequence=999,
                    flags=0x02,
                ),
                # Retransmitted SYN is not a third stream.
                _tcp_frame(
                    source="192.0.2.10",
                    destination="203.0.113.20",
                    source_port=51000,
                    destination_port=443,
                    sequence=999,
                    flags=0x02,
                ),
            ]
        )
    )

    stats = PcapL4ConversationTracker(path).poll()

    assert stats.total_flows == 2
    assert stats.tcp_conversations == 2
    assert stats.udp_conversations == 0


def test_ip_packet_tracker_counts_families_and_udp_443(tmp_path: Path) -> None:
    path = tmp_path / "capture.pcap"
    path.write_bytes(
        _pcap(
            [
                _tcp_frame(
                    source="192.0.2.10",
                    destination="203.0.113.20",
                    source_port=51000,
                    destination_port=443,
                    sequence=10,
                    flags=0x02,
                ),
                _udp6_frame(
                    source="2001:db8::10",
                    destination="2001:db8::20",
                    source_port=53000,
                    destination_port=443,
                ),
                _udp6_frame(
                    source="2001:db8::20",
                    destination="2001:db8::10",
                    source_port=443,
                    destination_port=53000,
                ),
            ]
        )
    )

    stats = PcapIpPacketTracker(path).poll()

    assert stats.ipv4_packets == 1
    assert stats.ipv6_packets == 2
    assert stats.tcp_packets == 1
    assert stats.udp_packets == 2
    assert stats.udp_443_conversations == 1
