import ipaddress
import struct
from pathlib import Path

from proxy_traffic_lab.capture.flow_tracker import PcapTcpFlowTracker


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


def _pcap(packets: list[bytes]) -> bytes:
    value = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
    for index, packet in enumerate(packets, start=1):
        value.extend(struct.pack("<IIII", index, 0, len(packet), len(packet)))
        value.extend(packet)
    return bytes(value)


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
