from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

from proxy_traffic_lab.controller.errors import ConfigurationError


@dataclass(frozen=True)
class TcpFlowStats:
    total_flows: int
    active_flows: int
    completed_flows: int
    ipv4_flows: int = 0
    ipv6_flows: int = 0
    active_ipv4_flows: int = 0
    active_ipv6_flows: int = 0
    completed_ipv4_flows: int = 0
    completed_ipv6_flows: int = 0


@dataclass(frozen=True)
class IpPacketStats:
    ipv4_packets: int
    ipv6_packets: int
    tcp_packets: int
    udp_packets: int
    udp_443_conversations: int


@dataclass
class _TcpFlow:
    syn_forward: tuple[bytes, bytes, int, int]
    ip_version: int
    active: bool = True
    fin_sides: set[int] = field(default_factory=set)


class PcapTcpFlowTracker:
    """Incrementally count complete outer TCP connection starts in a growing PCAP.

    A flow begins at a SYN without ACK. Retransmitted SYN packets are deduplicated
    by directional four-tuple and initial sequence number. A flow is inactive after
    an RST or after FIN has been observed from both directions.
    """

    def __init__(self, path: Path):
        self.path = path
        self._byte_order: str | None = None
        self._offset = 0
        self._flows: list[_TcpFlow] = []
        self._tuple_to_flow: dict[tuple[bytes, bytes, int, int], int] = {}
        self._seen_syns: dict[tuple[bytes, bytes, int, int, int], int] = {}

    def poll(self) -> TcpFlowStats:
        if not self.path.is_file():
            return self.stats()
        with self.path.open("rb") as stream:
            if self._byte_order is None:
                header = stream.read(24)
                if len(header) < 24:
                    return self.stats()
                magic = header[:4]
                if magic in {b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"}:
                    self._byte_order = "<"
                elif magic in {b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"}:
                    self._byte_order = ">"
                else:
                    raise ConfigurationError("flow tracking requires classic PCAP format")
                _, _, _, _, _, link_type = struct.unpack(
                    f"{self._byte_order}HHIIII", header[4:]
                )
                if link_type != 1:
                    raise ConfigurationError(
                        "flow tracking currently requires Ethernet (DLT_EN10MB) PCAP"
                    )
                self._offset = 24
            stream.seek(self._offset)
            while True:
                packet_offset = stream.tell()
                packet_header = stream.read(16)
                if len(packet_header) < 16:
                    break
                _, _, included_length, _ = struct.unpack(
                    f"{self._byte_order}IIII", packet_header
                )
                packet = stream.read(included_length)
                if len(packet) < included_length:
                    stream.seek(packet_offset)
                    break
                self._consume_ethernet(packet)
                self._offset = stream.tell()
        return self.stats()

    def stats(self) -> TcpFlowStats:
        active = sum(flow.active for flow in self._flows)
        ipv4 = sum(flow.ip_version == 4 for flow in self._flows)
        ipv6 = sum(flow.ip_version == 6 for flow in self._flows)
        active_ipv4 = sum(flow.active and flow.ip_version == 4 for flow in self._flows)
        active_ipv6 = sum(flow.active and flow.ip_version == 6 for flow in self._flows)
        return TcpFlowStats(
            total_flows=len(self._flows),
            active_flows=active,
            completed_flows=len(self._flows) - active,
            ipv4_flows=ipv4,
            ipv6_flows=ipv6,
            active_ipv4_flows=active_ipv4,
            active_ipv6_flows=active_ipv6,
            completed_ipv4_flows=ipv4 - active_ipv4,
            completed_ipv6_flows=ipv6 - active_ipv6,
        )

    def _consume_ethernet(self, packet: bytes) -> None:
        if len(packet) < 14:
            return
        ether_type = int.from_bytes(packet[12:14], "big")
        offset = 14
        while ether_type in {0x8100, 0x88A8}:
            if len(packet) < offset + 4:
                return
            ether_type = int.from_bytes(packet[offset + 2 : offset + 4], "big")
            offset += 4
        if ether_type == 0x0800:
            parsed = self._parse_ipv4_tcp(packet, offset)
            ip_version = 4
        elif ether_type == 0x86DD:
            parsed = self._parse_ipv6_tcp(packet, offset)
            ip_version = 6
        else:
            return
        if parsed is None:
            return
        source, destination, source_port, destination_port, sequence, flags = parsed
        forward = (source, destination, source_port, destination_port)
        reverse = (destination, source, destination_port, source_port)
        syn = bool(flags & 0x02)
        ack = bool(flags & 0x10)
        flow_index: int | None = None
        if syn and not ack:
            syn_key = (*forward, sequence)
            flow_index = self._seen_syns.get(syn_key)
            if flow_index is None:
                flow_index = len(self._flows)
                self._flows.append(_TcpFlow(syn_forward=forward, ip_version=ip_version))
                self._seen_syns[syn_key] = flow_index
                self._tuple_to_flow[forward] = flow_index
                self._tuple_to_flow[reverse] = flow_index
        else:
            flow_index = self._tuple_to_flow.get(forward)
        if flow_index is None:
            return
        flow = self._flows[flow_index]
        if flags & 0x04:
            flow.active = False
        if flags & 0x01:
            flow.fin_sides.add(0 if forward == flow.syn_forward else 1)
            if len(flow.fin_sides) == 2:
                flow.active = False

    @staticmethod
    def _parse_ipv4_tcp(
        packet: bytes, offset: int
    ) -> tuple[bytes, bytes, int, int, int, int] | None:
        if len(packet) < offset + 20:
            return None
        header_length = (packet[offset] & 0x0F) * 4
        if header_length < 20 or len(packet) < offset + header_length + 20:
            return None
        if packet[offset + 9] != 6:
            return None
        tcp = offset + header_length
        return (
            packet[offset + 12 : offset + 16],
            packet[offset + 16 : offset + 20],
            int.from_bytes(packet[tcp : tcp + 2], "big"),
            int.from_bytes(packet[tcp + 2 : tcp + 4], "big"),
            int.from_bytes(packet[tcp + 4 : tcp + 8], "big"),
            packet[tcp + 13],
        )

    @staticmethod
    def _parse_ipv6_tcp(
        packet: bytes, offset: int
    ) -> tuple[bytes, bytes, int, int, int, int] | None:
        if len(packet) < offset + 60 or packet[offset + 6] != 6:
            return None
        tcp = offset + 40
        return (
            packet[offset + 8 : offset + 24],
            packet[offset + 24 : offset + 40],
            int.from_bytes(packet[tcp : tcp + 2], "big"),
            int.from_bytes(packet[tcp + 2 : tcp + 4], "big"),
            int.from_bytes(packet[tcp + 4 : tcp + 8], "big"),
            packet[tcp + 13],
        )


class PcapIpPacketTracker:
    """Incrementally summarize IP packet families and UDP 443 conversations."""

    def __init__(self, path: Path):
        self.path = path
        self._byte_order: str | None = None
        self._offset = 0
        self._ipv4_packets = 0
        self._ipv6_packets = 0
        self._tcp_packets = 0
        self._udp_packets = 0
        self._udp_443_conversations: set[tuple[bytes, bytes, int, int]] = set()

    def poll(self) -> IpPacketStats:
        if not self.path.is_file():
            return self.stats()
        with self.path.open("rb") as stream:
            if self._byte_order is None:
                header = stream.read(24)
                if len(header) < 24:
                    return self.stats()
                magic = header[:4]
                if magic in {b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"}:
                    self._byte_order = "<"
                elif magic in {b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"}:
                    self._byte_order = ">"
                else:
                    raise ConfigurationError("IP tracking requires classic PCAP format")
                _, _, _, _, _, link_type = struct.unpack(
                    f"{self._byte_order}HHIIII", header[4:]
                )
                if link_type != 1:
                    raise ConfigurationError(
                        "IP tracking currently requires Ethernet (DLT_EN10MB) PCAP"
                    )
                self._offset = 24
            stream.seek(self._offset)
            while True:
                packet_offset = stream.tell()
                packet_header = stream.read(16)
                if len(packet_header) < 16:
                    break
                _, _, included_length, _ = struct.unpack(
                    f"{self._byte_order}IIII", packet_header
                )
                packet = stream.read(included_length)
                if len(packet) < included_length:
                    stream.seek(packet_offset)
                    break
                self._consume_ethernet(packet)
                self._offset = stream.tell()
        return self.stats()

    def stats(self) -> IpPacketStats:
        return IpPacketStats(
            ipv4_packets=self._ipv4_packets,
            ipv6_packets=self._ipv6_packets,
            tcp_packets=self._tcp_packets,
            udp_packets=self._udp_packets,
            udp_443_conversations=len(self._udp_443_conversations),
        )

    def _consume_ethernet(self, packet: bytes) -> None:
        if len(packet) < 14:
            return
        ether_type = int.from_bytes(packet[12:14], "big")
        offset = 14
        while ether_type in {0x8100, 0x88A8}:
            if len(packet) < offset + 4:
                return
            ether_type = int.from_bytes(packet[offset + 2 : offset + 4], "big")
            offset += 4
        if ether_type == 0x0800:
            self._consume_ipv4(packet, offset)
        elif ether_type == 0x86DD:
            self._consume_ipv6(packet, offset)

    def _consume_ipv4(self, packet: bytes, offset: int) -> None:
        if len(packet) < offset + 20:
            return
        header_length = (packet[offset] & 0x0F) * 4
        if header_length < 20 or len(packet) < offset + header_length:
            return
        self._ipv4_packets += 1
        self._consume_transport(
            packet,
            packet[offset + 9],
            offset + header_length,
            packet[offset + 12 : offset + 16],
            packet[offset + 16 : offset + 20],
        )

    def _consume_ipv6(self, packet: bytes, offset: int) -> None:
        if len(packet) < offset + 40:
            return
        self._ipv6_packets += 1
        self._consume_transport(
            packet,
            packet[offset + 6],
            offset + 40,
            packet[offset + 8 : offset + 24],
            packet[offset + 24 : offset + 40],
        )

    def _consume_transport(
        self,
        packet: bytes,
        protocol: int,
        offset: int,
        source: bytes,
        destination: bytes,
    ) -> None:
        if protocol == 6:
            self._tcp_packets += 1
        elif protocol == 17:
            if len(packet) < offset + 8:
                return
            self._udp_packets += 1
            source_port = int.from_bytes(packet[offset : offset + 2], "big")
            destination_port = int.from_bytes(packet[offset + 2 : offset + 4], "big")
            if source_port == 443 or destination_port == 443:
                forward = (source, destination, source_port, destination_port)
                reverse = (destination, source, destination_port, source_port)
                self._udp_443_conversations.add(min(forward, reverse))
