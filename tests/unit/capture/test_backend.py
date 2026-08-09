from pathlib import Path

import pytest

from proxy_traffic_lab.capture.backend import (
    build_dumpcap_command,
    parse_capinfos_table,
)
from proxy_traffic_lab.common.errors import ConfigurationError


def test_dumpcap_command_forces_classic_pcap_and_full_packets() -> None:
    command = build_dumpcap_command(
        interface="eth0",
        capture_filter="host 203.0.113.10 and tcp port 24443",
        output_path=Path("/data/capture.pcap"),
        use_sudo=True,
    )
    assert command[:2] == ["sudo", "-n"]
    assert command[2:5] == ["dumpcap", "-F", "pcap"]
    assert command[command.index("-s") + 1] == "0"
    assert Path(command[-1]) == Path("/data/capture.pcap")


def test_parse_capinfos_machine_table() -> None:
    values = parse_capinfos_table(
        'File name,Number of packets,File size,Data size,Capture duration,File encapsulation\n'
        'capture.pcap,190,72370,69306,35.004,Ethernet\n'
    )
    assert values["Number of packets"] == "190"
    assert values["File encapsulation"] == "Ethernet"


def test_rejects_incomplete_capinfos_table() -> None:
    with pytest.raises(ConfigurationError, match="incomplete"):
        parse_capinfos_table("File name,Number of packets\n")
