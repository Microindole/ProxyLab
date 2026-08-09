from pathlib import Path

import pytest
from pydantic import ValidationError

from proxy_traffic_lab.dataset.schema import ExperimentSpec


def _spec() -> dict[str, object]:
    return {
        "case_id": "class-05-vmess-websocket-tls",
        "dataset_class": 5,
        "profile": "web",
        "inner_network": "tcp",
        "outer_transport": "tcp",
        "server_ip": "203.0.113.10",
        "server_port": 24443,
        "proxy_url": "socks5://127.0.0.1:10808",
        "duration_seconds": 120,
        "seed": 12345,
        "output_root": Path("/data"),
    }


def test_experiment_spec_freezes_capture_format() -> None:
    spec = ExperimentSpec.model_validate(_spec())
    assert spec.capture.file_format == "pcap"
    assert spec.capture.backend == "dumpcap"
    assert spec.capture.snaplen == 0


def test_udp_profile_requires_udp_inner_network() -> None:
    value = _spec()
    value["profile"] = "udp"
    with pytest.raises(ValidationError, match="inner_network=udp"):
        ExperimentSpec.model_validate(value)


def test_normalizes_server_ip() -> None:
    value = _spec()
    value["server_ip"] = "2001:0db8::1"
    assert ExperimentSpec.model_validate(value).server_ip == "2001:db8::1"
