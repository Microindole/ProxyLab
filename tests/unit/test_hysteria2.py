from pathlib import Path

from proxy_traffic_lab.configuration.loader import load_protocol_matrix, project_root
from proxy_traffic_lab.protocols.hysteria2 import render_hysteria2_case
from proxy_traffic_lab.kernels.hysteria2 import load_image_lock
from proxy_traffic_lab.encryptions.material import TlsMaterial


def _material() -> TlsMaterial:
    return TlsMaterial(
        client_id="12345678-1234-4234-8234-123456789abc",
        server_name="lab.invalid",
        certificate_sha256="ab" * 32,
        certificate_path=Path("server.crt"),
        private_key_path=Path("server.key"),
    )


def test_class_11_renders_native_hysteria2_yaml_values() -> None:
    rendered = render_hysteria2_case(
        load_protocol_matrix().cases[10],
        _material(),
        server_address="203.0.113.10",
        server_port=24443,
    )
    assert rendered["server"]["listen"] == ":24443"
    assert rendered["client"]["server"] == "203.0.113.10:24443"
    assert rendered["client"]["socks5"]["listen"] == "127.0.0.1:10808"
    assert rendered["server"]["auth"]["password"] == rendered["client"]["auth"]
    assert "obfs" not in rendered["server"]


def test_class_12_renders_matching_salamander_settings() -> None:
    rendered = render_hysteria2_case(
        load_protocol_matrix().cases[11],
        _material(),
        server_address="2001:db8::10",
        server_port=24443,
        socks_port=10809,
    )
    assert rendered["client"]["server"] == "[2001:db8::10]:24443"
    assert rendered["server"]["obfs"] == rendered["client"]["obfs"]
    assert rendered["server"]["obfs"]["type"] == "salamander"
    assert rendered["client"]["socks5"]["listen"] == "127.0.0.1:10809"


def test_checked_in_official_image_is_digest_pinned() -> None:
    image = load_image_lock(project_root() / "configs" / "locks" / "hysteria2.json")
    assert image.startswith("tobyxdd/hysteria@sha256:")
