import json
from pathlib import Path
from typing import Self

import pytest

from proxy_traffic_lab.common.errors import ConfigurationError
from proxy_traffic_lab.configuration.loader import find_protocol_case
from proxy_traffic_lab.encryptions.material import TlsMaterial
from proxy_traffic_lab.protocols.xray.shadowsocks import (
    render_shadowsocks_2022_client,
    render_shadowsocks_2022_server,
)
from proxy_traffic_lab.protocols.xray.trojan import (
    render_trojan_raw_tls_client,
    render_trojan_raw_tls_server,
    render_trojan_websocket_tls_client,
    render_trojan_websocket_tls_server,
)
from proxy_traffic_lab.protocols.xray.vless import (
    render_vless_grpc_tls_client,
    render_vless_grpc_tls_server,
    render_vless_reality_vision_client,
    render_vless_reality_vision_server,
    render_vless_tls_client,
    render_vless_tls_server,
)
from proxy_traffic_lab.protocols.xray.vmess import (
    render_vmess_websocket_tls_client,
    render_vmess_websocket_tls_server,
    render_vmess_xhttp_h2_tls_client,
    render_vmess_xhttp_h2_tls_server,
)
import proxy_traffic_lab.lifecycle.xray.credentials as xray_credentials
import proxy_traffic_lab.lifecycle.xray.server as xray_server
from proxy_traffic_lab.lifecycle.xray.credentials import (
    ensure_reality_material,
    generate_reality_key_pair,
)
from proxy_traffic_lab.lifecycle.xray.documents import validate_generated_client_address
from proxy_traffic_lab.kernels.xray import (
    XRAY_OFFICIAL_IMAGE_TAG,
    validate_official_image_digest,
)


def _material() -> TlsMaterial:
    return TlsMaterial(
        client_id="123e4567-e89b-42d3-a456-426614174000",
        server_name="lab.invalid",
        certificate_sha256="a" * 64,
        certificate_path=Path("server.crt"),
        private_key_path=Path("server.key"),
        reality_private_key="priv",
        reality_public_key="pub",
        reality_short_id="0123abcd",
    )


def test_server_config_keeps_layers_explicit() -> None:
    config = render_vless_tls_server(_material(), port=24443)
    inbound = config["inbounds"][0]
    assert inbound["protocol"] == "vless"
    assert inbound["settings"]["decryption"] == "none"
    assert inbound["streamSettings"]["network"] == "tcp"
    assert inbound["streamSettings"]["method"] == "raw"
    assert inbound["streamSettings"]["security"] == "tls"


def test_class_01_uses_xray_shadowsocks_2022_tcp() -> None:
    server = render_shadowsocks_2022_server(_material(), port=24443, network="tcp")
    client = render_shadowsocks_2022_client(
        _material(),
        server_address="203.0.113.10",
        server_port=24443,
        network="tcp",
    )
    inbound = server["inbounds"][0]
    outbound = client["outbounds"][0]
    assert inbound["protocol"] == "shadowsocks"
    assert inbound["settings"]["method"] == "2022-blake3-aes-128-gcm"
    assert inbound["settings"]["network"] == "tcp"
    server_entry = outbound["settings"]["servers"][0]
    assert server_entry["address"] == "203.0.113.10"
    assert server_entry["port"] == 24443
    assert server_entry["method"] == inbound["settings"]["method"]
    assert server_entry["password"] == inbound["settings"]["password"]
    assert client["inbounds"][0]["settings"]["udp"] is False


def test_class_02_uses_xray_shadowsocks_2022_udp() -> None:
    server = render_shadowsocks_2022_server(_material(), port=24443, network="udp")
    client = render_shadowsocks_2022_client(
        _material(),
        server_address="203.0.113.10",
        server_port=24443,
        network="udp",
    )
    assert server["inbounds"][0]["settings"]["network"] == "udp"
    assert client["inbounds"][0]["settings"]["udp"] is True
    assert (
        client["outbounds"][0]["settings"]["servers"][0]["method"]
        == "2022-blake3-aes-128-gcm"
    )


def test_server_blocks_cloud_metadata() -> None:
    config = render_vless_tls_server(_material(), port=24443)
    assert "100.100.100.200/32" in config["routing"]["rules"][0]["ip"]


def test_class_05_server_uses_vmess_websocket_tls() -> None:
    config = render_vmess_websocket_tls_server(_material(), port=24443)
    inbound = config["inbounds"][0]
    stream = inbound["streamSettings"]
    assert inbound["protocol"] == "vmess"
    assert inbound["settings"]["clients"][0]["id"] == _material().client_id
    assert stream["method"] == "websocket"
    assert stream["security"] == "tls"
    assert stream["wsSettings"]["path"].startswith("/assets/")
    assert stream["tlsSettings"]["alpn"] == ["http/1.1"]


def test_class_05_client_matches_server_and_pins_certificate() -> None:
    server = render_vmess_websocket_tls_server(_material(), port=24443)
    client = render_vmess_websocket_tls_client(
        _material(), server_address="203.0.113.10", server_port=24443
    )
    inbound_stream = server["inbounds"][0]["streamSettings"]
    outbound = client["outbounds"][0]
    outbound_stream = outbound["streamSettings"]
    assert outbound["protocol"] == "vmess"
    assert outbound_stream["wsSettings"]["path"] == inbound_stream["wsSettings"]["path"]
    assert outbound_stream["wsSettings"]["host"] == inbound_stream["wsSettings"]["host"]
    assert outbound_stream["tlsSettings"]["pinnedPeerCertSha256"] == "a" * 64
    assert "allowInsecure" not in outbound_stream["tlsSettings"]


def test_class_06_server_uses_vmess_xhttp_h2_tls() -> None:
    config = render_vmess_xhttp_h2_tls_server(_material(), port=24443)
    inbound = config["inbounds"][0]
    stream = inbound["streamSettings"]
    assert inbound["protocol"] == "vmess"
    assert inbound["settings"]["clients"][0]["id"] == _material().client_id
    assert stream["method"] == "xhttp"
    assert stream["security"] == "tls"
    assert stream["xhttpSettings"]["path"].startswith("/xhttp/")
    assert stream["xhttpSettings"]["mode"] == "stream-up"
    assert stream["tlsSettings"]["alpn"] == ["h2"]


def test_class_06_matrix_separates_xhttp_mode_from_http_version() -> None:
    case = find_protocol_case("class-06-vmess-xhttp-h2-tls")
    assert case.parameters == {"xhttp_mode": "stream-up", "http_version": "h2"}


def test_class_06_client_matches_server_and_pins_certificate() -> None:
    server = render_vmess_xhttp_h2_tls_server(_material(), port=24443)
    client = render_vmess_xhttp_h2_tls_client(
        _material(), server_address="203.0.113.10", server_port=24443
    )
    inbound_stream = server["inbounds"][0]["streamSettings"]
    outbound_stream = client["outbounds"][0]["streamSettings"]
    assert outbound_stream["xhttpSettings"] == inbound_stream["xhttpSettings"]
    assert outbound_stream["tlsSettings"]["alpn"] == ["h2"]
    assert outbound_stream["tlsSettings"]["pinnedPeerCertSha256"] == "a" * 64
    assert "allowInsecure" not in outbound_stream["tlsSettings"]


def test_class_07_server_uses_vless_raw_reality_vision() -> None:
    config = render_vless_reality_vision_server(_material(), port=24443)
    inbound = config["inbounds"][0]
    stream = inbound["streamSettings"]
    client = inbound["settings"]["clients"][0]
    assert inbound["protocol"] == "vless"
    assert inbound["settings"]["decryption"] == "none"
    assert client["id"] == _material().client_id
    assert client["flow"] == "xtls-rprx-vision"
    assert stream["network"] == "tcp"
    assert stream["method"] == "raw"
    assert stream["security"] == "reality"
    assert stream["realitySettings"]["privateKey"] == "priv"
    assert stream["realitySettings"]["shortIds"] == ["0123abcd"]
    assert stream["realitySettings"]["serverNames"] == ["www.microsoft.com"]


def test_class_07_client_matches_reality_server() -> None:
    client = render_vless_reality_vision_client(
        _material(), server_address="203.0.113.10", server_port=24443
    )
    outbound = client["outbounds"][0]
    stream = outbound["streamSettings"]
    assert outbound["protocol"] == "vless"
    assert outbound["settings"]["flow"] == "xtls-rprx-vision"
    assert stream["network"] == "tcp"
    assert stream["method"] == "raw"
    assert stream["security"] == "reality"
    assert stream["realitySettings"]["publicKey"] == "pub"
    assert stream["realitySettings"]["shortId"] == "0123abcd"
    assert stream["realitySettings"]["serverName"] == "www.microsoft.com"


def test_class_08_server_uses_vless_grpc_tls() -> None:
    config = render_vless_grpc_tls_server(_material(), port=24443)
    inbound = config["inbounds"][0]
    stream = inbound["streamSettings"]
    assert inbound["protocol"] == "vless"
    assert inbound["settings"]["decryption"] == "none"
    assert stream["network"] == "grpc"
    assert stream["method"] == "grpc"
    assert stream["security"] == "tls"
    assert stream["grpcSettings"]["serviceName"].startswith("grpc")
    assert stream["tlsSettings"]["alpn"] == ["h2"]


def test_class_08_client_matches_server_and_pins_certificate() -> None:
    server = render_vless_grpc_tls_server(_material(), port=24443)
    client = render_vless_grpc_tls_client(
        _material(), server_address="203.0.113.10", server_port=24443
    )
    inbound_stream = server["inbounds"][0]["streamSettings"]
    outbound_stream = client["outbounds"][0]["streamSettings"]
    assert outbound_stream["network"] == "grpc"
    assert outbound_stream["grpcSettings"] == inbound_stream["grpcSettings"]
    assert outbound_stream["tlsSettings"]["alpn"] == ["h2"]
    assert outbound_stream["tlsSettings"]["pinnedPeerCertSha256"] == "a" * 64
    assert "allowInsecure" not in outbound_stream["tlsSettings"]


def test_class_09_server_uses_trojan_raw_tls() -> None:
    config = render_trojan_raw_tls_server(_material(), port=24443)
    inbound = config["inbounds"][0]
    stream = inbound["streamSettings"]
    assert inbound["protocol"] == "trojan"
    assert inbound["settings"]["clients"][0]["password"]
    assert stream["method"] == "raw"
    assert stream["security"] == "tls"


def test_class_09_client_matches_trojan_raw_tls_server() -> None:
    server = render_trojan_raw_tls_server(_material(), port=24443)
    client = render_trojan_raw_tls_client(
        _material(), server_address="203.0.113.10", server_port=24443
    )
    assert client["outbounds"][0]["protocol"] == "trojan"
    assert (
        client["outbounds"][0]["settings"]["servers"][0]["password"]
        == server["inbounds"][0]["settings"]["clients"][0]["password"]
    )
    assert client["outbounds"][0]["streamSettings"]["method"] == "raw"
    assert client["outbounds"][0]["streamSettings"]["security"] == "tls"


def test_class_10_server_uses_trojan_websocket_tls() -> None:
    config = render_trojan_websocket_tls_server(_material(), port=24443)
    inbound = config["inbounds"][0]
    stream = inbound["streamSettings"]
    assert inbound["protocol"] == "trojan"
    assert stream["method"] == "websocket"
    assert stream["security"] == "tls"
    assert stream["wsSettings"]["path"].startswith("/assets/")
    assert stream["tlsSettings"]["alpn"] == ["http/1.1"]


def test_class_10_client_matches_trojan_websocket_tls_server() -> None:
    server = render_trojan_websocket_tls_server(_material(), port=24443)
    client = render_trojan_websocket_tls_client(
        _material(), server_address="203.0.113.10", server_port=24443
    )
    outbound = client["outbounds"][0]
    assert outbound["protocol"] == "trojan"
    assert (
        outbound["settings"]["servers"][0]["password"]
        == server["inbounds"][0]["settings"]["clients"][0]["password"]
    )
    assert outbound["streamSettings"]["wsSettings"] == server["inbounds"][0][
        "streamSettings"
    ]["wsSettings"]


def test_ensure_reality_material_persists_generated_keys(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secrets_dir = tmp_path
    identity = {
        "client_id": _material().client_id,
        "server_name": "lab.invalid",
        "certificate_sha256": "a" * 64,
        "reality_short_id": "abcdef12",
    }
    (secrets_dir / "identity.json").write_text(json.dumps(identity), encoding="utf-8")

    def fake_run_command(*args: object, **kwargs: object) -> object:
        class Result:
            returncode = 0
            stdout = "Private key: generated-private\nPublic key: generated-public\n"
            stderr = ""

        return Result()

    monkeypatch.setattr(xray_credentials, "run_command", fake_run_command)
    material = ensure_reality_material(
        secrets_dir,
        TlsMaterial(
            client_id=_material().client_id,
            server_name="lab.invalid",
            certificate_sha256="a" * 64,
            certificate_path=secrets_dir / "server.crt",
            private_key_path=secrets_dir / "server.key",
            reality_short_id="abcdef12",
        ),
    )

    persisted = json.loads((secrets_dir / "identity.json").read_text())
    assert material.reality_private_key == "generated-private"
    assert material.reality_public_key == "generated-public"
    assert persisted["reality_private_key"] == "generated-private"


def test_generate_reality_key_pair_parses_stderr_camel_case(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run_command(*args: object, **kwargs: object) -> object:
        class Result:
            returncode = 0
            stdout = ""
            stderr = "privateKey: generated-private\npublicKey: generated-public\n"

        return Result()

    monkeypatch.setattr(xray_credentials, "run_command", fake_run_command)

    assert generate_reality_key_pair() == {
        "private_key": "generated-private",
        "public_key": "generated-public",
    }


def test_generate_reality_key_pair_accepts_xray_26_password_label(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run_command(*args: object, **kwargs: object) -> object:
        class Result:
            returncode = 0
            stdout = (
                "PrivateKey: generated-private\n"
                "Password: generated-public\n"
                "Hash32: ignored-hash\n"
            )
            stderr = ""

        return Result()

    monkeypatch.setattr(xray_credentials, "run_command", fake_run_command)

    assert generate_reality_key_pair() == {
        "private_key": "generated-private",
        "public_key": "generated-public",
    }


def test_generate_reality_key_pair_reports_unparsed_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run_command(*args: object, **kwargs: object) -> object:
        class Result:
            returncode = 0
            stdout = "unexpected output"
            stderr = ""

        return Result()

    monkeypatch.setattr(xray_credentials, "run_command", fake_run_command)

    with pytest.raises(ConfigurationError, match="unexpected output"):
        generate_reality_key_pair()


def test_client_pins_certificate_without_allow_insecure() -> None:
    config = render_vless_tls_client(
        _material(), server_address="203.0.113.10", server_port=24443
    )
    tls = config["outbounds"][0]["streamSettings"]["tlsSettings"]
    assert tls["pinnedPeerCertSha256"] == "a" * 64
    assert "allowInsecure" not in tls


def test_client_rejects_placeholder_server_address() -> None:
    with pytest.raises(ConfigurationError, match="placeholders"):
        render_vless_tls_client(
            _material(), server_address="你的服务器公网IP", server_port=24443
        )


def test_requires_official_digest() -> None:
    image = "ghcr.io/xtls/xray-core@sha256:" + "a" * 64
    assert validate_official_image_digest(image) == image
    with pytest.raises(ConfigurationError):
        validate_official_image_digest("ghcr.io/xtls/xray-core:latest")


def test_release_and_container_tag_naming_are_not_mixed() -> None:
    assert XRAY_OFFICIAL_IMAGE_TAG == "ghcr.io/xtls/xray-core:26.2.6"


def test_rejects_stale_generated_client_placeholder(tmp_path: Path) -> None:
    client = tmp_path / "client.json"
    client.write_text(
        '{"outbounds":[{"settings":{"address":"你的服务器公网IP"}}]}',
        encoding="utf-8",
    )
    with pytest.raises(ConfigurationError, match="rerun `lab xray render`"):
        validate_generated_client_address(client)


def test_server_status_reports_listener_health(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = tmp_path / "secrets" / "generated" / "server.json"
    config.parent.mkdir(parents=True)
    config.write_text(json.dumps({"inbounds": [{"port": 24443}]}), encoding="utf-8")
    monkeypatch.setattr(xray_server, "container_state", lambda _name: "running")

    class Connection:
        def __enter__(self) -> Self:
            return self

        def __exit__(self, *args: object) -> None:
            return None

    monkeypatch.setattr(xray_server.socket, "create_connection", lambda *args, **kwargs: Connection())
    status = xray_server.server_status(tmp_path)
    assert status["healthy"] is True
    assert status["port"] == 24443


def test_server_stop_is_idempotent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(xray_server, "container_state", lambda _name: "absent")
    assert xray_server.stop_server_container() == "already absent"
