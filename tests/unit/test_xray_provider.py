import json
from pathlib import Path
from typing import Self

import pytest

from proxy_traffic_lab.controller.errors import ConfigurationError
from proxy_traffic_lab.providers.xray import (
    XRAY_OFFICIAL_IMAGE_TAG,
    VlessTlsMaterial,
    render_vless_tls_client,
    render_vless_tls_server,
    render_vmess_websocket_tls_client,
    render_vmess_websocket_tls_server,
    validate_generated_client_address,
    validate_official_image_digest,
)
from proxy_traffic_lab.providers.xray import runtime as xray


def _material() -> VlessTlsMaterial:
    return VlessTlsMaterial(
        client_id="123e4567-e89b-42d3-a456-426614174000",
        server_name="lab.invalid",
        certificate_sha256="a" * 64,
        certificate_path=Path("server.crt"),
        private_key_path=Path("server.key"),
    )


def test_server_config_keeps_layers_explicit() -> None:
    config = render_vless_tls_server(_material(), port=24443)
    inbound = config["inbounds"][0]
    assert inbound["protocol"] == "vless"
    assert inbound["settings"]["decryption"] == "none"
    assert inbound["streamSettings"]["method"] == "raw"
    assert inbound["streamSettings"]["security"] == "tls"


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
    monkeypatch.setattr(xray, "_container_state", lambda: "running")

    class Connection:
        def __enter__(self) -> Self:
            return self

        def __exit__(self, *args: object) -> None:
            return None

    monkeypatch.setattr(xray.socket, "create_connection", lambda *args, **kwargs: Connection())
    status = xray.server_status(tmp_path)
    assert status["healthy"] is True
    assert status["port"] == 24443


def test_server_stop_is_idempotent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(xray, "_container_state", lambda: "absent")
    assert xray.stop_server_container() == "already absent"
