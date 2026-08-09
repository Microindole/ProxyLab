from pathlib import Path

from proxy_traffic_lab.configuration.loader import load_protocol_matrix
from proxy_traffic_lab.protocols.hysteria2 import render_hysteria2_case
from proxy_traffic_lab.protocols.shadowsocksr import render_case as render_ssr_case
from proxy_traffic_lab.encryptions.material import TlsMaterial
from proxy_traffic_lab.lifecycle.xray.rendering import (
    render_xray_case_client,
    render_xray_case_server,
)


def _material() -> TlsMaterial:
    return TlsMaterial(
        client_id="12345678-1234-4234-8234-123456789abc",
        server_name="lab.invalid",
        certificate_sha256="ab" * 32,
        certificate_path=Path("server.crt"),
        private_key_path=Path("server.key"),
        reality_private_key="private",
        reality_public_key="public",
        reality_short_id="0123abcd",
    )


def test_every_required_target_has_an_upstream_renderer() -> None:
    matrix = load_protocol_matrix()
    rendered_classes: set[int] = set()
    for case in matrix.cases:
        if case.server_core == "xray-core":
            assert render_xray_case_server(case, _material(), port=24443)["inbounds"]
            assert render_xray_case_client(
                case,
                _material(),
                server_address="203.0.113.10",
                server_port=24443,
            )["outbounds"]
        elif case.server_core == "hysteria2":
            rendered = render_hysteria2_case(
                case,
                _material(),
                server_address="203.0.113.10",
                server_port=24443,
            )
            assert rendered["server"] and rendered["client"]
        else:
            rendered = render_ssr_case(
                case,
                password="a-secure-test-password",
                server_address="203.0.113.10",
                server_port=24443,
            )
            assert rendered["server"] and rendered["client"]
        rendered_classes.add(case.dataset_class)

    assert rendered_classes == set(matrix.required_dataset_classes)


def test_renderer_dispatch_does_not_depend_on_dataset_id() -> None:
    case = load_protocol_matrix().cases[4].model_copy(update={"id": "renamed-vmess"})
    server = render_xray_case_server(case, _material(), port=24443)
    assert server["inbounds"][0]["protocol"] == "vmess"
