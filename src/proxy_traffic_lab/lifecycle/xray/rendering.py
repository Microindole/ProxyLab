from __future__ import annotations

from typing import Any

from proxy_traffic_lab.common.errors import ConfigurationError
from proxy_traffic_lab.configuration.models import ProtocolCase
from proxy_traffic_lab.encryptions.material import TlsMaterial


def render_xray_case_server(
    case: ProtocolCase,
    material: TlsMaterial,
    *,
    port: int,
) -> dict[str, Any]:
    if case.server_core != "xray-core":
        raise ConfigurationError(f"{case.id} is rendered by {case.server_core}, not Xray-core")
    key = (case.protocol, case.transport, case.encryption)
    if key == ("shadowsocks", "raw", "shadowsocks-2022"):
        from proxy_traffic_lab.protocols.xray.shadowsocks import (
            render_shadowsocks_2022_server,
        )

        return render_shadowsocks_2022_server(
            material,
            port=port,
            network=case.outer_transport,
        )
    if key == ("vmess", "websocket", "tls"):
        from proxy_traffic_lab.protocols.xray.vmess import (
            render_vmess_websocket_tls_server,
        )

        return render_vmess_websocket_tls_server(material, port=port)
    if key == ("vmess", "xhttp", "tls"):
        from proxy_traffic_lab.protocols.xray.vmess import (
            render_vmess_xhttp_h2_tls_server,
        )

        return render_vmess_xhttp_h2_tls_server(
            material,
            port=port,
            xhttp_mode=_required_parameter(case, "xhttp_mode"),
            http_version=_required_parameter(case, "http_version"),
        )
    if key == ("vless", "raw", "reality"):
        from proxy_traffic_lab.protocols.xray.vless import (
            render_vless_reality_vision_server,
        )

        return render_vless_reality_vision_server(material, port=port)
    if key == ("vless", "grpc", "tls"):
        from proxy_traffic_lab.protocols.xray.vless import (
            render_vless_grpc_tls_server,
        )

        return render_vless_grpc_tls_server(material, port=port)
    if key == ("trojan", "raw", "tls"):
        from proxy_traffic_lab.protocols.xray.trojan import (
            render_trojan_raw_tls_server,
        )

        return render_trojan_raw_tls_server(material, port=port)
    if key == ("trojan", "websocket", "tls"):
        from proxy_traffic_lab.protocols.xray.trojan import (
            render_trojan_websocket_tls_server,
        )

        return render_trojan_websocket_tls_server(material, port=port)
    raise ConfigurationError(f"Xray renderer is not implemented for composition: {key}")


def render_xray_case_client(
    case: ProtocolCase,
    material: TlsMaterial,
    *,
    server_address: str,
    server_port: int,
    socks_port: int = 10808,
) -> dict[str, Any]:
    if case.client_core != "xray-core":
        raise ConfigurationError(f"{case.id} is rendered by {case.client_core}, not Xray-core")
    key = (case.protocol, case.transport, case.encryption)
    if key == ("shadowsocks", "raw", "shadowsocks-2022"):
        from proxy_traffic_lab.protocols.xray.shadowsocks import (
            render_shadowsocks_2022_client,
        )

        return render_shadowsocks_2022_client(
            material,
            server_address=server_address,
            server_port=server_port,
            socks_port=socks_port,
            network=case.outer_transport,
        )
    if key == ("vmess", "websocket", "tls"):
        from proxy_traffic_lab.protocols.xray.vmess import (
            render_vmess_websocket_tls_client,
        )

        return render_vmess_websocket_tls_client(
            material,
            server_address=server_address,
            server_port=server_port,
            socks_port=socks_port,
        )
    if key == ("vmess", "xhttp", "tls"):
        from proxy_traffic_lab.protocols.xray.vmess import (
            render_vmess_xhttp_h2_tls_client,
        )

        return render_vmess_xhttp_h2_tls_client(
            material,
            server_address=server_address,
            server_port=server_port,
            socks_port=socks_port,
            xhttp_mode=_required_parameter(case, "xhttp_mode"),
            http_version=_required_parameter(case, "http_version"),
        )
    if key == ("vless", "raw", "reality"):
        from proxy_traffic_lab.protocols.xray.vless import (
            render_vless_reality_vision_client,
        )

        return render_vless_reality_vision_client(
            material,
            server_address=server_address,
            server_port=server_port,
            socks_port=socks_port,
        )
    if key == ("vless", "grpc", "tls"):
        from proxy_traffic_lab.protocols.xray.vless import (
            render_vless_grpc_tls_client,
        )

        return render_vless_grpc_tls_client(
            material,
            server_address=server_address,
            server_port=server_port,
            socks_port=socks_port,
        )
    if key == ("trojan", "raw", "tls"):
        from proxy_traffic_lab.protocols.xray.trojan import (
            render_trojan_raw_tls_client,
        )

        return render_trojan_raw_tls_client(
            material,
            server_address=server_address,
            server_port=server_port,
            socks_port=socks_port,
        )
    if key == ("trojan", "websocket", "tls"):
        from proxy_traffic_lab.protocols.xray.trojan import (
            render_trojan_websocket_tls_client,
        )

        return render_trojan_websocket_tls_client(
            material,
            server_address=server_address,
            server_port=server_port,
            socks_port=socks_port,
        )
    raise ConfigurationError(f"Xray renderer is not implemented for composition: {key}")


def _required_parameter(case: ProtocolCase, name: str) -> str:
    value = case.parameter(name)
    if not isinstance(value, str) or not value:
        raise ConfigurationError(f"{case.id} requires string parameter {name}")
    return value


