"""Runtime-core dispatch without reimplementing any proxy protocol."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from proxy_traffic_lab.controller.models import LabConfig, ProtocolCase, RuntimeCore


def resolve_runtime_core(
    config: LabConfig,
    *,
    explicit: str | RuntimeCore | None = None,
    case: ProtocolCase | None = None,
    side: Literal["client", "server"] = "server",
) -> RuntimeCore:
    if explicit is not None:
        selected = RuntimeCore(explicit)
        if case is not None:
            declared = resolve_runtime_core(config, case=case, side=side)
            if selected != declared:
                raise ValueError(
                    f"{case.id} declares {declared.value} for {side}, not {selected.value}"
                )
        return selected
    if case is not None:
        implementation = case.client if side == "client" else case.server
        if implementation == "xray":
            return RuntimeCore.XRAY_CORE
        if implementation == "hysteria2":
            return RuntimeCore.HYSTERIA2
        if implementation == "shadowsocksr-native":
            return RuntimeCore.SHADOWSOCKSR_NATIVE
        raise ValueError(
            f"{implementation} has config rendering but no managed container runtime"
        )
    return config.runtime.default_core


def start_server(core: RuntimeCore, project_root: Path) -> str:
    if core == RuntimeCore.XRAY_CORE:
        from proxy_traffic_lab.providers.xray import start_server_container

        return start_server_container(project_root)
    if core == RuntimeCore.HYSTERIA2:
        from proxy_traffic_lab.providers.hysteria2 import start_server_container

        return start_server_container(project_root)
    from proxy_traffic_lab.providers.shadowsocksr_native import start_server_container

    return start_server_container(project_root)


def server_status(core: RuntimeCore, project_root: Path) -> dict[str, object]:
    if core == RuntimeCore.XRAY_CORE:
        from proxy_traffic_lab.providers.xray import server_status as xray_status

        result = xray_status(project_root)
        result.setdefault("core", RuntimeCore.XRAY_CORE.value)
        return result
    if core == RuntimeCore.HYSTERIA2:
        from proxy_traffic_lab.providers.hysteria2 import server_status as hysteria_status

        return hysteria_status(project_root)
    from proxy_traffic_lab.providers.shadowsocksr_native import server_status as ssr_status

    return ssr_status(project_root)


def server_logs(core: RuntimeCore, *, tail: int) -> str:
    if core == RuntimeCore.XRAY_CORE:
        from proxy_traffic_lab.providers.xray import server_logs as xray_logs

        return xray_logs(tail=tail)
    if core == RuntimeCore.HYSTERIA2:
        from proxy_traffic_lab.providers.hysteria2 import server_logs as hysteria_logs

        return hysteria_logs(tail=tail)
    from proxy_traffic_lab.providers.shadowsocksr_native import server_logs as ssr_logs

    return ssr_logs(tail=tail)


def stop_server(core: RuntimeCore) -> str:
    if core == RuntimeCore.XRAY_CORE:
        from proxy_traffic_lab.providers.xray import stop_server_container

        return stop_server_container()
    if core == RuntimeCore.HYSTERIA2:
        from proxy_traffic_lab.providers.hysteria2 import stop_server_container

        return stop_server_container()
    from proxy_traffic_lab.providers.shadowsocksr_native import stop_server_container

    return stop_server_container()


def start_client(
    core: RuntimeCore, project_root: Path, config_path: Path | None = None
) -> str:
    if core == RuntimeCore.XRAY_CORE:
        from proxy_traffic_lab.providers.xray import start_client_container

        path = config_path or Path("~/proxy-lab-client/client.json")
        return start_client_container(path)
    if core == RuntimeCore.HYSTERIA2:
        from proxy_traffic_lab.providers.hysteria2 import start_client_container

        return start_client_container(project_root, config_path)
    from proxy_traffic_lab.providers.shadowsocksr_native import start_client_container

    return start_client_container(project_root, config_path)


def client_status(core: RuntimeCore, *, socks_port: int) -> dict[str, object]:
    if core == RuntimeCore.XRAY_CORE:
        from proxy_traffic_lab.providers.xray import client_status as xray_status

        result = xray_status(socks_port=socks_port)
        result.setdefault("core", RuntimeCore.XRAY_CORE.value)
        return result
    if core == RuntimeCore.HYSTERIA2:
        from proxy_traffic_lab.providers.hysteria2 import client_status as hysteria_status

        return hysteria_status(socks_port=socks_port)
    from proxy_traffic_lab.providers.shadowsocksr_native import client_status as ssr_status

    return ssr_status(socks_port=socks_port)


def client_logs(core: RuntimeCore, *, tail: int) -> str:
    if core == RuntimeCore.XRAY_CORE:
        from proxy_traffic_lab.providers.xray import client_logs as xray_logs

        return xray_logs(tail=tail)
    if core == RuntimeCore.HYSTERIA2:
        from proxy_traffic_lab.providers.hysteria2 import client_logs as hysteria_logs

        return hysteria_logs(tail=tail)
    from proxy_traffic_lab.providers.shadowsocksr_native import client_logs as ssr_logs

    return ssr_logs(tail=tail)


def stop_client(core: RuntimeCore) -> str:
    if core == RuntimeCore.XRAY_CORE:
        from proxy_traffic_lab.providers.xray import stop_client_container

        return stop_client_container()
    if core == RuntimeCore.HYSTERIA2:
        from proxy_traffic_lab.providers.hysteria2 import stop_client_container

        return stop_client_container()
    from proxy_traffic_lab.providers.shadowsocksr_native import stop_client_container

    return stop_client_container()
