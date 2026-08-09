"""Registry selecting one lifecycle implementation per upstream kernel."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Literal

from proxy_traffic_lab.configuration.models import LabConfig, ProtocolCase, RuntimeCore
from proxy_traffic_lab.lifecycle import hysteria2, shadowsocksr
from proxy_traffic_lab.lifecycle.xray import client as xray_client
from proxy_traffic_lab.lifecycle.xray import server as xray_server

Status = dict[str, object]


@dataclass(frozen=True)
class LifecycleAdapter:
    start_server: Callable[[Path], str]
    server_status: Callable[[Path], Status]
    server_logs: Callable[..., str]
    stop_server: Callable[[], str]
    start_client: Callable[[Path, Path | None], str]
    client_status: Callable[..., Status]
    client_logs: Callable[..., str]
    stop_client: Callable[[], str]


def _start_xray_client(_project_root: Path, config_path: Path | None) -> str:
    return xray_client.start_client_container(
        config_path or Path("~/proxy-lab-client/client.json")
    )


ADAPTERS: dict[RuntimeCore, LifecycleAdapter] = {
    RuntimeCore.XRAY_CORE: LifecycleAdapter(
        start_server=xray_server.start_server_container,
        server_status=xray_server.server_status,
        server_logs=xray_server.server_logs,
        stop_server=xray_server.stop_server_container,
        start_client=_start_xray_client,
        client_status=xray_client.client_status,
        client_logs=xray_client.client_logs,
        stop_client=xray_client.stop_client_container,
    ),
    RuntimeCore.HYSTERIA2: LifecycleAdapter(
        start_server=hysteria2.start_server_container,
        server_status=hysteria2.server_status,
        server_logs=hysteria2.server_logs,
        stop_server=hysteria2.stop_server_container,
        start_client=hysteria2.start_client_container,
        client_status=hysteria2.client_status,
        client_logs=hysteria2.client_logs,
        stop_client=hysteria2.stop_client_container,
    ),
    RuntimeCore.SHADOWSOCKSR_NATIVE: LifecycleAdapter(
        start_server=shadowsocksr.start_server_container,
        server_status=shadowsocksr.server_status,
        server_logs=shadowsocksr.server_logs,
        stop_server=shadowsocksr.stop_server_container,
        start_client=shadowsocksr.start_client_container,
        client_status=shadowsocksr.client_status,
        client_logs=shadowsocksr.client_logs,
        stop_client=shadowsocksr.stop_client_container,
    ),
}


def resolve_runtime_core(
    config: LabConfig,
    *,
    explicit: str | RuntimeCore | None = None,
    case: ProtocolCase | None = None,
    side: Literal["client", "server"] = "server",
) -> RuntimeCore:
    declared = None
    if case is not None:
        declared = RuntimeCore(
            case.client_core if side == "client" else case.server_core
        )
    if explicit is not None:
        selected = RuntimeCore(explicit)
        if declared is not None and selected != declared:
            raise ValueError(
                f"{case.id} declares {declared.value} for {side}, not {selected.value}"
            )
        return selected
    return declared or config.runtime.default_core


def adapter(core: RuntimeCore) -> LifecycleAdapter:
    return ADAPTERS[core]


def start_server(core: RuntimeCore, project_root: Path) -> str:
    return adapter(core).start_server(project_root)


def server_status(core: RuntimeCore, project_root: Path) -> Status:
    result = adapter(core).server_status(project_root)
    result.setdefault("core", core.value)
    return result


def server_logs(core: RuntimeCore, *, tail: int) -> str:
    return adapter(core).server_logs(tail=tail)


def stop_server(core: RuntimeCore) -> str:
    return adapter(core).stop_server()


def start_client(
    core: RuntimeCore, project_root: Path, config_path: Path | None = None
) -> str:
    return adapter(core).start_client(project_root, config_path)


def client_status(core: RuntimeCore, *, socks_port: int) -> Status:
    result = adapter(core).client_status(socks_port=socks_port)
    result.setdefault("core", core.value)
    return result


def client_logs(core: RuntimeCore, *, tail: int) -> str:
    return adapter(core).client_logs(tail=tail)


def stop_client(core: RuntimeCore) -> str:
    return adapter(core).stop_client()
