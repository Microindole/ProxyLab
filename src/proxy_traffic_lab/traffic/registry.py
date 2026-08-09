from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from proxy_traffic_lab.common.errors import ConfigurationError
from proxy_traffic_lab.configuration.models import ProtocolCase
from proxy_traffic_lab.traffic.models import WorkloadResult
from proxy_traffic_lab.traffic.playwright_web import generate_web_traffic
from proxy_traffic_lab.traffic.socks5_udp import generate_socks5_udp_traffic


WorkloadRunner = Callable[..., WorkloadResult]


@dataclass(frozen=True)
class WorkloadDefinition:
    name: str
    inner_network: str
    runner: WorkloadRunner


WORKLOADS = {
    "web": WorkloadDefinition("web", "tcp", generate_web_traffic),
    "udp": WorkloadDefinition("udp", "udp", generate_socks5_udp_traffic),
}


def resolve_workload(name: str, case: ProtocolCase) -> WorkloadDefinition:
    try:
        workload = WORKLOADS[name]
    except KeyError as exc:
        raise ConfigurationError(f"unknown workload: {name}") from exc
    if workload.inner_network not in case.inner_networks:
        raise ConfigurationError(
            f"{name} workload uses inner {workload.inner_network}, which is not valid for {case.id}"
        )
    return workload

