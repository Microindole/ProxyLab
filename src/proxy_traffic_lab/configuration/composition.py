from __future__ import annotations

from typing import Literal

from pydantic import Field

from proxy_traffic_lab.common.errors import ConfigurationError
from proxy_traffic_lab.configuration.models import ParameterValue, ProtocolCase, StrictModel
from proxy_traffic_lab.encryptions import EncryptionCatalog
from proxy_traffic_lab.protocols import ProtocolCatalog
from proxy_traffic_lab.transports import TransportCatalog


class CompatibilityRule(StrictModel):
    protocol: str
    cores: list[str] = Field(min_length=1)
    outer_transports: list[str] = Field(min_length=1)
    transport: str
    encryption: str
    parameters: dict[str, list[ParameterValue]] = Field(default_factory=dict)

    def matches(self, case: ProtocolCase) -> bool:
        if not (
            case.protocol == self.protocol
            and case.client_core in self.cores
            and case.server_core in self.cores
            and case.outer_transport in self.outer_transports
            and case.transport == self.transport
            and case.encryption == self.encryption
        ):
            return False
        if set(case.parameters) != set(self.parameters):
            return False
        return all(
            case.parameters[name] in allowed
            for name, allowed in self.parameters.items()
        )


class CompatibilityCatalog(StrictModel):
    schema_version: Literal[1]
    cores: list[str] = Field(min_length=1)
    rules: list[CompatibilityRule] = Field(min_length=1)


def validate_case_composition(
    case: ProtocolCase,
    *,
    protocols: ProtocolCatalog,
    transports: TransportCatalog,
    encryptions: EncryptionCatalog,
    compatibility: CompatibilityCatalog,
) -> None:
    unknown: list[str] = []
    if case.protocol not in protocols.ids():
        unknown.append(f"protocol={case.protocol}")
    if case.transport not in transports.ids():
        unknown.append(f"transport={case.transport}")
    if case.encryption not in encryptions.ids():
        unknown.append(f"encryption={case.encryption}")
    for side, core in (("client_core", case.client_core), ("server_core", case.server_core)):
        if core not in compatibility.cores:
            unknown.append(f"{side}={core}")
    if unknown:
        raise ConfigurationError(f"{case.id} references unknown components: {', '.join(unknown)}")

    transport = next(item for item in transports.transports if item.id == case.transport)
    if case.outer_transport not in transport.outer_transports:
        raise ConfigurationError(
            f"{case.id}: transport {case.transport} cannot use outer "
            f"{case.outer_transport}"
        )
    if not any(rule.matches(case) for rule in compatibility.rules):
        parameters = ", ".join(
            f"{key}={value}" for key, value in sorted(case.parameters.items())
        ) or "none"
        raise ConfigurationError(
            f"unsupported composition for {case.id}: {case.protocol} + "
            f"{case.transport} + {case.encryption} over {case.outer_transport}, "
            f"cores={case.client_core}/{case.server_core}, parameters={parameters}"
        )



