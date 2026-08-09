from __future__ import annotations

from typing import Literal

from pydantic import Field, model_validator

from proxy_traffic_lab.configuration.models import StrictModel


class ProtocolSpec(StrictModel):
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]*$")
    description: str


class ProtocolCatalog(StrictModel):
    schema_version: Literal[1]
    protocols: list[ProtocolSpec] = Field(min_length=1)

    @model_validator(mode="after")
    def unique_ids(self) -> ProtocolCatalog:
        ids = [item.id for item in self.protocols]
        if len(ids) != len(set(ids)):
            raise ValueError("protocol ids must be unique")
        return self

    def ids(self) -> set[str]:
        return {item.id for item in self.protocols}
