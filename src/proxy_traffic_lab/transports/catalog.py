from __future__ import annotations

from typing import Literal

from pydantic import Field, model_validator

from proxy_traffic_lab.configuration.models import StrictModel


class TransportSpec(StrictModel):
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]*$")
    outer_transports: list[str] = Field(min_length=1)
    description: str


class TransportCatalog(StrictModel):
    schema_version: Literal[1]
    transports: list[TransportSpec] = Field(min_length=1)

    @model_validator(mode="after")
    def unique_ids(self) -> TransportCatalog:
        ids = [item.id for item in self.transports]
        if len(ids) != len(set(ids)):
            raise ValueError("transport ids must be unique")
        return self

    def ids(self) -> set[str]:
        return {item.id for item in self.transports}
