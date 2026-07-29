from __future__ import annotations

from enum import StrEnum

from pydantic import AwareDatetime, Field

from ..knowledge.models import CapabilityId, ExecutionClass, SemanticType
from ..models import StrictModel, stable_digest


class CapabilityStatus(StrEnum):
    EXPERIMENTAL = "experimental"
    STABLE = "stable"
    DEPRECATED = "deprecated"


class CapabilityDefinition(StrictModel):
    capability_id: CapabilityId
    version: str = Field(default="1.0", pattern=r"^[1-9]\d*\.\d+$")
    title: str = Field(min_length=1)
    description: str = Field(min_length=1)
    execution_class: ExecutionClass
    input_types: list[SemanticType] = Field(default_factory=list)
    output_types: list[SemanticType] = Field(default_factory=list)
    side_effects: list[str] = Field(default_factory=list)
    adapter_contract: list[str] = Field(min_length=1)
    status: CapabilityStatus = CapabilityStatus.EXPERIMENTAL
    updated_at: AwareDatetime


class CapabilityCatalogManifest(StrictModel):
    schema_version: str = "1.0"
    capabilities: list[CapabilityDefinition]

    def digest(self) -> str:
        return stable_digest(self)
