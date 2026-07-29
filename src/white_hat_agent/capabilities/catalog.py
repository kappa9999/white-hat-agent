from __future__ import annotations

import re
from collections import Counter
from pathlib import Path

import yaml
from pydantic import Field, ValidationError

from ..knowledge.models import EXECUTION_CLASS_RANK, Playbook
from ..models import StrictModel
from .models import CapabilityCatalogManifest, CapabilityDefinition


class CapabilityCatalogIssue(StrictModel):
    code: str
    message: str


class CapabilityCatalogReport(StrictModel):
    path: str
    valid: bool
    capability_count: int = Field(ge=0)
    digest: str | None = None
    issues: list[CapabilityCatalogIssue] = Field(default_factory=list)


class CapabilitySearchHit(StrictModel):
    capability: CapabilityDefinition
    score: float
    matched_terms: list[str]


class CapabilityGapReport(StrictModel):
    required: list[str]
    available: list[str]
    missing: list[str]
    unknown: list[str]
    complete: bool


class CapabilityCompatibilityIssue(StrictModel):
    playbook_id: str
    capability_id: str
    code: str
    message: str


class CapabilityCompatibilityReport(StrictModel):
    valid: bool
    playbook_count: int = Field(ge=0)
    issues: list[CapabilityCompatibilityIssue] = Field(default_factory=list)


class CapabilityCatalog:
    def __init__(self, path: Path, *, max_catalog_bytes: int = 4_194_304) -> None:
        self.path = path.resolve()
        self.max_catalog_bytes = max_catalog_bytes
        self._manifest: CapabilityCatalogManifest | None = None
        self._items: dict[str, CapabilityDefinition] = {}

    def load(self) -> CapabilityCatalogReport:
        self._manifest = None
        self._items.clear()
        try:
            byte_length = self.path.stat().st_size
            if byte_length > self.max_catalog_bytes:
                raise ValueError(
                    f"capability catalog is {byte_length} bytes; maximum is {self.max_catalog_bytes}"
                )
            raw = yaml.safe_load(self.path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                raise ValueError("capability catalog must be a YAML mapping")
            manifest = CapabilityCatalogManifest.model_validate(raw)
            items = {item.capability_id: item for item in manifest.capabilities}
            if len(items) != len(manifest.capabilities):
                raise ValueError("capability identifiers must be unique")
        except (OSError, UnicodeError, yaml.YAMLError, ValidationError, ValueError) as exc:
            return CapabilityCatalogReport(
                path=str(self.path),
                valid=False,
                capability_count=0,
                issues=[CapabilityCatalogIssue(code="catalog.invalid", message=str(exc))],
            )
        self._manifest = manifest
        self._items = items
        return CapabilityCatalogReport(
            path=str(self.path),
            valid=True,
            capability_count=len(items),
            digest=manifest.digest(),
        )

    def all(self) -> list[CapabilityDefinition]:
        return [self._items[key] for key in sorted(self._items)]

    def get(self, capability_id: str) -> CapabilityDefinition:
        try:
            return self._items[capability_id]
        except KeyError as exc:
            raise KeyError(f"unknown capability: {capability_id}") from exc

    def search(self, query: str, *, limit: int = 20) -> list[CapabilitySearchHit]:
        if limit < 1 or limit > 100:
            raise ValueError("limit must be between 1 and 100")
        wanted = _terms(query)
        hits: list[CapabilitySearchHit] = []
        for item in self._items.values():
            weighted: Counter[str] = Counter()
            for text, weight in (
                (item.capability_id, 6),
                (item.title, 4),
                (item.description, 2),
                (" ".join(item.adapter_contract), 1),
            ):
                for term in _terms(text):
                    weighted[term] += weight
            matched = sorted(wanted.intersection(weighted))
            if wanted and not matched:
                continue
            hits.append(
                CapabilitySearchHit(
                    capability=item,
                    score=float(sum(weighted[term] for term in matched) or 1),
                    matched_terms=matched,
                )
            )
        return sorted(
            hits,
            key=lambda hit: (-hit.score, hit.capability.capability_id),
        )[:limit]

    def gaps(self, playbooks: list[Playbook], available: list[str]) -> CapabilityGapReport:
        required = sorted({cap for playbook in playbooks for cap in playbook.capabilities()})
        available_set = set(available)
        missing = sorted(set(required) - available_set)
        unknown = sorted(set(required) - set(self._items))
        return CapabilityGapReport(
            required=required,
            available=sorted(available_set),
            missing=missing,
            unknown=unknown,
            complete=not missing and not unknown,
        )

    def validate_playbooks(self, playbooks: list[Playbook]) -> CapabilityCompatibilityReport:
        issues: list[CapabilityCompatibilityIssue] = []
        for playbook in playbooks:
            for capability_id in sorted(playbook.capabilities()):
                definition = self._items.get(capability_id)
                if definition is None:
                    issues.append(
                        CapabilityCompatibilityIssue(
                            playbook_id=playbook.metadata.playbook_id,
                            capability_id=capability_id,
                            code="capability.unknown",
                            message="playbook references a capability absent from the catalog",
                        )
                    )
                    continue
                if (
                    EXECUTION_CLASS_RANK[definition.execution_class]
                    > EXECUTION_CLASS_RANK[playbook.scope.minimum_execution_class]
                ):
                    issues.append(
                        CapabilityCompatibilityIssue(
                            playbook_id=playbook.metadata.playbook_id,
                            capability_id=capability_id,
                            code="capability.execution-underclassified",
                            message=(
                                f"capability requires {definition.execution_class.value} but playbook "
                                f"declares {playbook.scope.minimum_execution_class.value}"
                            ),
                        )
                    )
        return CapabilityCompatibilityReport(
            valid=not issues,
            playbook_count=len(playbooks),
            issues=issues,
        )


def _terms(value: str) -> set[str]:
    return {item for item in re.findall(r"[\w.-]+", value.lower(), flags=re.UNICODE) if len(item) > 1}
