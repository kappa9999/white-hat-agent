from __future__ import annotations

import re
from enum import StrEnum
from typing import Annotated, Self

from pydantic import AwareDatetime, Field, JsonValue, model_validator

from ..models import Sha256, StrictModel, stable_digest, utc_now

Slug = Annotated[str, Field(pattern=r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")]
CapabilityId = Annotated[str, Field(pattern=r"^[a-z0-9]+(?:[._:-][a-z0-9]+)*$")]
SemanticType = Annotated[str, Field(pattern=r"^[a-z0-9]+(?:[._:/-][a-z0-9]+)*$")]
SemVer = Annotated[
    str,
    Field(
        pattern=(
            r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
            r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
            r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
        ),
        max_length=64,
    ),
]


class ReviewState(StrEnum):
    DRAFT = "draft"
    PROPOSED = "proposed"
    REVIEWED = "reviewed"
    VALIDATED = "validated"
    DEPRECATED = "deprecated"


class ExecutionClass(StrEnum):
    ANALYSIS = "analysis"
    READ_ONLY = "read-only"
    CONTROLLED_ACTIVE = "controlled-active"
    STATE_CHANGING = "state-changing"
    HIGH_IMPACT = "high-impact"


EXECUTION_CLASS_RANK: dict[ExecutionClass, int] = {
    ExecutionClass.ANALYSIS: 0,
    ExecutionClass.READ_ONLY: 1,
    ExecutionClass.CONTROLLED_ACTIVE: 2,
    ExecutionClass.STATE_CHANGING: 3,
    ExecutionClass.HIGH_IMPACT: 4,
}


class StepKind(StrEnum):
    DISCOVER = "discover"
    OBSERVE = "observe"
    ANALYZE = "analyze"
    HYPOTHESIZE = "hypothesize"
    PREPARE = "prepare"
    EXECUTE = "execute"
    VERIFY = "verify"
    DOCUMENT = "document"
    CLEANUP = "cleanup"


class SourceKind(StrEnum):
    FIRST_HAND = "first-hand"
    PUBLICATION = "publication"
    ADVISORY = "advisory"
    CODE = "code"
    STANDARD = "standard"
    DATASET = "dataset"
    OTHER = "other"


class RightsDeclaration(StrEnum):
    ORIGINAL = "original-contribution"
    PERMISSION = "permission-granted"
    LICENSED = "compatible-source-license"
    PUBLIC_DOMAIN = "public-domain"


class TaxonomyReference(StrictModel):
    scheme: str = Field(min_length=1, max_length=40)
    identifier: str = Field(min_length=1, max_length=100)
    url: str | None = None
    relationship: str = "related-to"

    @model_validator(mode="after")
    def normalized_scheme(self) -> Self:
        if self.scheme != self.scheme.upper():
            raise ValueError("taxonomy scheme must be uppercase, for example CWE or CAPEC")
        return self


class SourceReference(StrictModel):
    source_id: Slug
    kind: SourceKind
    title: str = Field(min_length=1)
    url: str | None = None
    authors: list[str] = Field(default_factory=list)
    license: str | None = None
    content_sha256: Sha256 | None = None
    accessed_at: AwareDatetime | None = None
    notes: str | None = None


class KnowledgeSubmission(StrictModel):
    schema_version: str = "1.0"
    submission_id: Slug
    title_hint: str | None = None
    original_language: str = Field(default="und", pattern=r"^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*$|^und$")
    original_text: str = Field(min_length=1, max_length=1_000_000)
    domain_hints: list[Slug] = Field(default_factory=list)
    contributor_handle: str | None = None
    rights: RightsDeclaration
    sources: list[SourceReference] = Field(default_factory=list)
    submitted_at: AwareDatetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def unique_lists(self) -> Self:
        if len(self.domain_hints) != len(set(self.domain_hints)):
            raise ValueError("domain_hints must be unique")
        source_ids = [item.source_id for item in self.sources]
        if len(source_ids) != len(set(source_ids)):
            raise ValueError("source ids must be unique")
        return self

    def digest(self) -> str:
        return stable_digest(self)


class ValueSpec(StrictModel):
    name: Slug
    semantic_type: SemanticType
    description: str = Field(min_length=1)
    required: bool = True
    secret: bool = False
    examples: list[JsonValue] = Field(default_factory=list)


class EvidenceRequirement(StrictModel):
    evidence_type: SemanticType
    description: str = Field(min_length=1)
    minimum_count: int = Field(default=1, ge=1)
    independent: bool = False


class PlaybookStep(StrictModel):
    step_id: Slug
    kind: StepKind
    title: str = Field(min_length=1)
    instruction: str = Field(min_length=1)
    localized_instructions: dict[str, str] = Field(default_factory=dict)
    depends_on: list[Slug] = Field(default_factory=list)
    required_capabilities: list[CapabilityId] = Field(default_factory=list)
    inputs: list[ValueSpec] = Field(default_factory=list)
    outputs: list[ValueSpec] = Field(default_factory=list)
    action_template: dict[str, JsonValue] | None = None
    success_signals: list[str] = Field(min_length=1)
    failure_signals: list[str] = Field(min_length=1)
    evidence: list[EvidenceRequirement] = Field(default_factory=list)
    side_effects: list[str] = Field(default_factory=list)
    cleanup: list[str] = Field(default_factory=list)
    timeout_seconds: int = Field(default=300, ge=1, le=86400)
    max_repetitions: int = Field(default=1, ge=1, le=10000)

    @model_validator(mode="after")
    def unique_lists(self) -> Self:
        for label, values in (
            ("depends_on", self.depends_on),
            ("required_capabilities", self.required_capabilities),
            ("success_signals", self.success_signals),
            ("failure_signals", self.failure_signals),
            ("side_effects", self.side_effects),
            ("cleanup", self.cleanup),
        ):
            if len(values) != len(set(values)):
                raise ValueError(f"{label} must be unique")
        for label, values in (("inputs", self.inputs), ("outputs", self.outputs)):
            names = [item.name for item in values]
            if len(names) != len(set(names)):
                raise ValueError(f"step {label} names must be unique")
        return self


class PlaybookMetadata(StrictModel):
    playbook_id: Slug
    version: SemVer
    title: str = Field(min_length=1)
    summary: str = Field(min_length=1)
    domains: list[Slug] = Field(min_length=1)
    tags: list[Slug] = Field(default_factory=list)
    original_languages: list[str] = Field(default_factory=lambda: ["en"])
    maintainers: list[str] = Field(default_factory=list)
    contributors: list[str] = Field(default_factory=list)
    review_state: ReviewState = ReviewState.DRAFT
    created_at: AwareDatetime
    updated_at: AwareDatetime
    deprecated_by: Slug | None = None

    @model_validator(mode="after")
    def valid_metadata(self) -> Self:
        if self.updated_at < self.created_at:
            raise ValueError("updated_at cannot precede created_at")
        for label, values in (
            ("domains", self.domains),
            ("tags", self.tags),
            ("original_languages", self.original_languages),
            ("maintainers", self.maintainers),
            ("contributors", self.contributors),
        ):
            if len(values) != len(set(values)):
                raise ValueError(f"{label} must be unique")
        return self


class Applicability(StrictModel):
    target_kinds: list[Slug] = Field(min_length=1)
    platforms: list[Slug] = Field(default_factory=list)
    technologies: list[str] = Field(default_factory=list)
    preconditions: list[str] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    exclusions: list[str] = Field(default_factory=list)


class ScopeRequirements(StrictModel):
    minimum_execution_class: ExecutionClass
    requires_scope_manifest: bool = True
    requires_target_match: bool = True
    authorization_evidence_required: bool = True
    minimum_request_budget: int = Field(default=0, ge=0)
    recommended_concurrency: int = Field(default=1, ge=1, le=10000)
    action_tags: list[Slug] = Field(default_factory=list)
    data_classes: list[Slug] = Field(default_factory=list)

    @model_validator(mode="after")
    def unique_scope_lists(self) -> Self:
        for label, values in (("action_tags", self.action_tags), ("data_classes", self.data_classes)):
            if len(values) != len(set(values)):
                raise ValueError(f"{label} must be unique")
        return self


class CompositionContract(StrictModel):
    consumes: list[SemanticType] = Field(default_factory=list)
    provides: list[SemanticType] = Field(default_factory=list)
    compatible_after: list[Slug] = Field(default_factory=list)
    compatible_before: list[Slug] = Field(default_factory=list)
    conflicts_with: list[Slug] = Field(default_factory=list)

    @model_validator(mode="after")
    def unique_lists(self) -> Self:
        for label, values in (
            ("consumes", self.consumes),
            ("provides", self.provides),
            ("compatible_after", self.compatible_after),
            ("compatible_before", self.compatible_before),
            ("conflicts_with", self.conflicts_with),
        ):
            if len(values) != len(set(values)):
                raise ValueError(f"{label} must be unique")
        return self


class ValidationRecord(StrictModel):
    fixture_ids: list[Slug] = Field(default_factory=list)
    test_commands: list[str] = Field(default_factory=list)
    known_limitations: list[str] = Field(default_factory=list)
    last_validated_at: AwareDatetime | None = None
    validated_by: list[str] = Field(default_factory=list)


class Playbook(StrictModel):
    schema_version: str = "1.0"
    metadata: PlaybookMetadata
    applicability: Applicability
    scope: ScopeRequirements
    taxonomies: list[TaxonomyReference] = Field(default_factory=list)
    inputs: list[ValueSpec] = Field(default_factory=list)
    outputs: list[ValueSpec] = Field(default_factory=list)
    steps: list[PlaybookStep] = Field(min_length=1)
    composition: CompositionContract = Field(default_factory=CompositionContract)
    evidence_requirements: list[EvidenceRequirement] = Field(default_factory=list)
    failure_modes: list[str] = Field(default_factory=list)
    variations: list[str] = Field(default_factory=list)
    sources: list[SourceReference] = Field(default_factory=list)
    validation: ValidationRecord = Field(default_factory=ValidationRecord)
    submission_id: Slug | None = None

    @model_validator(mode="after")
    def valid_playbook(self) -> Self:
        step_ids = [item.step_id for item in self.steps]
        if len(step_ids) != len(set(step_ids)):
            raise ValueError("playbook step ids must be unique")
        known = set(step_ids)
        for step in self.steps:
            unknown = set(step.depends_on) - known
            if unknown:
                raise ValueError(f"step {step.step_id} has unknown dependencies: {sorted(unknown)}")
            if step.step_id in step.depends_on:
                raise ValueError(f"step {step.step_id} cannot depend on itself")
        _assert_acyclic({item.step_id: item.depends_on for item in self.steps})
        for label, values in (("inputs", self.inputs), ("outputs", self.outputs)):
            names = [item.name for item in values]
            if len(names) != len(set(names)):
                raise ValueError(f"playbook {label} names must be unique")
        taxonomy_keys = [(item.scheme, item.identifier) for item in self.taxonomies]
        if len(taxonomy_keys) != len(set(taxonomy_keys)):
            raise ValueError("taxonomy references must be unique")
        source_ids = [item.source_id for item in self.sources]
        if len(source_ids) != len(set(source_ids)):
            raise ValueError("source ids must be unique")
        if self.metadata.review_state == ReviewState.VALIDATED:
            if not self.validation.last_validated_at or not self.validation.validated_by:
                raise ValueError("validated playbooks require validation time and validator identity")
            if not self.validation.fixture_ids and not self.validation.test_commands:
                raise ValueError("validated playbooks require a fixture or test command")
        if self.metadata.review_state == ReviewState.DEPRECATED and not self.metadata.deprecated_by:
            raise ValueError("deprecated playbooks must name their replacement")
        if self.metadata.deprecated_by and self.metadata.review_state != ReviewState.DEPRECATED:
            raise ValueError("deprecated_by is only valid for deprecated playbooks")
        return self

    def digest(self) -> str:
        return stable_digest(self)

    def capabilities(self) -> set[str]:
        return {capability for step in self.steps for capability in step.required_capabilities}


class CompilationDraft(StrictModel):
    compiler_id: str
    submission: KnowledgeSubmission
    playbook: Playbook
    unresolved_fields: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class CorpusEntry(StrictModel):
    playbook_id: Slug
    version: SemVer
    digest: Sha256
    relative_path: str
    title: str
    summary: str
    domains: list[Slug]
    tags: list[Slug]
    review_state: ReviewState
    capabilities: list[CapabilityId]
    consumes: list[SemanticType]
    provides: list[SemanticType]


class CorpusManifest(StrictModel):
    schema_version: str = "1.0"
    corpus_version: str
    generated_at: AwareDatetime
    entries: list[CorpusEntry]
    manifest_digest: Sha256 | None = None

    def computed_digest(self) -> str:
        payload = self.model_dump(mode="json", exclude={"manifest_digest"})
        return stable_digest(payload)


def _assert_acyclic(dependencies: dict[str, list[str]]) -> None:
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(item_id: str) -> None:
        if item_id in visiting:
            raise ValueError(f"dependency cycle includes {item_id}")
        if item_id in visited:
            return
        visiting.add(item_id)
        for dependency in dependencies[item_id]:
            visit(dependency)
        visiting.remove(item_id)
        visited.add(item_id)

    for key in dependencies:
        visit(key)


def slugify(value: str, fallback: str = "community-technique") -> str:
    normalized = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return normalized or fallback


def semver_key(value: str) -> tuple[int, int, int, int, tuple[tuple[int, int | str], ...]]:
    """Return a SemVer precedence key; build metadata intentionally has no precedence."""

    core_and_prerelease = value.split("+", 1)[0]
    core, separator, prerelease = core_and_prerelease.partition("-")
    major, minor, patch = (int(part) for part in core.split("."))
    if not separator:
        return (major, minor, patch, 1, ())
    parts: list[tuple[int, int | str]] = []
    for identifier in prerelease.split("."):
        parts.append((0, int(identifier)) if identifier.isdigit() else (1, identifier))
    return (major, minor, patch, 0, tuple(parts))
