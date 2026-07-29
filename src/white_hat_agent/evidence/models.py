from __future__ import annotations

from enum import StrEnum

from pydantic import AwareDatetime, Field, JsonValue, model_validator

from ..knowledge.models import SemanticType, Slug
from ..models import ProofTier, Sha256, StrictModel, stable_digest, stable_id, utc_now


class Sensitivity(StrEnum):
    PUBLIC = "public"
    PROGRAM_CONFIDENTIAL = "program-confidential"
    PERSONAL_DATA = "personal-data"
    SECRET = "secret"


class RedactionState(StrEnum):
    UNREVIEWED = "unreviewed"
    SANITIZED = "sanitized"
    WITHHELD = "withheld"


class FindingStatus(StrEnum):
    CANDIDATE = "candidate"
    SUPPORTED = "supported"
    VERIFIED = "verified"
    REFUTED = "refuted"
    DUPLICATE = "duplicate"
    SUBMITTED = "submitted"
    RESOLVED = "resolved"


class FindingSeverity(StrEnum):
    UNKNOWN = "unknown"
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EvidenceDescriptor(StrictModel):
    campaign_id: Slug
    task_id: str | None = None
    target: str = Field(min_length=1)
    evidence_type: SemanticType
    title: str = Field(min_length=1)
    description: str = Field(min_length=1)
    producer: str = Field(min_length=1)
    sensitivity: Sensitivity = Sensitivity.PROGRAM_CONFIDENTIAL
    redaction_state: RedactionState = RedactionState.UNREVIEWED
    captured_at: AwareDatetime = Field(default_factory=utc_now)
    provenance: dict[str, JsonValue] = Field(default_factory=dict)


class EvidenceRecord(StrictModel):
    schema_version: str = "1.0"
    evidence_id: str
    descriptor: EvidenceDescriptor
    content_sha256: Sha256
    byte_length: int = Field(ge=0)
    media_type: str = Field(min_length=1)
    storage_path: str | None = None
    external_uri: str | None = None
    registered_at: AwareDatetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def exactly_one_location(self):
        if bool(self.storage_path) == bool(self.external_uri):
            raise ValueError("evidence requires exactly one storage_path or external_uri")
        return self

    def digest(self) -> str:
        return stable_digest(self.model_dump(mode="json", exclude={"registered_at"}))

    @classmethod
    def create(
        cls,
        *,
        descriptor: EvidenceDescriptor,
        content_sha256: str,
        byte_length: int,
        media_type: str,
        storage_path: str | None = None,
        external_uri: str | None = None,
    ) -> EvidenceRecord:
        identity = {
            "descriptor": descriptor.model_dump(mode="json"),
            "content_sha256": content_sha256,
            "byte_length": byte_length,
            "media_type": media_type,
        }
        return cls(
            evidence_id=stable_id("evidence", identity),
            descriptor=descriptor,
            content_sha256=content_sha256,
            byte_length=byte_length,
            media_type=media_type,
            storage_path=storage_path,
            external_uri=external_uri,
        )


class FindingRecord(StrictModel):
    schema_version: str = "1.0"
    finding_id: str
    revision: int = Field(default=1, ge=1)
    previous_digest: Sha256 | None = None
    campaign_id: Slug
    task_id: str | None = None
    target: str = Field(min_length=1)
    playbook_id: Slug
    title: str = Field(min_length=1)
    summary: str = Field(min_length=1)
    status: FindingStatus = FindingStatus.CANDIDATE
    severity: FindingSeverity = FindingSeverity.UNKNOWN
    proof_tier: ProofTier = ProofTier.SIGNAL
    impact: str | None = None
    reproduction: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    unknowns: list[str] = Field(default_factory=list)
    remediation: list[str] = Field(default_factory=list)
    disclosure_notes: list[str] = Field(default_factory=list)
    created_at: AwareDatetime = Field(default_factory=utc_now)
    updated_at: AwareDatetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def evidence_and_time_invariants(self):
        if self.updated_at < self.created_at:
            raise ValueError("updated_at cannot precede created_at")
        if len(self.evidence_ids) != len(set(self.evidence_ids)):
            raise ValueError("evidence_ids must be unique")
        if self.status in {FindingStatus.SUPPORTED, FindingStatus.VERIFIED} and not self.evidence_ids:
            raise ValueError("supported and verified findings require evidence")
        if (self.revision == 1) != (self.previous_digest is None):
            raise ValueError("revision 1 has no previous digest; later revisions require one")
        return self

    def digest(self) -> str:
        return stable_digest(self.model_dump(mode="json", exclude={"updated_at"}))

    @classmethod
    def create(cls, **values) -> FindingRecord:
        identity = {
            key: values.get(key) for key in ("campaign_id", "task_id", "target", "playbook_id", "title")
        }
        return cls(finding_id=stable_id("finding", identity), **values)
