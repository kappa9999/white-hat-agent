from __future__ import annotations

from enum import StrEnum
from typing import Literal, Self

from pydantic import AwareDatetime, Field, JsonValue, model_validator

from ..models import Sha256, StrictModel, UnitScore


class IntelligenceSource(StrEnum):
    CISA_KEV = "cisa-kev"
    CVE_LIST_V5 = "cve-list-v5"
    OSV = "osv"
    EPSS = "epss"


class SnapshotKind(StrEnum):
    FULL_FEED = "full-feed"
    DELTA_LOG = "delta-log"
    INDEX_PREFIX = "index-prefix"
    SELECTION_MANIFEST = "selection-manifest"
    SOURCE_RECORD = "source-record"
    ENRICHMENT = "enrichment"


class SyncStatus(StrEnum):
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    SKIPPED = "skipped"


class CveRecordState(StrEnum):
    PUBLISHED = "PUBLISHED"
    REJECTED = "REJECTED"


class UpsertState(StrEnum):
    INSERTED = "inserted"
    UPDATED = "updated"
    UNCHANGED = "unchanged"
    TOMBSTONED = "tombstoned"


class IdentifierRelation(StrEnum):
    ALIAS = "alias"
    RELATED = "related"


class ReferenceType(StrEnum):
    ADVISORY = "advisory"
    ARTICLE = "article"
    DETECTION = "detection"
    DISCUSSION = "discussion"
    EVIDENCE = "evidence"
    FIX = "fix"
    INTRODUCED = "introduced"
    PACKAGE = "package"
    REPORT = "report"
    WEB = "web"
    UNKNOWN = "unknown"


class RangeType(StrEnum):
    ECOSYSTEM = "ecosystem"
    GIT = "git"
    SEMVER = "semver"
    UNKNOWN = "unknown"


class SeverityKind(StrEnum):
    CVSS = "cvss"
    EPSS = "epss"
    QUALITATIVE = "qualitative"
    OTHER = "other"


class SourceAttribution(StrictModel):
    publisher: str = Field(min_length=1)
    dataset: str = Field(min_length=1)
    attribution: str = Field(min_length=1)
    license_name: str = Field(min_length=1)
    license_url: str | None = None


class RawSnapshotProvenance(StrictModel):
    """Immutable metadata for one content-addressed upstream payload."""

    schema_version: Literal["1.0"] = "1.0"
    snapshot_id: str = Field(min_length=1)
    source: IntelligenceSource
    kind: SnapshotKind
    source_url: str = Field(min_length=1)
    source_record_id: str | None = None
    retrieved_at: AwareDatetime
    content_sha256: Sha256
    byte_length: int = Field(ge=0)
    media_type: str = Field(min_length=1)
    http_status: int = Field(default=200, ge=100, le=599)
    etag: str | None = None
    last_modified: str | None = None
    source_schema_version: str | None = None
    source_metadata: dict[str, JsonValue] = Field(default_factory=dict)
    attribution: SourceAttribution
    storage_path: str = Field(min_length=1)

    @model_validator(mode="after")
    def safe_public_provenance(self) -> Self:
        if not self.source_url.startswith("https://"):
            raise ValueError("snapshot source_url must use https")
        path_parts = self.storage_path.replace("\\", "/").split("/")
        if self.storage_path.startswith(("/", "\\")) or ".." in path_parts:
            raise ValueError("snapshot storage_path must be relative and contained")
        return self


class IdentifierLink(StrictModel):
    left: str = Field(min_length=1)
    right: str = Field(min_length=1)
    relation: IdentifierRelation
    source: IntelligenceSource

    @model_validator(mode="after")
    def different_endpoints(self) -> Self:
        if self.left.casefold() == self.right.casefold():
            raise ValueError("identifier link endpoints must differ")
        return self


class AdvisoryReference(StrictModel):
    url: str = Field(min_length=1)
    type: ReferenceType = ReferenceType.UNKNOWN
    raw_type: str | None = None
    title: str | None = None
    source: IntelligenceSource

    @model_validator(mode="after")
    def public_url(self) -> Self:
        if not self.url.startswith(("https://", "http://")):
            raise ValueError("advisory reference must use http or https")
        return self


class VersionEvent(StrictModel):
    introduced: str | None = None
    fixed: str | None = None
    last_affected: str | None = None
    limit: str | None = None

    @model_validator(mode="after")
    def exactly_one_event(self) -> Self:
        if sum(value is not None for value in self.model_dump().values()) != 1:
            raise ValueError("version event requires exactly one event value")
        return self


class AffectedRange(StrictModel):
    type: RangeType
    raw_type: str | None = None
    repository: str | None = None
    events: list[VersionEvent] = Field(default_factory=list)
    database_specific: dict[str, JsonValue] = Field(default_factory=dict)


class AffectedPackage(StrictModel):
    ecosystem: str | None = None
    name: str = Field(min_length=1)
    purl: str | None = None
    vendor: str | None = None
    ranges: list[AffectedRange] = Field(default_factory=list)
    versions: list[str] = Field(default_factory=list)
    ecosystem_specific: dict[str, JsonValue] = Field(default_factory=dict)
    database_specific: dict[str, JsonValue] = Field(default_factory=dict)

    @model_validator(mode="after")
    def unique_versions(self) -> Self:
        if len(self.versions) != len(set(self.versions)):
            raise ValueError("affected package versions must be unique")
        return self


class SeveritySignal(StrictModel):
    kind: SeverityKind
    source: IntelligenceSource
    score: float | None = Field(default=None, ge=0.0, le=10.0)
    vector: str | None = None
    label: str | None = None
    probability: UnitScore | None = None
    percentile: UnitScore | None = None
    observed_at: AwareDatetime | None = None
    source_url: str | None = None
    metadata: dict[str, JsonValue] = Field(default_factory=dict)

    @model_validator(mode="after")
    def kind_specific_values(self) -> Self:
        if self.kind == SeverityKind.EPSS and self.probability is None:
            raise ValueError("EPSS severity signals require probability")
        if self.kind != SeverityKind.EPSS and self.percentile is not None:
            raise ValueError("percentile is only valid for EPSS signals")
        return self


class NormalizedAdvisory(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    advisory_id: str = Field(min_length=1)
    identifiers: list[str] = Field(min_length=1)
    related_identifiers: list[str] = Field(default_factory=list)
    identifier_links: list[IdentifierLink] = Field(default_factory=list)
    sources: list[IntelligenceSource] = Field(min_length=1)
    tombstoned_sources: list[IntelligenceSource] = Field(default_factory=list)
    cve_record_state: CveRecordState | None = None
    title: str | None = None
    summary: str | None = None
    details: str | None = None
    published_at: AwareDatetime | None = None
    modified_at: AwareDatetime | None = None
    withdrawn_at: AwareDatetime | None = None
    known_exploited: bool = False
    cisa_due_date: AwareDatetime | None = None
    required_action: str | None = None
    known_ransomware_use: str | None = None
    cwes: list[str] = Field(default_factory=list)
    affected: list[AffectedPackage] = Field(default_factory=list)
    references: list[AdvisoryReference] = Field(default_factory=list)
    severity: list[SeveritySignal] = Field(default_factory=list)
    provenance: list[RawSnapshotProvenance] = Field(default_factory=list)
    source_metadata: dict[str, JsonValue] = Field(default_factory=dict)

    @model_validator(mode="after")
    def graph_and_source_invariants(self) -> Self:
        for label, values in (
            ("identifiers", [item.casefold() for item in self.identifiers]),
            ("related_identifiers", [item.casefold() for item in self.related_identifiers]),
            ("sources", [item.value for item in self.sources]),
            ("tombstoned_sources", [item.value for item in self.tombstoned_sources]),
            ("cwes", [item.casefold() for item in self.cwes]),
        ):
            if len(values) != len(set(values)):
                raise ValueError(f"{label} must contain unique values")
        if not set(self.tombstoned_sources).issubset(self.sources):
            raise ValueError("tombstoned_sources must be a subset of sources")
        if self.cve_record_state is not None and IntelligenceSource.CVE_LIST_V5 not in self.sources:
            raise ValueError("cve_record_state requires the cve-list-v5 source")
        alias_nodes = {item.casefold() for item in self.identifiers}
        for link in self.identifier_links:
            if link.relation == IdentifierRelation.ALIAS and (
                link.left.casefold() not in alias_nodes or link.right.casefold() not in alias_nodes
            ):
                raise ValueError("alias link endpoints must occur in identifiers")
        return self


class PriorityFactors(StrictModel):
    """Fully disclosed inputs for deterministic KEV-first priority ranking."""

    algorithm_version: Literal["kev-epss-recency-severity-evidence-v1"] = (
        "kev-epss-recency-severity-evidence-v1"
    )
    as_of: AwareDatetime
    confirmed_kev: bool
    kev_weight: float = 1000.0
    kev_component: float = Field(ge=0.0)
    epss_probability: UnitScore | None = None
    epss_weight: float = 100.0
    epss_component: float = Field(ge=0.0)
    recency_age_days: float | None = Field(default=None, ge=0.0)
    recency_window_days: float = 90.0
    recency_score: UnitScore
    recency_weight: float = 40.0
    recency_component: float = Field(ge=0.0)
    severity_score: UnitScore
    severity_weight: float = 60.0
    severity_component: float = Field(ge=0.0)
    evidence_completeness: UnitScore
    evidence_weight: float = 20.0
    evidence_component: float = Field(ge=0.0)
    total_score: float = Field(ge=0.0)
    reasons: list[str] = Field(min_length=1)


class RankedAdvisory(StrictModel):
    advisory: NormalizedAdvisory
    priority: PriorityFactors


class SyncIssue(StrictModel):
    code: str = Field(min_length=1)
    message: str = Field(min_length=1, max_length=500)
    retriable: bool = False
    record_id: str | None = None


class SourceSyncResult(StrictModel):
    source: IntelligenceSource
    status: SyncStatus
    started_at: AwareDatetime
    finished_at: AwareDatetime
    records_seen: int = Field(default=0, ge=0)
    records_selected: int = Field(default=0, ge=0)
    records_inserted: int = Field(default=0, ge=0)
    records_updated: int = Field(default=0, ge=0)
    records_unchanged: int = Field(default=0, ge=0)
    records_tombstoned: int = Field(default=0, ge=0)
    records_filtered: int = Field(default=0, ge=0)
    snapshots_stored: int = Field(default=0, ge=0)
    truncated: bool = False
    cursor_before: AwareDatetime | None = None
    cursor_after: AwareDatetime | None = None
    issues: list[SyncIssue] = Field(default_factory=list)
    metadata: dict[str, JsonValue] = Field(default_factory=dict)

    @model_validator(mode="after")
    def valid_timing(self) -> Self:
        if self.finished_at < self.started_at:
            raise ValueError("source sync finished_at cannot precede started_at")
        if self.status == SyncStatus.FAILED and not self.issues:
            raise ValueError("failed source sync requires an issue")
        return self


class IntelligenceSyncReport(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    run_id: str = Field(min_length=1)
    status: SyncStatus
    started_at: AwareDatetime
    finished_at: AwareDatetime
    requested_sources: list[IntelligenceSource] = Field(min_length=1)
    since_hours: float = Field(gt=0.0)
    ecosystems: list[str] = Field(default_factory=list)
    limit_per_source: int = Field(ge=1)
    enrich_epss: bool
    results: list[SourceSyncResult] = Field(min_length=1)

    @property
    def successful(self) -> bool:
        required = set(self.requested_sources)
        primary_results = {
            result.source: result.status for result in self.results if result.source in required
        }
        return required == set(primary_results) and all(
            status == SyncStatus.SUCCESS for status in primary_results.values()
        )


class SourceState(StrictModel):
    source: IntelligenceSource
    last_attempt_at: AwareDatetime | None = None
    last_success_at: AwareDatetime | None = None
    cursor_at: AwareDatetime | None = None
    etag: str | None = None
    last_modified: str | None = None
    last_snapshot_id: str | None = None
    last_status: SyncStatus | None = None
    metadata: dict[str, JsonValue] = Field(default_factory=dict)


class SourceStatus(StrictModel):
    source: IntelligenceSource
    state: SourceState | None = None
    active_records: int = Field(default=0, ge=0)
    tombstoned_records: int = Field(default=0, ge=0)


class IntelligenceStatus(StrictModel):
    initialized: bool
    advisory_count: int = Field(default=0, ge=0)
    withdrawn_count: int = Field(default=0, ge=0)
    rejected_cve_count: int = Field(default=0, ge=0)
    snapshot_count: int = Field(default=0, ge=0)
    sync_run_count: int = Field(default=0, ge=0)
    sources: list[SourceStatus] = Field(default_factory=list)
    latest_sync: IntelligenceSyncReport | None = None


class IntelligenceLimits(StrictModel):
    timeout_seconds: float = Field(default=20.0, gt=0.0, le=120.0)
    max_cisa_bytes: int = Field(default=32 * 1024 * 1024, ge=1024)
    max_cisa_items: int = Field(default=25_000, ge=1)
    max_cve_delta_bytes: int = Field(default=32 * 1024 * 1024, ge=1024)
    max_cve_delta_batches: int = Field(default=10_000, ge=1)
    max_cve_delta_entries: int = Field(default=500_000, ge=1)
    max_cve_candidates: int = Field(default=10_000, ge=1)
    max_cve_record_bytes: int = Field(default=4 * 1024 * 1024, ge=1024)
    max_cve_consecutive_server_errors: int = Field(default=3, ge=1, le=20)
    max_osv_index_bytes: int = Field(default=64 * 1024 * 1024, ge=1024)
    max_osv_index_lines: int = Field(default=1_000_000, ge=1)
    max_osv_candidates: int = Field(default=5_000, ge=1)
    max_osv_record_bytes: int = Field(default=4 * 1024 * 1024, ge=1024)
    max_osv_consecutive_server_errors: int = Field(default=3, ge=1, le=20)
    max_epss_bytes: int = Field(default=4 * 1024 * 1024, ge=1024)
    max_epss_cves_per_request: int = Field(default=100, ge=1, le=500)
    max_limit_per_source: int = Field(default=10_000, ge=1, le=10_000)
    cve_overlap_hours: float = Field(default=2.0, ge=0.0, le=24.0)
    osv_overlap_hours: float = Field(default=2.0, ge=0.0, le=24.0)
    max_snapshot_bytes: int = Field(default=64 * 1024 * 1024, ge=1024)
