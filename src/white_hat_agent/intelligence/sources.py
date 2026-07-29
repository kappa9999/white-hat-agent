from __future__ import annotations

import csv
import hashlib
import io
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import unquote

from .errors import IntelligenceLimitError, IntelligenceParseError
from .models import (
    AdvisoryReference,
    AffectedPackage,
    AffectedRange,
    CveRecordState,
    IdentifierLink,
    IdentifierRelation,
    IntelligenceSource,
    NormalizedAdvisory,
    RangeType,
    RawSnapshotProvenance,
    ReferenceType,
    SeverityKind,
    SeveritySignal,
    SourceAttribution,
    SyncIssue,
    VersionEvent,
)
from .transport import CVE_LIST_V5_RECORD_BASE_URL

CISA_ATTRIBUTION = SourceAttribution(
    publisher="Cybersecurity and Infrastructure Security Agency",
    dataset="Known Exploited Vulnerabilities Catalog",
    attribution="CISA Known Exploited Vulnerabilities Catalog",
    license_name="CC0 1.0 Universal",
    license_url="https://www.cisa.gov/sites/default/files/licenses/kev/license.txt",
)
CVE_LIST_V5_ATTRIBUTION = SourceAttribution(
    publisher="CVE Program",
    dataset="CVE List V5",
    attribution="CVE Program CVE List in CVE Record Format",
    license_name="CVE Program Terms of Use",
    license_url="https://www.cve.org/Legal/TermsOfUse",
)
OSV_ATTRIBUTION = SourceAttribution(
    publisher="OSV.dev aggregation service and identified upstream advisory databases",
    dataset="OSV.dev vulnerability database API",
    attribution="OSV.dev and the advisory source identified by each OSV record",
    license_name="Source-database-specific terms",
    license_url="https://google.github.io/osv.dev/data/#data-sources",
)
EPSS_ATTRIBUTION = SourceAttribution(
    publisher="Forum of Incident Response and Security Teams",
    dataset="Exploit Prediction Scoring System",
    attribution="FIRST Exploit Prediction Scoring System (EPSS)",
    license_name="FIRST EPSS data terms",
    license_url="https://www.first.org/epss/",
)

_MAX_ALIASES = 1_000
_MAX_RELATED = 1_000
_MAX_AFFECTED = 5_000
_MAX_RANGES_PER_PACKAGE = 1_000
_MAX_EVENTS_PER_RANGE = 10_000
_MAX_VERSIONS_PER_PACKAGE = 100_000
_MAX_REFERENCES = 10_000
_MAX_SEVERITY_SIGNALS = 1_000
_MAX_EPSS_ITEMS = 10_000
_MAX_CVE_ADP_CONTAINERS = 1_000
_URL_RE = re.compile(r"https?://[^\s,;]+")
_CVE_ID_RE = re.compile(r"^CVE-(\d{4})-(\d{4,})$", re.IGNORECASE)
_SUPPORTED_CVE_DATA_VERSIONS = {
    "5.0": "5.0.0",
    "5.1": "5.1.1",
    "5.2": "5.2.0",
}


@dataclass(frozen=True, slots=True)
class ParsedSourceRecord:
    source: IntelligenceSource
    source_record_id: str
    advisory: NormalizedAdvisory
    raw_record_sha256: str


@dataclass(frozen=True, slots=True)
class CveDeltaEntry:
    cve_id: str
    modified_at: datetime
    batch_fetch_at: datetime
    cve_org_url: str
    record_url: str
    change_type: str


@dataclass(frozen=True, slots=True)
class CveDeltaSelection:
    entries: tuple[CveDeltaEntry, ...]
    batches_seen: int
    entries_seen: int
    newest_fetch_at: datetime
    oldest_fetch_at: datetime
    window_complete: bool
    candidate_limit_reached: bool
    issues: tuple[SyncIssue, ...]


@dataclass(frozen=True, slots=True)
class OsvIndexEntry:
    advisory_id: str
    modified_at: datetime
    ecosystem: str | None = None


@dataclass(frozen=True, slots=True)
class OsvIndexSelection:
    entries: tuple[OsvIndexEntry, ...]
    lines_seen: int
    reached_boundary: bool
    candidate_limit_reached: bool
    entries_filtered: int
    issues: tuple[SyncIssue, ...]


@dataclass(frozen=True, slots=True)
class ParsedEpssSignal:
    cve: str
    signal: SeveritySignal
    raw_record_sha256: str
    metadata: dict[str, Any]


def decode_json_object(payload: bytes, *, source: IntelligenceSource) -> dict[str, Any]:
    try:
        decoded = payload.decode("utf-8")
        value = json.loads(decoded, parse_constant=_reject_json_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise IntelligenceParseError("public source returned invalid JSON", source=source) from exc
    if not isinstance(value, dict):
        raise IntelligenceParseError("public source JSON root must be an object", source=source)
    return value


def decode_json_array(payload: bytes, *, source: IntelligenceSource) -> list[Any]:
    try:
        decoded = payload.decode("utf-8")
        value = json.loads(decoded, parse_constant=_reject_json_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise IntelligenceParseError("public source returned invalid JSON", source=source) from exc
    if not isinstance(value, list):
        raise IntelligenceParseError("public source JSON root must be an array", source=source)
    return value


def parse_cisa_kev(
    document: dict[str, Any],
    provenance: RawSnapshotProvenance,
    *,
    max_items: int,
) -> list[ParsedSourceRecord]:
    raw_items = document.get("vulnerabilities")
    if not isinstance(raw_items, list):
        raise IntelligenceParseError(
            "CISA KEV feed is missing vulnerabilities", source=IntelligenceSource.CISA_KEV
        )
    if len(raw_items) > max_items:
        raise IntelligenceLimitError(
            f"CISA KEV feed exceeds {max_items} item limit", source=IntelligenceSource.CISA_KEV
        )
    declared_count = document.get("count")
    if isinstance(declared_count, bool) or not isinstance(declared_count, int):
        raise IntelligenceParseError(
            "CISA KEV feed count must be an integer", source=IntelligenceSource.CISA_KEV
        )
    if declared_count != len(raw_items):
        raise IntelligenceParseError(
            "CISA KEV feed count does not match vulnerabilities",
            source=IntelligenceSource.CISA_KEV,
        )
    catalog_version = _optional_string(document.get("catalogVersion"))
    date_released = _optional_string(document.get("dateReleased"))
    records: list[ParsedSourceRecord] = []
    for raw in raw_items:
        if not isinstance(raw, dict):
            raise IntelligenceParseError(
                "CISA KEV vulnerability must be an object", source=IntelligenceSource.CISA_KEV
            )
        cve = _required_identifier(raw.get("cveID"), "CISA KEV cveID")
        product = _optional_string(raw.get("product")) or "Unspecified product"
        vendor = _optional_string(raw.get("vendorProject"))
        title = _optional_string(raw.get("vulnerabilityName"))
        summary = _optional_string(raw.get("shortDescription"))
        required_action = _optional_string(raw.get("requiredAction"))
        notes = _optional_string(raw.get("notes"))
        references = [
            AdvisoryReference(
                url=url,
                type=ReferenceType.ADVISORY,
                raw_type="notes",
                source=IntelligenceSource.CISA_KEV,
            )
            for url in _extract_urls(notes)
        ]
        cwes = _unique_strings(_bounded_list(raw.get("cwes"), "CISA cwes", 1_000))
        source_metadata: dict[str, Any] = {
            "catalog_version": catalog_version,
            "catalog_date_released": date_released,
            "date_added": _optional_string(raw.get("dateAdded")),
            "vendor_project": vendor,
            "product": product,
            "notes": notes,
            "unknown_fields": sorted(
                set(raw)
                - {
                    "cveID",
                    "vendorProject",
                    "product",
                    "vulnerabilityName",
                    "dateAdded",
                    "shortDescription",
                    "requiredAction",
                    "dueDate",
                    "knownRansomwareCampaignUse",
                    "notes",
                    "cwes",
                }
            ),
        }
        source_metadata = {key: value for key, value in source_metadata.items() if value is not None}
        advisory = NormalizedAdvisory(
            advisory_id=cve,
            identifiers=[cve],
            sources=[IntelligenceSource.CISA_KEV],
            title=title,
            summary=summary,
            published_at=_optional_datetime(raw.get("dateAdded")),
            known_exploited=True,
            cisa_due_date=_optional_datetime(raw.get("dueDate")),
            required_action=required_action,
            known_ransomware_use=_optional_string(raw.get("knownRansomwareCampaignUse")),
            cwes=cwes,
            affected=[AffectedPackage(ecosystem="CISA KEV", name=product, vendor=vendor)],
            references=references,
            provenance=[provenance],
            source_metadata={IntelligenceSource.CISA_KEV.value: source_metadata},
        )
        records.append(
            ParsedSourceRecord(
                source=IntelligenceSource.CISA_KEV,
                source_record_id=cve,
                advisory=advisory,
                raw_record_sha256=_canonical_sha256(raw),
            )
        )
    return records


def parse_cve_delta_log(
    document: list[Any],
    *,
    boundary: datetime,
    max_batches: int,
    max_entries: int,
    max_candidates: int,
) -> CveDeltaSelection:
    source = IntelligenceSource.CVE_LIST_V5
    if not document:
        raise IntelligenceParseError("CVE List V5 delta log is empty", source=source)
    if len(document) > max_batches:
        raise IntelligenceLimitError(
            f"CVE List V5 delta log exceeds {max_batches} batch limit", source=source
        )
    entries_by_id: dict[str, CveDeltaEntry] = {}
    issues: list[SyncIssue] = []
    fetch_times: list[datetime] = []
    entries_seen = 0
    for batch_index, batch in enumerate(document, start=1):
        if not isinstance(batch, dict):
            issues.append(
                SyncIssue(
                    code="invalid_delta_batch",
                    message=f"ignored malformed CVE delta batch {batch_index}",
                )
            )
            continue
        fetch_at = _optional_datetime(batch.get("fetchTime"))
        if fetch_at is None:
            issues.append(
                SyncIssue(
                    code="invalid_delta_batch_time",
                    message=f"ignored CVE delta batch {batch_index} without a valid fetchTime",
                )
            )
            continue
        else:
            fetch_times.append(fetch_at)
        observed_changes = 0
        for change_type in ("new", "updated"):
            raw_entries = batch.get(change_type)
            if not isinstance(raw_entries, list):
                issues.append(
                    SyncIssue(
                        code="invalid_delta_change_list",
                        message=f"CVE delta batch {batch_index} has invalid {change_type} entries",
                    )
                )
                continue
            observed_changes += len(raw_entries)
            for raw in raw_entries:
                entries_seen += 1
                if entries_seen > max_entries:
                    raise IntelligenceLimitError(
                        f"CVE List V5 delta log exceeds {max_entries} entry limit",
                        source=source,
                    )
                if not isinstance(raw, dict):
                    issues.append(
                        SyncIssue(
                            code="invalid_delta_entry",
                            message="ignored malformed CVE delta entry",
                        )
                    )
                    continue
                try:
                    cve_id = _required_cve_id(raw.get("cveId"))
                    modified_at = _required_datetime(raw.get("dateUpdated"))
                    cve_org_url = f"https://www.cve.org/CVERecord?id={cve_id}"
                    record_url = cve_list_v5_record_url(cve_id)
                    if (
                        _optional_string(raw.get("cveOrgLink")) != cve_org_url
                        or _optional_string(raw.get("githubLink")) != record_url
                    ):
                        raise ValueError("record URL mismatch")
                except (IntelligenceParseError, ValueError):
                    issues.append(
                        SyncIssue(
                            code="invalid_delta_entry",
                            message="ignored malformed CVE delta entry",
                            record_id=_optional_string(raw.get("cveId")),
                        )
                    )
                    continue
                if fetch_at < boundary:
                    continue
                candidate = CveDeltaEntry(
                    cve_id=cve_id,
                    modified_at=modified_at,
                    batch_fetch_at=fetch_at,
                    cve_org_url=cve_org_url,
                    record_url=record_url,
                    change_type=change_type,
                )
                previous = entries_by_id.get(cve_id.casefold())
                if previous is None or (
                    candidate.batch_fetch_at,
                    candidate.modified_at,
                ) > (
                    previous.batch_fetch_at,
                    previous.modified_at,
                ):
                    entries_by_id[cve_id.casefold()] = candidate
        raw_errors = batch.get("error")
        if isinstance(raw_errors, list):
            observed_changes += len(raw_errors)
            for raw_error in raw_errors:
                record_id = _optional_string(raw_error.get("cveId")) if isinstance(raw_error, dict) else None
                issues.append(
                    SyncIssue(
                        code="upstream_delta_error",
                        message="CVE List V5 delta log reported an upstream collection error",
                        retriable=True,
                        record_id=record_id,
                    )
                )
        elif raw_errors is not None:
            issues.append(
                SyncIssue(
                    code="invalid_delta_error_list",
                    message=f"CVE delta batch {batch_index} has an invalid error list",
                )
            )
        declared_changes = batch.get("numberOfChanges")
        if (
            isinstance(declared_changes, bool)
            or not isinstance(declared_changes, int)
            or declared_changes != observed_changes
        ):
            issues.append(
                SyncIssue(
                    code="delta_change_count_mismatch",
                    message=f"CVE delta batch {batch_index} change count does not match its entries",
                )
            )
    if not fetch_times:
        raise IntelligenceParseError("CVE List V5 delta log has no valid batch timestamp", source=source)
    entries = sorted(
        entries_by_id.values(),
        key=lambda item: (
            -item.batch_fetch_at.timestamp(),
            -item.modified_at.timestamp(),
            item.cve_id.casefold(),
        ),
    )
    candidate_limit_reached = len(entries) > max_candidates
    entries = entries[:max_candidates]
    newest_fetch_at = max(fetch_times)
    oldest_fetch_at = min(fetch_times)
    window_complete = oldest_fetch_at <= boundary
    if not window_complete:
        issues.append(
            SyncIssue(
                code="delta_history_gap",
                message="CVE List V5 rolling delta does not cover the requested boundary",
            )
        )
    return CveDeltaSelection(
        entries=tuple(entries),
        batches_seen=len(document),
        entries_seen=entries_seen,
        newest_fetch_at=newest_fetch_at,
        oldest_fetch_at=oldest_fetch_at,
        window_complete=window_complete,
        candidate_limit_reached=candidate_limit_reached,
        issues=tuple(issues),
    )


def cve_list_v5_record_url(cve_id: str) -> str:
    normalized = _required_cve_id(cve_id)
    match = _CVE_ID_RE.fullmatch(normalized)
    if match is None:  # pragma: no cover - guarded by _required_cve_id
        raise IntelligenceParseError(
            "CVE List V5 identifier is invalid", source=IntelligenceSource.CVE_LIST_V5
        )
    year, serial_text = match.groups()
    bucket = f"{int(serial_text) // 1000}xxx"
    return f"{CVE_LIST_V5_RECORD_BASE_URL}{year}/{bucket}/{normalized}.json"


def parse_cve_record(document: dict[str, Any], provenance: RawSnapshotProvenance) -> ParsedSourceRecord:
    source = IntelligenceSource.CVE_LIST_V5
    if document.get("dataType") != "CVE_RECORD":
        raise IntelligenceParseError("CVE record has an invalid dataType", source=source)
    data_version = _optional_string(document.get("dataVersion"))
    if data_version not in _SUPPORTED_CVE_DATA_VERSIONS:
        raise IntelligenceParseError("CVE record has an unsupported dataVersion", source=source)
    metadata = _json_object(document.get("cveMetadata"))
    if not metadata:
        raise IntelligenceParseError("CVE record is missing cveMetadata", source=source)
    cve_id = _required_cve_id(metadata.get("cveId"))
    serial = metadata.get("serial")
    if serial is not None and (isinstance(serial, bool) or not isinstance(serial, int) or serial < 1):
        raise IntelligenceParseError("CVE record has an invalid serial", source=source)
    if _optional_datetime(metadata.get("dateUpdated")) is None:
        raise IntelligenceParseError("CVE record has an invalid dateUpdated", source=source)
    try:
        record_state = CveRecordState((_optional_string(metadata.get("state")) or "").upper())
    except ValueError as exc:
        raise IntelligenceParseError("CVE record has an invalid state", source=source) from exc
    containers = _json_object(document.get("containers"))
    cna = _json_object(containers.get("cna"))
    if not cna:
        raise IntelligenceParseError("CVE record is missing its CNA container", source=source)
    provider_metadata = _json_object(cna.get("providerMetadata"))
    if not _optional_string(provider_metadata.get("orgId")):
        raise IntelligenceParseError("CVE CNA container is missing providerMetadata", source=source)
    if containers.get("adp") is not None and not isinstance(containers.get("adp"), list):
        raise IntelligenceParseError("CVE record has an invalid ADP container", source=source)
    adp = _bounded_list(containers.get("adp"), "CVE ADP containers", _MAX_CVE_ADP_CONTAINERS)
    if any(not isinstance(container, dict) for container in adp):
        raise IntelligenceParseError("CVE record has an invalid ADP container", source=source)
    typed_adp = [container for container in adp if isinstance(container, dict)]
    semantic_containers = [
        ("/containers/cna", cna),
        *[(f"/containers/adp/{index}", container) for index, container in enumerate(typed_adp)],
    ]
    descriptions = _cve_text_values(cna.get("descriptions"), "CVE descriptions")
    rejected_reasons = _cve_text_values(cna.get("rejectedReasons"), "CVE rejected reasons")
    if record_state == CveRecordState.PUBLISHED:
        if _optional_datetime(metadata.get("datePublished")) is None or not descriptions:
            raise IntelligenceParseError("published CVE record is missing required fields", source=source)
    elif not rejected_reasons or typed_adp:
        raise IntelligenceParseError("rejected CVE record has an invalid container", source=source)
    title = _optional_string(cna.get("title"))
    if record_state == CveRecordState.REJECTED:
        title = title or "Rejected CVE record"
    summary = (rejected_reasons or descriptions or [None])[0]
    details_values = rejected_reasons if rejected_reasons else descriptions
    affected = _unique_models(
        [
            package
            for container_pointer, container in semantic_containers
            for package in _parse_cve_affected(
                container.get("affected"),
                container_pointer=container_pointer,
            )
        ],
        key=lambda item: _canonical_sha256(item.model_dump(mode="json")),
    )
    references = _unique_models(
        [
            reference
            for _, container in semantic_containers
            for reference in _parse_cve_references(container.get("references"))
        ],
        key=lambda item: (item.url, item.type.value, item.raw_type or ""),
    )
    severity = _unique_models(
        [
            signal
            for _, container in semantic_containers
            for signal in _parse_cve_metrics(
                container.get("metrics"),
                provider_metadata=_json_object(container.get("providerMetadata")),
                source_url=provenance.source_url,
            )
        ],
        key=lambda item: _canonical_sha256(item.model_dump(mode="json")),
    )
    cwes = _unique_strings(
        [
            cwe
            for _, container in semantic_containers
            for cwe in _parse_cve_problem_types(container.get("problemTypes"))
        ]
    )
    modified_at = _optional_datetime(metadata.get("dateUpdated"))
    source_metadata = {
        "data_type": document.get("dataType"),
        "data_version": data_version,
        "schema_release": _SUPPORTED_CVE_DATA_VERSIONS[data_version],
        "state": record_state.value,
        "assigner_org_id": _optional_string(metadata.get("assignerOrgId")),
        "assigner_short_name": _optional_string(metadata.get("assignerShortName")),
        "date_reserved": _optional_string(metadata.get("dateReserved")),
        "date_published": _optional_string(metadata.get("datePublished")),
        "date_rejected": _optional_string(metadata.get("dateRejected")),
        "date_updated": _optional_string(metadata.get("dateUpdated")),
        "serial": serial,
        "container_index": [
            {
                "json_pointer": pointer,
                "provider_metadata": _json_object(container.get("providerMetadata")),
            }
            for pointer, container in semantic_containers
        ],
        "unknown_top_level_fields": sorted(
            set(document) - {"dataType", "dataVersion", "cveMetadata", "containers"}
        ),
    }
    source_metadata = {key: value for key, value in source_metadata.items() if value is not None}
    advisory = NormalizedAdvisory(
        advisory_id=cve_id,
        identifiers=[cve_id],
        sources=[source],
        cve_record_state=record_state,
        title=title,
        summary=summary,
        details="\n\n".join(details_values) if details_values else None,
        published_at=_optional_datetime(metadata.get("datePublished")),
        modified_at=modified_at,
        withdrawn_at=None,
        cwes=cwes,
        affected=affected,
        references=references,
        severity=severity,
        provenance=[provenance],
        source_metadata={source.value: source_metadata},
    )
    return ParsedSourceRecord(
        source=source,
        source_record_id=cve_id,
        advisory=advisory,
        raw_record_sha256=_canonical_sha256(document),
    )


def parse_osv_record(document: dict[str, Any], provenance: RawSnapshotProvenance) -> ParsedSourceRecord:
    advisory_id = _required_identifier(document.get("id"), "OSV id")
    aliases = _unique_strings(_bounded_list(document.get("aliases"), "OSV aliases", _MAX_ALIASES))
    related = _unique_strings(_bounded_list(document.get("related"), "OSV related", _MAX_RELATED))
    identifiers = _unique_strings([advisory_id, *aliases])
    alias_links = [
        IdentifierLink(
            left=advisory_id,
            right=alias,
            relation=IdentifierRelation.ALIAS,
            source=IntelligenceSource.OSV,
        )
        for alias in aliases
        if alias.casefold() != advisory_id.casefold()
    ]
    related_links = [
        IdentifierLink(
            left=advisory_id,
            right=other,
            relation=IdentifierRelation.RELATED,
            source=IntelligenceSource.OSV,
        )
        for other in related
        if other.casefold() != advisory_id.casefold()
    ]
    affected = _parse_osv_affected(document.get("affected"))
    references = _parse_osv_references(document.get("references"))
    severity = _parse_osv_severity(document.get("severity"))
    database_specific = _json_object(document.get("database_specific"))
    qualitative = _optional_string(database_specific.get("severity"))
    if qualitative:
        severity.append(
            SeveritySignal(
                kind=SeverityKind.QUALITATIVE,
                source=IntelligenceSource.OSV,
                label=qualitative,
                source_url=provenance.source_url,
            )
        )
    metadata: dict[str, Any] = {
        "schema_version": _optional_string(document.get("schema_version")),
        "database_specific": database_specific,
        "source_database": _osv_source_database(advisory_id, database_specific),
        "credits": _bounded_list(document.get("credits"), "OSV credits", 10_000),
        "unknown_fields": sorted(
            set(document)
            - {
                "schema_version",
                "id",
                "modified",
                "published",
                "withdrawn",
                "aliases",
                "related",
                "summary",
                "details",
                "affected",
                "references",
                "severity",
                "database_specific",
                "credits",
            }
        ),
    }
    summary = _optional_string(document.get("summary"))
    advisory = NormalizedAdvisory(
        advisory_id=_canonical_identifier(identifiers),
        identifiers=identifiers,
        related_identifiers=related,
        identifier_links=[*alias_links, *related_links],
        sources=[IntelligenceSource.OSV],
        title=summary,
        summary=summary,
        details=_optional_string(document.get("details")),
        published_at=_optional_datetime(document.get("published")),
        modified_at=_optional_datetime(document.get("modified")),
        withdrawn_at=_optional_datetime(document.get("withdrawn")),
        affected=affected,
        references=references,
        severity=severity,
        provenance=[provenance],
        source_metadata={IntelligenceSource.OSV.value: metadata},
    )
    return ParsedSourceRecord(
        source=IntelligenceSource.OSV,
        source_record_id=advisory_id,
        advisory=advisory,
        raw_record_sha256=_canonical_sha256(document),
    )


def parse_osv_modified_index(
    payload: bytes,
    *,
    boundary: datetime,
    max_lines: int,
    max_candidates: int,
    ecosystems: list[str] | None = None,
) -> OsvIndexSelection:
    try:
        text = payload.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise IntelligenceParseError(
            "OSV modified index is not UTF-8", source=IntelligenceSource.OSV
        ) from exc
    reader = csv.reader(io.StringIO(text, newline=""))
    entries: list[OsvIndexEntry] = []
    issues: list[SyncIssue] = []
    lines_seen = 0
    reached_boundary = False
    candidate_limit_reached = False
    entries_filtered = 0
    seen_ids: set[str] = set()
    selected_ecosystems = {item.casefold() for item in ecosystems or []}
    id_index: int | None = None
    modified_index: int | None = None
    for row in reader:
        lines_seen += 1
        if lines_seen > max_lines:
            raise IntelligenceLimitError(
                f"OSV modified index exceeds {max_lines} line limit",
                source=IntelligenceSource.OSV,
            )
        if not row or not any(cell.strip() for cell in row):
            continue
        if id_index is None and modified_index is None:
            lowered = [cell.strip().casefold() for cell in row]
            if "id" in lowered and "modified" in lowered:
                id_index = lowered.index("id")
                modified_index = lowered.index("modified")
                continue
        try:
            indexed_id, modified_at = _parse_osv_index_row(
                row, id_index=id_index, modified_index=modified_index
            )
        except ValueError:
            issues.append(
                SyncIssue(
                    code="invalid_index_row",
                    message=f"ignored malformed OSV index row {lines_seen}",
                )
            )
            continue
        if modified_at < boundary:
            reached_boundary = True
            break
        advisory_id, ecosystem = _parse_osv_index_identifier(indexed_id)
        if selected_ecosystems and ecosystem and ecosystem.casefold() not in selected_ecosystems:
            entries_filtered += 1
            continue
        identifier_key = advisory_id.casefold()
        if identifier_key in seen_ids:
            entries_filtered += 1
            continue
        seen_ids.add(identifier_key)
        entries.append(
            OsvIndexEntry(
                advisory_id=advisory_id,
                modified_at=modified_at,
                ecosystem=ecosystem,
            )
        )
        if len(entries) >= max_candidates:
            candidate_limit_reached = True
            break
    if lines_seen == 0:
        raise IntelligenceParseError(
            "OSV modified index is empty",
            source=IntelligenceSource.OSV,
        )
    return OsvIndexSelection(
        entries=tuple(entries),
        lines_seen=lines_seen,
        reached_boundary=reached_boundary,
        candidate_limit_reached=candidate_limit_reached,
        entries_filtered=entries_filtered,
        issues=tuple(issues),
    )


def parse_epss(document: dict[str, Any], provenance: RawSnapshotProvenance) -> list[ParsedEpssSignal]:
    rows = document.get("data")
    if not isinstance(rows, list):
        raise IntelligenceParseError("EPSS response is missing data", source=IntelligenceSource.EPSS)
    if len(rows) > _MAX_EPSS_ITEMS:
        raise IntelligenceLimitError(
            f"EPSS response exceeds {_MAX_EPSS_ITEMS} item limit",
            source=IntelligenceSource.EPSS,
        )
    result: list[ParsedEpssSignal] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        cve = _required_identifier(row.get("cve"), "EPSS cve")
        try:
            probability = float(row["epss"])
            percentile = float(row["percentile"]) if row.get("percentile") is not None else None
        except (KeyError, TypeError, ValueError) as exc:
            raise IntelligenceParseError(
                f"EPSS record has invalid score: {cve}", source=IntelligenceSource.EPSS
            ) from exc
        observed_at = _optional_datetime(row.get("date")) or provenance.retrieved_at
        signal = SeveritySignal(
            kind=SeverityKind.EPSS,
            source=IntelligenceSource.EPSS,
            probability=probability,
            percentile=percentile,
            observed_at=observed_at,
            source_url=provenance.source_url,
            metadata={
                "model_version": _optional_string(document.get("model_version")),
                "score_date": _optional_string(row.get("date")),
            },
        )
        result.append(
            ParsedEpssSignal(
                cve=cve,
                signal=signal,
                raw_record_sha256=_canonical_sha256(row),
                metadata={"record": row},
            )
        )
    return result


def _parse_cve_affected(value: Any, *, container_pointer: str) -> list[AffectedPackage]:
    items = _bounded_list(value, "CVE affected products", _MAX_AFFECTED)
    affected: list[AffectedPackage] = []
    for item_index, item in enumerate(items):
        if not isinstance(item, dict):
            continue
        item_pointer = f"{container_pointer}/affected/{item_index}"
        purl = _optional_string(item.get("packageURL"))
        ecosystem, purl_name = _cve_purl_identity(purl)
        vendor = _optional_string(item.get("vendor"))
        product = _optional_string(item.get("product")) or purl_name or vendor
        if product is None:
            continue
        default_status = _optional_string(item.get("defaultStatus"))
        ranges: list[AffectedRange] = []
        exact_versions: list[str] = []
        raw_versions = _bounded_list(item.get("versions"), "CVE affected versions", _MAX_VERSIONS_PER_PACKAGE)
        for version_index, raw_version in enumerate(raw_versions):
            if not isinstance(raw_version, dict):
                continue
            version_pointer = f"{item_pointer}/versions/{version_index}"
            status = (_optional_string(raw_version.get("status")) or "unknown").casefold()
            version = _optional_string(raw_version.get("version"))
            less_than = _optional_string(raw_version.get("lessThan"))
            less_than_or_equal = _optional_string(raw_version.get("lessThanOrEqual"))
            raw_type = _optional_string(raw_version.get("versionType")) or "unknown"
            changes = _bounded_list(raw_version.get("changes"), "CVE version changes", _MAX_EVENTS_PER_RANGE)
            has_range_shape = bool(less_than or less_than_or_equal or changes or version == "*")
            events: list[VersionEvent] = []
            if status == "affected" and version and version != "*" and not has_range_shape:
                exact_versions.append(version)
            elif has_range_shape:
                default_status_key = (default_status or "unknown").casefold()
                typed_changes: list[tuple[str, str]] = []
                changes_are_translatable = True
                for change in changes:
                    if not isinstance(change, dict):
                        changes_are_translatable = False
                        continue
                    at = _optional_string(change.get("at"))
                    change_status = (_optional_string(change.get("status")) or "").casefold()
                    if not at or change_status not in {"affected", "unaffected"}:
                        changes_are_translatable = False
                        continue
                    typed_changes.append((at, change_status))
                translation_is_exact = (
                    default_status_key == "unaffected"
                    and status in {"affected", "unaffected"}
                    and not (less_than and less_than_or_equal)
                    and changes_are_translatable
                    and (status != "affected" or bool(version))
                )
                if translation_is_exact:
                    current_status = status
                    if current_status == "affected":
                        events.append(VersionEvent(introduced="0" if version == "*" else version))
                    for at, change_status in typed_changes:
                        if change_status == "affected" and current_status == "unaffected":
                            events.append(VersionEvent(introduced=at))
                        elif change_status == "unaffected" and current_status == "affected":
                            events.append(VersionEvent(fixed=at))
                        current_status = change_status
                    if current_status == "affected":
                        if less_than and less_than != "*":
                            events.append(VersionEvent(fixed=less_than))
                        elif less_than_or_equal and less_than_or_equal != "*":
                            events.append(VersionEvent(last_affected=less_than_or_equal))
            events = _unique_models(events, key=lambda event: _canonical_sha256(event.model_dump()))
            if events or has_range_shape:
                range_type = {
                    "git": RangeType.GIT,
                    "semver": RangeType.SEMVER,
                }.get(raw_type.casefold(), RangeType.ECOSYSTEM)
                ranges.append(
                    AffectedRange(
                        type=range_type,
                        raw_type=(raw_type if range_type == RangeType.ECOSYSTEM else None),
                        events=events,
                        database_specific={
                            "status": status,
                            "default_status": default_status,
                            "json_pointer": version_pointer,
                        },
                    )
                )
        affected.append(
            AffectedPackage(
                ecosystem=ecosystem,
                name=product,
                purl=purl,
                vendor=vendor,
                ranges=ranges,
                versions=_unique_strings(exact_versions),
                database_specific={
                    key: value
                    for key, value in {
                        "default_status": default_status,
                        "json_pointer": item_pointer,
                        "collection_url": _optional_string(item.get("collectionURL")),
                        "cpes": _bounded_list(item.get("cpes"), "CVE CPEs", 10_000),
                    }.items()
                    if value not in (None, [])
                },
            )
        )
    return affected


def _parse_cve_references(value: Any) -> list[AdvisoryReference]:
    references: list[AdvisoryReference] = []
    for item in _bounded_list(value, "CVE references", _MAX_REFERENCES):
        if not isinstance(item, dict):
            continue
        url = _optional_string(item.get("url"))
        if not url or not url.startswith(("https://", "http://")):
            continue
        tags = _unique_strings(_bounded_list(item.get("tags"), "CVE reference tags", 1_000))
        references.append(
            AdvisoryReference(
                url=url,
                type=ReferenceType.ADVISORY,
                raw_type=",".join(tags) if tags else None,
                title=_optional_string(item.get("name")),
                source=IntelligenceSource.CVE_LIST_V5,
            )
        )
    return references


def _parse_cve_metrics(
    value: Any,
    *,
    provider_metadata: dict[str, Any],
    source_url: str,
) -> list[SeveritySignal]:
    severity: list[SeveritySignal] = []
    for metric in _bounded_list(value, "CVE metrics", _MAX_SEVERITY_SIGNALS):
        if not isinstance(metric, dict):
            continue
        cvss_key = next((key for key in sorted(metric) if key.casefold().startswith("cvssv")), None)
        if cvss_key is None or not isinstance(metric.get(cvss_key), dict):
            continue
        cvss = metric[cvss_key]
        raw_score = cvss.get("baseScore")
        score = (
            float(raw_score)
            if isinstance(raw_score, (int, float))
            and not isinstance(raw_score, bool)
            and 0 <= float(raw_score) <= 10
            else None
        )
        severity.append(
            SeveritySignal(
                kind=SeverityKind.CVSS,
                source=IntelligenceSource.CVE_LIST_V5,
                score=score,
                vector=_optional_string(cvss.get("vectorString")),
                label=_optional_string(cvss.get("baseSeverity")),
                source_url=source_url,
                metadata={
                    "raw_type": cvss_key,
                    "version": _optional_string(cvss.get("version")),
                    "format": _optional_string(metric.get("format")),
                    "provider_metadata": provider_metadata,
                },
            )
        )
    return severity


def _parse_cve_problem_types(value: Any) -> list[str]:
    cwes: list[str] = []
    for problem_type in _bounded_list(value, "CVE problem types", 10_000):
        if not isinstance(problem_type, dict):
            continue
        for description in _bounded_list(
            problem_type.get("descriptions"), "CVE problem type descriptions", 10_000
        ):
            if not isinstance(description, dict):
                continue
            cwe = _optional_string(description.get("cweId"))
            if cwe and re.fullmatch(r"CWE-\d+", cwe, re.IGNORECASE):
                cwes.append(cwe.upper())
    return cwes


def _cve_text_values(value: Any, label: str) -> list[str]:
    rows = _bounded_list(value, label, 10_000)
    localized: list[tuple[bool, int, str]] = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            continue
        text = _optional_string(row.get("value"))
        if text:
            language = (_optional_string(row.get("lang")) or "und").casefold()
            localized.append((language.startswith("en"), index, text))
    localized.sort(key=lambda item: (not item[0], item[1]))
    return _unique_strings([item[2] for item in localized])


def _cve_purl_identity(purl: str | None) -> tuple[str | None, str | None]:
    if not purl or not purl.casefold().startswith("pkg:"):
        return None, None
    body = purl[4:].split("?", 1)[0].split("#", 1)[0]
    if "/" not in body:
        return None, None
    package_type, name = body.split("/", 1)
    name = name.split("@", 1)[0]
    ecosystem = {
        "golang": "Go",
        "pypi": "PyPI",
        "github": "GitHub",
    }.get(package_type.casefold(), package_type)
    return ecosystem or None, unquote(name) or None


def _parse_osv_affected(value: Any) -> list[AffectedPackage]:
    items = _bounded_list(value, "OSV affected", _MAX_AFFECTED)
    affected: list[AffectedPackage] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        package = _json_object(item.get("package"))
        name = _optional_string(package.get("name"))
        if not name:
            continue
        ranges: list[AffectedRange] = []
        for raw_range in _bounded_list(item.get("ranges"), "OSV package ranges", _MAX_RANGES_PER_PACKAGE):
            if not isinstance(raw_range, dict):
                continue
            raw_type = _optional_string(raw_range.get("type")) or "UNKNOWN"
            range_type = {
                "ECOSYSTEM": RangeType.ECOSYSTEM,
                "GIT": RangeType.GIT,
                "SEMVER": RangeType.SEMVER,
            }.get(raw_type.upper(), RangeType.UNKNOWN)
            events: list[VersionEvent] = []
            for raw_event in _bounded_list(
                raw_range.get("events"), "OSV range events", _MAX_EVENTS_PER_RANGE
            ):
                if not isinstance(raw_event, dict):
                    continue
                recognized = {
                    key: _optional_string(raw_event.get(key))
                    for key in ("introduced", "fixed", "last_affected", "limit")
                    if raw_event.get(key) is not None
                }
                if len(recognized) == 1 and next(iter(recognized.values())) is not None:
                    events.append(VersionEvent(**recognized))
            ranges.append(
                AffectedRange(
                    type=range_type,
                    raw_type=raw_type if range_type == RangeType.UNKNOWN else None,
                    repository=_optional_string(raw_range.get("repo")),
                    events=events,
                    database_specific=_json_object(raw_range.get("database_specific")),
                )
            )
        versions = _unique_strings(
            _bounded_list(item.get("versions"), "OSV affected versions", _MAX_VERSIONS_PER_PACKAGE)
        )
        affected.append(
            AffectedPackage(
                ecosystem=_optional_string(package.get("ecosystem")),
                name=name,
                purl=_optional_string(package.get("purl")),
                ranges=ranges,
                versions=versions,
                ecosystem_specific=_json_object(item.get("ecosystem_specific")),
                database_specific=_json_object(item.get("database_specific")),
            )
        )
    return affected


def _parse_osv_references(value: Any) -> list[AdvisoryReference]:
    items = _bounded_list(value, "OSV references", _MAX_REFERENCES)
    references: list[AdvisoryReference] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        url = _optional_string(item.get("url"))
        if not url or not url.startswith(("https://", "http://")):
            continue
        raw_type = _optional_string(item.get("type")) or "UNKNOWN"
        try:
            reference_type = ReferenceType(raw_type.casefold())
        except ValueError:
            reference_type = ReferenceType.UNKNOWN
        references.append(
            AdvisoryReference(
                url=url,
                type=reference_type,
                raw_type=raw_type if reference_type == ReferenceType.UNKNOWN else None,
                source=IntelligenceSource.OSV,
            )
        )
    return _unique_models(references, key=lambda item: (item.url, item.type.value, item.raw_type or ""))


def _parse_osv_severity(value: Any) -> list[SeveritySignal]:
    items = _bounded_list(value, "OSV severity", _MAX_SEVERITY_SIGNALS)
    severity: list[SeveritySignal] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        raw_type = _optional_string(item.get("type")) or "OTHER"
        raw_score = item.get("score")
        score: float | None = None
        vector: str | None = None
        if isinstance(raw_score, (int, float)) and not isinstance(raw_score, bool):
            score = float(raw_score)
        elif isinstance(raw_score, str):
            try:
                candidate = float(raw_score)
            except ValueError:
                vector = raw_score
            else:
                if 0.0 <= candidate <= 10.0:
                    score = candidate
                else:
                    vector = raw_score
        severity.append(
            SeveritySignal(
                kind=SeverityKind.CVSS if raw_type.upper().startswith("CVSS") else SeverityKind.OTHER,
                source=IntelligenceSource.OSV,
                score=score,
                vector=vector,
                metadata={"raw_type": raw_type},
            )
        )
    return severity


def _parse_osv_index_row(
    row: list[str], *, id_index: int | None, modified_index: int | None
) -> tuple[str, datetime]:
    if id_index is not None and modified_index is not None:
        if max(id_index, modified_index) >= len(row):
            raise ValueError("short row")
        return _required_osv_index_path(row[id_index]), _required_datetime(row[modified_index])
    if len(row) < 2:
        raise ValueError("short row")
    first_time = _optional_datetime(row[0])
    if first_time is not None:
        return _required_osv_index_path(row[1]), first_time
    second_time = _optional_datetime(row[1])
    if second_time is not None:
        return _required_osv_index_path(row[0]), second_time
    raise ValueError("no timestamp")


def _parse_osv_index_identifier(value: str) -> tuple[str, str | None]:
    normalized = unquote(value.strip()).replace("\\", "/").strip("/")
    parts = normalized.split("/")
    ecosystem = parts[0] if len(parts) > 1 else None
    advisory_id = parts[-1]
    if advisory_id.casefold().endswith(".json"):
        advisory_id = advisory_id[:-5]
    return _required_identifier(advisory_id, "OSV index id"), ecosystem


def _required_osv_index_path(value: Any) -> str:
    """Validate the index path while allowing official ecosystem names such as ``Red Hat``."""

    result = _optional_string(value)
    if not result or len(result) > 1_000 or any(character in "\x00\r\n" for character in result):
        raise IntelligenceParseError("OSV index id is invalid", source=IntelligenceSource.OSV)
    return result


def _required_cve_id(value: Any) -> str:
    result = _optional_string(value)
    if result is None or _CVE_ID_RE.fullmatch(result) is None:
        raise IntelligenceParseError(
            "CVE List V5 identifier is invalid", source=IntelligenceSource.CVE_LIST_V5
        )
    return result.upper()


def _required_identifier(value: Any, label: str) -> str:
    result = _optional_string(value)
    if not result or len(result) > 500 or any(character.isspace() for character in result):
        raise IntelligenceParseError(f"{label} is invalid")
    return result


def _optional_string(value: Any) -> str | None:
    if isinstance(value, str):
        stripped = value.strip()
        return stripped or None
    return None


def _required_datetime(value: Any) -> datetime:
    result = _optional_datetime(value)
    if result is None:
        raise ValueError("invalid timestamp")
    return result


def _optional_datetime(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    raw = value.strip()
    try:
        parsed = datetime.fromisoformat(raw[:-1] + "+00:00" if raw.endswith("Z") else raw)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _bounded_list(value: Any, label: str, max_items: int) -> list[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        return []
    if len(value) > max_items:
        raise IntelligenceLimitError(f"{label} exceeds {max_items} item limit")
    return value


def _json_object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _unique_strings(values: list[Any]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        candidate = _optional_string(value)
        if candidate is None or candidate.casefold() in seen:
            continue
        seen.add(candidate.casefold())
        result.append(candidate)
    return result


def _unique_models(items, *, key):
    result = []
    seen = set()
    for item in items:
        identity = key(item)
        if identity in seen:
            continue
        seen.add(identity)
        result.append(item)
    return result


def _extract_urls(value: str | None) -> list[str]:
    if value is None:
        return []
    return list(dict.fromkeys(match.rstrip(".)]") for match in _URL_RE.findall(value)))


def _canonical_identifier(identifiers: list[str]) -> str:
    cves = sorted(
        (identifier for identifier in identifiers if identifier.upper().startswith("CVE-")),
        key=str.casefold,
    )
    return cves[0] if cves else min(identifiers, key=str.casefold)


def _canonical_sha256(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _reject_json_constant(value: str):
    raise ValueError(f"non-finite JSON number: {value}")


def _osv_source_database(advisory_id: str, database_specific: dict[str, Any]) -> str:
    for key in ("source", "database", "advisory_database"):
        value = _optional_string(database_specific.get(key))
        if value:
            return value
    prefix = advisory_id.split("-", 1)[0].upper()
    return {
        "GHSA": "GitHub Advisory Database",
        "GO": "Go Vulnerability Database",
        "MAL": "OSV malicious packages",
        "PYSEC": "Python Packaging Advisory Database",
        "RUSTSEC": "RustSec Advisory Database",
        "UBUNTU": "Ubuntu Security Notices",
    }.get(prefix, f"OSV source prefix {prefix}")
