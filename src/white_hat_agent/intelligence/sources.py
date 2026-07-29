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

CISA_ATTRIBUTION = SourceAttribution(
    publisher="Cybersecurity and Infrastructure Security Agency",
    dataset="Known Exploited Vulnerabilities Catalog",
    attribution="CISA Known Exploited Vulnerabilities Catalog",
    license_name="CC0 1.0 Universal",
    license_url="https://www.cisa.gov/sites/default/files/licenses/kev/license.txt",
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
_URL_RE = re.compile(r"https?://[^\s,;]+")


@dataclass(frozen=True, slots=True)
class ParsedSourceRecord:
    source: IntelligenceSource
    source_record_id: str
    advisory: NormalizedAdvisory
    raw_record_sha256: str


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
