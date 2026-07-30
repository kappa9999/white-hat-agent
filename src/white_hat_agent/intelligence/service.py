from __future__ import annotations

import csv
import hashlib
import io
import json
import time
import uuid
from collections.abc import Callable, Iterable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from urllib.parse import quote, unquote, urlencode

from pydantic import ValidationError

from ..models import utc_now
from .errors import (
    IntelligenceError,
    IntelligenceLimitError,
    IntelligenceParseError,
    IntelligenceTransportError,
)
from .models import (
    EpssHistory,
    IntelligenceLimits,
    IntelligenceSource,
    IntelligenceStatus,
    IntelligenceSyncReport,
    NormalizedAdvisory,
    RankedAdvisory,
    SnapshotKind,
    SourceState,
    SourceSyncResult,
    SyncIssue,
    SyncStatus,
    UpsertState,
)
from .ranking import rank_advisory
from .sources import (
    CISA_ATTRIBUTION,
    CVE_LIST_V5_ATTRIBUTION,
    EPSS_ATTRIBUTION,
    NVD_ATTRIBUTION,
    OSV_ATTRIBUTION,
    NvdPage,
    ParsedSourceRecord,
    decode_json_array,
    decode_json_object,
    parse_cisa_kev,
    parse_cve_delta_log,
    parse_cve_record,
    parse_epss,
    parse_nvd_page,
    parse_osv_modified_index,
    parse_osv_record,
)
from .store import EpssCandidateState, IntelligenceStore
from .transport import (
    CISA_KEV_URL,
    CVE_LIST_V5_DELTA_URL,
    DEFAULT_USER_AGENT,
    EPSS_API_URL,
    NVD_CVE_API_URL,
    OSV_API_BASE_URL,
    OSV_MODIFIED_INDEX_URL,
    HttpResponse,
    HttpTransport,
    UrllibHttpTransport,
    nvd_cve_api_url,
)


@dataclass(frozen=True, slots=True)
class _SourceOutcome:
    result: SourceSyncResult
    advisory_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class _EpssCandidate:
    state: EpssCandidateState
    reason: str
    priority: int


class IntelligenceService:
    """Bounded public vulnerability intelligence synchronization and retrieval."""

    def __init__(
        self,
        store: IntelligenceStore,
        *,
        transport: HttpTransport | None = None,
        clock: Callable[[], datetime] = utc_now,
        limits: IntelligenceLimits | None = None,
    ) -> None:
        self.store = store
        self.transport = transport or UrllibHttpTransport()
        self.clock = clock
        self.limits = limits or IntelligenceLimits()

    def sync(
        self,
        *,
        sources: Iterable[IntelligenceSource | str] | None = None,
        since_hours: float = 24.0,
        ecosystems: Iterable[str] | None = None,
        limit_per_source: int = 1000,
        enrich_epss: bool = False,
    ) -> IntelligenceSyncReport:
        requested_sources = _normalize_sources(sources)
        normalized_ecosystems = _normalize_ecosystems(ecosystems)
        self._validate_sync_bounds(
            sources=requested_sources,
            since_hours=since_hours,
            ecosystems=normalized_ecosystems,
            limit_per_source=limit_per_source,
        )
        self.store.initialize()
        started_at = _aware_utc(self.clock())
        run_id = f"intelligence-sync-{uuid.uuid4().hex}"
        request = {
            "sources": [source.value for source in requested_sources],
            "since_hours": since_hours,
            "ecosystems": normalized_ecosystems,
            "limit_per_source": limit_per_source,
            "enrich_epss": enrich_epss,
        }
        self.store.begin_sync(run_id, started_at=started_at, request=request)
        try:
            outcomes: list[_SourceOutcome] = []
            for source in requested_sources:
                try:
                    if source == IntelligenceSource.CISA_KEV:
                        outcome = self._sync_cisa(started_at, limit_per_source)
                    elif source == IntelligenceSource.CVE_LIST_V5:
                        outcome = self._sync_cve_list_v5(
                            started_at,
                            since_hours=since_hours,
                            limit_per_source=limit_per_source,
                        )
                    elif source == IntelligenceSource.NVD:
                        outcome = self._sync_nvd(
                            started_at,
                            since_hours=since_hours,
                            limit_per_source=limit_per_source,
                        )
                    elif source == IntelligenceSource.OSV:
                        outcome = self._sync_osv(
                            started_at,
                            since_hours=since_hours,
                            ecosystems=normalized_ecosystems,
                            limit_per_source=limit_per_source,
                        )
                    else:  # pragma: no cover - guarded by normalization
                        raise IntelligenceParseError(f"unsupported primary source: {source.value}")
                except IntelligenceError as exc:
                    outcome = _SourceOutcome(self._failed_source_result(source, started_at, exc))
                except ValidationError:
                    failure = IntelligenceParseError(
                        "normalized public source record failed validation", source=source
                    )
                    outcome = _SourceOutcome(self._failed_source_result(source, started_at, failure))
                except Exception as exc:  # pragma: no cover - defensive public boundary
                    failure = IntelligenceError(f"unexpected {type(exc).__name__}", source=source)
                    outcome = _SourceOutcome(self._failed_source_result(source, started_at, failure))
                outcomes.append(outcome)

            if enrich_epss:
                selected_ids = _unique_strings(
                    [advisory_id for outcome in outcomes for advisory_id in outcome.advisory_ids]
                )
                try:
                    outcomes.append(self._sync_epss(started_at, selected_ids, limit_per_source))
                except IntelligenceError as exc:
                    outcomes.append(
                        _SourceOutcome(self._failed_source_result(IntelligenceSource.EPSS, started_at, exc))
                    )
                except ValidationError:
                    failure = IntelligenceParseError(
                        "normalized EPSS record failed validation", source=IntelligenceSource.EPSS
                    )
                    outcomes.append(
                        _SourceOutcome(
                            self._failed_source_result(IntelligenceSource.EPSS, started_at, failure)
                        )
                    )
                except Exception as exc:  # pragma: no cover - defensive public boundary
                    failure = IntelligenceError(
                        f"unexpected {type(exc).__name__}", source=IntelligenceSource.EPSS
                    )
                    outcomes.append(
                        _SourceOutcome(
                            self._failed_source_result(IntelligenceSource.EPSS, started_at, failure)
                        )
                    )

            finished_at = _not_before(_aware_utc(self.clock()), started_at)
            result_models = [outcome.result for outcome in outcomes]
            report = IntelligenceSyncReport(
                run_id=run_id,
                status=_combined_status(result_models),
                started_at=started_at,
                finished_at=finished_at,
                requested_sources=requested_sources,
                since_hours=since_hours,
                ecosystems=normalized_ecosystems,
                limit_per_source=limit_per_source,
                enrich_epss=enrich_epss,
                results=result_models,
            )
            self.store.finish_sync(report)
            return report
        except BaseException:
            with suppress(Exception):
                self.store.interrupt_sync(
                    run_id,
                    finished_at=_not_before(_aware_utc(self.clock()), started_at),
                )
            raise

    def get(self, advisory_id: str) -> NormalizedAdvisory:
        return self.store.get_advisory(advisory_id)

    def epss_history(
        self,
        cve: str,
        *,
        as_of: date | None = None,
        limit: int = 31,
    ) -> EpssHistory:
        return self.store.epss_history(cve, as_of=as_of, limit=limit)

    def list(
        self,
        *,
        sources: Iterable[IntelligenceSource | str] | None = None,
        ecosystems: Iterable[str] | None = None,
        known_exploited: bool | None = None,
        withdrawn: bool | None = None,
        rejected: bool | None = False,
        limit: int = 100,
        as_of: datetime | None = None,
    ) -> list[RankedAdvisory]:
        if limit < 1 or limit > 1000:
            raise IntelligenceLimitError("list limit must be between 1 and 1000")
        normalized_sources = _normalize_filter_sources(sources) if sources is not None else None
        normalized_ecosystems = _normalize_ecosystems(ecosystems)
        advisory_candidates = self.store.list_advisories(
            sources=normalized_sources,
            ecosystems=normalized_ecosystems,
            known_exploited=known_exploited,
            withdrawn=withdrawn,
            rejected=rejected,
            limit=1000,
        )
        ranking_time = _aware_utc(as_of or self.clock())
        ranked = [
            RankedAdvisory(
                advisory=advisory,
                priority=rank_advisory(advisory, as_of=ranking_time),
            )
            for advisory in advisory_candidates
        ]
        ranked.sort(
            key=lambda item: (
                -item.priority.total_score,
                -_timestamp(item.advisory.modified_at or item.advisory.published_at),
                item.advisory.advisory_id.casefold(),
            )
        )
        return ranked[:limit]

    def status(self) -> IntelligenceStatus:
        return self.store.status()

    def brief(
        self,
        *,
        sources: Iterable[IntelligenceSource | str] | None = None,
        ecosystems: Iterable[str] | None = None,
        known_exploited: bool | None = None,
        withdrawn: bool | None = False,
        rejected: bool | None = False,
        limit: int = 20,
        as_of: datetime | None = None,
    ) -> str:
        ranking_time = _aware_utc(as_of or self.clock())
        ranked = self.list(
            sources=sources,
            ecosystems=ecosystems,
            known_exploited=known_exploited,
            withdrawn=withdrawn,
            rejected=rejected,
            limit=limit,
            as_of=ranking_time,
        )
        lines = [
            "# Public Vulnerability Intelligence Brief",
            "",
            f"Generated: {ranking_time.isoformat()}",
            f"Advisories: {len(ranked)}",
            "",
        ]
        if not ranked:
            lines.append("No advisories matched the bounded local selection.")
            return "\n".join(lines) + "\n"
        for index, item in enumerate(ranked, start=1):
            advisory = item.advisory
            title = advisory.title or advisory.summary or "Untitled advisory"
            lines.extend(
                [
                    f"## {index}. {_markdown(advisory.advisory_id)} — {_markdown(title)}",
                    "",
                    f"- Priority: **{item.priority.total_score:.3f}** ({item.priority.algorithm_version})",
                    f"- Sources: {', '.join(source.value for source in advisory.sources)}",
                    f"- Known exploited: {'yes' if item.priority.confirmed_kev else 'no'}",
                    f"- Modified: {_format_datetime(advisory.modified_at)}",
                    f"- Affected: {_affected_summary(advisory)}",
                    f"- Why: {'; '.join(item.priority.reasons)}",
                ]
            )
            if advisory.references:
                lines.append(f"- Reference: {advisory.references[0].url}")
            lines.append("")
        return "\n".join(lines).rstrip() + "\n"

    def _sync_cisa(self, started_at: datetime, _limit: int) -> _SourceOutcome:
        source = IntelligenceSource.CISA_KEV
        previous_state = self.store.get_source_state(source)
        snapshot_count = self.store.snapshot_count()
        response = self._get(
            CISA_KEV_URL,
            max_bytes=self.limits.max_cisa_bytes,
            accept="application/json",
            conditional_headers=_conditional_headers(previous_state),
        )
        if response.status == 304:
            if previous_state is None or previous_state.last_snapshot_id is None:
                raise IntelligenceTransportError(
                    "cisa-kev returned 304 without a local baseline", source=source
                )
            self.store.verify_snapshot(previous_state.last_snapshot_id)
            finished_at = _not_before(_aware_utc(self.clock()), started_at)
            state = SourceState(
                source=source,
                last_attempt_at=finished_at,
                last_success_at=finished_at,
                cursor_at=previous_state.cursor_at if previous_state else None,
                etag=response.header("ETag") or (previous_state.etag if previous_state else None),
                last_modified=response.header("Last-Modified")
                or (previous_state.last_modified if previous_state else None),
                last_snapshot_id=previous_state.last_snapshot_id if previous_state else None,
                last_status=SyncStatus.SUCCESS,
                metadata=previous_state.metadata if previous_state else {},
            )
            self.store.set_source_state(state)
            return _SourceOutcome(
                SourceSyncResult(
                    source=source,
                    status=SyncStatus.SUCCESS,
                    started_at=started_at,
                    finished_at=finished_at,
                )
            )
        _require_success(response, source)
        document = decode_json_object(response.body, source=source)
        retrieved_at = started_at
        snapshot = self.store.save_snapshot(
            response.body,
            source=source,
            kind=SnapshotKind.FULL_FEED,
            source_url=response.url,
            retrieved_at=retrieved_at,
            media_type=response.header("Content-Type") or "application/json",
            attribution=CISA_ATTRIBUTION,
            http_status=response.status,
            etag=response.header("ETag"),
            last_modified=response.header("Last-Modified"),
            source_schema_version=_string(document.get("catalogVersion")),
            source_metadata={
                "feed_title": _string(document.get("title")),
                "catalog_version": _string(document.get("catalogVersion")),
                "date_released": _string(document.get("dateReleased")),
            },
        )
        records = parse_cisa_kev(document, snapshot, max_items=self.limits.max_cisa_items)
        existing = self.store.source_record_states(source)
        current = {record.source_record_id: record for record in records}
        changes = [
            record
            for record in records
            if record.source_record_id not in existing
            or existing[record.source_record_id].raw_record_sha256 != record.raw_record_sha256
            or existing[record.source_record_id].tombstoned
        ]
        unchanged_in_feed = sum(
            1
            for record in records
            if record.source_record_id in existing
            and not existing[record.source_record_id].tombstoned
            and existing[record.source_record_id].raw_record_sha256 == record.raw_record_sha256
        )
        missing = sorted(
            record_id
            for record_id, state in existing.items()
            if not state.tombstoned and record_id not in current
        )
        events = [(record.source_record_id.casefold(), "upsert", record) for record in changes] + [
            (record_id.casefold(), "tombstone", record_id) for record_id in missing
        ]
        events.sort(key=lambda item: (item[0], item[1]))
        counts = _empty_counts()
        selected_ids: list[str] = []
        for _, event_type, value in events:
            if event_type == "upsert":
                record = value
                state = self.store.upsert_source_record(
                    record, snapshot_id=snapshot.snapshot_id, seen_at=retrieved_at
                )
                selected_ids.append(self.store.get_advisory(record.source_record_id).advisory_id)
            else:
                state = self.store.tombstone_source_record(
                    source,
                    value,
                    snapshot_id=snapshot.snapshot_id,
                    tombstoned_at=retrieved_at,
                )
            _increment_count(counts, state)
        finished_at = _not_before(_aware_utc(self.clock()), started_at)
        status = SyncStatus.SUCCESS
        state = SourceState(
            source=source,
            last_attempt_at=finished_at,
            last_success_at=(
                finished_at
                if status == SyncStatus.SUCCESS
                else (previous_state.last_success_at if previous_state else None)
            ),
            cursor_at=previous_state.cursor_at if previous_state else None,
            etag=response.header("ETag"),
            last_modified=response.header("Last-Modified"),
            last_snapshot_id=snapshot.snapshot_id,
            last_status=status,
            metadata={
                "diff_strategy": "full-feed-record-digest",
                "feed_sha256": snapshot.content_sha256,
                "feed_records": len(records),
                "pending_changes": 0,
                "date_added_is_cursor": False,
            },
        )
        self.store.set_source_state(state)
        result = SourceSyncResult(
            source=source,
            status=status,
            started_at=started_at,
            finished_at=finished_at,
            records_seen=len(records),
            records_selected=len(events),
            records_inserted=counts[UpsertState.INSERTED],
            records_updated=counts[UpsertState.UPDATED],
            records_unchanged=counts[UpsertState.UNCHANGED] + unchanged_in_feed,
            records_tombstoned=counts[UpsertState.TOMBSTONED],
            snapshots_stored=self.store.snapshot_count() - snapshot_count,
            truncated=False,
            metadata={"feed_snapshot_id": snapshot.snapshot_id, "delta_records": len(events)},
        )
        return _SourceOutcome(result, tuple(_unique_strings(selected_ids)))

    def _sync_cve_list_v5(
        self,
        started_at: datetime,
        *,
        since_hours: float,
        limit_per_source: int,
    ) -> _SourceOutcome:
        source = IntelligenceSource.CVE_LIST_V5
        previous_state = self.store.get_source_state(source)
        window_anchor = (
            previous_state.cursor_at
            if previous_state and previous_state.cursor_at
            else started_at - timedelta(hours=since_hours)
        )
        boundary = window_anchor - timedelta(hours=self.limits.cve_overlap_hours)
        snapshot_count = self.store.snapshot_count()
        delta_response = self._get(
            CVE_LIST_V5_DELTA_URL,
            max_bytes=self.limits.max_cve_delta_bytes,
            accept="application/json",
        )
        delta_digest = hashlib.sha256(delta_response.body).hexdigest()
        delta_snapshot = self.store.save_snapshot(
            delta_response.body,
            source=source,
            kind=SnapshotKind.DELTA_LOG,
            source_url=delta_response.url,
            retrieved_at=started_at,
            media_type=delta_response.header("Content-Type") or "application/json",
            attribution=CVE_LIST_V5_ATTRIBUTION,
            http_status=delta_response.status,
            etag=delta_response.header("ETag"),
            last_modified=delta_response.header("Last-Modified"),
            source_metadata={
                "closed_window_boundary": boundary.isoformat(),
                "fetch_error": delta_response.status != 200,
            },
        )
        _require_success(delta_response, source)
        delta_document = decode_json_array(delta_response.body, source=source)
        selection = parse_cve_delta_log(
            delta_document,
            boundary=boundary,
            max_batches=self.limits.max_cve_delta_batches,
            max_entries=self.limits.max_cve_delta_entries,
            max_candidates=self.limits.max_cve_candidates,
        )
        issues = list(selection.issues)
        manifest_entries: list[dict[str, object]] = []
        counts = _empty_counts()
        selected_ids: list[str] = []
        records_selected = 0
        records_attempted = 0
        consecutive_server_errors = 0
        record_loop_interrupted = False
        for entry in selection.entries:
            if records_attempted >= limit_per_source:
                break
            records_attempted += 1
            record_url = entry.record_url
            manifest_entry: dict[str, object] = {
                "id": entry.cve_id,
                "modified": entry.modified_at.isoformat(),
                "batch_fetch_at": entry.batch_fetch_at.isoformat(),
                "change_type": entry.change_type,
                "cve_org_url": entry.cve_org_url,
                "record_url": entry.record_url,
                "selected": False,
            }
            try:
                response = self._get(
                    record_url,
                    max_bytes=self.limits.max_cve_record_bytes,
                    accept="application/json",
                )
            except IntelligenceLimitError as error:
                manifest_entry["fetch_error"] = "record_response_limit"
                issues.append(
                    SyncIssue(
                        code="record_response_limit",
                        message=str(error),
                        retriable=True,
                        record_id=entry.cve_id,
                    )
                )
                manifest_entries.append(manifest_entry)
                continue
            manifest_entry["http_status"] = response.status
            snapshot = self.store.save_snapshot(
                response.body,
                source=source,
                kind=SnapshotKind.SOURCE_RECORD,
                source_url=response.url,
                source_record_id=entry.cve_id,
                retrieved_at=started_at,
                media_type=response.header("Content-Type") or "application/octet-stream",
                attribution=CVE_LIST_V5_ATTRIBUTION,
                http_status=response.status,
                etag=response.header("ETag"),
                last_modified=response.header("Last-Modified"),
                source_metadata={
                    "delta_modified": entry.modified_at.isoformat(),
                    "change_type": entry.change_type,
                    "fetch_error": response.status != 200,
                },
            )
            manifest_entry["snapshot_id"] = snapshot.snapshot_id
            if response.status != 200:
                retriable = response.status in {404, 429} or response.status >= 500
                issues.append(
                    SyncIssue(
                        code="record_http_error",
                        message=f"CVE List V5 record returned HTTP {response.status}",
                        retriable=retriable,
                        record_id=entry.cve_id,
                    )
                )
                manifest_entries.append(manifest_entry)
                if response.status == 429:
                    record_loop_interrupted = True
                    break
                if response.status >= 500:
                    consecutive_server_errors += 1
                    if consecutive_server_errors >= self.limits.max_cve_consecutive_server_errors:
                        record_loop_interrupted = True
                        break
                else:
                    consecutive_server_errors = 0
                continue
            consecutive_server_errors = 0
            try:
                document = decode_json_object(response.body, source=source)
                record = parse_cve_record(document, snapshot)
            except (IntelligenceError, ValidationError):
                issues.append(
                    SyncIssue(
                        code="invalid_source_data",
                        message="CVE List V5 record failed normalized validation",
                        record_id=entry.cve_id,
                    )
                )
                manifest_entries.append(manifest_entry)
                continue
            if record.source_record_id.casefold() != entry.cve_id.casefold():
                issues.append(
                    SyncIssue(
                        code="record_identity_mismatch",
                        message="CVE record id differs from the delta log id",
                        record_id=entry.cve_id,
                    )
                )
                manifest_entries.append(manifest_entry)
                continue
            if record.advisory.modified_at is not None and record.advisory.modified_at < entry.modified_at:
                issues.append(
                    SyncIssue(
                        code="record_older_than_delta",
                        message="CVE record dateUpdated predates the selected delta entry",
                        retriable=True,
                        record_id=entry.cve_id,
                    )
                )
                manifest_entries.append(manifest_entry)
                continue
            state = self.store.upsert_source_record(
                record, snapshot_id=snapshot.snapshot_id, seen_at=started_at
            )
            _increment_count(counts, state)
            records_selected += 1
            manifest_entry["selected"] = True
            selected_ids.append(self.store.get_advisory(entry.cve_id).advisory_id)
            manifest_entries.append(manifest_entry)

        manifest = {
            "schema_version": "1.0",
            "kind": "cve-list-v5-delta-selection",
            "source_url": CVE_LIST_V5_DELTA_URL,
            "retrieved_at": started_at.isoformat(),
            "closed_window_boundary": boundary.isoformat(),
            "overlap_hours": self.limits.cve_overlap_hours,
            "delta_log": {
                "sha256": delta_digest,
                "byte_length": len(delta_response.body),
                "snapshot_id": delta_snapshot.snapshot_id,
                "etag": delta_response.header("ETag"),
                "last_modified": delta_response.header("Last-Modified"),
                "batches_seen": selection.batches_seen,
                "entries_seen": selection.entries_seen,
                "newest_fetch_at": selection.newest_fetch_at.isoformat(),
                "oldest_fetch_at": selection.oldest_fetch_at.isoformat(),
                "window_complete": selection.window_complete,
            },
            "entries": manifest_entries,
        }
        manifest_body = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
            "utf-8"
        )
        manifest_snapshot = self.store.save_snapshot(
            manifest_body,
            source=source,
            kind=SnapshotKind.SELECTION_MANIFEST,
            source_url=CVE_LIST_V5_DELTA_URL,
            retrieved_at=started_at,
            media_type="application/vnd.white-hat-agent.cve-list-v5-selection+json",
            attribution=CVE_LIST_V5_ATTRIBUTION,
            http_status=delta_response.status,
            etag=delta_response.header("ETag"),
            last_modified=delta_response.header("Last-Modified"),
            source_schema_version="1.0",
            source_metadata={
                "upstream_content_sha256": delta_digest,
                "delta_log_snapshot_id": delta_snapshot.snapshot_id,
            },
        )
        limit_cutoff = records_attempted >= limit_per_source and records_attempted < len(selection.entries)
        truncated = (
            selection.candidate_limit_reached
            or limit_cutoff
            or record_loop_interrupted
            or not selection.window_complete
        )
        status = SyncStatus.PARTIAL if issues or truncated else SyncStatus.SUCCESS
        finished_at = _not_before(_aware_utc(self.clock()), started_at)
        cursor_after = previous_state.cursor_at if previous_state else None
        if status == SyncStatus.SUCCESS:
            cursor_after = (
                max(cursor_after, selection.newest_fetch_at) if cursor_after else selection.newest_fetch_at
            )
        state = SourceState(
            source=source,
            last_attempt_at=finished_at,
            last_success_at=(
                finished_at
                if status == SyncStatus.SUCCESS
                else (previous_state.last_success_at if previous_state else None)
            ),
            cursor_at=cursor_after,
            etag=(
                delta_response.header("ETag")
                if status == SyncStatus.SUCCESS
                else (previous_state.etag if previous_state else None)
            ),
            last_modified=(
                delta_response.header("Last-Modified")
                if status == SyncStatus.SUCCESS
                else (previous_state.last_modified if previous_state else None)
            ),
            last_snapshot_id=manifest_snapshot.snapshot_id,
            last_status=status,
            metadata={
                "closed_window_boundary": boundary.isoformat(),
                "overlap_hours": self.limits.cve_overlap_hours,
                "selection_manifest_id": manifest_snapshot.snapshot_id,
                "delta_log_snapshot_id": delta_snapshot.snapshot_id,
                "delta_log_sha256": delta_digest,
                "newest_fetch_at": selection.newest_fetch_at.isoformat(),
                "oldest_fetch_at": selection.oldest_fetch_at.isoformat(),
            },
        )
        self.store.set_source_state(state)
        result = SourceSyncResult(
            source=source,
            status=status,
            started_at=started_at,
            finished_at=finished_at,
            records_seen=len(selection.entries),
            records_selected=records_selected,
            records_inserted=counts[UpsertState.INSERTED],
            records_updated=counts[UpsertState.UPDATED],
            records_unchanged=counts[UpsertState.UNCHANGED],
            records_tombstoned=counts[UpsertState.TOMBSTONED],
            snapshots_stored=self.store.snapshot_count() - snapshot_count,
            truncated=truncated,
            cursor_before=previous_state.cursor_at if previous_state else None,
            cursor_after=cursor_after,
            issues=issues,
            metadata={
                "selection_manifest_id": manifest_snapshot.snapshot_id,
                "delta_log_snapshot_id": delta_snapshot.snapshot_id,
                "delta_batches_seen": selection.batches_seen,
                "delta_entries_seen": selection.entries_seen,
                "records_attempted": records_attempted,
                "record_loop_interrupted": record_loop_interrupted,
            },
        )
        return _SourceOutcome(result, tuple(_unique_strings(selected_ids)))

    def _sync_nvd(
        self,
        started_at: datetime,
        *,
        since_hours: float,
        limit_per_source: int,
    ) -> _SourceOutcome:
        source = IntelligenceSource.NVD
        previous_state = self.store.get_source_state(source)
        window_anchor = started_at - timedelta(hours=since_hours)
        if previous_state and previous_state.cursor_at:
            window_anchor = max(window_anchor, previous_state.cursor_at)
        boundary = window_anchor - timedelta(hours=self.limits.nvd_overlap_hours)
        boundary = max(boundary, started_at - timedelta(days=120))
        page_size = min(self.limits.max_nvd_records_per_page, limit_per_source)
        snapshot_count = self.store.snapshot_count()
        pages: list[tuple[NvdPage, str, str, int]] = []
        issues: list[SyncIssue] = []
        total_results: int | None = None
        start_index = 0
        last_etag: str | None = None
        last_modified: str | None = None
        truncated = False

        while True:
            if len(pages) >= self.limits.max_nvd_pages:
                truncated = True
                issues.append(
                    SyncIssue(
                        code="nvd_page_limit",
                        message=f"NVD response exceeded the {self.limits.max_nvd_pages}-page ceiling",
                        retriable=True,
                    )
                )
                break
            if pages and isinstance(self.transport, UrllibHttpTransport):
                time.sleep(self.limits.nvd_request_delay_seconds)
            url = nvd_cve_api_url(
                boundary,
                started_at,
                results_per_page=page_size,
                start_index=start_index,
            )
            response = self._get(
                url,
                max_bytes=self.limits.max_nvd_page_bytes,
                accept="application/json",
            )
            page_digest = hashlib.sha256(response.body).hexdigest()
            snapshot = self.store.save_snapshot(
                response.body,
                source=source,
                kind=SnapshotKind.API_PAGE,
                source_url=response.url,
                retrieved_at=started_at,
                media_type=response.header("Content-Type") or "application/json",
                attribution=NVD_ATTRIBUTION,
                http_status=response.status,
                etag=response.header("ETag"),
                last_modified=response.header("Last-Modified"),
                source_metadata={
                    "closed_window_boundary": boundary.isoformat(),
                    "closed_window_end": started_at.isoformat(),
                    "requested_start_index": start_index,
                    "requested_results_per_page": page_size,
                    "fetch_error": response.status != 200,
                },
            )
            _require_success(response, source)
            document = decode_json_object(response.body, source=source)
            page = parse_nvd_page(
                document,
                snapshot,
                expected_start_index=start_index,
                max_items=page_size,
                max_record_bytes=self.limits.max_nvd_record_bytes,
            )
            if total_results is None:
                total_results = page.total_results
                if total_results > limit_per_source:
                    truncated = True
                    issues.append(
                        SyncIssue(
                            code="nvd_candidate_limit",
                            message=(
                                f"NVD window returned {total_results} records, exceeding the "
                                f"{limit_per_source}-record fail-closed ceiling"
                            ),
                            retriable=True,
                        )
                    )
            elif page.total_results != total_results:
                raise IntelligenceParseError(
                    "NVD totalResults changed during pagination",
                    source=source,
                    retriable=True,
                )
            pages.append((page, snapshot.snapshot_id, page_digest, len(response.body)))
            last_etag = response.header("ETag")
            last_modified = response.header("Last-Modified")
            if truncated or start_index + len(page.records) >= page.total_results:
                break
            start_index += len(page.records)

        record_snapshots = [
            (record, snapshot_id) for page, snapshot_id, _, _ in pages for record in page.records
        ]
        if truncated:
            record_snapshots = []
        identifiers = [record.source_record_id.casefold() for record, _ in record_snapshots]
        if len(identifiers) != len(set(identifiers)):
            raise IntelligenceParseError("NVD pagination returned duplicate CVE records", source=source)

        counts = _empty_counts()
        selected_ids: list[str] = []
        for record, page_snapshot_id in record_snapshots:
            state = self.store.upsert_source_record(
                record,
                snapshot_id=page_snapshot_id,
                seen_at=started_at,
            )
            _increment_count(counts, state)
            selected_ids.append(self.store.get_advisory(record.source_record_id).advisory_id)

        manifest = {
            "schema_version": "1.0",
            "kind": "nvd-cve-api-last-modified-selection",
            "source_url": NVD_CVE_API_URL,
            "retrieved_at": started_at.isoformat(),
            "closed_window_boundary": boundary.isoformat(),
            "closed_window_end": started_at.isoformat(),
            "overlap_hours": self.limits.nvd_overlap_hours,
            "total_results": total_results or 0,
            "fail_closed": truncated,
            "pages": [
                {
                    "start_index": page.start_index,
                    "results_per_page": page.results_per_page,
                    "records": len(page.records),
                    "generated_at": page.generated_at.isoformat(),
                    "snapshot_id": snapshot_id,
                    "sha256": digest,
                    "byte_length": byte_length,
                }
                for page, snapshot_id, digest, byte_length in pages
            ],
            "records": [
                {
                    "id": record.source_record_id,
                    "raw_record_sha256": record.raw_record_sha256,
                    "snapshot_id": snapshot_id,
                }
                for page, snapshot_id, _, _ in pages
                for record in page.records
                if not truncated
            ],
        }
        manifest_body = json.dumps(
            manifest,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        manifest_snapshot = self.store.save_snapshot(
            manifest_body,
            source=source,
            kind=SnapshotKind.SELECTION_MANIFEST,
            source_url=NVD_CVE_API_URL,
            retrieved_at=started_at,
            media_type="application/vnd.white-hat-agent.nvd-selection+json",
            attribution=NVD_ATTRIBUTION,
            source_schema_version="1.0",
            source_metadata={
                "page_snapshot_ids": [snapshot_id for _, snapshot_id, _, _ in pages],
                "total_results": total_results or 0,
                "fail_closed": truncated,
            },
        )
        status = SyncStatus.PARTIAL if issues or truncated else SyncStatus.SUCCESS
        finished_at = _not_before(_aware_utc(self.clock()), started_at)
        cursor_after = (
            started_at
            if status == SyncStatus.SUCCESS
            else (previous_state.cursor_at if previous_state else None)
        )
        state = SourceState(
            source=source,
            last_attempt_at=finished_at,
            last_success_at=(
                finished_at
                if status == SyncStatus.SUCCESS
                else (previous_state.last_success_at if previous_state else None)
            ),
            cursor_at=cursor_after,
            etag=(
                last_etag
                if status == SyncStatus.SUCCESS
                else (previous_state.etag if previous_state else None)
            ),
            last_modified=(
                last_modified
                if status == SyncStatus.SUCCESS
                else (previous_state.last_modified if previous_state else None)
            ),
            last_snapshot_id=manifest_snapshot.snapshot_id,
            last_status=status,
            metadata={
                "closed_window_boundary": boundary.isoformat(),
                "closed_window_end": started_at.isoformat(),
                "overlap_hours": self.limits.nvd_overlap_hours,
                "selection_manifest_id": manifest_snapshot.snapshot_id,
                "page_snapshot_ids": [snapshot_id for _, snapshot_id, _, _ in pages],
                "total_results": total_results or 0,
            },
        )
        self.store.set_source_state(state)
        result = SourceSyncResult(
            source=source,
            status=status,
            started_at=started_at,
            finished_at=finished_at,
            records_seen=total_results or 0,
            records_selected=len(record_snapshots),
            records_inserted=counts[UpsertState.INSERTED],
            records_updated=counts[UpsertState.UPDATED],
            records_unchanged=counts[UpsertState.UNCHANGED],
            snapshots_stored=self.store.snapshot_count() - snapshot_count,
            truncated=truncated,
            cursor_before=previous_state.cursor_at if previous_state else None,
            cursor_after=cursor_after,
            issues=issues,
            metadata={
                "selection_manifest_id": manifest_snapshot.snapshot_id,
                "page_snapshot_ids": [snapshot_id for _, snapshot_id, _, _ in pages],
                "page_count": len(pages),
                "total_results": total_results or 0,
            },
        )
        return _SourceOutcome(result, tuple(_unique_strings(selected_ids)))

    def _sync_osv(
        self,
        started_at: datetime,
        *,
        since_hours: float,
        ecosystems: list[str],
        limit_per_source: int,
    ) -> _SourceOutcome:
        source = IntelligenceSource.OSV
        previous_state = self.store.get_source_state(source)
        window_anchor = started_at - timedelta(hours=since_hours)
        if previous_state and previous_state.last_success_at:
            window_anchor = max(window_anchor, previous_state.last_success_at)
        boundary = window_anchor - timedelta(hours=self.limits.osv_overlap_hours)
        max_candidates = min(
            self.limits.max_osv_candidates,
            max(limit_per_source, limit_per_source * 5),
        )
        snapshot_count = self.store.snapshot_count()
        index_response = self._get_osv_index(boundary, max_candidates=max_candidates, ecosystems=ecosystems)
        _require_success(index_response, source, allowed={200, 206})
        index_digest = hashlib.sha256(index_response.body).hexdigest()
        index_snapshot = self.store.save_snapshot(
            index_response.body,
            source=source,
            kind=SnapshotKind.INDEX_PREFIX,
            source_url=OSV_MODIFIED_INDEX_URL,
            retrieved_at=started_at,
            media_type=index_response.header("Content-Type") or "text/csv",
            attribution=OSV_ATTRIBUTION,
            http_status=index_response.status,
            etag=index_response.header("ETag"),
            last_modified=index_response.header("Last-Modified"),
            source_metadata={
                "closed_window_boundary": boundary.isoformat(),
                "complete_response": index_response.complete,
                "line_count": index_response.line_count,
            },
        )
        selection = parse_osv_modified_index(
            index_response.body,
            boundary=boundary,
            max_lines=self.limits.max_osv_index_lines,
            max_candidates=max_candidates,
            ecosystems=ecosystems,
        )
        issues = list(selection.issues)
        manifest_entries: list[dict[str, object]] = []
        counts = _empty_counts()
        selected_ids: list[str] = []
        records_filtered = selection.entries_filtered
        records_selected = 0
        records_attempted = 0
        record_loop_interrupted = False
        consecutive_server_errors = 0
        for entry in selection.entries:
            if records_attempted >= limit_per_source:
                break
            records_attempted += 1
            record_url = OSV_API_BASE_URL + quote(entry.advisory_id, safe="-._~")
            response = self._get(
                record_url,
                max_bytes=self.limits.max_osv_record_bytes,
                accept="application/json",
            )
            manifest_entry: dict[str, object] = {
                "id": entry.advisory_id,
                "modified": entry.modified_at.isoformat(),
                "ecosystem": entry.ecosystem,
                "http_status": response.status,
                "selected": False,
            }
            if response.status == 404:
                consecutive_server_errors = 0
                error_snapshot = self.store.save_snapshot(
                    response.body,
                    source=source,
                    kind=SnapshotKind.SOURCE_RECORD,
                    source_url=response.url,
                    source_record_id=entry.advisory_id,
                    retrieved_at=started_at,
                    media_type=response.header("Content-Type") or "application/octet-stream",
                    attribution=OSV_ATTRIBUTION,
                    http_status=response.status,
                    etag=response.header("ETag"),
                    last_modified=response.header("Last-Modified"),
                    source_metadata={"record_missing": True},
                )
                state = self.store.tombstone_source_record(
                    source,
                    entry.advisory_id,
                    snapshot_id=error_snapshot.snapshot_id,
                    tombstoned_at=started_at,
                )
                _increment_count(counts, state)
                records_selected += 1
                manifest_entry["selected"] = True
                manifest_entry["snapshot_id"] = error_snapshot.snapshot_id
                manifest_entries.append(manifest_entry)
                continue
            if response.status != 200:
                retriable = response.status == 429 or response.status >= 500
                issues.append(
                    SyncIssue(
                        code="record_http_error",
                        message=f"OSV record returned HTTP {response.status}",
                        retriable=retriable,
                        record_id=entry.advisory_id,
                    )
                )
                manifest_entries.append(manifest_entry)
                if response.status == 429:
                    record_loop_interrupted = True
                    break
                if response.status >= 500:
                    consecutive_server_errors += 1
                    if consecutive_server_errors >= self.limits.max_osv_consecutive_server_errors:
                        record_loop_interrupted = True
                        break
                else:
                    consecutive_server_errors = 0
                continue
            consecutive_server_errors = 0
            try:
                document = decode_json_object(response.body, source=source)
            except IntelligenceParseError as exc:
                snapshot = self.store.save_snapshot(
                    response.body,
                    source=source,
                    kind=SnapshotKind.SOURCE_RECORD,
                    source_url=response.url,
                    source_record_id=entry.advisory_id,
                    retrieved_at=started_at,
                    media_type=response.header("Content-Type") or "application/octet-stream",
                    attribution=OSV_ATTRIBUTION,
                    http_status=response.status,
                    etag=response.header("ETag"),
                    last_modified=response.header("Last-Modified"),
                    source_metadata={
                        "index_modified": entry.modified_at.isoformat(),
                        "parse_error": True,
                    },
                )
                manifest_entry["snapshot_id"] = snapshot.snapshot_id
                issues.append(
                    SyncIssue(
                        code=exc.code,
                        message="OSV record returned invalid JSON",
                        record_id=entry.advisory_id,
                    )
                )
                manifest_entries.append(manifest_entry)
                continue
            snapshot = self.store.save_snapshot(
                response.body,
                source=source,
                kind=SnapshotKind.SOURCE_RECORD,
                source_url=response.url,
                source_record_id=entry.advisory_id,
                retrieved_at=started_at,
                media_type=response.header("Content-Type") or "application/json",
                attribution=OSV_ATTRIBUTION,
                http_status=response.status,
                etag=response.header("ETag"),
                last_modified=response.header("Last-Modified"),
                source_schema_version=_string(document.get("schema_version")),
                source_metadata={"index_modified": entry.modified_at.isoformat()},
            )
            manifest_entry["snapshot_id"] = snapshot.snapshot_id
            try:
                record = parse_osv_record(document, snapshot)
            except (IntelligenceError, ValidationError):
                issues.append(
                    SyncIssue(
                        code="invalid_source_data",
                        message="OSV record failed normalized validation",
                        record_id=entry.advisory_id,
                    )
                )
                manifest_entries.append(manifest_entry)
                continue
            if record.source_record_id.casefold() != entry.advisory_id.casefold():
                issues.append(
                    SyncIssue(
                        code="record_identity_mismatch",
                        message="OSV API record id differs from the modified index id",
                        record_id=entry.advisory_id,
                    )
                )
                manifest_entries.append(manifest_entry)
                continue
            if ecosystems and not _matches_ecosystems(record.advisory, ecosystems):
                records_filtered += 1
                manifest_entries.append(manifest_entry)
                continue
            state = self.store.upsert_source_record(
                record, snapshot_id=snapshot.snapshot_id, seen_at=started_at
            )
            _increment_count(counts, state)
            records_selected += 1
            manifest_entry["selected"] = True
            selected_ids.append(self.store.get_advisory(record.source_record_id).advisory_id)
            manifest_entries.append(manifest_entry)

        manifest = {
            "schema_version": "1.0",
            "kind": "osv-modified-selection",
            "source_url": OSV_MODIFIED_INDEX_URL,
            "retrieved_at": started_at.isoformat(),
            "closed_window_boundary": boundary.isoformat(),
            "overlap_hours": self.limits.osv_overlap_hours,
            "index_prefix": {
                "sha256": index_digest,
                "byte_length": len(index_response.body),
                "snapshot_id": index_snapshot.snapshot_id,
                "line_count": index_response.line_count,
                "complete_response": index_response.complete,
                "etag": index_response.header("ETag"),
                "last_modified": index_response.header("Last-Modified"),
            },
            "entries": manifest_entries,
        }
        manifest_body = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
            "utf-8"
        )
        manifest_snapshot = self.store.save_snapshot(
            manifest_body,
            source=source,
            kind=SnapshotKind.SELECTION_MANIFEST,
            source_url=OSV_MODIFIED_INDEX_URL,
            retrieved_at=started_at,
            media_type="application/vnd.white-hat-agent.osv-selection+json",
            attribution=OSV_ATTRIBUTION,
            http_status=index_response.status,
            etag=index_response.header("ETag"),
            last_modified=index_response.header("Last-Modified"),
            source_schema_version="1.0",
            source_metadata={
                "upstream_content_sha256": index_digest,
                "upstream_prefix_bytes": len(index_response.body),
                "index_prefix_snapshot_id": index_snapshot.snapshot_id,
                "full_index_stored": False,
            },
        )
        limit_cutoff = records_attempted >= limit_per_source and records_attempted < len(selection.entries)
        truncated = selection.candidate_limit_reached or limit_cutoff or record_loop_interrupted
        if not selection.reached_boundary and not index_response.complete:
            truncated = truncated or selection.candidate_limit_reached
        status = SyncStatus.PARTIAL if issues or truncated else SyncStatus.SUCCESS
        finished_at = _not_before(_aware_utc(self.clock()), started_at)
        cursor_after = (
            started_at
            if status == SyncStatus.SUCCESS
            else (previous_state.cursor_at if previous_state else None)
        )
        state = SourceState(
            source=source,
            last_attempt_at=finished_at,
            last_success_at=(
                finished_at
                if status == SyncStatus.SUCCESS
                else (previous_state.last_success_at if previous_state else None)
            ),
            cursor_at=cursor_after,
            etag=index_response.header("ETag"),
            last_modified=index_response.header("Last-Modified"),
            last_snapshot_id=manifest_snapshot.snapshot_id,
            last_status=status,
            metadata={
                "closed_window_boundary": boundary.isoformat(),
                "overlap_hours": self.limits.osv_overlap_hours,
                "selection_manifest_id": manifest_snapshot.snapshot_id,
                "index_prefix_snapshot_id": index_snapshot.snapshot_id,
                "index_prefix_sha256": index_digest,
                "index_prefix_bytes": len(index_response.body),
                "full_index_stored": False,
            },
        )
        self.store.set_source_state(state)
        result = SourceSyncResult(
            source=source,
            status=status,
            started_at=started_at,
            finished_at=finished_at,
            records_seen=len(selection.entries),
            records_selected=records_selected,
            records_inserted=counts[UpsertState.INSERTED],
            records_updated=counts[UpsertState.UPDATED],
            records_unchanged=counts[UpsertState.UNCHANGED],
            records_tombstoned=counts[UpsertState.TOMBSTONED],
            records_filtered=records_filtered,
            snapshots_stored=self.store.snapshot_count() - snapshot_count,
            truncated=truncated,
            cursor_before=previous_state.cursor_at if previous_state else None,
            cursor_after=cursor_after,
            issues=issues,
            metadata={
                "selection_manifest_id": manifest_snapshot.snapshot_id,
                "index_prefix_snapshot_id": index_snapshot.snapshot_id,
                "index_lines_seen": selection.lines_seen,
                "index_prefix_bytes": len(index_response.body),
                "records_attempted": records_attempted,
                "record_loop_interrupted": record_loop_interrupted,
            },
        )
        return _SourceOutcome(result, tuple(_unique_strings(selected_ids)))

    def _sync_epss(
        self, started_at: datetime, advisory_ids: list[str], limit_per_source: int
    ) -> _SourceOutcome:
        source = IntelligenceSource.EPSS
        expected_score_date = started_at.date() - timedelta(days=1)
        candidates = _select_epss_candidates(
            self.store.epss_candidate_states(advisory_ids),
            expected_score_date=expected_score_date,
        )
        candidate_count = len(candidates)
        selected = candidates[:limit_per_source]
        omitted = candidates[limit_per_source:]
        cves = [candidate.state.cve for candidate in selected]
        selection_metadata = {
            "selection": "history-aware-priority-v1",
            "candidate_count": candidate_count,
            "requested": len(cves),
            "omitted": len(omitted),
            "expected_score_date": expected_score_date.isoformat(),
            "selected_by_reason": _reason_counts(selected),
            "omitted_by_reason": _reason_counts(omitted),
        }
        if not cves:
            now = _not_before(_aware_utc(self.clock()), started_at)
            return _SourceOutcome(
                SourceSyncResult(
                    source=source,
                    status=SyncStatus.SKIPPED,
                    started_at=started_at,
                    finished_at=now,
                    metadata={**selection_metadata, "reason": "no eligible CVE aliases"},
                )
            )
        previous_state = self.store.get_source_state(source)
        snapshot_count = self.store.snapshot_count()
        counts = _empty_counts()
        truncated = candidate_count > limit_per_source
        issues: list[SyncIssue] = []
        if truncated:
            issues.append(
                SyncIssue(
                    code="epss_candidate_limit",
                    message=(
                        f"EPSS candidate set exceeded the {limit_per_source} record ceiling; "
                        f"selected {len(cves)} of {candidate_count}"
                    ),
                )
            )
        enriched_ids: list[str] = []
        seen_cves: set[str] = set()
        last_snapshot_id: str | None = None
        history_observations_seen = 0
        history_observations_written = 0
        chunks = _epss_chunks(cves, max_items=self.limits.max_epss_cves_per_request)
        for chunk in chunks:
            url = f"{EPSS_API_URL}?{urlencode({'cve': ','.join(chunk), 'scope': 'time-series'})}"
            response = self._get(url, max_bytes=self.limits.max_epss_bytes, accept="application/json")
            _require_success(response, source)
            document = decode_json_object(response.body, source=source)
            snapshot = self.store.save_snapshot(
                response.body,
                source=source,
                kind=SnapshotKind.ENRICHMENT,
                source_url=response.url,
                retrieved_at=started_at,
                media_type=response.header("Content-Type") or "application/json",
                attribution=EPSS_ATTRIBUTION,
                http_status=response.status,
                etag=response.header("ETag"),
                last_modified=response.header("Last-Modified"),
                source_schema_version=_string(document.get("version")),
                source_metadata={"requested_cves": chunk},
            )
            last_snapshot_id = snapshot.snapshot_id
            parsed = parse_epss(document, snapshot)
            chunk_records: list[ParsedSourceRecord] = []
            history_batches = []
            for item in parsed:
                cve = item.cve.upper()
                if cve not in chunk:
                    continue
                seen_cves.add(cve)
                history_observations_seen += len(item.history)
                history_batches.append((cve, item.history))
                chunk_records.append(
                    ParsedSourceRecord(
                        source=source,
                        source_record_id=cve,
                        advisory=NormalizedAdvisory(
                            advisory_id=cve,
                            identifiers=[cve],
                            sources=[source],
                            severity=[item.signal],
                            provenance=[snapshot],
                            source_metadata={source.value: item.metadata},
                        ),
                        raw_record_sha256=item.raw_record_sha256,
                    )
                )
                enriched_ids.append(cve)
            history_observations_written += self.store.upsert_epss_observation_batches(
                history_batches,
                snapshot_id=snapshot.snapshot_id,
            )
            states = self.store.upsert_source_records(
                chunk_records,
                snapshot_id=snapshot.snapshot_id,
                seen_at=started_at,
            )
            for state in states:
                _increment_count(counts, state)
        missing = sorted(set(cves) - seen_cves)
        if missing:
            issues.append(
                SyncIssue(
                    code="epss_scores_missing",
                    message=f"EPSS omitted {len(missing)} requested CVE score(s)",
                    retriable=True,
                )
            )
        finished_at = _not_before(_aware_utc(self.clock()), started_at)
        status = SyncStatus.PARTIAL if issues else SyncStatus.SUCCESS
        selection_metadata.update(
            {
                "request_count": len(chunks),
                "history_observations_seen": history_observations_seen,
                "history_observations_written": history_observations_written,
            }
        )
        state = SourceState(
            source=source,
            last_attempt_at=finished_at,
            last_success_at=(
                finished_at
                if status == SyncStatus.SUCCESS
                else (previous_state.last_success_at if previous_state else None)
            ),
            cursor_at=started_at
            if status == SyncStatus.SUCCESS
            else (previous_state.cursor_at if previous_state else None),
            etag=None,
            last_modified=None,
            last_snapshot_id=last_snapshot_id,
            last_status=status,
            metadata=selection_metadata,
        )
        self.store.set_source_state(state)
        return _SourceOutcome(
            SourceSyncResult(
                source=source,
                status=status,
                started_at=started_at,
                finished_at=finished_at,
                records_seen=len(seen_cves),
                records_selected=len(cves),
                records_inserted=counts[UpsertState.INSERTED],
                records_updated=counts[UpsertState.UPDATED],
                records_unchanged=counts[UpsertState.UNCHANGED],
                snapshots_stored=self.store.snapshot_count() - snapshot_count,
                truncated=truncated,
                cursor_before=previous_state.cursor_at if previous_state else None,
                cursor_after=state.cursor_at,
                issues=issues,
                metadata=selection_metadata,
            ),
            tuple(_unique_strings(enriched_ids)),
        )

    def _get_osv_index(
        self, boundary: datetime, *, max_candidates: int, ecosystems: list[str]
    ) -> HttpResponse:
        streaming_get = getattr(self.transport, "get_until_line", None)
        if callable(streaming_get):
            stop_after = _osv_stream_stop(boundary, max_candidates=max_candidates, ecosystems=ecosystems)
            return streaming_get(
                OSV_MODIFIED_INDEX_URL,
                headers={"Accept": "text/csv", "User-Agent": DEFAULT_USER_AGENT},
                timeout=self.limits.timeout_seconds,
                max_bytes=self.limits.max_osv_index_bytes,
                max_lines=self.limits.max_osv_index_lines,
                max_line_bytes=1024 * 1024,
                stop_after=stop_after,
            )
        return self._get(
            OSV_MODIFIED_INDEX_URL,
            max_bytes=self.limits.max_osv_index_bytes,
            accept="text/csv",
        )

    def _get(
        self,
        url: str,
        *,
        max_bytes: int,
        accept: str,
        conditional_headers: Mapping[str, str] | None = None,
    ) -> HttpResponse:
        headers = {"Accept": accept, "User-Agent": DEFAULT_USER_AGENT}
        for key, value in (conditional_headers or {}).items():
            if key not in {"If-None-Match", "If-Modified-Since"}:
                raise ValueError(f"unsupported conditional HTTP header: {key}")
            if len(value) > 1_000 or "\r" in value or "\n" in value:
                raise IntelligenceTransportError("conditional HTTP header value is invalid")
            headers[key] = value
        try:
            return self.transport.get(
                url,
                headers=headers,
                timeout=self.limits.timeout_seconds,
                max_bytes=max_bytes,
            )
        except IntelligenceError:
            raise
        except Exception as exc:
            raise IntelligenceTransportError(
                f"public source transport failed: {type(exc).__name__}", retriable=True
            ) from exc

    def _failed_source_result(
        self, source: IntelligenceSource, started_at: datetime, error: IntelligenceError
    ) -> SourceSyncResult:
        finished_at = _not_before(_aware_utc(self.clock()), started_at)
        previous = self.store.get_source_state(source)
        self.store.set_source_state(
            SourceState(
                source=source,
                last_attempt_at=finished_at,
                last_success_at=previous.last_success_at if previous else None,
                cursor_at=previous.cursor_at if previous else None,
                etag=previous.etag if previous else None,
                last_modified=previous.last_modified if previous else None,
                last_snapshot_id=previous.last_snapshot_id if previous else None,
                last_status=SyncStatus.FAILED,
                metadata=previous.metadata if previous else {},
            )
        )
        return SourceSyncResult(
            source=source,
            status=SyncStatus.FAILED,
            started_at=started_at,
            finished_at=finished_at,
            issues=[SyncIssue(code=error.code, message=error.message, retriable=error.retriable)],
        )

    def _validate_sync_bounds(
        self,
        *,
        sources: list[IntelligenceSource],
        since_hours: float,
        ecosystems: list[str],
        limit_per_source: int,
    ) -> None:
        if not 0.0 < since_hours <= 24 * 365:
            raise IntelligenceLimitError("since_hours must be between 0 and 8760")
        if limit_per_source < 1 or limit_per_source > self.limits.max_limit_per_source:
            raise IntelligenceLimitError(
                f"limit_per_source must be between 1 and {self.limits.max_limit_per_source}"
            )
        if IntelligenceSource.NVD in sources and since_hours > 120 * 24:
            raise IntelligenceLimitError("NVD since_hours cannot exceed the API's 120-day window")
        if len(ecosystems) > 100:
            raise IntelligenceLimitError("ecosystems filter exceeds 100 items")
        if any(len(ecosystem) > 200 for ecosystem in ecosystems):
            raise IntelligenceLimitError("ecosystem name exceeds 200 characters")


def _normalize_sources(
    values: Iterable[IntelligenceSource | str] | None,
) -> list[IntelligenceSource]:
    if values is None:
        return [IntelligenceSource.CISA_KEV, IntelligenceSource.OSV]
    if isinstance(values, str):
        values = values.split(",")
    result: list[IntelligenceSource] = []
    for value in values:
        try:
            normalized = value if isinstance(value, IntelligenceSource) else IntelligenceSource(value.strip())
        except ValueError as exc:
            raise IntelligenceParseError(f"unknown intelligence source: {value}") from exc
        if normalized == IntelligenceSource.EPSS:
            raise IntelligenceParseError("EPSS is enrichment-only; set enrich_epss=True")
        if normalized not in result:
            result.append(normalized)
    if not result:
        raise IntelligenceParseError("at least one intelligence source is required")
    return result


def _normalize_filter_sources(
    values: Iterable[IntelligenceSource | str],
) -> list[IntelligenceSource]:
    if isinstance(values, str):
        values = values.split(",")
    result: list[IntelligenceSource] = []
    for value in values:
        try:
            source = value if isinstance(value, IntelligenceSource) else IntelligenceSource(value.strip())
        except ValueError as exc:
            raise IntelligenceParseError(f"unknown intelligence source: {value}") from exc
        if source not in result:
            result.append(source)
    return result


def _normalize_ecosystems(values: Iterable[str] | None) -> list[str]:
    if values is None:
        return []
    if isinstance(values, str):
        values = values.split(",")
    return _unique_strings([value.strip() for value in values if value.strip()])


def _matches_ecosystems(advisory: NormalizedAdvisory, ecosystems: list[str]) -> bool:
    selected = {value.casefold() for value in ecosystems}
    return any(item.ecosystem and item.ecosystem.casefold() in selected for item in advisory.affected)


def _require_success(
    response: HttpResponse,
    source: IntelligenceSource,
    *,
    allowed: set[int] | None = None,
) -> None:
    allowed = allowed or {200}
    if response.status not in allowed:
        raise IntelligenceTransportError(
            f"{source.value} returned HTTP {response.status}",
            source=source,
            retriable=response.status >= 500 or response.status == 429,
        )


def _select_epss_candidates(
    states: list[EpssCandidateState],
    *,
    expected_score_date: date,
) -> list[_EpssCandidate]:
    candidates: list[_EpssCandidate] = []
    for state in states:
        if state.current_run and state.known_exploited:
            reason, priority = "current-run-kev", 0
        elif state.current_run and state.latest_score_date is None:
            reason, priority = "current-run-unscored", 1
        elif state.known_exploited and state.latest_score_date is None:
            reason, priority = "kev-unscored-backfill", 2
        elif state.current_run:
            reason, priority = "current-run-refresh", 3
        elif state.known_exploited and state.latest_score_date < expected_score_date:
            reason, priority = "stale-kev-refresh", 4
        elif state.latest_score_date is not None and state.latest_score_date < expected_score_date:
            reason, priority = "stale-observation-refresh", 5
        else:
            continue
        candidates.append(_EpssCandidate(state=state, reason=reason, priority=priority))
    return sorted(
        candidates,
        key=lambda item: (
            item.priority,
            item.state.latest_score_date or date.min,
            item.state.cve,
        ),
    )


def _reason_counts(candidates: list[_EpssCandidate]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for candidate in candidates:
        counts[candidate.reason] = counts.get(candidate.reason, 0) + 1
    return {reason: counts[reason] for reason in sorted(counts)}


def _epss_chunks(cves: list[str], *, max_items: int) -> list[list[str]]:
    chunks: list[list[str]] = []
    current: list[str] = []
    current_length = 0
    for cve in cves:
        if len(cve) > 2_000:
            raise IntelligenceLimitError("EPSS CVE query value exceeds FIRST's 2000 character limit")
        added_length = len(cve) + (1 if current else 0)
        if current and (len(current) >= max_items or current_length + added_length > 2_000):
            chunks.append(current)
            current = []
            current_length = 0
            added_length = len(cve)
        current.append(cve)
        current_length += added_length
    if current:
        chunks.append(current)
    return chunks


def _empty_counts() -> dict[UpsertState, int]:
    return {state: 0 for state in UpsertState}


def _increment_count(counts: dict[UpsertState, int], state: UpsertState) -> None:
    counts[state] += 1


def _combined_status(results: list[SourceSyncResult]) -> SyncStatus:
    statuses = [result.status for result in results]
    if all(status in {SyncStatus.SUCCESS, SyncStatus.SKIPPED} for status in statuses):
        return SyncStatus.SUCCESS
    if all(status == SyncStatus.FAILED for status in statuses):
        return SyncStatus.FAILED
    return SyncStatus.PARTIAL


def _conditional_headers(state: SourceState | None) -> dict[str, str]:
    if state is None:
        return {}
    headers: dict[str, str] = {}
    if state.etag:
        headers["If-None-Match"] = state.etag
    if state.last_modified:
        headers["If-Modified-Since"] = state.last_modified
    return headers


def _osv_stream_stop(
    boundary: datetime, *, max_candidates: int, ecosystems: list[str]
) -> Callable[[bytes], bool]:
    candidate_count = 0
    seen_ids: set[str] = set()
    selected_ecosystems = {item.casefold() for item in ecosystems}

    def stop(line: bytes) -> bool:
        nonlocal candidate_count
        try:
            row = next(csv.reader(io.StringIO(line.decode("utf-8-sig"))))
        except (UnicodeDecodeError, csv.Error, StopIteration):
            return False
        if not row:
            return False
        lowered = [cell.strip().casefold() for cell in row]
        if "id" in lowered and "modified" in lowered:
            return False
        parsed_times = [(index, _try_datetime(cell)) for index, cell in enumerate(row)]
        timestamp_entry = next(((index, value) for index, value in parsed_times if value is not None), None)
        modified = timestamp_entry[1] if timestamp_entry else None
        if modified is None:
            return False
        if modified < boundary:
            return True
        id_cells = [cell for index, cell in enumerate(row) if index != timestamp_entry[0]]
        if not id_cells:
            return False
        indexed_id = unquote(id_cells[0].strip()).replace("\\", "/").strip("/")
        parts = indexed_id.split("/")
        ecosystem = parts[0] if len(parts) > 1 else None
        advisory_id = parts[-1]
        if advisory_id.casefold().endswith(".json"):
            advisory_id = advisory_id[:-5]
        if selected_ecosystems and ecosystem and ecosystem.casefold() not in selected_ecosystems:
            return False
        identifier_key = advisory_id.casefold()
        if identifier_key in seen_ids:
            return False
        seen_ids.add(identifier_key)
        candidate_count += 1
        return candidate_count >= max_candidates

    return stop


def _try_datetime(value: str) -> datetime | None:
    raw = value.strip()
    if not raw:
        return None
    try:
        parsed = datetime.fromisoformat(raw[:-1] + "+00:00" if raw.endswith("Z") else raw)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _unique_strings(values: list[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        key = value.casefold()
        if not value or key in seen:
            continue
        seen.add(key)
        result.append(value)
    return result


def _aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("intelligence timestamps must be timezone-aware")
    return value.astimezone(UTC)


def _not_before(value: datetime, lower_bound: datetime) -> datetime:
    return max(value, lower_bound)


def _timestamp(value: datetime | None) -> float:
    return value.timestamp() if value else 0.0


def _string(value) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def _format_datetime(value: datetime | None) -> str:
    return value.isoformat() if value else "unknown"


def _affected_summary(advisory: NormalizedAdvisory) -> str:
    values = [f"{item.ecosystem or 'unknown'}:{item.name}" for item in advisory.affected[:5]]
    if not values:
        return "not specified"
    suffix = f" (+{len(advisory.affected) - 5} more)" if len(advisory.affected) > 5 else ""
    return ", ".join(_markdown(value) for value in values) + suffix


def _markdown(value: str) -> str:
    return value.replace("\\", "\\\\").replace("`", "\\`").replace("*", "\\*").replace("_", "\\_")
