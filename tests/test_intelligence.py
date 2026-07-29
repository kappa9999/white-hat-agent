from __future__ import annotations

import io
import json
from collections import defaultdict
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from white_hat_agent.intelligence import (
    CISA_ATTRIBUTION,
    CISA_KEV_URL,
    EPSS_API_URL,
    OSV_API_BASE_URL,
    OSV_ATTRIBUTION,
    OSV_MODIFIED_INDEX_URL,
    AdvisoryNotFoundError,
    AffectedPackage,
    IntelligenceLimitError,
    IntelligenceLimits,
    IntelligenceParseError,
    IntelligenceService,
    IntelligenceSource,
    IntelligenceStore,
    IntelligenceStoreError,
    IntelligenceTransportError,
    NormalizedAdvisory,
    ParsedSourceRecord,
    SeverityKind,
    SeveritySignal,
    SnapshotKind,
    SyncStatus,
    parse_cisa_kev,
    parse_osv_modified_index,
    rank_advisory,
)
from white_hat_agent.intelligence.transport import (
    HttpResponse,
    UrllibHttpTransport,
    _AllowlistedRedirectHandler,
)

NOW = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)


class FakeTransport:
    def __init__(self, responses: dict[str, list[HttpResponse] | HttpResponse]) -> None:
        self.responses = {
            url: list(value) if isinstance(value, list) else [value] for url, value in responses.items()
        }
        self.requests: list[tuple[str, dict[str, str], int]] = []
        self.streamed_bodies: list[bytes] = []

    def get(self, url, *, headers, timeout, max_bytes) -> HttpResponse:
        self.requests.append((url, dict(headers), max_bytes))
        try:
            response = self.responses[url].pop(0)
        except (KeyError, IndexError) as exc:
            raise AssertionError(f"unexpected synthetic request: {url}") from exc
        if len(response.body) > max_bytes:
            raise AssertionError("fixture exceeded requested bound")
        return response

    def get_until_line(
        self,
        url,
        *,
        headers,
        timeout,
        max_bytes,
        max_lines,
        max_line_bytes,
        stop_after,
    ) -> HttpResponse:
        response = self.get(url, headers=headers, timeout=timeout, max_bytes=max_bytes)
        selected: list[bytes] = []
        complete = True
        for index, line in enumerate(response.body.splitlines(keepends=True), start=1):
            assert index <= max_lines
            assert len(line) <= max_line_bytes
            selected.append(line)
            if stop_after(line):
                complete = False
                break
        body = b"".join(selected)
        assert len(body) <= max_bytes
        self.streamed_bodies.append(body)
        return replace(response, body=body, complete=complete, line_count=len(selected))


class _SyntheticUrlResponse(io.BytesIO):
    status = 200

    def __init__(self, body: bytes, *, url: str, headers: dict[str, str]) -> None:
        super().__init__(body)
        self._url = url
        self.headers = headers

    def geturl(self) -> str:
        return self._url


def _response(url: str, body: bytes, *, status: int = 200, headers=None) -> HttpResponse:
    return HttpResponse(
        status=status,
        headers=headers or {"Content-Type": "application/json"},
        body=body,
        url=url,
    )


def _json_response(url: str, value: dict, *, headers=None, status: int = 200) -> HttpResponse:
    return _response(
        url,
        json.dumps(value, sort_keys=True).encode(),
        status=status,
        headers=headers,
    )


def _store(tmp_path: Path) -> IntelligenceStore:
    store = IntelligenceStore(tmp_path / "state.db", tmp_path / "snapshots")
    store.initialize()
    return store


def _cisa_item(
    cve: str,
    *,
    description: str = "Synthetic vulnerable behavior.",
    date_added: str = "2024-01-02",
) -> dict:
    return {
        "cveID": cve,
        "vendorProject": "Fixture Vendor",
        "product": "Fixture Product",
        "vulnerabilityName": f"Fixture {cve}",
        "dateAdded": date_added,
        "shortDescription": description,
        "requiredAction": "Apply the vendor update.",
        "dueDate": "2026-08-01",
        "knownRansomwareCampaignUse": "Unknown",
        "notes": "https://example.test/advisory",
        "cwes": ["CWE-79"],
        "futureUpstreamField": {"accepted": True},
    }


def _cisa_feed(*items: dict, version: str = "2026.07.29") -> dict:
    return {
        "title": "CISA Known Exploited Vulnerabilities Catalog",
        "catalogVersion": version,
        "dateReleased": "2026-07-29T10:00:00Z",
        "count": len(items),
        "vulnerabilities": list(items),
    }


def _snapshot(store: IntelligenceStore, payload: bytes = b"{}"):
    return store.save_snapshot(
        payload,
        source=IntelligenceSource.CISA_KEV,
        kind=SnapshotKind.FULL_FEED,
        source_url=CISA_KEV_URL,
        retrieved_at=NOW,
        media_type="application/json",
        attribution=CISA_ATTRIBUTION,
    )


def test_strict_provenance_and_cisa_count_integrity_and_bounds(tmp_path) -> None:
    store = _store(tmp_path)
    provenance = _snapshot(store)
    valid = _cisa_feed(_cisa_item("CVE-2026-1000"))

    record = parse_cisa_kev(valid, provenance, max_items=10)[0]

    assert record.advisory.published_at == datetime(2024, 1, 2, tzinfo=UTC)
    assert record.advisory.modified_at is None
    assert record.advisory.source_metadata["cisa-kev"]["catalog_version"] == "2026.07.29"
    assert "futureUpstreamField" in record.advisory.source_metadata["cisa-kev"]["unknown_fields"]

    invalid_type = {**valid, "count": "1"}
    with pytest.raises(IntelligenceParseError, match="count must be an integer"):
        parse_cisa_kev(invalid_type, provenance, max_items=10)
    invalid_count = {**valid, "count": 2}
    with pytest.raises(IntelligenceParseError, match="does not match"):
        parse_cisa_kev(invalid_count, provenance, max_items=10)
    with pytest.raises(IntelligenceLimitError, match="item limit"):
        parse_cisa_kev(valid, provenance, max_items=0)
    with pytest.raises(ValidationError, match="Extra inputs"):
        provenance.model_copy(update={"unexpected": True}).model_validate(
            {**provenance.model_dump(mode="json"), "unexpected": True}
        )


def test_snapshot_round_trip_idempotence_and_tamper_detection(tmp_path) -> None:
    store = _store(tmp_path)
    first = _snapshot(store, b'{"fixture":true}\n')
    second = store.save_snapshot(
        b'{"fixture":true}\n',
        source=IntelligenceSource.CISA_KEV,
        kind=SnapshotKind.FULL_FEED,
        source_url=CISA_KEV_URL,
        retrieved_at=NOW.replace(hour=13),
        media_type="application/json",
        attribution=CISA_ATTRIBUTION,
    )

    assert first == second
    assert store.read_snapshot(first.snapshot_id) == b'{"fixture":true}\n'
    assert store.verify_snapshot(first.snapshot_id)
    assert store.status().snapshot_count == 1

    stored_path = tmp_path / "snapshots" / first.storage_path
    stored_path.chmod(0o644)
    stored_path.write_bytes(b"tampered")
    with pytest.raises(IntelligenceStoreError, match="verification failed"):
        store.read_snapshot(first.snapshot_id)


def test_cisa_full_feed_diffs_old_updates_and_tombstones_without_limit_loss(tmp_path) -> None:
    first_feed = _cisa_feed(
        _cisa_item("CVE-2024-0001", description="old text", date_added="2024-01-01"),
        _cisa_item("CVE-2024-0002", date_added="2024-01-02"),
        version="1",
    )
    second_feed = _cisa_feed(
        _cisa_item("CVE-2024-0001", description="corrected old record", date_added="2024-01-01"),
        version="2",
    )
    transport = FakeTransport(
        {
            CISA_KEV_URL: [
                _json_response(
                    CISA_KEV_URL,
                    first_feed,
                    headers={"Content-Type": "application/json", "ETag": '"feed-1"'},
                ),
                _json_response(
                    CISA_KEV_URL,
                    second_feed,
                    headers={
                        "Content-Type": "application/json",
                        "ETag": '"feed-2"',
                        "Last-Modified": "Wed, 29 Jul 2026 10:00:00 GMT",
                    },
                ),
                _response(CISA_KEV_URL, b"", status=304, headers={"ETag": '"feed-2"'}),
            ]
        }
    )
    store = _store(tmp_path)
    service = IntelligenceService(store, transport=transport, clock=lambda: NOW)

    first = service.sync(sources=["cisa-kev"], limit_per_source=1)
    second = service.sync(sources=["cisa-kev"], limit_per_source=1)
    third = service.sync(sources=["cisa-kev"], limit_per_source=1)

    assert first.results[0].records_inserted == 2
    assert first.results[0].records_selected == 2
    assert second.results[0].records_updated == 1
    assert second.results[0].records_tombstoned == 1
    assert second.results[0].truncated is False
    assert service.get("CVE-2024-0001").summary == "corrected old record"
    removed = service.get("CVE-2024-0002")
    assert removed.tombstoned_sources == [IntelligenceSource.CISA_KEV]
    assert removed.known_exploited is False
    assert third.results[0].records_selected == 0
    assert transport.requests[1][1]["If-None-Match"] == '"feed-1"'
    assert transport.requests[2][1]["If-None-Match"] == '"feed-2"'
    assert store.status().snapshot_count == 2


def test_osv_index_prefilters_ecosystem_deduplicates_and_stops_boundary() -> None:
    payload = (
        b"modified,id\n"
        b"2026-07-29T11:00:00Z,npm/GHSA-new.json\n"
        b"2026-07-29T10:59:00Z,PyPI/PYSEC-ignore.json\n"
        b"2026-07-29T10:58:00Z,npm/GHSA-new.json\n"
        b"2026-07-28T08:00:00Z,npm/GHSA-old.json\n"
        b"2026-07-29T11:30:00Z,npm/GHSA-after-boundary.json\n"
    )

    selection = parse_osv_modified_index(
        payload,
        boundary=datetime(2026, 7, 28, 10, tzinfo=UTC),
        max_lines=100,
        max_candidates=10,
        ecosystems=["NPM"],
    )

    assert [(item.advisory_id, item.ecosystem) for item in selection.entries] == [("GHSA-new", "npm")]
    assert selection.entries_filtered == 2
    assert selection.reached_boundary
    with pytest.raises(IntelligenceParseError, match="index is empty"):
        parse_osv_modified_index(
            b"",
            boundary=datetime(2026, 7, 28, 10, tzinfo=UTC),
            max_lines=100,
            max_candidates=10,
        )
    assert selection.lines_seen == 5
    with pytest.raises(IntelligenceLimitError, match="line limit"):
        parse_osv_modified_index(
            payload,
            boundary=datetime(2026, 7, 28, 10, tzinfo=UTC),
            max_lines=2,
            max_candidates=10,
        )


def test_osv_index_accepts_current_headerless_paths_with_spaced_ecosystems() -> None:
    payload = (
        b"2026-07-29T10:18:45.611422849Z,Red Hat/RHSA-2026:42880\n"
        b"2026-07-29T10:17:00.123456789Z,npm/GHSA-current-format\n"
        b"2026-07-28T08:00:00Z,npm/GHSA-old\n"
    )

    selection = parse_osv_modified_index(
        payload,
        boundary=datetime(2026, 7, 28, 10, tzinfo=UTC),
        max_lines=100,
        max_candidates=10,
        ecosystems=["npm"],
    )

    assert [(item.advisory_id, item.ecosystem) for item in selection.entries] == [
        ("GHSA-current-format", "npm")
    ]
    assert selection.entries_filtered == 1
    assert selection.reached_boundary


def test_transport_enforces_declared_byte_bound_without_network() -> None:
    response = _SyntheticUrlResponse(
        b"12345",
        url=CISA_KEV_URL,
        headers={"Content-Length": "5", "Content-Type": "application/json"},
    )

    with pytest.raises(IntelligenceLimitError, match="4 byte limit"):
        UrllibHttpTransport._read_response(
            response,
            requested_url=CISA_KEV_URL,
            max_bytes=4,
        )


def test_osv_no_cve_withdrawal_ranges_manifest_and_streaming_prefix(tmp_path) -> None:
    index_body = (
        b"modified,id\n"
        b"2026-07-29T11:00:00Z,npm/GHSA-no-cve.json\n"
        b"2026-07-29T10:00:00Z,PyPI/PYSEC-filtered.json\n"
        b"2026-07-29T09:00:00Z,npm/GHSA-no-cve.json\n"
        b"2026-07-28T08:00:00Z,npm/GHSA-old.json\n"
        b"2026-07-29T11:30:00Z,npm/SHOULD-NOT-BE-TRANSFERRED.json\n"
    )
    record_url = OSV_API_BASE_URL + "GHSA-no-cve"
    osv_record = {
        "schema_version": "1.7.4",
        "id": "GHSA-no-cve",
        "aliases": [],
        "summary": "Synthetic withdrawn npm advisory",
        "details": "Fixture details",
        "published": "2026-07-20T00:00:00Z",
        "modified": "2026-07-29T11:00:00Z",
        "withdrawn": "2026-07-29T11:30:00Z",
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "fixture-package"},
                "ranges": [
                    {
                        "type": "SEMVER",
                        "events": [{"introduced": "0"}, {"fixed": "2.0.0"}],
                    }
                ],
                "versions": ["1.0.0"],
            }
        ],
        "references": [{"type": "ADVISORY", "url": "https://example.test/osv"}],
        "database_specific": {"source": "Fixture Advisory Database"},
        "unknown_future_field": True,
    }
    transport = FakeTransport(
        {
            OSV_MODIFIED_INDEX_URL: _response(
                OSV_MODIFIED_INDEX_URL,
                index_body,
                headers={"Content-Type": "text/csv", "ETag": '"index"'},
            ),
            record_url: _json_response(record_url, osv_record),
        }
    )
    store = _store(tmp_path)
    service = IntelligenceService(store, transport=transport, clock=lambda: NOW)

    report = service.sync(
        sources=[IntelligenceSource.OSV],
        ecosystems=["NPM"],
        since_hours=24,
        limit_per_source=2,
    )
    advisory = service.get("GHSA-no-cve")

    assert report.status == SyncStatus.SUCCESS
    assert report.results[0].records_selected == 1
    assert report.results[0].records_filtered == 2
    assert advisory.identifiers == ["GHSA-no-cve"]
    assert advisory.withdrawn_at == datetime(2026, 7, 29, 11, 30, tzinfo=UTC)
    assert advisory.affected[0].ranges[0].events[1].fixed == "2.0.0"
    assert advisory.source_metadata["osv"]["source_database"] == "Fixture Advisory Database"
    assert len([request for request in transport.requests if request[0].startswith(OSV_API_BASE_URL)]) == 1
    assert b"SHOULD-NOT-BE-TRANSFERRED" not in transport.streamed_bodies[0]
    state = store.get_source_state(IntelligenceSource.OSV)
    manifest = json.loads(store.read_snapshot(state.last_snapshot_id))
    assert manifest["index_prefix"]["complete_response"] is False
    assert store.read_snapshot(manifest["index_prefix"]["snapshot_id"]) == transport.streamed_bodies[0]
    assert manifest["entries"] == [
        {
            "ecosystem": "npm",
            "http_status": 200,
            "id": "GHSA-no-cve",
            "modified": "2026-07-29T11:00:00+00:00",
            "selected": True,
            "snapshot_id": advisory.provenance[0].snapshot_id,
        }
    ]
    assert (
        store.read_snapshot(advisory.provenance[0].snapshot_id)
        == json.dumps(osv_record, sort_keys=True).encode()
    )


def test_epss_enriches_only_locally_selected_cve_aliases_and_alias_graph(tmp_path) -> None:
    index_body = (
        b"modified,id\n2026-07-29T11:00:00Z,npm/GHSA-epss.json\n2026-07-28T08:00:00Z,npm/GHSA-old.json\n"
    )
    record_url = OSV_API_BASE_URL + "GHSA-epss"
    epss_url = f"{EPSS_API_URL}?cve=CVE-2026-1234"
    osv_record = {
        "id": "GHSA-epss",
        "aliases": ["CVE-2026-1234"],
        "summary": "Synthetic aliased advisory",
        "modified": "2026-07-29T11:00:00Z",
        "affected": [{"package": {"ecosystem": "npm", "name": "aliased-package"}}],
    }
    epss = {
        "status": "OK",
        "version": "1.0",
        "data": [
            {
                "cve": "CVE-2026-1234",
                "epss": "0.125",
                "percentile": "0.75",
                "date": "2026-07-29",
            }
        ],
    }
    transport = FakeTransport(
        {
            OSV_MODIFIED_INDEX_URL: _response(OSV_MODIFIED_INDEX_URL, index_body),
            record_url: _json_response(record_url, osv_record),
            epss_url: _json_response(epss_url, epss),
        }
    )
    service = IntelligenceService(_store(tmp_path), transport=transport, clock=lambda: NOW)

    report = service.sync(sources=["osv"], limit_per_source=5, enrich_epss=True)
    advisory = service.get("GHSA-epss")

    assert [result.source for result in report.results] == [
        IntelligenceSource.OSV,
        IntelligenceSource.EPSS,
    ]
    assert advisory.advisory_id == "CVE-2026-1234"
    assert {item.value for item in advisory.sources} == {"osv", "epss"}
    assert any(
        signal.kind == SeverityKind.EPSS and signal.probability == 0.125 for signal in advisory.severity
    )
    assert [request[0] for request in transport.requests].count(epss_url) == 1


def test_epss_candidate_ceiling_is_explicit_and_does_not_fail_primary_checkpoint(tmp_path) -> None:
    cves = ["CVE-2026-1001", "CVE-2026-1002", "CVE-2026-1003"]
    epss_url = f"{EPSS_API_URL}?cve=CVE-2026-1001%2CCVE-2026-1002"
    epss = {
        "status": "OK",
        "data": [{"cve": cve, "epss": "0.01", "percentile": "0.5", "date": "2026-07-29"} for cve in cves[:2]],
    }
    transport = FakeTransport(
        {
            CISA_KEV_URL: _json_response(
                CISA_KEV_URL,
                _cisa_feed(*[_cisa_item(cve) for cve in cves]),
            ),
            epss_url: _json_response(epss_url, epss),
        }
    )
    service = IntelligenceService(_store(tmp_path), transport=transport, clock=lambda: NOW)

    report = service.sync(sources=["cisa-kev"], limit_per_source=2, enrich_epss=True)
    primary, enrichment = report.results

    assert primary.status == SyncStatus.SUCCESS
    assert enrichment.status == SyncStatus.PARTIAL
    assert enrichment.truncated
    assert enrichment.records_selected == 2
    assert enrichment.metadata == {
        "selection": "locally-selected-cve-aliases",
        "candidate_count": 3,
        "requested": 2,
    }
    assert enrichment.issues[0].code == "epss_candidate_limit"
    assert report.status == SyncStatus.PARTIAL
    assert report.successful


def test_osv_request_ceiling_counts_failed_record_fetches(tmp_path) -> None:
    index_body = (
        b"2026-07-29T11:00:00Z,npm/GHSA-failure-one\n"
        b"2026-07-29T10:59:00Z,npm/GHSA-failure-two\n"
        b"2026-07-29T10:58:00Z,npm/GHSA-must-not-fetch\n"
        b"2026-07-28T08:00:00Z,npm/GHSA-old\n"
    )
    first_url = OSV_API_BASE_URL + "GHSA-failure-one"
    second_url = OSV_API_BASE_URL + "GHSA-failure-two"
    transport = FakeTransport(
        {
            OSV_MODIFIED_INDEX_URL: _response(OSV_MODIFIED_INDEX_URL, index_body),
            first_url: _response(first_url, b"upstream unavailable", status=503),
            second_url: _response(second_url, b"upstream unavailable", status=503),
        }
    )
    service = IntelligenceService(_store(tmp_path), transport=transport, clock=lambda: NOW)

    report = service.sync(sources=["osv"], ecosystems=["npm"], limit_per_source=2)
    result = report.results[0]

    assert result.status == SyncStatus.PARTIAL
    assert result.records_selected == 0
    assert result.truncated
    assert result.metadata["records_attempted"] == 2
    assert [request[0] for request in transport.requests] == [
        OSV_MODIFIED_INDEX_URL,
        first_url,
        second_url,
    ]


def test_osv_throttle_stops_immediately_and_preserves_cursor_for_replay(tmp_path) -> None:
    index_body = (
        b"2026-07-29T11:00:00Z,npm/GHSA-throttled\n"
        b"2026-07-29T10:59:00Z,npm/GHSA-must-not-fetch\n"
        b"2026-07-28T08:00:00Z,npm/GHSA-old\n"
    )
    throttled_url = OSV_API_BASE_URL + "GHSA-throttled"
    transport = FakeTransport(
        {
            OSV_MODIFIED_INDEX_URL: _response(OSV_MODIFIED_INDEX_URL, index_body),
            throttled_url: _response(throttled_url, b"rate limited", status=429),
        }
    )
    store = _store(tmp_path)
    service = IntelligenceService(store, transport=transport, clock=lambda: NOW)

    report = service.sync(sources=["osv"], ecosystems=["npm"], limit_per_source=1000)
    result = report.results[0]
    state = store.get_source_state(IntelligenceSource.OSV)

    assert result.status == SyncStatus.PARTIAL
    assert result.truncated
    assert result.cursor_after is None
    assert result.metadata["records_attempted"] == 1
    assert result.metadata["record_loop_interrupted"] is True
    assert result.issues[0].retriable is True
    assert state.last_success_at is None and state.cursor_at is None
    assert [request[0] for request in transport.requests] == [
        OSV_MODIFIED_INDEX_URL,
        throttled_url,
    ]


def test_osv_systemic_server_errors_stop_at_bounded_threshold(tmp_path) -> None:
    index_body = (
        b"2026-07-29T11:00:00Z,npm/GHSA-failure-one\n"
        b"2026-07-29T10:59:00Z,npm/GHSA-failure-two\n"
        b"2026-07-29T10:58:00Z,npm/GHSA-must-not-fetch\n"
        b"2026-07-28T08:00:00Z,npm/GHSA-old\n"
    )
    first_url = OSV_API_BASE_URL + "GHSA-failure-one"
    second_url = OSV_API_BASE_URL + "GHSA-failure-two"
    transport = FakeTransport(
        {
            OSV_MODIFIED_INDEX_URL: _response(OSV_MODIFIED_INDEX_URL, index_body),
            first_url: _response(first_url, b"upstream unavailable", status=503),
            second_url: _response(second_url, b"upstream unavailable", status=503),
        }
    )
    limits = IntelligenceLimits(max_osv_consecutive_server_errors=2)
    service = IntelligenceService(_store(tmp_path), transport=transport, clock=lambda: NOW, limits=limits)

    result = service.sync(sources=["osv"], ecosystems=["npm"], limit_per_source=1000).results[0]

    assert result.status == SyncStatus.PARTIAL
    assert result.truncated
    assert result.metadata["records_attempted"] == 2
    assert result.metadata["record_loop_interrupted"] is True
    assert all(issue.retriable for issue in result.issues)
    assert [request[0] for request in transport.requests] == [
        OSV_MODIFIED_INDEX_URL,
        first_url,
        second_url,
    ]


def test_osv_index_prefix_is_saved_before_per_record_transport_failure(tmp_path) -> None:
    index_body = b"2026-07-29T11:00:00Z,npm/GHSA-transport-failure\n2026-07-28T08:00:00Z,npm/GHSA-old\n"
    store = _store(tmp_path)
    service = IntelligenceService(
        store,
        transport=FakeTransport({OSV_MODIFIED_INDEX_URL: _response(OSV_MODIFIED_INDEX_URL, index_body)}),
        clock=lambda: NOW,
    )

    result = service.sync(sources=["osv"], ecosystems=["npm"]).results[0]
    snapshot_files = [path for path in (tmp_path / "snapshots").rglob("*") if path.is_file()]

    assert result.status == SyncStatus.FAILED
    assert store.snapshot_count() == 1
    assert len(snapshot_files) == 1
    assert snapshot_files[0].read_bytes() == index_body


def test_osv_index_prefix_is_saved_before_index_parse_failure(tmp_path) -> None:
    invalid_index = b"\xff\n"
    store = _store(tmp_path)
    service = IntelligenceService(
        store,
        transport=FakeTransport({OSV_MODIFIED_INDEX_URL: _response(OSV_MODIFIED_INDEX_URL, invalid_index)}),
        clock=lambda: NOW,
    )

    result = service.sync(sources=["osv"], ecosystems=["npm"]).results[0]
    snapshot_files = [path for path in (tmp_path / "snapshots").rglob("*") if path.is_file()]

    assert result.status == SyncStatus.FAILED
    assert store.snapshot_count() == 1
    assert len(snapshot_files) == 1
    assert snapshot_files[0].read_bytes() == invalid_index


def test_kev_priority_dominates_low_epss_and_factors_are_transparent() -> None:
    kev = NormalizedAdvisory(
        advisory_id="CVE-2024-0001",
        identifiers=["CVE-2024-0001"],
        sources=[IntelligenceSource.CISA_KEV],
        known_exploited=True,
    )
    speculative = NormalizedAdvisory(
        advisory_id="CVE-2026-9999",
        identifiers=["CVE-2026-9999"],
        sources=[IntelligenceSource.EPSS],
        modified_at=NOW,
        affected=[AffectedPackage(ecosystem="npm", name="fixture")],
        severity=[
            SeveritySignal(
                kind=SeverityKind.EPSS,
                source=IntelligenceSource.EPSS,
                probability=0.99,
            ),
            SeveritySignal(kind=SeverityKind.CVSS, source=IntelligenceSource.OSV, score=10.0),
        ],
    )

    kev_rank = rank_advisory(kev, as_of=NOW)
    speculative_rank = rank_advisory(speculative, as_of=NOW)

    assert kev_rank.total_score > speculative_rank.total_score
    assert kev_rank.kev_component == 1000.0
    assert kev_rank.algorithm_version == "kev-epss-recency-severity-evidence-v1"
    assert any("confirmed CISA KEV" in reason for reason in kev_rank.reasons)


def test_persistence_alias_lookup_list_status_and_deterministic_brief(tmp_path) -> None:
    store = _store(tmp_path)
    provenance = store.save_snapshot(
        b'{"id":"GHSA-persist"}',
        source=IntelligenceSource.OSV,
        kind=SnapshotKind.SOURCE_RECORD,
        source_url=OSV_API_BASE_URL + "GHSA-persist",
        source_record_id="GHSA-persist",
        retrieved_at=NOW,
        media_type="application/json",
        attribution=OSV_ATTRIBUTION,
    )
    advisory = NormalizedAdvisory(
        advisory_id="CVE-2026-4321",
        identifiers=["GHSA-persist", "CVE-2026-4321"],
        sources=[IntelligenceSource.OSV],
        title="Persistent fixture",
        modified_at=NOW,
        affected=[AffectedPackage(ecosystem="PyPI", name="fixture")],
        provenance=[provenance],
    )
    store.upsert_source_record(
        ParsedSourceRecord(
            source=IntelligenceSource.OSV,
            source_record_id="GHSA-persist",
            advisory=advisory,
            raw_record_sha256="1" * 64,
        ),
        snapshot_id=provenance.snapshot_id,
        seen_at=NOW,
    )
    reopened = IntelligenceStore(tmp_path / "state.db", tmp_path / "snapshots")
    service = IntelligenceService(reopened, transport=FakeTransport({}), clock=lambda: NOW)

    assert service.get("GHSA-persist").advisory_id == "CVE-2026-4321"
    listed = service.list(ecosystems=["pypi"], limit=10, as_of=NOW)
    assert [item.advisory.advisory_id for item in listed] == ["CVE-2026-4321"]
    status = service.status()
    assert status.initialized and status.advisory_count == 1 and status.snapshot_count == 1
    first = service.brief(ecosystems=["PyPI"], as_of=NOW)
    second = service.brief(ecosystems=["PyPI"], as_of=NOW)
    assert first == second
    assert "Persistent fixture" in first
    assert "kev-epss-recency-severity-evidence-v1" in first
    with pytest.raises(AdvisoryNotFoundError):
        service.get("CVE-0000-0000")


def test_redirect_handler_rejects_non_allowlisted_target_without_network() -> None:
    handler = _AllowlistedRedirectHandler()
    with pytest.raises(IntelligenceTransportError, match="outside the official allowlist"):
        handler.redirect_request(
            None,
            None,
            302,
            "Found",
            defaultdict(str),
            "https://attacker.invalid/collect",
        )


def test_sync_bounds_fail_before_any_network_request(tmp_path) -> None:
    transport = FakeTransport({})
    service = IntelligenceService(
        _store(tmp_path),
        transport=transport,
        clock=lambda: NOW,
        limits=IntelligenceLimits(max_limit_per_source=10),
    )

    with pytest.raises(IntelligenceLimitError, match="limit_per_source"):
        service.sync(sources=["osv"], limit_per_source=11)
    assert transport.requests == []
