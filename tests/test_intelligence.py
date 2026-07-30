from __future__ import annotations

import io
import json
import sqlite3
from collections import defaultdict
from dataclasses import replace
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from white_hat_agent.intelligence import (
    CISA_ATTRIBUTION,
    CISA_KEV_URL,
    CVE_LIST_V5_ATTRIBUTION,
    CVE_LIST_V5_DELTA_URL,
    EPSS_API_URL,
    EPSS_ATTRIBUTION,
    NVD_ATTRIBUTION,
    NVD_CVE_API_URL,
    OSV_API_BASE_URL,
    OSV_ATTRIBUTION,
    OSV_MODIFIED_INDEX_URL,
    AdvisoryNotFoundError,
    AffectedPackage,
    CveRecordState,
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
    cve_list_v5_record_url,
    nvd_cve_api_url,
    parse_cisa_kev,
    parse_cve_delta_log,
    parse_cve_record,
    parse_nvd_page,
    parse_osv_modified_index,
    rank_advisory,
)
from white_hat_agent.intelligence.transport import (
    HttpResponse,
    UrllibHttpTransport,
    _AllowlistedRedirectHandler,
    _validate_official_url,
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


class _ReadTrackingUrlResponse(_SyntheticUrlResponse):
    def __init__(self, body: bytes, *, url: str, headers: dict[str, str]) -> None:
        super().__init__(body, url=url, headers=headers)
        self.read_sizes: list[int] = []
        self.bytes_returned = 0

    def read(self, size: int = -1) -> bytes:
        self.read_sizes.append(size)
        chunk = super().read(size)
        self.bytes_returned += len(chunk)
        return chunk


class _OversizedCveRecordTransport(FakeTransport):
    def __init__(self, delta_response: HttpResponse, *, record_url: str, record_body: bytes) -> None:
        super().__init__({CVE_LIST_V5_DELTA_URL: delta_response})
        self.record_url = record_url
        self.record_body = record_body
        self.record_read_sizes: list[int] = []
        self.record_bytes_consumed = 0

    def get(self, url, *, headers, timeout, max_bytes) -> HttpResponse:
        if url != self.record_url:
            return super().get(
                url,
                headers=headers,
                timeout=timeout,
                max_bytes=max_bytes,
            )
        self.requests.append((url, dict(headers), max_bytes))
        response = _ReadTrackingUrlResponse(
            self.record_body,
            url=url,
            headers={"Content-Type": "application/json"},
        )
        try:
            return UrllibHttpTransport._read_response(
                response,
                requested_url=url,
                max_bytes=max_bytes,
            )
        finally:
            self.record_read_sizes = response.read_sizes
            self.record_bytes_consumed = response.bytes_returned


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


def _cve_snapshot(store: IntelligenceStore, cve: str, payload: bytes = b"{}"):
    return store.save_snapshot(
        payload,
        source=IntelligenceSource.CVE_LIST_V5,
        kind=SnapshotKind.SOURCE_RECORD,
        source_url=cve_list_v5_record_url(cve),
        source_record_id=cve,
        retrieved_at=NOW,
        media_type="application/json",
        attribution=CVE_LIST_V5_ATTRIBUTION,
        source_schema_version="5.2",
    )


def _nvd_record(cve: str, *, summary: str = "NVD fixture description.") -> dict:
    return {
        "id": cve,
        "sourceIdentifier": "fixture@example.test",
        "published": "2026-07-20T00:00:00.000",
        "lastModified": "2026-07-29T11:00:00.000",
        "vulnStatus": "Analyzed",
        "descriptions": [{"lang": "en", "value": summary}],
        "metrics": {
            "cvssMetricV31": [
                {
                    "source": "nvd@nist.gov",
                    "type": "Primary",
                    "cvssData": {
                        "version": "3.1",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                        "baseScore": 9.1,
                        "baseSeverity": "CRITICAL",
                    },
                    "exploitabilityScore": 3.9,
                    "impactScore": 5.2,
                }
            ],
            "ssvcV203": [
                {
                    "source": "nvd@nist.gov",
                    "ssvcData": {
                        "timestamp": "2026-07-29T11:30:00Z",
                        "id": cve,
                        "options": [
                            {"exploitation": "poc"},
                            {"automatable": "yes"},
                            {"technicalImpact": "total"},
                        ],
                        "role": "CISA Coordinator",
                        "version": "2.0.3",
                    },
                }
            ],
        },
        "weaknesses": [
            {
                "source": "nvd@nist.gov",
                "type": "Primary",
                "description": [{"lang": "en", "value": "CWE-89"}],
            }
        ],
        "configurations": [
            {
                "nodes": [
                    {
                        "operator": "OR",
                        "negate": False,
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:fixture:product:*:*:*:*:*:*:*:*",
                                "versionEndExcluding": "2.0.0",
                                "matchCriteriaId": "00000000-0000-4000-8000-000000000001",
                            }
                        ],
                    }
                ]
            }
        ],
        "affected": [
            {
                "source": "fixture@example.test",
                "affectedData": [
                    {
                        "vendor": "Fixture",
                        "product": "Product",
                        "versions": [
                            {
                                "version": "1.0.0",
                                "lessThan": "2.0.0",
                                "versionType": "semver",
                                "status": "affected",
                            }
                        ],
                    }
                ],
            }
        ],
        "references": [
            {
                "url": "https://example.test/vendor-advisory",
                "source": "fixture@example.test",
                "tags": ["Vendor Advisory", "Patch"],
            }
        ],
        "cveTags": [{"sourceIdentifier": "fixture@example.test", "tags": ["disputed"]}],
        "futureNvdField": {"preserved": True},
    }


def _nvd_page(*records: dict, total: int, start_index: int) -> dict:
    return {
        "format": "NVD_CVE",
        "version": "2.0",
        "timestamp": "2026-07-29T12:00:00.000",
        "totalResults": total,
        "startIndex": start_index,
        "resultsPerPage": len(records),
        "vulnerabilities": [{"cve": record} for record in records],
    }


def _nvd_snapshot(store: IntelligenceStore, payload: bytes = b"{}"):
    url = nvd_cve_api_url(
        NOW - timedelta(hours=26),
        NOW,
        results_per_page=100,
        start_index=0,
    )
    return store.save_snapshot(
        payload,
        source=IntelligenceSource.NVD,
        kind=SnapshotKind.API_PAGE,
        source_url=url,
        retrieved_at=NOW,
        media_type="application/json",
        attribution=NVD_ATTRIBUTION,
    )


def _cve_record(cve: str, *, state: str = "PUBLISHED") -> dict:
    metadata = {
        "cveId": cve,
        "assignerOrgId": "11111111-1111-4111-8111-111111111111",
        "assignerShortName": "fixture-cna",
        "state": state,
        "serial": 1,
        "dateUpdated": "2026-07-29T11:00:00Z",
    }
    provider = {
        "orgId": "11111111-1111-4111-8111-111111111111",
        "shortName": "fixture-cna",
        "dateUpdated": "2026-07-29T11:00:00Z",
    }
    if state == "REJECTED":
        metadata["dateRejected"] = "2026-07-29T11:00:00Z"
        cna = {
            "providerMetadata": provider,
            "rejectedReasons": [{"lang": "en", "value": "Duplicate of another record."}],
        }
    else:
        metadata["datePublished"] = "2026-07-20T00:00:00Z"
        cna = {
            "providerMetadata": provider,
            "title": "Canonical fixture title",
            "descriptions": [{"lang": "en", "value": "Canonical fixture description."}],
            "affected": [
                {
                    "vendor": "Fixture Vendor",
                    "product": "fixture-package",
                    "packageURL": "pkg:npm/fixture-package",
                    "defaultStatus": "unaffected",
                    "versions": [
                        {
                            "version": "0",
                            "lessThan": "2.0.0",
                            "versionType": "semver",
                            "status": "affected",
                        }
                    ],
                }
            ],
            "problemTypes": [{"descriptions": [{"lang": "en", "cweId": "CWE-79", "description": "XSS"}]}],
            "references": [{"url": "https://example.test/cna", "tags": ["vendor-advisory"]}],
            "metrics": [
                {
                    "cvssV3_1": {
                        "version": "3.1",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "baseScore": 9.8,
                        "baseSeverity": "CRITICAL",
                    }
                }
            ],
            "futureContainerField": {"preserved": True},
        }
    containers = {"cna": cna}
    if state != "REJECTED":
        containers["adp"] = [
            {
                "providerMetadata": {
                    "orgId": "22222222-2222-4222-8222-222222222222",
                    "shortName": "fixture-adp",
                    "dateUpdated": "2026-07-29T11:30:00Z",
                },
                "metrics": [
                    {
                        "cvssV4_0": {
                            "version": "4.0",
                            "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                            "baseScore": 9.3,
                            "baseSeverity": "CRITICAL",
                        }
                    }
                ],
            }
        ]
    return {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.2",
        "cveMetadata": metadata,
        "containers": containers,
        "futureTopLevelField": {"preserved": True},
    }


def _cve_delta_batch(fetch_time: str, *changes: tuple[str, str, str]) -> dict:
    batch = {"new": [], "updated": [], "error": []}
    for change_type, cve, modified in changes:
        batch[change_type].append(
            {
                "cveId": cve,
                "cveOrgLink": f"https://www.cve.org/CVERecord?id={cve}",
                "githubLink": cve_list_v5_record_url(cve),
                "dateUpdated": modified,
            }
        )
    batch["fetchTime"] = fetch_time
    batch["numberOfChanges"] = len(changes)
    return batch


def _cve_delta(*changes: tuple[str, str, str]) -> list[dict]:
    return [
        _cve_delta_batch("2026-07-29T11:40:00Z", *changes),
        _cve_delta_batch("2026-07-28T09:00:00Z"),
    ]


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


def test_nvd_page_preserves_native_configuration_and_normalizes_priority_signals(tmp_path) -> None:
    store = _store(tmp_path)
    raw = _nvd_record("CVE-2026-60137")
    document = _nvd_page(raw, total=1, start_index=0)
    snapshot = _nvd_snapshot(store, json.dumps(document, sort_keys=True).encode())

    page = parse_nvd_page(
        document,
        snapshot,
        expected_start_index=0,
        max_items=100,
        max_record_bytes=1024 * 1024,
    )
    advisory = page.records[0].advisory

    assert page.total_results == 1 and page.results_per_page == 1
    assert advisory.identifiers == ["CVE-2026-60137"]
    assert advisory.cwes == ["CWE-89"]
    assert advisory.affected == []
    assert {signal.kind for signal in advisory.severity} == {
        SeverityKind.CVSS,
        SeverityKind.SSVC,
    }
    assert next(signal for signal in advisory.severity if signal.kind == SeverityKind.CVSS).score == 9.1
    ssvc = next(signal for signal in advisory.severity if signal.kind == SeverityKind.SSVC)
    assert ssvc.label == "poc"
    assert ssvc.metadata["options"] == {
        "automatable": "yes",
        "exploitation": "poc",
        "technicalImpact": "total",
    }
    assert advisory.references[0].type.value == "fix"
    metadata = advisory.source_metadata["nvd"]
    assert metadata["configurations"] == raw["configurations"]
    assert metadata["affected"] == raw["affected"]
    assert metadata["unknown_fields"] == ["futureNvdField"]
    assert advisory.provenance[0].attribution.attribution.startswith("This product uses data")

    malformed = _nvd_page(raw, total=0, start_index=0)
    with pytest.raises(IntelligenceParseError, match="exceeds totalResults"):
        parse_nvd_page(
            malformed,
            snapshot,
            expected_start_index=0,
            max_items=100,
            max_record_bytes=1024 * 1024,
        )


def test_nvd_incremental_sync_pages_then_commits_one_closed_window(tmp_path) -> None:
    first_cve = "CVE-2026-60137"
    second_cve = "CVE-2026-60138"
    boundary = NOW - timedelta(hours=26)
    first_url = nvd_cve_api_url(boundary, NOW, results_per_page=1, start_index=0)
    second_url = nvd_cve_api_url(boundary, NOW, results_per_page=1, start_index=1)
    transport = FakeTransport(
        {
            first_url: _json_response(
                first_url,
                _nvd_page(_nvd_record(first_cve), total=2, start_index=0),
            ),
            second_url: _json_response(
                second_url,
                _nvd_page(_nvd_record(second_cve), total=2, start_index=1),
            ),
        }
    )
    limits = IntelligenceLimits(
        max_nvd_records_per_page=1,
        nvd_request_delay_seconds=0,
    )
    store = _store(tmp_path)
    service = IntelligenceService(store, transport=transport, clock=lambda: NOW, limits=limits)

    report = service.sync(sources=["nvd"], since_hours=24, limit_per_source=2)
    result = report.results[0]
    state = store.get_source_state(IntelligenceSource.NVD)
    manifest = json.loads(store.read_snapshot(state.last_snapshot_id))

    assert report.status == SyncStatus.SUCCESS and report.successful
    assert result.records_seen == result.records_selected == result.records_inserted == 2
    assert result.snapshots_stored == 3
    assert result.cursor_before is None and result.cursor_after == NOW
    assert state.cursor_at == NOW and state.last_status == SyncStatus.SUCCESS
    assert [request[0] for request in transport.requests] == [first_url, second_url]
    assert all(request[1]["User-Agent"].startswith("white-hat-agent") for request in transport.requests)
    assert manifest["total_results"] == 2 and manifest["fail_closed"] is False
    assert [page["snapshot_id"] for page in manifest["pages"]] == result.metadata["page_snapshot_ids"]
    assert {item["id"] for item in manifest["records"]} == {first_cve, second_cve}
    assert {source.value for source in service.get(first_cve).sources} == {"nvd"}


def test_nvd_candidate_ceiling_is_fail_closed_and_preserves_cursor(tmp_path) -> None:
    boundary = NOW - timedelta(hours=26)
    url = nvd_cve_api_url(boundary, NOW, results_per_page=1, start_index=0)
    transport = FakeTransport(
        {
            url: _json_response(
                url,
                _nvd_page(_nvd_record("CVE-2026-60137"), total=2, start_index=0),
            )
        }
    )
    store = _store(tmp_path)
    service = IntelligenceService(
        store,
        transport=transport,
        clock=lambda: NOW,
        limits=IntelligenceLimits(max_nvd_records_per_page=1, nvd_request_delay_seconds=0),
    )

    report = service.sync(sources=["nvd"], since_hours=24, limit_per_source=1)
    result = report.results[0]
    state = store.get_source_state(IntelligenceSource.NVD)

    assert report.status == SyncStatus.PARTIAL and not report.successful
    assert result.truncated and result.records_seen == 2 and result.records_selected == 0
    assert result.issues[0].code == "nvd_candidate_limit"
    assert result.cursor_after is None and state.cursor_at is None
    assert service.list(sources=["nvd"]) == []
    assert store.snapshot_count() == 2
    assert [request[0] for request in transport.requests] == [url]
    _validate_official_url(url)
    with pytest.raises(IntelligenceTransportError, match="outside the official allowlist"):
        _validate_official_url(f"{NVD_CVE_API_URL}?cveIds=CVE-2026-60137")


def test_nvd_enriches_canonical_cve_without_replacing_its_semantics(tmp_path) -> None:
    cve = "CVE-2026-60137"
    store = _store(tmp_path)
    cve_snapshot = _cve_snapshot(store, cve)
    nvd_snapshot = _nvd_snapshot(store)
    canonical = parse_cve_record(_cve_record(cve), cve_snapshot)
    nvd = parse_nvd_page(
        _nvd_page(_nvd_record(cve), total=1, start_index=0),
        nvd_snapshot,
        expected_start_index=0,
        max_items=1,
        max_record_bytes=1024 * 1024,
    ).records[0]

    store.upsert_source_record(
        canonical,
        snapshot_id=cve_snapshot.snapshot_id,
        seen_at=NOW,
    )
    store.upsert_source_record(
        nvd,
        snapshot_id=nvd_snapshot.snapshot_id,
        seen_at=NOW,
    )
    merged = store.get_advisory(cve)

    assert merged.title == "Canonical fixture title"
    assert merged.summary == "Canonical fixture description."
    assert {source.value for source in merged.sources} == {"cve-list-v5", "nvd"}
    assert merged.cwes == ["CWE-79", "CWE-89"]
    assert {signal.source for signal in merged.severity} == {
        IntelligenceSource.CVE_LIST_V5,
        IntelligenceSource.NVD,
    }
    assert merged.source_metadata["nvd"]["configurations"] == _nvd_record(cve)["configurations"]
    assert merged.affected and all(item.ecosystem != "NVD" for item in merged.affected)


def test_cve_list_v5_delta_deduplicates_and_proves_closed_window() -> None:
    document = _cve_delta(
        ("new", "CVE-2026-1234", "2026-07-29T10:00:00Z"),
        ("updated", "CVE-2026-1234", "2026-07-29T11:00:00Z"),
        ("new", "CVE-2026-9999", "2026-07-29T10:30:00Z"),
    )

    selection = parse_cve_delta_log(
        document,
        boundary=datetime(2026, 7, 28, 10, tzinfo=UTC),
        max_batches=10,
        max_entries=10,
        max_candidates=10,
    )

    assert [entry.cve_id for entry in selection.entries] == [
        "CVE-2026-1234",
        "CVE-2026-9999",
    ]
    assert selection.entries[0].change_type == "updated"
    assert selection.window_complete
    assert not selection.candidate_limit_reached
    assert selection.issues == ()

    broken = _cve_delta(("new", "CVE-2026-1234", "2026-07-29T10:00:00Z"))
    broken[0]["new"][0]["githubLink"] = "https://raw.githubusercontent.com/other/repo/main/a.json"
    malformed = parse_cve_delta_log(
        broken,
        boundary=datetime(2026, 7, 28, 10, tzinfo=UTC),
        max_batches=10,
        max_entries=10,
        max_candidates=10,
    )
    assert malformed.entries == ()
    assert malformed.issues[0].code == "invalid_delta_entry"


def test_cve_list_v5_parser_preserves_cna_adp_state_and_unknown_fields(tmp_path) -> None:
    store = _store(tmp_path)
    published_document = _cve_record("CVE-2026-1234")
    published_raw = json.dumps(published_document).encode()
    published_snapshot = _cve_snapshot(store, "CVE-2026-1234", published_raw)
    published = parse_cve_record(
        published_document,
        published_snapshot,
    )

    assert published.advisory.cve_record_state == CveRecordState.PUBLISHED
    assert published.advisory.title == "Canonical fixture title"
    assert published.advisory.affected[0].purl == "pkg:npm/fixture-package"
    assert published.advisory.affected[0].ecosystem == "npm"
    assert [
        event.model_dump(exclude_none=True) for event in published.advisory.affected[0].ranges[0].events
    ] == [
        {"introduced": "0"},
        {"fixed": "2.0.0"},
    ]
    assert published.advisory.cwes == ["CWE-79"]
    assert {signal.metadata["version"] for signal in published.advisory.severity} == {
        "3.1",
        "4.0",
    }
    metadata = published.advisory.source_metadata["cve-list-v5"]
    assert metadata["container_index"] == [
        {
            "json_pointer": "/containers/cna",
            "provider_metadata": published_document["containers"]["cna"]["providerMetadata"],
        },
        {
            "json_pointer": "/containers/adp/0",
            "provider_metadata": published_document["containers"]["adp"][0]["providerMetadata"],
        },
    ]
    assert "containers" not in metadata
    assert "futureContainerField" not in json.dumps(metadata)
    assert metadata["unknown_top_level_fields"] == ["futureTopLevelField"]
    assert store.read_snapshot(published_snapshot.snapshot_id) == published_raw

    current_shape = _cve_record("CVE-2026-4321")
    current_shape["cveMetadata"].pop("serial")
    current_shape["containers"]["cna"]["affected"][0]["versions"] = [
        {"status": "affected", "version": "6.5.3"},
    ]
    current = parse_cve_record(
        current_shape,
        _cve_snapshot(store, "CVE-2026-4321", json.dumps(current_shape).encode()),
    )
    assert "serial" not in current.advisory.source_metadata["cve-list-v5"]
    assert current.advisory.affected[0].versions == ["6.5.3"]
    assert current.advisory.affected[0].ranges == []

    invalid_serial = _cve_record("CVE-2026-4322")
    invalid_serial["cveMetadata"]["serial"] = True
    with pytest.raises(IntelligenceParseError, match="invalid serial"):
        parse_cve_record(
            invalid_serial,
            _cve_snapshot(store, "CVE-2026-4322", json.dumps(invalid_serial).encode()),
        )

    rejected_document = _cve_record("CVE-2026-5678", state="REJECTED")
    rejected = parse_cve_record(
        rejected_document,
        _cve_snapshot(store, "CVE-2026-5678", json.dumps(rejected_document).encode()),
    )
    assert rejected.advisory.cve_record_state == CveRecordState.REJECTED
    assert rejected.advisory.withdrawn_at is None
    assert rejected.advisory.summary == "Duplicate of another record."

    unsupported = _cve_record("CVE-2026-9012")
    unsupported["cveMetadata"]["state"] = "RESERVED"
    with pytest.raises(IntelligenceParseError, match="invalid state"):
        parse_cve_record(
            unsupported,
            _cve_snapshot(store, "CVE-2026-9012", json.dumps(unsupported).encode()),
        )


@pytest.mark.parametrize("expression", ["< 6.6.0", ">= 2.1.3, < 2.1.4"])
def test_cve_list_v5_untyped_constraints_are_not_exact_versions(tmp_path, expression) -> None:
    cve = "CVE-2026-4323"
    document = _cve_record(cve)
    document["containers"]["cna"]["affected"][0]["versions"] = [{"status": "affected", "version": expression}]
    store = _store(tmp_path)

    parsed = parse_cve_record(
        document,
        _cve_snapshot(store, cve, json.dumps(document).encode()),
    )
    package = parsed.advisory.affected[0]

    assert package.versions == []
    assert len(package.ranges) == 1
    untyped_constraint = package.ranges[0]
    assert untyped_constraint.type.value == "unknown"
    assert untyped_constraint.raw_type == "unknown"
    assert untyped_constraint.events == []
    assert untyped_constraint.database_specific == {
        "status": "affected",
        "default_status": "unaffected",
        "json_pointer": "/containers/cna/affected/0/versions/0",
        "version_expression": expression,
    }


def test_cve_list_v5_unaffected_native_range_does_not_invent_fixed_event(tmp_path) -> None:
    cve = "CVE-2026-9013"
    document = _cve_record(cve)
    document["containers"]["cna"]["affected"][0]["versions"] = [
        {
            "version": "1.0.0",
            "lessThan": "2.0.0",
            "versionType": "semver",
            "status": "unaffected",
        }
    ]
    raw = json.dumps(document, sort_keys=True).encode()
    store = _store(tmp_path)
    snapshot = _cve_snapshot(store, cve, raw)

    parsed = parse_cve_record(document, snapshot)
    native_range = parsed.advisory.affected[0].ranges[0]

    assert native_range.type.value == "semver"
    assert native_range.events == []
    assert native_range.database_specific == {
        "status": "unaffected",
        "default_status": "unaffected",
        "json_pointer": "/containers/cna/affected/0/versions/0",
    }
    assert store.read_snapshot(snapshot.snapshot_id) == raw


def test_cve_list_v5_pkg_github_maps_to_generic_github(tmp_path) -> None:
    cve = "CVE-2026-9014"
    document = _cve_record(cve)
    affected = document["containers"]["cna"]["affected"][0]
    affected.pop("product")
    affected["packageURL"] = "pkg:github/example/project@v1.2.3"
    store = _store(tmp_path)

    parsed = parse_cve_record(
        document,
        _cve_snapshot(store, cve, json.dumps(document).encode()),
    )
    package = parsed.advisory.affected[0]

    assert package.ecosystem == "GitHub"
    assert package.ecosystem != "GitHub Actions"
    assert package.name == "example/project"


def test_cve_list_v5_sync_is_idempotent_merges_aliases_and_stages_raw_records(tmp_path) -> None:
    cve = "CVE-2026-1234"
    record_url = cve_list_v5_record_url(cve)
    record = _cve_record(cve)
    delta = _cve_delta(("new", cve, "2026-07-29T11:00:00Z"))
    transport = FakeTransport(
        {
            CVE_LIST_V5_DELTA_URL: [
                _json_response(CVE_LIST_V5_DELTA_URL, delta),
                _json_response(CVE_LIST_V5_DELTA_URL, delta),
            ],
            record_url: [
                _json_response(record_url, record),
                _json_response(record_url, record),
            ],
        }
    )
    store = _store(tmp_path)
    service = IntelligenceService(store, transport=transport, clock=lambda: NOW)

    first = service.sync(
        sources=["cve-list-v5"],
        since_hours=24,
        ecosystems=["Go"],
        limit_per_source=10,
    )
    second = service.sync(sources=["cve-list-v5"], since_hours=24, limit_per_source=10)
    advisory = service.get(cve)

    assert first.results[0].status == SyncStatus.SUCCESS
    assert first.results[0].records_inserted == 1
    assert second.results[0].status == SyncStatus.SUCCESS
    assert second.results[0].records_unchanged == 1
    assert second.results[0].cursor_after == datetime(2026, 7, 29, 11, 40, tzinfo=UTC)
    assert advisory.cve_record_state == CveRecordState.PUBLISHED
    assert advisory.provenance[0].source == IntelligenceSource.CVE_LIST_V5
    assert (
        store.read_snapshot(advisory.provenance[0].snapshot_id) == json.dumps(record, sort_keys=True).encode()
    )
    state = store.get_source_state(IntelligenceSource.CVE_LIST_V5)
    manifest = json.loads(store.read_snapshot(state.last_snapshot_id))
    assert manifest["entries"][0]["snapshot_id"] == advisory.provenance[0].snapshot_id
    assert store.verify_snapshot(manifest["delta_log"]["snapshot_id"])


def test_cve_list_v5_rejected_records_are_hidden_by_default_but_queryable(tmp_path) -> None:
    cve = "CVE-2026-5678"
    record_url = cve_list_v5_record_url(cve)
    record = _cve_record(cve, state="REJECTED")
    service = IntelligenceService(
        _store(tmp_path),
        transport=FakeTransport(
            {
                CVE_LIST_V5_DELTA_URL: _json_response(
                    CVE_LIST_V5_DELTA_URL,
                    _cve_delta(("updated", cve, "2026-07-29T11:00:00Z")),
                ),
                record_url: _json_response(record_url, record),
            }
        ),
        clock=lambda: NOW,
    )

    report = service.sync(sources=["cve-list-v5"], limit_per_source=10)

    assert report.successful
    assert service.list(limit=10) == []
    assert [item.advisory.advisory_id for item in service.list(rejected=True, limit=10)] == [cve]
    assert service.get(cve).cve_record_state == CveRecordState.REJECTED


def test_cve_list_v5_failure_evidence_and_transport_allowlist_are_bounded(tmp_path) -> None:
    failure_body = b"upstream unavailable"
    store = _store(tmp_path)
    service = IntelligenceService(
        store,
        transport=FakeTransport(
            {CVE_LIST_V5_DELTA_URL: _response(CVE_LIST_V5_DELTA_URL, failure_body, status=503)}
        ),
        clock=lambda: NOW,
    )

    result = service.sync(sources=["cve-list-v5"]).results[0]

    assert result.status == SyncStatus.FAILED
    assert store.snapshot_count() == 1
    assert next(path for path in (tmp_path / "snapshots").rglob("*") if path.is_file()).read_bytes() == (
        failure_body
    )
    _validate_official_url(cve_list_v5_record_url("CVE-2026-1234"))
    with pytest.raises(IntelligenceTransportError, match="outside the official allowlist"):
        _validate_official_url("https://raw.githubusercontent.com/CVEProject/cvelistV5/main/README.md")


def test_cve_list_v5_partial_replay_preserves_upstream_cursor_and_validator(tmp_path) -> None:
    first_cve = "CVE-2026-1234"
    second_cve = "CVE-2026-5678"
    initial_delta = _cve_delta(("new", first_cve, "2026-07-29T11:00:00Z"))
    partial_delta = _cve_delta(
        ("updated", first_cve, "2026-07-29T11:50:00Z"),
        ("new", second_cve, "2026-07-29T11:45:00Z"),
    )
    partial_delta[0]["fetchTime"] = "2026-07-29T12:00:00Z"
    first_record = _cve_record(first_cve)
    updated_record = _cve_record(first_cve)
    updated_record["cveMetadata"]["dateUpdated"] = "2026-07-29T11:50:00Z"
    transport = FakeTransport(
        {
            CVE_LIST_V5_DELTA_URL: [
                _json_response(
                    CVE_LIST_V5_DELTA_URL,
                    initial_delta,
                    headers={"Content-Type": "application/json", "ETag": '"delta-1"'},
                ),
                _json_response(
                    CVE_LIST_V5_DELTA_URL,
                    partial_delta,
                    headers={"Content-Type": "application/json", "ETag": '"delta-2"'},
                ),
            ],
            cve_list_v5_record_url(first_cve): [
                _json_response(cve_list_v5_record_url(first_cve), first_record),
                _json_response(cve_list_v5_record_url(first_cve), updated_record),
            ],
        }
    )
    store = _store(tmp_path)
    service = IntelligenceService(store, transport=transport, clock=lambda: NOW)

    first = service.sync(sources=["cve-list-v5"], limit_per_source=10).results[0]
    partial = service.sync(sources=["cve-list-v5"], limit_per_source=1).results[0]
    state = store.get_source_state(IntelligenceSource.CVE_LIST_V5)

    assert first.cursor_after == datetime(2026, 7, 29, 11, 40, tzinfo=UTC)
    assert partial.status == SyncStatus.PARTIAL
    assert partial.truncated
    assert partial.cursor_before == first.cursor_after
    assert partial.cursor_after == first.cursor_after
    assert state.cursor_at == first.cursor_after
    assert state.etag == '"delta-1"'
    assert state.metadata["newest_fetch_at"] == "2026-07-29T12:00:00+00:00"


def test_cve_list_v5_checkpoint_catches_up_after_a_schedule_gap(tmp_path) -> None:
    baseline_cve = "CVE-2026-7000"
    store = _store(tmp_path)
    first_service = IntelligenceService(
        store,
        transport=FakeTransport(
            {
                CVE_LIST_V5_DELTA_URL: _json_response(
                    CVE_LIST_V5_DELTA_URL,
                    _cve_delta(("new", baseline_cve, "2026-07-29T11:00:00Z")),
                ),
                cve_list_v5_record_url(baseline_cve): _json_response(
                    cve_list_v5_record_url(baseline_cve), _cve_record(baseline_cve)
                ),
            }
        ),
        clock=lambda: NOW,
    )
    first_service.sync(sources=["cve-list-v5"], since_hours=6, limit_per_source=10)

    missed_cve = "CVE-2026-7001"
    recent_cve = "CVE-2026-7002"
    missed_record = _cve_record(missed_cve)
    missed_record["cveMetadata"]["dateUpdated"] = "2026-07-29T13:50:00Z"
    recent_record = _cve_record(recent_cve)
    recent_record["cveMetadata"]["dateUpdated"] = "2026-07-30T10:50:00Z"
    catchup_delta = [
        _cve_delta_batch("2026-07-30T11:00:00Z", ("new", recent_cve, "2026-07-30T10:50:00Z")),
        _cve_delta_batch("2026-07-29T14:00:00Z", ("new", missed_cve, "2026-07-29T13:50:00Z")),
        _cve_delta_batch("2026-07-28T09:00:00Z"),
    ]
    catchup_service = IntelligenceService(
        store,
        transport=FakeTransport(
            {
                CVE_LIST_V5_DELTA_URL: _json_response(CVE_LIST_V5_DELTA_URL, catchup_delta),
                cve_list_v5_record_url(missed_cve): _json_response(
                    cve_list_v5_record_url(missed_cve), missed_record
                ),
                cve_list_v5_record_url(recent_cve): _json_response(
                    cve_list_v5_record_url(recent_cve), recent_record
                ),
            }
        ),
        clock=lambda: datetime(2026, 7, 30, 12, 0, tzinfo=UTC),
    )

    result = catchup_service.sync(sources=["cve-list-v5"], since_hours=6, limit_per_source=10).results[0]

    assert result.status == SyncStatus.SUCCESS
    assert result.records_selected == 2
    assert catchup_service.get(missed_cve).advisory_id == missed_cve
    assert result.cursor_after == datetime(2026, 7, 30, 11, 0, tzinfo=UTC)


def test_cve_list_v5_future_data_version_preserves_raw_record_and_checkpoint(tmp_path) -> None:
    cve = "CVE-2026-7001"
    record_url = cve_list_v5_record_url(cve)
    baseline_record = _cve_record(cve)
    future_record = _cve_record(cve)
    future_record["dataVersion"] = "5.3"
    future_record["cveMetadata"]["dateUpdated"] = "2026-07-29T11:50:00Z"
    future_raw = json.dumps(future_record, indent=2, ensure_ascii=False).encode() + b"\n"
    future_delta = _cve_delta(("updated", cve, "2026-07-29T11:50:00Z"))
    future_delta[0]["fetchTime"] = "2026-07-29T12:00:00Z"
    baseline_last_modified = "Tue, 29 Jul 2026 11:40:00 GMT"
    transport = FakeTransport(
        {
            CVE_LIST_V5_DELTA_URL: [
                _json_response(
                    CVE_LIST_V5_DELTA_URL,
                    _cve_delta(("new", cve, "2026-07-29T11:00:00Z")),
                    headers={
                        "Content-Type": "application/json",
                        "ETag": '"delta-1"',
                        "Last-Modified": baseline_last_modified,
                    },
                ),
                _json_response(
                    CVE_LIST_V5_DELTA_URL,
                    future_delta,
                    headers={
                        "Content-Type": "application/json",
                        "ETag": '"delta-2"',
                        "Last-Modified": "Tue, 29 Jul 2026 12:00:00 GMT",
                    },
                ),
            ],
            record_url: [
                _json_response(record_url, baseline_record),
                _response(record_url, future_raw),
            ],
        }
    )
    store = _store(tmp_path)
    baseline_service = IntelligenceService(store, transport=transport, clock=lambda: NOW)

    baseline = baseline_service.sync(sources=["cve-list-v5"], limit_per_source=10).results[0]
    baseline_state = store.get_source_state(IntelligenceSource.CVE_LIST_V5)
    later_service = IntelligenceService(
        store,
        transport=transport,
        clock=lambda: datetime(2026, 7, 29, 13, 0, tzinfo=UTC),
    )
    partial = later_service.sync(sources=["cve-list-v5"], limit_per_source=10).results[0]
    state = store.get_source_state(IntelligenceSource.CVE_LIST_V5)
    manifest = json.loads(store.read_snapshot(partial.metadata["selection_manifest_id"]))
    record_snapshot_id = manifest["entries"][0]["snapshot_id"]

    assert baseline.status == SyncStatus.SUCCESS
    assert baseline_state.cursor_at == datetime(2026, 7, 29, 11, 40, tzinfo=UTC)
    assert partial.status == SyncStatus.PARTIAL
    assert partial.cursor_before == baseline_state.cursor_at
    assert partial.cursor_after == baseline_state.cursor_at
    assert [(issue.code, issue.record_id) for issue in partial.issues] == [("invalid_source_data", cve)]
    assert partial.records_selected == 0
    assert manifest["entries"][0]["selected"] is False
    assert store.read_snapshot(record_snapshot_id) == future_raw
    assert state.cursor_at == baseline_state.cursor_at
    assert state.etag == baseline_state.etag == '"delta-1"'
    assert state.last_modified == baseline_state.last_modified == baseline_last_modified
    assert state.last_success_at == baseline_state.last_success_at
    assert state.last_attempt_at > baseline_state.last_attempt_at
    assert later_service.get(cve).source_metadata["cve-list-v5"]["data_version"] == "5.2"


def test_cve_list_v5_oversized_record_is_bounded_partial_without_checkpoint_advance(
    tmp_path,
) -> None:
    baseline_cve = "CVE-2026-7001"
    oversized_cve = "CVE-2026-7002"
    baseline_record_url = cve_list_v5_record_url(baseline_cve)
    oversized_record_url = cve_list_v5_record_url(oversized_cve)
    baseline_last_modified = "Tue, 29 Jul 2026 11:40:00 GMT"
    store = _store(tmp_path)
    baseline_service = IntelligenceService(
        store,
        transport=FakeTransport(
            {
                CVE_LIST_V5_DELTA_URL: _json_response(
                    CVE_LIST_V5_DELTA_URL,
                    _cve_delta(("new", baseline_cve, "2026-07-29T11:00:00Z")),
                    headers={
                        "Content-Type": "application/json",
                        "ETag": '"delta-1"',
                        "Last-Modified": baseline_last_modified,
                    },
                ),
                baseline_record_url: _json_response(
                    baseline_record_url,
                    _cve_record(baseline_cve),
                ),
            }
        ),
        clock=lambda: NOW,
    )
    baseline = baseline_service.sync(sources=["cve-list-v5"], limit_per_source=10).results[0]
    baseline_state = store.get_source_state(IntelligenceSource.CVE_LIST_V5)

    oversized_record = _cve_record(oversized_cve)
    oversized_record["cveMetadata"]["dateUpdated"] = "2026-07-29T11:50:00Z"
    oversized_record["futureTopLevelField"]["padding"] = "x" * 8_192
    oversized_raw = json.dumps(oversized_record).encode()
    record_limit = 1_024
    oversized_delta = _cve_delta(("new", oversized_cve, "2026-07-29T11:50:00Z"))
    oversized_delta[0]["fetchTime"] = "2026-07-29T12:00:00Z"
    transport = _OversizedCveRecordTransport(
        _json_response(
            CVE_LIST_V5_DELTA_URL,
            oversized_delta,
            headers={
                "Content-Type": "application/json",
                "ETag": '"delta-2"',
                "Last-Modified": "Tue, 29 Jul 2026 12:00:00 GMT",
            },
        ),
        record_url=oversized_record_url,
        record_body=oversized_raw,
    )
    later_service = IntelligenceService(
        store,
        transport=transport,
        clock=lambda: datetime(2026, 7, 29, 13, 0, tzinfo=UTC),
        limits=IntelligenceLimits(max_cve_record_bytes=record_limit),
    )

    partial = later_service.sync(sources=["cve-list-v5"], limit_per_source=10).results[0]
    state = store.get_source_state(IntelligenceSource.CVE_LIST_V5)
    manifest = json.loads(store.read_snapshot(partial.metadata["selection_manifest_id"]))

    assert baseline.status == SyncStatus.SUCCESS
    assert len(oversized_raw) > record_limit
    assert partial.status == SyncStatus.PARTIAL
    assert partial.cursor_before == baseline_state.cursor_at
    assert partial.cursor_after == baseline_state.cursor_at
    assert [(issue.code, issue.record_id, issue.retriable) for issue in partial.issues] == [
        ("record_response_limit", oversized_cve, True)
    ]
    assert partial.records_selected == 0
    assert manifest["entries"] == [
        {
            "batch_fetch_at": "2026-07-29T12:00:00+00:00",
            "change_type": "new",
            "cve_org_url": f"https://www.cve.org/CVERecord?id={oversized_cve}",
            "fetch_error": "record_response_limit",
            "id": oversized_cve,
            "modified": "2026-07-29T11:50:00+00:00",
            "record_url": oversized_record_url,
            "selected": False,
        }
    ]
    assert state.cursor_at == baseline_state.cursor_at
    assert state.etag == baseline_state.etag == '"delta-1"'
    assert state.last_modified == baseline_state.last_modified == baseline_last_modified
    assert state.last_success_at == baseline_state.last_success_at
    assert state.last_attempt_at > baseline_state.last_attempt_at
    assert transport.record_read_sizes == [record_limit + 1]
    assert transport.record_bytes_consumed == record_limit + 1
    assert transport.record_bytes_consumed < len(oversized_raw)
    assert [request[0] for request in transport.requests] == [
        CVE_LIST_V5_DELTA_URL,
        oversized_record_url,
    ]
    with pytest.raises(AdvisoryNotFoundError):
        later_service.get(oversized_cve)


def test_rejected_cve_alias_does_not_hide_an_active_osv_advisory(tmp_path) -> None:
    cve = "CVE-2026-5678"
    store = _store(tmp_path)
    osv_payload = b'{"id":"GHSA-active"}'
    osv_snapshot = store.save_snapshot(
        osv_payload,
        source=IntelligenceSource.OSV,
        kind=SnapshotKind.SOURCE_RECORD,
        source_url=OSV_API_BASE_URL + "GHSA-active",
        source_record_id="GHSA-active",
        retrieved_at=NOW,
        media_type="application/json",
        attribution=OSV_ATTRIBUTION,
    )
    store.upsert_source_record(
        ParsedSourceRecord(
            source=IntelligenceSource.OSV,
            source_record_id="GHSA-active",
            advisory=NormalizedAdvisory(
                advisory_id=cve,
                identifiers=[cve, "GHSA-active"],
                sources=[IntelligenceSource.OSV],
                title="Active ecosystem advisory",
                modified_at=NOW,
                provenance=[osv_snapshot],
            ),
            raw_record_sha256="a" * 64,
        ),
        snapshot_id=osv_snapshot.snapshot_id,
        seen_at=NOW,
    )
    record = _cve_record(cve, state="REJECTED")
    service = IntelligenceService(
        store,
        transport=FakeTransport(
            {
                CVE_LIST_V5_DELTA_URL: _json_response(
                    CVE_LIST_V5_DELTA_URL,
                    _cve_delta(("updated", cve, "2026-07-29T11:00:00Z")),
                ),
                cve_list_v5_record_url(cve): _json_response(cve_list_v5_record_url(cve), record),
            }
        ),
        clock=lambda: NOW,
    )

    service.sync(sources=["cve-list-v5"], limit_per_source=10)
    merged = service.get("GHSA-active")

    assert merged.cve_record_state == CveRecordState.REJECTED
    assert merged.title == "Active ecosystem advisory"
    assert {source.value for source in merged.sources} == {"cve-list-v5", "osv"}
    assert [item.advisory.advisory_id for item in service.list(limit=10)] == [cve]
    assert service.status().rejected_cve_count == 1


def test_intelligence_store_migrates_pre_cve_rejected_index(tmp_path) -> None:
    database = tmp_path / "legacy.db"
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            CREATE TABLE intelligence_advisories (
                advisory_id TEXT PRIMARY KEY,
                known_exploited INTEGER NOT NULL,
                withdrawn INTEGER NOT NULL,
                published_at TEXT,
                modified_at TEXT,
                record_json TEXT NOT NULL,
                record_digest TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )

    store = IntelligenceStore(database, tmp_path / "snapshots")
    store.initialize()

    with sqlite3.connect(database) as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(intelligence_advisories)")}
    assert "cve_rejected" in columns


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
    epss_url = f"{EPSS_API_URL}?cve=CVE-2026-1234&scope=time-series"
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
                "time-series": [
                    {
                        "epss": "0.100",
                        "percentile": "0.70",
                        "date": "2026-07-28",
                    }
                ],
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
    history = service.epss_history("CVE-2026-1234", as_of=date(2026, 7, 28))
    assert history.total_observations == 2
    assert history.latest.score_date == date(2026, 7, 29)
    assert history.selected_at_or_before.signal.probability == 0.1
    assert [request[0] for request in transport.requests].count(epss_url) == 1


def test_epss_candidate_ceiling_is_explicit_and_does_not_fail_primary_checkpoint(tmp_path) -> None:
    cves = ["CVE-2026-1001", "CVE-2026-1002", "CVE-2026-1003"]
    epss_url = f"{EPSS_API_URL}?cve=CVE-2026-1001%2CCVE-2026-1002&scope=time-series"
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
    assert enrichment.metadata["selection"] == "history-aware-priority-v1"
    assert enrichment.metadata["candidate_count"] == 3
    assert enrichment.metadata["requested"] == 2
    assert enrichment.metadata["omitted"] == 1
    assert enrichment.metadata["selected_by_reason"] == {"current-run-kev": 2}
    assert enrichment.metadata["omitted_by_reason"] == {"current-run-kev": 1}
    assert enrichment.metadata["request_count"] == 1
    assert enrichment.issues[0].code == "epss_candidate_limit"
    assert report.status == SyncStatus.PARTIAL
    assert report.successful


def test_epss_selection_prioritizes_current_run_over_older_lexical_history(tmp_path) -> None:
    store = _store(tmp_path)
    old_cve = "CVE-2020-0001"
    current_cve = "CVE-2026-9999"
    old_snapshot = store.save_snapshot(
        b'{"id":"CVE-2020-0001"}',
        source=IntelligenceSource.OSV,
        kind=SnapshotKind.SOURCE_RECORD,
        source_url=OSV_API_BASE_URL + old_cve,
        source_record_id=old_cve,
        retrieved_at=NOW - timedelta(days=5),
        media_type="application/json",
        attribution=OSV_ATTRIBUTION,
    )
    store.upsert_source_record(
        ParsedSourceRecord(
            source=IntelligenceSource.OSV,
            source_record_id=old_cve,
            advisory=NormalizedAdvisory(
                advisory_id=old_cve,
                identifiers=[old_cve],
                sources=[IntelligenceSource.OSV],
                provenance=[old_snapshot],
            ),
            raw_record_sha256="a" * 64,
        ),
        snapshot_id=old_snapshot.snapshot_id,
        seen_at=NOW - timedelta(days=5),
    )
    old_epss_snapshot = store.save_snapshot(
        b'{"data":[]}',
        source=IntelligenceSource.EPSS,
        kind=SnapshotKind.ENRICHMENT,
        source_url=EPSS_API_URL,
        retrieved_at=NOW - timedelta(days=5),
        media_type="application/json",
        attribution=EPSS_ATTRIBUTION,
    )
    old_observed_at = NOW - timedelta(days=5)
    store.upsert_epss_observations(
        old_cve,
        [
            SeveritySignal(
                kind=SeverityKind.EPSS,
                source=IntelligenceSource.EPSS,
                probability=0.25,
                observed_at=old_observed_at,
                source_url=EPSS_API_URL,
                metadata={"score_date": old_observed_at.date().isoformat()},
            )
        ],
        snapshot_id=old_epss_snapshot.snapshot_id,
    )
    epss_url = f"{EPSS_API_URL}?cve={current_cve}&scope=time-series"
    transport = FakeTransport(
        {
            CISA_KEV_URL: _json_response(CISA_KEV_URL, _cisa_feed(_cisa_item(current_cve))),
            epss_url: _json_response(
                epss_url,
                {
                    "status": "OK",
                    "data": [
                        {
                            "cve": current_cve,
                            "epss": "0.5",
                            "percentile": "0.9",
                            "date": "2026-07-29",
                        }
                    ],
                },
            ),
        }
    )
    service = IntelligenceService(store, transport=transport, clock=lambda: NOW)

    enrichment = service.sync(sources=["cisa-kev"], limit_per_source=1, enrich_epss=True).results[1]

    assert transport.requests[-1][0] == epss_url
    assert enrichment.metadata["selected_by_reason"] == {"current-run-kev": 1}
    assert enrichment.metadata["omitted_by_reason"] == {"stale-observation-refresh": 1}


def test_interrupted_sync_is_not_left_running(tmp_path) -> None:
    class InterruptingTransport:
        def get(self, *_args, **_kwargs):
            raise KeyboardInterrupt

    store = _store(tmp_path)
    service = IntelligenceService(store, transport=InterruptingTransport(), clock=lambda: NOW)

    with pytest.raises(KeyboardInterrupt):
        service.sync(sources=["cisa-kev"])

    with sqlite3.connect(store.database) as connection:
        row = connection.execute("SELECT status, finished_at FROM intelligence_sync_runs").fetchone()
    assert row == ("interrupted", NOW.isoformat())
    status = service.status()
    assert status.running_sync_count == 0
    assert status.interrupted_sync_count == 1


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
    assert kev_rank.algorithm_version == "kev-epss-recency-severity-evidence-v2"
    assert any("confirmed CISA KEV" in reason for reason in kev_rank.reasons)


def test_ranking_uses_latest_dated_epss_observation_instead_of_historical_maximum() -> None:
    older = NOW - timedelta(days=2)
    latest = NOW - timedelta(days=1)
    advisory = NormalizedAdvisory(
        advisory_id="CVE-2026-8888",
        identifiers=["CVE-2026-8888"],
        sources=[IntelligenceSource.EPSS],
        severity=[
            SeveritySignal(
                kind=SeverityKind.EPSS,
                source=IntelligenceSource.EPSS,
                probability=0.99,
                observed_at=older,
            ),
            SeveritySignal(
                kind=SeverityKind.EPSS,
                source=IntelligenceSource.EPSS,
                probability=0.10,
                observed_at=latest,
            ),
        ],
    )

    factors = rank_advisory(advisory, as_of=NOW)

    assert factors.epss_probability == 0.10
    assert factors.epss_provider == "FIRST EPSS"
    assert factors.epss_observed_at == latest
    assert latest.date().isoformat() in factors.reasons[1]


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
    assert "kev-epss-recency-severity-evidence-v2" in first
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
