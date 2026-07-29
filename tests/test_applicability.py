from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from fastmcp import Client
from jsonschema import validate
from pydantic import ValidationError

from white_hat_agent.cli import main
from white_hat_agent.intelligence import (
    AdvisoryApplicabilityRequest,
    AffectedPackage,
    AffectedRange,
    ApplicabilityStatus,
    ApplicabilitySubject,
    CveRecordState,
    IntelligenceSource,
    NormalizedAdvisory,
    RangeType,
    VersionEvent,
    assess_advisory_applicability,
)
from white_hat_agent.mcp_server import create_server
from white_hat_agent.schemas import export_schemas
from white_hat_agent.workspace import Workspace

NOW = datetime(2026, 7, 29, 18, tzinfo=UTC)


def _advisory(
    affected: list[AffectedPackage],
    *,
    state: CveRecordState | None = None,
    withdrawn: bool = False,
) -> NormalizedAdvisory:
    return NormalizedAdvisory(
        advisory_id="OSV-TEST-1",
        identifiers=["OSV-TEST-1"],
        sources=[IntelligenceSource.CVE_LIST_V5 if state else IntelligenceSource.OSV],
        cve_record_state=state,
        title="Synthetic applicability fixture",
        modified_at=NOW,
        withdrawn_at=NOW if withdrawn else None,
        affected=affected,
    )


def _subject(**changes) -> ApplicabilitySubject:
    values = {
        "subject_id": "artifact-widget",
        "purl": "pkg:pypi/widget",
        "version": "1.5.0",
        "artifact_sha256": "a" * 64,
        "observed_at": NOW,
    }
    values.update(changes)
    return ApplicabilitySubject(**values)


def _request(
    advisory: NormalizedAdvisory,
    subject: ApplicabilitySubject | None = None,
    *,
    evaluated_at: datetime = NOW,
) -> AdvisoryApplicabilityRequest:
    return AdvisoryApplicabilityRequest(
        advisory=advisory,
        subject=subject or _subject(),
        evaluated_at=evaluated_at,
    )


def _semver_package(*events: VersionEvent) -> AffectedPackage:
    return AffectedPackage(
        ecosystem="PyPI",
        name="widget",
        purl="pkg:pypi/widget",
        ranges=[AffectedRange(type=RangeType.SEMVER, events=list(events))],
    )


def test_exact_version_and_semver_results_are_deterministic() -> None:
    exact = _advisory(
        [
            AffectedPackage(
                ecosystem="PyPI",
                name="widget",
                purl="pkg:pypi/widget",
                versions=["1.5.0"],
            )
        ]
    )
    exact_request = _request(exact)
    first = assess_advisory_applicability(exact_request)

    assert first == assess_advisory_applicability(exact_request)
    assert first.status == ApplicabilityStatus.APPLICABLE
    assert first.traces[0].basis == "exact-version"
    assert first.blockers == []
    purl_version = _subject(purl="pkg:pypi/widget@1.5.0", version=None)
    assert assess_advisory_applicability(_request(exact, purl_version)).status == first.status

    ranged = _advisory([_semver_package(VersionEvent(introduced="1.0.0"), VersionEvent(fixed="2.0.0"))])
    assert assess_advisory_applicability(_request(ranged)).status == ApplicabilityStatus.APPLICABLE
    assert (
        assess_advisory_applicability(_request(ranged, _subject(version="2.0.0"))).status
        == ApplicabilityStatus.NOT_APPLICABLE
    )
    assert (
        assess_advisory_applicability(_request(ranged, _subject(version="2.0.0-rc.1"))).status
        == ApplicabilityStatus.APPLICABLE
    )
    assert (
        assess_advisory_applicability(_request(ranged, _subject(version="2.0.0-01"))).status
        == ApplicabilityStatus.INDETERMINATE
    )
    multiple_windows = _advisory(
        [
            _semver_package(
                VersionEvent(introduced="1.0.0"),
                VersionEvent(fixed="2.0.0"),
                VersionEvent(introduced="3.0.0"),
                VersionEvent(fixed="4.0.0"),
            )
        ]
    )
    assert (
        assess_advisory_applicability(_request(multiple_windows, _subject(version="2.5.0"))).status
        == ApplicabilityStatus.NOT_APPLICABLE
    )
    assert (
        assess_advisory_applicability(_request(multiple_windows, _subject(version="3.5.0"))).status
        == ApplicabilityStatus.APPLICABLE
    )
    assert (
        assess_advisory_applicability(_request(multiple_windows, _subject(version="4.0.0"))).status
        == ApplicabilityStatus.NOT_APPLICABLE
    )
    last_affected = _advisory(
        [_semver_package(VersionEvent(introduced="3.0.0"), VersionEvent(last_affected="3.5.0"))]
    )
    assert (
        assess_advisory_applicability(_request(last_affected, _subject(version="3.5.0"))).status
        == ApplicabilityStatus.APPLICABLE
    )
    assert (
        assess_advisory_applicability(_request(last_affected, _subject(version="3.5.1"))).status
        == ApplicabilityStatus.NOT_APPLICABLE
    )
    unsorted_source = _advisory(
        [_semver_package(VersionEvent(fixed="2.0.0"), VersionEvent(introduced="1.0.0"))]
    )
    assert assess_advisory_applicability(_request(unsorted_source)).status == ApplicabilityStatus.APPLICABLE


def test_unknown_facts_never_become_false_not_applicable() -> None:
    exact_miss = _advisory(
        [AffectedPackage(ecosystem="PyPI", name="widget", purl="pkg:pypi/widget", versions=["1.0.0"])]
    )
    cross_package = _advisory(
        [AffectedPackage(ecosystem="PyPI", name="different", purl="pkg:pypi/different", versions=["1.5.0"])]
    )
    ecosystem_range = _advisory(
        [
            AffectedPackage(
                ecosystem="PyPI",
                name="widget",
                purl="pkg:pypi/widget",
                ranges=[
                    AffectedRange(
                        type=RangeType.ECOSYSTEM,
                        events=[VersionEvent(introduced="0"), VersionEvent(fixed="2.0")],
                    )
                ],
            )
        ]
    )
    limited = _advisory(
        [
            _semver_package(
                VersionEvent(introduced="1.0.0"),
                VersionEvent(limit="2.0.0"),
            )
        ]
    )
    malformed = _advisory(
        [
            _semver_package(
                VersionEvent(introduced="1.0.0"),
                VersionEvent(introduced="1.1.0"),
            )
        ]
    )
    qualified_variant = _advisory(
        [
            AffectedPackage(
                ecosystem="PyPI",
                name="widget",
                purl="pkg:pypi/widget?arch=x86_64",
                versions=["1.5.0"],
            )
        ]
    )
    rejected = _advisory([], state=CveRecordState.REJECTED)
    withdrawn = _advisory([], withdrawn=True)

    for advisory in (
        exact_miss,
        cross_package,
        ecosystem_range,
        limited,
        malformed,
        qualified_variant,
        rejected,
        withdrawn,
    ):
        decision = assess_advisory_applicability(_request(advisory))
        assert decision.status == ApplicabilityStatus.INDETERMINATE
        assert decision.blockers

    one_sided_purl = _advisory([AffectedPackage(ecosystem="PyPI", name="widget", versions=["1.5.0"])])
    contradictory = _subject(purl="pkg:npm/other")
    assert (
        assess_advisory_applicability(_request(one_sided_purl, contradictory)).status
        == ApplicabilityStatus.INDETERMINATE
    )


def test_git_ranges_require_complete_bounded_ancestry() -> None:
    introduced, fixed, current = "1" * 40, "2" * 40, "3" * 40
    advisory = _advisory(
        [
            AffectedPackage(
                ecosystem="GitHub",
                name="acme/widget",
                purl="pkg:github/acme/widget",
                ranges=[
                    AffectedRange(
                        type=RangeType.GIT,
                        repository="https://github.com/acme/widget.git",
                        events=[VersionEvent(introduced=introduced), VersionEvent(fixed=fixed)],
                    )
                ],
            )
        ]
    )
    common = {
        "purl": "pkg:github/acme/widget",
        "version": None,
        "repository": "https://github.com/acme/widget",
        "commit_sha": current,
    }
    affected = _subject(**common, git_ancestor_commits=[introduced, current], git_ancestry_complete=True)
    fixed_subject = _subject(
        **common,
        git_ancestor_commits=[introduced, fixed, current],
        git_ancestry_complete=True,
    )
    incomplete = _subject(**common, git_ancestor_commits=[introduced, current])

    assert (
        assess_advisory_applicability(_request(advisory, affected)).status == ApplicabilityStatus.APPLICABLE
    )
    assert (
        assess_advisory_applicability(_request(advisory, fixed_subject)).status
        == ApplicabilityStatus.NOT_APPLICABLE
    )
    assert (
        assess_advisory_applicability(_request(advisory, incomplete)).status
        == ApplicabilityStatus.INDETERMINATE
    )


def test_decision_identity_is_content_based_and_subject_identity_is_unambiguous() -> None:
    advisory = _advisory([_semver_package(VersionEvent(introduced="0"))])
    request = _request(advisory)
    decision = assess_advisory_applicability(request)
    later = assess_advisory_applicability(_request(advisory, evaluated_at=NOW + timedelta(hours=1)))
    changed_subject = assess_advisory_applicability(_request(advisory, _subject(version="1.6.0")))
    changed_advisory = assess_advisory_applicability(
        _request(advisory.model_copy(update={"summary": "changed advisory content"}))
    )

    assert decision.decision_id == later.decision_id
    assert decision.decision_id != changed_subject.decision_id
    assert decision.decision_id != changed_advisory.decision_id
    assert "scope evaluator" in decision.reasons[-1]

    pair_advisory = _advisory([AffectedPackage(ecosystem="PyPI", name="widget", versions=["1.5.0"])])
    pair = _subject(purl=None, ecosystem="PyPI", package_name="widget")
    assert (
        assess_advisory_applicability(_request(pair_advisory, pair)).status == ApplicabilityStatus.APPLICABLE
    )
    with pytest.raises(ValidationError, match="either purl identity"):
        _subject(package_name="widget")
    with pytest.raises(ValidationError, match="ecosystem/package pair"):
        _subject(purl=None, ecosystem="PyPI")
    with pytest.raises(ValidationError, match="commit identity requires"):
        _subject(commit_sha="1" * 40, repository=None)
    with pytest.raises(ValidationError, match="complete Git ancestry"):
        _subject(
            version=None,
            repository="https://github.com/acme/widget",
            commit_sha="1" * 40,
            git_ancestry_complete=True,
        )


def test_applicability_cli_is_workspace_free_and_schemas_validate(tmp_path, monkeypatch) -> None:
    request = _request(_advisory([_semver_package(VersionEvent(introduced="0"))]))
    request_path = tmp_path / "request.json"
    output_path = tmp_path / "decision.json"
    request_path.write_text(request.model_dump_json(indent=2), encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    result = main(
        [
            "intelligence",
            "applicability",
            "--request",
            str(request_path),
            "--out",
            str(output_path),
        ]
    )
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    schemas = export_schemas(tmp_path / "schemas")
    schema_by_name = {path.name: path for path in schemas}
    request_schema = json.loads(schema_by_name["advisory-applicability-request.schema.json"].read_text())
    decision_schema = json.loads(schema_by_name["advisory-applicability-decision.schema.json"].read_text())

    assert result == 0
    assert payload["status"] == "applicable"
    assert not (tmp_path / "whitehat.toml").exists()
    assert "applicability-subject.schema.json" not in schema_by_name
    validate(request.model_dump(mode="json"), request_schema)
    validate(payload, decision_schema)


@pytest.mark.asyncio
async def test_applicability_mcp_is_read_only_and_does_not_enqueue(tmp_path) -> None:
    workspace = Workspace.initialize(tmp_path)
    request = _request(_advisory([_semver_package(VersionEvent(introduced="0"))]))

    async with Client(create_server(tmp_path)) as client:
        tools = {tool.name: tool for tool in await client.list_tools()}
        result = await client.call_tool(
            "intelligence_applicability",
            {"request": request.model_dump(mode="json")},
        )

    assert tools["intelligence_applicability"].annotations.readOnlyHint is True
    assert result.structured_content["status"] == "applicable"
    assert workspace.fleet.list_opportunities() == []
    stats = workspace.fleet.stats()
    assert stats.campaigns == stats.queued == stats.leased == 0
