from __future__ import annotations

import json

from jsonschema import validate

from white_hat_agent.cli import main
from white_hat_agent.fixtures import (
    build_active_data_episode,
    build_active_data_transcript,
    build_stalled_recovery_fixture,
)
from white_hat_agent.intelligence import (
    IntelligenceSource,
    IntelligenceSyncReport,
    NormalizedAdvisory,
    RankedAdvisory,
    SourceSyncResult,
    SyncIssue,
    SyncStatus,
    rank_advisory,
)
from white_hat_agent.models import utc_now
from white_hat_agent.schemas import export_schemas
from white_hat_agent.workspace import Workspace


def _write_json(path, model) -> None:
    path.write_text(json.dumps(model.model_dump(mode="json")), encoding="utf-8")


def test_plan_cli_writes_machine_readable_result(tmp_path) -> None:
    episode_path = tmp_path / "episode.json"
    output_path = tmp_path / "plan.json"
    _write_json(episode_path, build_active_data_episode())

    result = main(
        [
            "discovery",
            "plan",
            "--episode",
            str(episode_path),
            "--limit",
            "2",
            "--out",
            str(output_path),
        ]
    )
    payload = json.loads(output_path.read_text(encoding="utf-8"))

    assert result == 0
    assert payload["mode"] == "explore"
    assert len(payload["selected"]) == 2
    assert payload["selected"][0]["hypothesis_id"] == "h-external-reference"


def test_simulation_cli_runs_complete_episode(tmp_path) -> None:
    episode = build_active_data_episode()
    episode_path = tmp_path / "episode.json"
    replay_path = tmp_path / "replay.json"
    output_path = tmp_path / "simulation.json"
    _write_json(episode_path, episode)
    _write_json(replay_path, build_active_data_transcript(episode))

    result = main(
        [
            "discovery",
            "simulate",
            "--episode",
            str(episode_path),
            "--replay",
            str(replay_path),
            "--out",
            str(output_path),
        ]
    )
    payload = json.loads(output_path.read_text(encoding="utf-8"))

    assert result == 0
    assert payload["halt_reason"] == "complete"
    assert payload["cycles"] == 5


def test_exported_episode_schema_validates_fixture(tmp_path) -> None:
    paths = export_schemas(tmp_path)
    schema_path = next(path for path in paths if path.name == "discovery-episode.schema.json")
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    instance = build_active_data_episode().model_dump(mode="json")

    validate(instance=instance, schema=schema)
    names = {path.name for path in paths}
    assert len(paths) >= 20
    assert "playbook.schema.json" in names
    assert "scope-manifest.schema.json" in names
    assert "campaign-manifest.schema.json" in names
    assert "normalized-advisory.schema.json" in names
    assert "intelligence-sync-report.schema.json" in names


def test_intelligence_cli_status_and_empty_brief_are_local(tmp_path) -> None:
    Workspace.initialize(tmp_path)
    status_path = tmp_path / "status.json"
    brief_path = tmp_path / "brief.md"

    status_result = main(
        [
            "intelligence",
            "status",
            "--workspace",
            str(tmp_path),
            "--out",
            str(status_path),
        ]
    )
    brief_result = main(
        [
            "intelligence",
            "brief",
            "--workspace",
            str(tmp_path),
            "--out",
            str(brief_path),
        ]
    )

    assert status_result == 0
    assert brief_result == 0
    assert json.loads(status_path.read_text(encoding="utf-8"))["initialized"] is True
    assert "No advisories matched" in brief_path.read_text(encoding="utf-8")


def test_intelligence_sync_require_success_writes_failure_report(tmp_path, monkeypatch, capsys) -> None:
    Workspace.initialize(tmp_path)
    report_path = tmp_path / "sync.json"
    now = utc_now()
    failed_report = IntelligenceSyncReport(
        run_id="intelligence-sync-fixture",
        status=SyncStatus.FAILED,
        started_at=now,
        finished_at=now,
        requested_sources=[IntelligenceSource.CISA_KEV],
        since_hours=24,
        limit_per_source=10,
        enrich_epss=False,
        results=[
            SourceSyncResult(
                source=IntelligenceSource.CISA_KEV,
                status=SyncStatus.FAILED,
                started_at=now,
                finished_at=now,
                issues=[SyncIssue(code="fixture_failure", message="synthetic source failure")],
            )
        ],
    )
    assert not failed_report.successful

    monkeypatch.setattr(
        "white_hat_agent.cli.IntelligenceService.sync",
        lambda _service, **_kwargs: failed_report,
    )
    result = main(
        [
            "intelligence",
            "sync",
            "--workspace",
            str(tmp_path),
            "--source",
            "cisa-kev",
            "--limit-per-source",
            "10",
            "--require-success",
            "--out",
            str(report_path),
        ]
    )

    assert result == 2
    assert json.loads(report_path.read_text(encoding="utf-8"))["status"] == "failed"
    assert "required intelligence source did not synchronize successfully" in capsys.readouterr().err


def test_intelligence_list_cli_serializes_ranked_models(tmp_path, monkeypatch) -> None:
    Workspace.initialize(tmp_path)
    output_path = tmp_path / "ranked.json"
    now = utc_now()
    advisory = NormalizedAdvisory(
        advisory_id="CVE-2026-4242",
        identifiers=["CVE-2026-4242"],
        sources=[IntelligenceSource.CISA_KEV],
        known_exploited=True,
        modified_at=now,
    )
    monkeypatch.setattr(
        "white_hat_agent.cli.IntelligenceService.list",
        lambda _service, **_kwargs: [
            RankedAdvisory(advisory=advisory, priority=rank_advisory(advisory, as_of=now))
        ],
    )

    result = main(
        [
            "intelligence",
            "list",
            "--workspace",
            str(tmp_path),
            "--out",
            str(output_path),
        ]
    )

    assert result == 0
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload[0]["advisory"]["advisory_id"] == "CVE-2026-4242"
    assert payload[0]["priority"]["kev_component"] == 1000.0


def test_simulation_cli_recovers_stalled_portfolio_with_expansion_replay(tmp_path) -> None:
    episode, replay, expansions = build_stalled_recovery_fixture()
    episode_path = tmp_path / "episode.json"
    replay_path = tmp_path / "replay.json"
    expansions_path = tmp_path / "expansions.json"
    output_path = tmp_path / "simulation.json"
    _write_json(episode_path, episode)
    _write_json(replay_path, replay)
    _write_json(expansions_path, expansions)

    result = main(
        [
            "discovery",
            "simulate",
            "--episode",
            str(episode_path),
            "--replay",
            str(replay_path),
            "--expansions",
            str(expansions_path),
            "--out",
            str(output_path),
        ]
    )
    payload = json.loads(output_path.read_text(encoding="utf-8"))

    assert result == 0
    assert payload["halt_reason"] == "complete"
    assert payload["cycles"] == 1
    assert payload["expansions"][0]["hypothesis_ids"] == ["h-parser-frontier"]
