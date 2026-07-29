from __future__ import annotations

import json

from jsonschema import validate

from white_hat_agent.cli import main
from white_hat_agent.fixtures import (
    build_active_data_episode,
    build_active_data_transcript,
    build_stalled_recovery_fixture,
)
from white_hat_agent.schemas import export_schemas


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
