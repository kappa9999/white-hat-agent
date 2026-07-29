from __future__ import annotations

import pytest

from white_hat_agent.adapters import AdapterError, ReplayAdapter
from white_hat_agent.expansion import ReplayHypothesisGenerator
from white_hat_agent.fixtures import (
    build_active_data_episode,
    build_active_data_transcript,
    build_stalled_recovery_fixture,
)
from white_hat_agent.models import HypothesisStatus
from white_hat_agent.simulator import SimulationHalt, run_simulation


def test_replay_runs_closed_loop_to_completion() -> None:
    episode = build_active_data_episode()
    adapter = ReplayAdapter(build_active_data_transcript(episode))

    result = run_simulation(episode, adapter)

    assert result.halt_reason == SimulationHalt.COMPLETE
    assert result.cycles == 5
    assert [item.hypothesis_id for item in result.steps[:3]] == [
        "h-external-reference",
        "h-template-expression",
        "h-template-causal-differential",
    ]
    assert len({item.observation_id for item in result.steps}) == len(result.steps)
    assert result.final_episode.graph.revision == 2
    assert result.final_episode.budget.used_cost_units == 5.0
    causal = next(
        item
        for item in result.final_episode.hypotheses
        if item.hypothesis_id == "h-template-causal-differential"
    )
    assert causal.status == HypothesisStatus.SUPPORTED
    assert adapter.remaining_rules() == 0


def test_replay_rejects_target_identity_drift() -> None:
    episode = build_active_data_episode()
    adapter = ReplayAdapter(build_active_data_transcript(episode))
    episode.objective.target.build_id = "different-build"

    with pytest.raises(AdapterError, match="target identity"):
        adapter.execute(episode, episode.hypotheses[0])


def test_stalled_campaign_generates_frontier_hypothesis_and_resumes() -> None:
    episode, replay, expansions = build_stalled_recovery_fixture()

    result = run_simulation(
        episode,
        ReplayAdapter(replay),
        generator=ReplayHypothesisGenerator(expansions),
    )

    assert result.halt_reason == SimulationHalt.COMPLETE
    assert result.cycles == 1
    assert len(result.expansions) == 1
    assert result.expansions[0].hypothesis_ids == ["h-parser-frontier"]
    assert result.steps[0].hypothesis_id == "h-parser-frontier"
    assert result.final_episode.hypotheses[0].status == HypothesisStatus.SUPPORTED
