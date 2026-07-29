from __future__ import annotations

import pytest

from white_hat_agent.episode import apply_observation
from white_hat_agent.fixtures import build_active_data_episode, build_active_data_transcript
from white_hat_agent.models import HypothesisStatus


def _observation(name: str):
    transcript = build_active_data_transcript()
    return next(item.observation for item in transcript.rules if item.observation.observation_id == name)


def test_apply_observation_is_copy_on_write_and_records_exact_attempt() -> None:
    episode = build_active_data_episode()
    before = episode.digest()
    observation = _observation("obs-external-negative")

    updated = apply_observation(episode, observation)

    assert episode.digest() == before
    assert not episode.attempts
    assert updated.budget.used_attempts == 1
    assert updated.budget.used_iterations == 1
    assert updated.budget.used_cost_units == 1.0
    assert updated.attempts[0].probe_digest == episode.hypotheses[0].probe.digest()
    assert updated.attempts[0].observation_id == observation.observation_id
    assert updated.hypotheses[0].status == HypothesisStatus.REFUTED
    assert updated.hypotheses[0].evidence_ids == ["ev-external-negative"]


def test_graph_growth_and_adjacent_hypothesis_are_validated_together() -> None:
    episode = build_active_data_episode()
    observation = _observation("obs-template-supported")

    updated = apply_observation(episode, observation)

    assert updated.graph.revision == 2
    assert "n-evaluator" in {item.node_id for item in updated.graph.nodes}
    assert "edge-parser-evaluator" in {item.edge_id for item in updated.graph.edges}
    assert "h-template-causal-differential" in {item.hypothesis_id for item in updated.hypotheses}
    causal = next(
        item for item in updated.hypotheses if item.hypothesis_id == "h-template-causal-differential"
    )
    assert causal.dependency_ids == ["h-template-expression"]
    assert causal.evidence_ids == ["ev-template-trace"]


def test_duplicate_observation_cannot_be_replayed() -> None:
    episode = build_active_data_episode()
    observation = _observation("obs-external-negative")
    updated = apply_observation(episode, observation)

    with pytest.raises(ValueError, match="observation already applied"):
        apply_observation(updated, observation)


def test_stale_hypothesis_revision_is_rejected() -> None:
    episode = build_active_data_episode()
    observation = _observation("obs-external-negative").model_copy(update={"hypothesis_revision": 99})

    with pytest.raises(ValueError, match="stale observation revision"):
        apply_observation(episode, observation)


def test_observation_cost_must_match_typed_probe() -> None:
    episode = build_active_data_episode()
    observation = _observation("obs-external-negative").model_copy(update={"cost_units": 2.0})

    with pytest.raises(ValueError, match="cost must match"):
        apply_observation(episode, observation)
