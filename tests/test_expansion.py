from __future__ import annotations

import pytest

from white_hat_agent.expansion import (
    ExpansionError,
    ReplayHypothesisGenerator,
    apply_expansion,
)
from white_hat_agent.fixtures import build_stalled_recovery_fixture
from white_hat_agent.models import ExpansionTrigger, HypothesisStatus
from white_hat_agent.planner import AdaptivePlanner


def test_stalled_portfolio_expands_against_exact_manifest() -> None:
    episode, _, transcript = build_stalled_recovery_fixture()
    plan = AdaptivePlanner().plan(episode)
    generator = ReplayHypothesisGenerator(transcript)

    batch = generator.expand(episode, plan, ExpansionTrigger.STALLED, limit=4)
    assert batch is not None
    updated = apply_expansion(episode, batch)

    assert not episode.hypotheses
    assert [item.hypothesis_id for item in updated.hypotheses] == ["h-parser-frontier"]
    assert updated.hypotheses[0].status == HypothesisStatus.PROPOSED
    assert updated.expansions[0].expansion_id == batch.expansion_id()
    assert updated.expansions[0].base_episode_digest == episode.digest()
    assert generator.remaining_batches() == 0


def test_stale_expansion_cannot_cross_episode_revision() -> None:
    episode, _, transcript = build_stalled_recovery_fixture()
    batch = transcript.batches[0].model_copy(update={"base_episode_digest": "0" * 64})

    with pytest.raises(ExpansionError, match="stale"):
        apply_expansion(episode, batch)


def test_replay_generator_rejects_wrong_trigger() -> None:
    episode, _, transcript = build_stalled_recovery_fixture()
    generator = ReplayHypothesisGenerator(transcript)
    plan = AdaptivePlanner().plan(episode)

    with pytest.raises(ExpansionError, match="trigger"):
        generator.expand(episode, plan, ExpansionTrigger.PLATEAU, limit=4)
