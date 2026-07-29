from __future__ import annotations

from datetime import timedelta

from white_hat_agent.episode import apply_observation
from white_hat_agent.fixtures import FIXTURE_TIME, build_active_data_episode, build_active_data_transcript
from white_hat_agent.models import (
    AttemptOutcome,
    DiscoveryBudget,
    DiscoveryObservation,
    PlanMode,
)
from white_hat_agent.planner import AdaptivePlanner


def _low_progress_observation(episode, hypothesis_id: str, index: int) -> DiscoveryObservation:
    hypothesis = next(item for item in episode.hypotheses if item.hypothesis_id == hypothesis_id)
    started = FIXTURE_TIME + timedelta(minutes=index)
    return DiscoveryObservation(
        observation_id=f"obs-plateau-{index}",
        hypothesis_id=hypothesis_id,
        hypothesis_revision=hypothesis.revision,
        outcome=AttemptOutcome.INCONCLUSIVE,
        summary="The bounded probe added no discriminating evidence",
        progress_delta=0.01,
        conclusive=False,
        cost_units=hypothesis.probe.cost_units,
        started_at=started,
        observed_at=started + timedelta(seconds=1),
    )


def test_plan_is_deterministic_and_explainable() -> None:
    episode = build_active_data_episode()
    planner = AdaptivePlanner()

    first = planner.plan(episode, limit=3)
    second = planner.plan(episode, limit=3)

    assert first == second
    assert first.plan_id == second.plan_id
    assert first.mode == PlanMode.EXPLORE
    assert first.selected[0].hypothesis_id == "h-external-reference"
    assert first.selected[0].reward_score > first.selected[0].penalty_score
    assert all(item.reasons for item in first.selected)


def test_terminal_negative_suppresses_unchanged_probe() -> None:
    episode = build_active_data_episode()
    observation = next(
        item.observation
        for item in build_active_data_transcript(episode).rules
        if item.hypothesis_id == "h-external-reference"
    )
    updated = apply_observation(episode, observation)

    plan = AdaptivePlanner().plan(updated)
    blocked = {item.hypothesis_id: item.reasons for item in plan.blocked}

    assert "h-external-reference" not in {item.hypothesis_id for item in plan.selected}
    assert any("unchanged probe" in reason for reason in blocked["h-external-reference"])


def test_plateau_recovery_changes_goal_function_and_prioritizes_untried_family() -> None:
    episode = build_active_data_episode()
    for index, hypothesis_id in enumerate(
        ["h-external-reference", "h-template-expression", "h-envelope-offset"], start=1
    ):
        episode = apply_observation(episode, _low_progress_observation(episode, hypothesis_id, index))

    plan = AdaptivePlanner().plan(episode, limit=1)

    assert plan.plateau_detected is True
    assert plan.mode == PlanMode.PLATEAU_RECOVERY
    assert plan.effective_goal_weights.novelty > episode.objective.goal_weights.novelty
    assert plan.effective_goal_weights.information_gain > episode.objective.goal_weights.information_gain
    assert plan.selected[0].hypothesis_id == "h-sibling-variant"
    assert "plateau-untried-family" in plan.selected[0].bonuses


def test_failed_transport_attempt_can_retry_but_is_penalized() -> None:
    episode = build_active_data_episode()
    hypothesis = episode.hypotheses[0]
    observation = DiscoveryObservation(
        observation_id="obs-transient-failure",
        hypothesis_id=hypothesis.hypothesis_id,
        hypothesis_revision=hypothesis.revision,
        outcome=AttemptOutcome.FAILED,
        summary="The replay transport failed before producing target evidence",
        progress_delta=0.0,
        cost_units=hypothesis.probe.cost_units,
        started_at=FIXTURE_TIME,
        observed_at=FIXTURE_TIME + timedelta(seconds=1),
    )
    updated = apply_observation(episode, observation)

    plan = AdaptivePlanner().plan(updated, limit=4)
    ranked = next(item for item in plan.selected if item.hypothesis_id == hypothesis.hypothesis_id)

    assert ranked.bonuses["retry-penalty"] < 0


def test_exhausted_budget_is_an_explicit_terminal_plan() -> None:
    episode = build_active_data_episode()
    episode.budget = DiscoveryBudget(
        max_attempts=4,
        max_iterations=4,
        max_cost_units=4.0,
        used_attempts=4,
        used_iterations=4,
        used_cost_units=4.0,
    )

    plan = AdaptivePlanner().plan(episode)

    assert plan.mode == PlanMode.BUDGET_EXHAUSTED
    assert not plan.selected
    assert "attempt budget exhausted" in plan.rationale


def test_missing_adapter_capability_blocks_probe_before_execution() -> None:
    episode = build_active_data_episode()
    episode.objective.allowed_capabilities = []

    plan = AdaptivePlanner().plan(episode)

    assert plan.mode == PlanMode.STALLED
    assert not plan.selected
    assert all(any("missing capabilities" in reason for reason in item.reasons) for item in plan.blocked)
