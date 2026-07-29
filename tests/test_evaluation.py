from __future__ import annotations

from white_hat_agent.adapters import ReplayAdapter
from white_hat_agent.evaluation import evaluate_episode, evaluate_simulation
from white_hat_agent.fixtures import build_active_data_episode, build_active_data_transcript
from white_hat_agent.simulator import run_simulation


def test_simulation_evaluation_measures_discovery_not_action_volume() -> None:
    episode = build_active_data_episode()
    result = run_simulation(episode, ReplayAdapter(build_active_data_transcript(episode)))

    evaluation = evaluate_simulation(result)

    assert evaluation.completed is True
    assert evaluation.score > 60
    assert evaluation.metrics.attempt_count == 5
    assert evaluation.metrics.supported_count == 2
    assert evaluation.metrics.terminal_retry_violations == 0
    assert evaluation.metrics.causal_evidence_ratio > 0
    assert "no unchanged terminal probe was retried" in evaluation.strengths


def test_empty_episode_has_zero_yield_without_division_errors() -> None:
    episode = build_active_data_episode()
    episode.hypotheses = []

    metrics = evaluate_episode(episode)

    assert metrics.attempt_count == 0
    assert metrics.progress_per_cost == 0
    assert metrics.family_coverage == 0
    assert metrics.causal_evidence_ratio == 0
