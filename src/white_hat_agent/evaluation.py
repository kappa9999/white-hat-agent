from __future__ import annotations

from pydantic import Field

from .models import (
    AttemptOutcome,
    DiscoveryEpisode,
    EvidenceKind,
    HypothesisStatus,
    StrictModel,
)
from .simulator import SimulationHalt, SimulationResult


class DiscoveryMetrics(StrictModel):
    attempt_count: int = Field(ge=0)
    expansion_count: int = Field(ge=0)
    hypothesis_count: int = Field(ge=0)
    supported_count: int = Field(ge=0)
    refuted_count: int = Field(ge=0)
    evidence_count: int = Field(ge=0)
    graph_node_count: int = Field(ge=0)
    graph_edge_count: int = Field(ge=0)
    used_cost_units: float = Field(ge=0)
    total_progress: float = Field(ge=0)
    progress_per_cost: float = Field(ge=0)
    supported_per_cost: float = Field(ge=0)
    evidence_per_cost: float = Field(ge=0)
    family_coverage: float = Field(ge=0, le=1)
    causal_evidence_ratio: float = Field(ge=0, le=1)
    terminal_retry_violations: int = Field(ge=0)


class SimulationEvaluation(StrictModel):
    score: float = Field(ge=0, le=100)
    completed: bool
    plateau_recovery_plans: int = Field(ge=0)
    expansion_yield: float = Field(ge=0)
    metrics: DiscoveryMetrics
    strengths: list[str] = Field(default_factory=list)
    improvement_targets: list[str] = Field(default_factory=list)


def evaluate_episode(episode: DiscoveryEpisode) -> DiscoveryMetrics:
    attempts = episode.attempts
    hypotheses = {item.hypothesis_id: item for item in episode.hypotheses}
    families = {item.family.value for item in episode.hypotheses}
    attempted_families = {
        hypotheses[item.hypothesis_id].family.value for item in attempts if item.hypothesis_id in hypotheses
    }
    causal_kinds = {
        EvidenceKind.DIFFERENTIAL,
        EvidenceKind.INTERVENTION,
        EvidenceKind.REPRODUCTION,
    }
    causal_evidence = sum(item.kind in causal_kinds for item in episode.evidence)
    cost = episode.budget.used_cost_units
    progress = sum(item.progress_delta for item in attempts)

    seen_terminal: set[tuple[str, int, str]] = set()
    retry_violations = 0
    for attempt in attempts:
        key = (attempt.hypothesis_id, attempt.hypothesis_revision, attempt.probe_digest)
        if key in seen_terminal:
            retry_violations += 1
        if attempt.outcome != AttemptOutcome.FAILED:
            seen_terminal.add(key)

    return DiscoveryMetrics(
        attempt_count=len(attempts),
        expansion_count=len(episode.expansions),
        hypothesis_count=len(episode.hypotheses),
        supported_count=sum(item.status == HypothesisStatus.SUPPORTED for item in episode.hypotheses),
        refuted_count=sum(item.status == HypothesisStatus.REFUTED for item in episode.hypotheses),
        evidence_count=len(episode.evidence),
        graph_node_count=len(episode.graph.nodes),
        graph_edge_count=len(episode.graph.edges),
        used_cost_units=cost,
        total_progress=round(progress, 6),
        progress_per_cost=round(progress / cost, 6) if cost else 0.0,
        supported_per_cost=(
            round(
                sum(item.status == HypothesisStatus.SUPPORTED for item in episode.hypotheses) / cost,
                6,
            )
            if cost
            else 0.0
        ),
        evidence_per_cost=round(len(episode.evidence) / cost, 6) if cost else 0.0,
        family_coverage=round(len(attempted_families) / len(families), 6) if families else 0.0,
        causal_evidence_ratio=(
            round(causal_evidence / len(episode.evidence), 6) if episode.evidence else 0.0
        ),
        terminal_retry_violations=retry_violations,
    )


def evaluate_simulation(result: SimulationResult) -> SimulationEvaluation:
    metrics = evaluate_episode(result.final_episode)
    completed = result.halt_reason == SimulationHalt.COMPLETE
    no_retry_score = 1.0 if metrics.terminal_retry_violations == 0 else 0.0
    progress_score = min(1.0, metrics.progress_per_cost * 2.0)
    supported_yield = min(1.0, metrics.supported_count / max(1, metrics.attempt_count))
    evidence_yield = min(1.0, metrics.evidence_count / max(1, metrics.attempt_count))
    score = 100.0 * (
        0.20 * float(completed)
        + 0.20 * no_retry_score
        + 0.15 * progress_score
        + 0.15 * supported_yield
        + 0.10 * metrics.family_coverage
        + 0.10 * metrics.causal_evidence_ratio
        + 0.10 * evidence_yield
    )
    expansion_yield = (
        sum(len(item.hypothesis_ids) for item in result.expansions) / len(result.expansions)
        if result.expansions
        else 0.0
    )

    strengths: list[str] = []
    improvements: list[str] = []
    if completed:
        strengths.append("episode reached an explicit complete state")
    else:
        improvements.append(f"resolve non-complete halt state: {result.halt_reason.value}")
    if metrics.terminal_retry_violations == 0:
        strengths.append("no unchanged terminal probe was retried")
    else:
        improvements.append("eliminate unchanged terminal-probe retries")
    if metrics.causal_evidence_ratio > 0:
        strengths.append("episode contains causal, intervention, or differential evidence")
    else:
        improvements.append("add causal intervention or differential evidence")
    if metrics.family_coverage < 0.5:
        improvements.append("increase independent hypothesis-family coverage")
    if metrics.progress_per_cost < 0.1:
        improvements.append("increase information gain per cost unit")

    return SimulationEvaluation(
        score=round(score, 6),
        completed=completed,
        plateau_recovery_plans=sum(item.plateau_detected for item in result.plans),
        expansion_yield=round(expansion_yield, 6),
        metrics=metrics,
        strengths=strengths,
        improvement_targets=improvements,
    )
