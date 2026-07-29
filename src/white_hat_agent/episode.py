from __future__ import annotations

from .models import (
    AttemptOutcome,
    DiscoveryAttempt,
    DiscoveryBudget,
    DiscoveryEpisode,
    DiscoveryObservation,
    HypothesisStatus,
    stable_id,
)


def apply_observation(episode: DiscoveryEpisode, observation: DiscoveryObservation) -> DiscoveryEpisode:
    """Apply one normalized observation and return a newly validated manifest."""

    if any(item.observation_id == observation.observation_id for item in episode.attempts):
        raise ValueError(f"observation already applied: {observation.observation_id}")
    hypothesis_by_id = {item.hypothesis_id: item for item in episode.hypotheses}
    if observation.hypothesis_id not in hypothesis_by_id:
        raise ValueError(f"unknown hypothesis: {observation.hypothesis_id}")
    hypothesis = hypothesis_by_id[observation.hypothesis_id]
    if observation.hypothesis_revision != hypothesis.revision:
        message = (
            f"stale observation revision {observation.hypothesis_revision}; "
            f"current revision is {hypothesis.revision}"
        )
        raise ValueError(message)
    if abs(observation.cost_units - hypothesis.probe.cost_units) > 1e-9:
        raise ValueError("observation cost must match the selected probe cost")
    if not episode.budget.can_afford(observation.cost_units):
        raise ValueError("observation exceeds the remaining episode budget")

    updated = DiscoveryEpisode.model_validate(episode.model_dump(mode="python"))
    evidence_ids = {item.evidence_id for item in updated.evidence}
    node_ids = {item.node_id for item in updated.graph.nodes}
    edge_ids = {item.edge_id for item in updated.graph.edges}
    hypothesis_ids = {item.hypothesis_id for item in updated.hypotheses}

    duplicate_evidence = sorted(evidence_ids & {item.evidence_id for item in observation.new_evidence})
    duplicate_nodes = sorted(node_ids & {item.node_id for item in observation.new_nodes})
    duplicate_edges = sorted(edge_ids & {item.edge_id for item in observation.new_edges})
    duplicate_hypotheses = sorted(
        hypothesis_ids & {item.hypothesis_id for item in observation.adjacent_hypotheses}
    )
    if duplicate_evidence:
        raise ValueError(f"new evidence ids already exist: {', '.join(duplicate_evidence)}")
    if duplicate_nodes:
        raise ValueError(f"new node ids already exist: {', '.join(duplicate_nodes)}")
    if duplicate_edges:
        raise ValueError(f"new edge ids already exist: {', '.join(duplicate_edges)}")
    if duplicate_hypotheses:
        raise ValueError(f"adjacent hypothesis ids already exist: {', '.join(duplicate_hypotheses)}")

    all_node_ids = node_ids | {item.node_id for item in observation.new_nodes}
    all_evidence_ids = evidence_ids | {item.evidence_id for item in observation.new_evidence}
    all_hypothesis_ids = hypothesis_ids | {item.hypothesis_id for item in observation.adjacent_hypotheses}
    for edge in observation.new_edges:
        if edge.source not in all_node_ids or edge.target not in all_node_ids:
            raise ValueError(f"new edge {edge.edge_id} references an unknown endpoint")
        if not set(edge.evidence_ids) <= all_evidence_ids:
            raise ValueError(f"new edge {edge.edge_id} references unknown evidence")
        if not set(edge.hypothesis_ids) <= all_hypothesis_ids:
            raise ValueError(f"new edge {edge.edge_id} references unknown hypotheses")
    for node in observation.new_nodes:
        if not set(node.evidence_ids) <= all_evidence_ids:
            raise ValueError(f"new node {node.node_id} references unknown evidence")
    for adjacent in observation.adjacent_hypotheses:
        if not set(adjacent.anchor_node_ids) <= all_node_ids:
            raise ValueError(f"adjacent hypothesis {adjacent.hypothesis_id} references unknown anchors")
        if not set(adjacent.target_node_ids) <= all_node_ids:
            raise ValueError(f"adjacent hypothesis {adjacent.hypothesis_id} references unknown targets")
        if not set(adjacent.dependency_ids) <= all_hypothesis_ids:
            raise ValueError(f"adjacent hypothesis {adjacent.hypothesis_id} references unknown dependencies")
        if not set(adjacent.evidence_ids) <= all_evidence_ids:
            raise ValueError(f"adjacent hypothesis {adjacent.hypothesis_id} references unknown evidence")

    graph_before = updated.graph.revision
    updated.evidence.extend(observation.new_evidence)
    updated.graph.nodes.extend(observation.new_nodes)
    updated.graph.edges.extend(observation.new_edges)
    changed_graph = bool(observation.new_nodes or observation.new_edges)
    if changed_graph:
        updated.graph.revision += 1
    updated.hypotheses.extend(observation.adjacent_hypotheses)

    current = next(item for item in updated.hypotheses if item.hypothesis_id == observation.hypothesis_id)
    new_evidence_ids = [item.evidence_id for item in observation.new_evidence]
    current.evidence_ids = list(dict.fromkeys([*current.evidence_ids, *new_evidence_ids]))
    current.status = _status_after_observation(observation)

    attempt_payload = {
        "episode_id": episode.episode_id,
        "observation_id": observation.observation_id,
        "hypothesis_id": observation.hypothesis_id,
        "hypothesis_revision": observation.hypothesis_revision,
        "probe_digest": hypothesis.probe.digest(),
        "graph_revision_before": graph_before,
        "graph_revision_after": updated.graph.revision,
    }
    updated.attempts.append(
        DiscoveryAttempt(
            attempt_id=stable_id("attempt", attempt_payload),
            observation_id=observation.observation_id,
            hypothesis_id=observation.hypothesis_id,
            hypothesis_revision=observation.hypothesis_revision,
            probe_digest=hypothesis.probe.digest(),
            outcome=observation.outcome,
            progress_delta=observation.progress_delta,
            new_node_ids=[item.node_id for item in observation.new_nodes],
            new_edge_ids=[item.edge_id for item in observation.new_edges],
            evidence_ids=new_evidence_ids,
            graph_revision_before=graph_before,
            graph_revision_after=updated.graph.revision,
            cost_units=observation.cost_units,
            started_at=observation.started_at,
            finished_at=observation.observed_at,
        )
    )
    updated.budget = DiscoveryBudget(
        max_attempts=updated.budget.max_attempts,
        max_iterations=updated.budget.max_iterations,
        max_cost_units=updated.budget.max_cost_units,
        used_attempts=updated.budget.used_attempts + 1,
        used_iterations=updated.budget.used_iterations + 1,
        used_cost_units=updated.budget.used_cost_units + observation.cost_units,
    )
    updated.updated_at = observation.observed_at
    return DiscoveryEpisode.model_validate(updated.model_dump(mode="python"))


def _status_after_observation(observation: DiscoveryObservation) -> HypothesisStatus:
    if observation.outcome == AttemptOutcome.BLOCKED:
        return HypothesisStatus.BLOCKED
    if observation.outcome == AttemptOutcome.NEGATIVE:
        return HypothesisStatus.REFUTED if observation.conclusive else HypothesisStatus.INCONCLUSIVE
    if observation.outcome == AttemptOutcome.SUCCEEDED:
        return HypothesisStatus.SUPPORTED if observation.conclusive else HypothesisStatus.TESTING
    if observation.outcome == AttemptOutcome.INCONCLUSIVE:
        return HypothesisStatus.INCONCLUSIVE
    return HypothesisStatus.TESTING
