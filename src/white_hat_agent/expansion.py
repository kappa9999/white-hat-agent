from __future__ import annotations

from collections import deque
from typing import Protocol, runtime_checkable

from pydantic import Field, model_validator

from .models import (
    DiscoveryEpisode,
    DiscoveryPlan,
    ExpansionTrigger,
    HypothesisExpansionBatch,
    HypothesisExpansionRecord,
    StrictModel,
)


class ExpansionError(RuntimeError):
    """Raised when a hypothesis expansion violates manifest invariants."""


@runtime_checkable
class HypothesisGenerator(Protocol):
    """Semantic frontier-expansion boundary for a model or deterministic generator."""

    generator_id: str

    def expand(
        self,
        episode: DiscoveryEpisode,
        plan: DiscoveryPlan,
        trigger: ExpansionTrigger,
        limit: int,
    ) -> HypothesisExpansionBatch | None:
        """Return new typed hypotheses grounded in the exact episode digest."""


class ReplayExpansionTranscript(StrictModel):
    transcript_id: str = Field(min_length=1)
    generator_id: str = Field(min_length=1)
    batches: list[HypothesisExpansionBatch] = Field(min_length=1)

    @model_validator(mode="after")
    def unique_batches(self) -> ReplayExpansionTranscript:
        expansion_ids = [item.expansion_id() for item in self.batches]
        if len(expansion_ids) != len(set(expansion_ids)):
            raise ValueError("replay expansion ids must be unique")
        if any(item.generator_id != self.generator_id for item in self.batches):
            raise ValueError("replay batch generator does not match transcript generator")
        return self


class ReplayHypothesisGenerator:
    def __init__(self, transcript: ReplayExpansionTranscript) -> None:
        self.generator_id = transcript.generator_id
        self._batches = deque(item.model_copy(deep=True) for item in transcript.batches)

    def expand(
        self,
        episode: DiscoveryEpisode,
        plan: DiscoveryPlan,
        trigger: ExpansionTrigger,
        limit: int,
    ) -> HypothesisExpansionBatch | None:
        if limit < 1:
            raise ValueError("expansion limit must be positive")
        if not self._batches:
            return None
        batch = self._batches[0]
        if batch.episode_id != episode.episode_id:
            raise ExpansionError("expansion episode identity does not match current episode")
        if batch.base_episode_digest != episode.digest() or plan.episode_digest != episode.digest():
            raise ExpansionError("expansion is stale for the current episode digest")
        if batch.trigger != trigger:
            raise ExpansionError(
                f"expansion trigger {batch.trigger.value} does not match requested trigger {trigger.value}"
            )
        if len(batch.hypotheses) > limit:
            raise ExpansionError("expansion contains more hypotheses than the requested limit")
        self._batches.popleft()
        return batch

    def remaining_batches(self) -> int:
        return len(self._batches)


def apply_expansion(episode: DiscoveryEpisode, batch: HypothesisExpansionBatch) -> DiscoveryEpisode:
    """Validate and atomically add a frontier expansion to the episode manifest."""

    if batch.episode_id != episode.episode_id:
        raise ExpansionError("expansion episode identity does not match current episode")
    if batch.base_episode_digest != episode.digest():
        raise ExpansionError("expansion is stale for the current episode digest")
    if batch.generated_at < episode.updated_at:
        raise ExpansionError("expansion timestamp precedes the current episode state")
    if any(item.expansion_id == batch.expansion_id() for item in episode.expansions):
        raise ExpansionError(f"expansion already applied: {batch.expansion_id()}")

    existing_hypothesis_ids = {item.hypothesis_id for item in episode.hypotheses}
    new_hypothesis_ids = {item.hypothesis_id for item in batch.hypotheses}
    duplicates = sorted(existing_hypothesis_ids & new_hypothesis_ids)
    if duplicates:
        raise ExpansionError(f"expanded hypothesis ids already exist: {', '.join(duplicates)}")

    known_nodes = {item.node_id for item in episode.graph.nodes}
    known_evidence = {item.evidence_id for item in episode.evidence}
    all_hypotheses = existing_hypothesis_ids | new_hypothesis_ids
    for hypothesis in batch.hypotheses:
        if not set(hypothesis.anchor_node_ids) <= known_nodes:
            raise ExpansionError(f"expanded hypothesis {hypothesis.hypothesis_id} has unknown anchors")
        if not set(hypothesis.target_node_ids) <= known_nodes:
            raise ExpansionError(f"expanded hypothesis {hypothesis.hypothesis_id} has unknown targets")
        if not set(hypothesis.evidence_ids) <= known_evidence:
            raise ExpansionError(f"expanded hypothesis {hypothesis.hypothesis_id} has unknown evidence")
        if not set(hypothesis.dependency_ids) <= all_hypotheses:
            raise ExpansionError(f"expanded hypothesis {hypothesis.hypothesis_id} has unknown dependencies")

    updated = episode.model_copy(deep=True)
    updated.hypotheses.extend(item.model_copy(deep=True) for item in batch.hypotheses)
    updated.expansions.append(
        HypothesisExpansionRecord(
            expansion_id=batch.expansion_id(),
            generator_id=batch.generator_id,
            trigger=batch.trigger,
            base_episode_digest=batch.base_episode_digest,
            hypothesis_ids=[item.hypothesis_id for item in batch.hypotheses],
            rationale=batch.rationale,
            applied_at=batch.generated_at,
        )
    )
    updated.updated_at = batch.generated_at
    return DiscoveryEpisode.model_validate(updated.model_dump(mode="python"))
