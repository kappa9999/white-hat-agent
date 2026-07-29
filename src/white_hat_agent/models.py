from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    model_validator,
)

Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
UnitScore = Annotated[float, Field(ge=0.0, le=1.0)]
Weight = Annotated[float, Field(ge=0.0, le=10.0)]


def utc_now() -> datetime:
    return datetime.now(UTC)


def canonical_json(value: BaseModel | dict[str, JsonValue] | list[JsonValue]) -> str:
    payload = value.model_dump(mode="json", exclude_none=True) if isinstance(value, BaseModel) else value
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def stable_digest(value: BaseModel | dict[str, JsonValue] | list[JsonValue]) -> str:
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


def stable_id(prefix: str, value: BaseModel | dict[str, JsonValue] | list[JsonValue]) -> str:
    return f"{prefix}-{stable_digest(value)[:20]}"


def _unique(values: list[str], label: str) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"{label} must contain unique values")


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class FrozenStrictModel(StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ExecutionMode(StrEnum):
    OFFLINE = "offline"
    SANDBOX = "sandbox"
    LIVE_READONLY = "live-readonly"
    LIVE_ACTIVE = "live-active"


class MutationLevel(StrEnum):
    NONE = "none"
    TARGET_LOCAL = "target-local"
    EXTERNAL_STATE = "external-state"


MUTATION_RANK: dict[MutationLevel, int] = {
    MutationLevel.NONE: 0,
    MutationLevel.TARGET_LOCAL: 1,
    MutationLevel.EXTERNAL_STATE: 2,
}


class SurfaceKind(StrEnum):
    ARTIFACT = "artifact"
    INPUT = "input"
    PARSER = "parser"
    INTERPRETER = "interpreter"
    MODULE = "module"
    FUNCTION = "function"
    MESSAGE = "message"
    IDENTITY = "identity"
    SERVICE = "service"
    STATE = "state"
    CONTROL = "control"
    EVIDENCE = "evidence"
    OTHER = "other"


class Relation(StrEnum):
    FLOWS_TO = "flows-to"
    READS = "reads"
    WRITES = "writes"
    INVOKES = "invokes"
    LOADS = "loads"
    SERIALIZES = "serializes"
    VALIDATES = "validates"
    MINTS = "mints"
    DELEGATES = "delegates"
    TRUSTS = "trusts"
    VARIANT_OF = "variant-of"
    CORRELATES = "correlates"
    CAUSES = "causes"
    OTHER = "other"


class HypothesisFamily(StrEnum):
    ACTIVE_DATA = "active-data"
    VARIANT_ANALYSIS = "variant-analysis"
    NATIVE_MEMORY = "native-memory"
    MANAGED_RUNTIME = "managed-runtime"
    SCRIPT_BRIDGE = "script-bridge"
    PROTOCOL = "protocol"
    STATE_MACHINE = "state-machine"
    AUTHORITY = "authority"
    SUPPLY_CHAIN = "supply-chain"
    FORENSICS = "forensics"
    OTHER = "other"


class HypothesisStatus(StrEnum):
    PROPOSED = "proposed"
    TESTING = "testing"
    SUPPORTED = "supported"
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"
    BLOCKED = "blocked"


class AttemptOutcome(StrEnum):
    SUCCEEDED = "succeeded"
    NEGATIVE = "negative"
    FAILED = "failed"
    INCONCLUSIVE = "inconclusive"
    BLOCKED = "blocked"


class EvidenceKind(StrEnum):
    ARTIFACT = "artifact"
    STATIC = "static"
    RUNTIME = "runtime"
    PROTOCOL = "protocol"
    DIFFERENTIAL = "differential"
    REPRODUCTION = "reproduction"
    INTERVENTION = "intervention"
    TRACE = "trace"
    OTHER = "other"


class PlanMode(StrEnum):
    EXPLORE = "explore"
    EXPLOIT = "exploit"
    PLATEAU_RECOVERY = "plateau-recovery"
    COMPLETE = "complete"
    BUDGET_EXHAUSTED = "budget-exhausted"
    STALLED = "stalled"


class ExpansionTrigger(StrEnum):
    STALLED = "stalled"
    PLATEAU = "plateau"
    FRONTIER = "frontier"
    ADJACENT = "adjacent"
    CAMPAIGN_ROLLOVER = "campaign-rollover"


class CausalVerdict(StrEnum):
    CONFIRMED = "confirmed"
    SUPPORTED = "supported"
    ALTERNATE_FINDING = "alternate-finding"
    INCONCLUSIVE = "inconclusive"
    REFUTED = "refuted"


class ProofTier(StrEnum):
    SIGNAL = "signal"
    REPRODUCED = "reproduced"
    CAUSAL = "causal"
    DIFFERENTIAL = "differential"
    REGRESSION_CLOSED = "regression-closed"


class TargetIdentity(StrictModel):
    target_id: str = Field(min_length=1)
    build_id: str = Field(min_length=1)
    artifacts: dict[str, Sha256] = Field(default_factory=dict)
    environment_fingerprint: Sha256 | None = None


class GoalWeights(StrictModel):
    impact: Weight = 1.0
    reachability: Weight = 1.0
    evidence_strength: Weight = 1.2
    information_gain: Weight = 1.2
    novelty: Weight = 1.0
    causal_verifiability: Weight = 1.4
    transferability: Weight = 0.7
    cost: Weight = 0.8
    blast_radius: Weight = 0.8
    redundancy: Weight = 1.0
    diversity_bonus: Weight = 0.8
    plateau_diversity_bonus: Weight = 2.0
    retry_penalty: Weight = 0.7

    @model_validator(mode="after")
    def nonzero_groups(self) -> Self:
        reward = (
            self.impact
            + self.reachability
            + self.evidence_strength
            + self.information_gain
            + self.novelty
            + self.causal_verifiability
            + self.transferability
        )
        penalty = self.cost + self.blast_radius + self.redundancy
        if reward <= 0:
            raise ValueError("at least one reward weight must be positive")
        if penalty <= 0:
            raise ValueError("at least one penalty weight must be positive")
        return self


class DiscoveryObjective(StrictModel):
    objective_id: str = Field(min_length=1)
    statement: str = Field(min_length=1)
    success_criteria: list[str] = Field(min_length=1)
    target: TargetIdentity
    allowed_capabilities: list[str] = Field(default_factory=list)
    allowed_modes: list[ExecutionMode] = Field(default_factory=lambda: [ExecutionMode.OFFLINE])
    maximum_mutation_level: MutationLevel = MutationLevel.NONE
    minimum_alignment: UnitScore = 0.55
    minimum_anchor_confidence: UnitScore = 0.25
    goal_weights: GoalWeights = Field(default_factory=GoalWeights)

    @model_validator(mode="after")
    def unique_lists(self) -> Self:
        _unique(self.success_criteria, "success_criteria")
        _unique(self.allowed_capabilities, "allowed_capabilities")
        _unique([item.value for item in self.allowed_modes], "allowed_modes")
        return self


class EvidenceRecord(FrozenStrictModel):
    evidence_id: str = Field(min_length=1)
    kind: EvidenceKind
    source_ref: str = Field(min_length=1)
    content_sha256: Sha256
    summary: str = Field(min_length=1)
    confidence: UnitScore
    captured_at: AwareDatetime


class SurfaceNode(StrictModel):
    node_id: str = Field(min_length=1)
    kind: SurfaceKind
    label: str = Field(min_length=1)
    confidence: UnitScore
    authority: UnitScore = 0.0
    evidence_ids: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def unique_lists(self) -> Self:
        _unique(self.evidence_ids, "evidence_ids")
        _unique(self.tags, "tags")
        return self


class SurfaceEdge(StrictModel):
    edge_id: str = Field(min_length=1)
    source: str = Field(min_length=1)
    target: str = Field(min_length=1)
    relation: Relation
    confidence: UnitScore
    evidence_ids: list[str] = Field(default_factory=list)
    hypothesis_ids: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def unique_lists(self) -> Self:
        _unique(self.evidence_ids, "evidence_ids")
        _unique(self.hypothesis_ids, "hypothesis_ids")
        return self


class SurfaceGraph(StrictModel):
    revision: int = Field(default=1, ge=1)
    nodes: list[SurfaceNode] = Field(default_factory=list)
    edges: list[SurfaceEdge] = Field(default_factory=list)

    @model_validator(mode="after")
    def valid_graph(self) -> Self:
        node_ids = [item.node_id for item in self.nodes]
        edge_ids = [item.edge_id for item in self.edges]
        _unique(node_ids, "surface node ids")
        _unique(edge_ids, "surface edge ids")
        known = set(node_ids)
        for edge in self.edges:
            if edge.source not in known or edge.target not in known:
                raise ValueError(f"edge {edge.edge_id} references an unknown endpoint")
        return self


class HypothesisMeasures(StrictModel):
    objective_alignment: UnitScore
    impact: UnitScore
    reachability: UnitScore
    evidence_strength: UnitScore
    information_gain: UnitScore
    novelty: UnitScore
    causal_verifiability: UnitScore
    transferability: UnitScore
    cost: UnitScore
    blast_radius: UnitScore
    redundancy: UnitScore


class ProbeSpec(StrictModel):
    adapter_id: str = Field(min_length=1)
    action: str = Field(min_length=1)
    parameters: dict[str, JsonValue] = Field(default_factory=dict)
    expected_observations: list[str] = Field(min_length=1)
    falsifiers: list[str] = Field(min_length=1)
    required_capabilities: list[str] = Field(default_factory=list)
    mode: ExecutionMode = ExecutionMode.OFFLINE
    mutation_level: MutationLevel = MutationLevel.NONE
    max_steps: int = Field(default=20, ge=1)
    max_seconds: int = Field(default=300, ge=1)
    cost_units: float = Field(default=1.0, gt=0)

    @model_validator(mode="after")
    def unique_lists(self) -> Self:
        _unique(self.expected_observations, "expected_observations")
        _unique(self.falsifiers, "falsifiers")
        _unique(self.required_capabilities, "required_capabilities")
        return self

    def digest(self) -> str:
        return stable_digest(self)


class Hypothesis(StrictModel):
    hypothesis_id: str = Field(min_length=1)
    revision: int = Field(default=1, ge=1)
    title: str = Field(min_length=1)
    statement: str = Field(min_length=1)
    family: HypothesisFamily
    status: HypothesisStatus = HypothesisStatus.PROPOSED
    anchor_node_ids: list[str] = Field(min_length=1)
    target_node_ids: list[str] = Field(default_factory=list)
    dependency_ids: list[str] = Field(default_factory=list)
    blockers: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    measures: HypothesisMeasures
    probe: ProbeSpec
    attempt_limit: int = Field(default=3, ge=1)

    @model_validator(mode="after")
    def unique_lists(self) -> Self:
        _unique(self.anchor_node_ids, "anchor_node_ids")
        _unique(self.target_node_ids, "target_node_ids")
        _unique(self.dependency_ids, "dependency_ids")
        _unique(self.blockers, "blockers")
        _unique(self.evidence_ids, "evidence_ids")
        if self.hypothesis_id in self.dependency_ids:
            raise ValueError("a hypothesis cannot depend on itself")
        return self


class DiscoveryAttempt(FrozenStrictModel):
    attempt_id: str = Field(min_length=1)
    observation_id: str = Field(min_length=1)
    hypothesis_id: str = Field(min_length=1)
    hypothesis_revision: int = Field(ge=1)
    probe_digest: Sha256
    outcome: AttemptOutcome
    progress_delta: UnitScore
    new_node_ids: list[str] = Field(default_factory=list)
    new_edge_ids: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    graph_revision_before: int = Field(ge=1)
    graph_revision_after: int = Field(ge=1)
    cost_units: float = Field(gt=0)
    started_at: AwareDatetime
    finished_at: AwareDatetime

    @model_validator(mode="after")
    def valid_attempt(self) -> Self:
        if self.finished_at < self.started_at:
            raise ValueError("finished_at cannot precede started_at")
        if self.graph_revision_after < self.graph_revision_before:
            raise ValueError("graph revision cannot move backwards")
        _unique(self.new_node_ids, "new_node_ids")
        _unique(self.new_edge_ids, "new_edge_ids")
        _unique(self.evidence_ids, "evidence_ids")
        return self


class DiscoveryBudget(StrictModel):
    max_attempts: int = Field(default=100, ge=1)
    max_iterations: int = Field(default=100, ge=1)
    max_cost_units: float = Field(default=100.0, gt=0)
    used_attempts: int = Field(default=0, ge=0)
    used_iterations: int = Field(default=0, ge=0)
    used_cost_units: float = Field(default=0.0, ge=0)

    def exhausted_reasons(self) -> list[str]:
        reasons: list[str] = []
        if self.used_attempts >= self.max_attempts:
            reasons.append("attempt budget exhausted")
        if self.used_iterations >= self.max_iterations:
            reasons.append("iteration budget exhausted")
        if self.used_cost_units >= self.max_cost_units:
            reasons.append("cost budget exhausted")
        return reasons

    def can_afford(self, cost_units: float) -> bool:
        return (
            self.used_attempts < self.max_attempts
            and self.used_iterations < self.max_iterations
            and self.used_cost_units + cost_units <= self.max_cost_units
        )


class DiscoveryObservation(StrictModel):
    observation_id: str = Field(min_length=1)
    hypothesis_id: str = Field(min_length=1)
    hypothesis_revision: int = Field(ge=1)
    outcome: AttemptOutcome
    summary: str = Field(min_length=1)
    progress_delta: UnitScore
    conclusive: bool = False
    new_evidence: list[EvidenceRecord] = Field(default_factory=list)
    new_nodes: list[SurfaceNode] = Field(default_factory=list)
    new_edges: list[SurfaceEdge] = Field(default_factory=list)
    adjacent_hypotheses: list[Hypothesis] = Field(default_factory=list)
    cost_units: float = Field(gt=0)
    started_at: AwareDatetime
    observed_at: AwareDatetime

    @model_validator(mode="after")
    def valid_observation(self) -> Self:
        if self.observed_at < self.started_at:
            raise ValueError("observed_at cannot precede started_at")
        _unique([item.evidence_id for item in self.new_evidence], "new evidence ids")
        _unique([item.node_id for item in self.new_nodes], "new node ids")
        _unique([item.edge_id for item in self.new_edges], "new edge ids")
        _unique([item.hypothesis_id for item in self.adjacent_hypotheses], "adjacent hypothesis ids")
        return self


class HypothesisExpansionBatch(StrictModel):
    generator_id: str = Field(min_length=1)
    episode_id: str = Field(min_length=1)
    base_episode_digest: Sha256
    trigger: ExpansionTrigger
    hypotheses: list[Hypothesis] = Field(min_length=1)
    rationale: list[str] = Field(min_length=1)
    generated_at: AwareDatetime

    @model_validator(mode="after")
    def unique_hypotheses(self) -> Self:
        _unique([item.hypothesis_id for item in self.hypotheses], "expansion hypothesis ids")
        _unique(self.rationale, "expansion rationale")
        return self

    def expansion_id(self) -> str:
        return stable_id("expansion", self)


class HypothesisExpansionRecord(FrozenStrictModel):
    expansion_id: str = Field(min_length=1)
    generator_id: str = Field(min_length=1)
    trigger: ExpansionTrigger
    base_episode_digest: Sha256
    hypothesis_ids: list[str] = Field(min_length=1)
    rationale: list[str] = Field(min_length=1)
    applied_at: AwareDatetime

    @model_validator(mode="after")
    def unique_lists(self) -> Self:
        _unique(self.hypothesis_ids, "expansion hypothesis ids")
        _unique(self.rationale, "expansion rationale")
        return self


class DiscoveryEpisode(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    episode_id: str = Field(min_length=1)
    objective: DiscoveryObjective
    graph: SurfaceGraph
    evidence: list[EvidenceRecord] = Field(default_factory=list)
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    attempts: list[DiscoveryAttempt] = Field(default_factory=list)
    expansions: list[HypothesisExpansionRecord] = Field(default_factory=list)
    budget: DiscoveryBudget = Field(default_factory=DiscoveryBudget)
    created_at: AwareDatetime = Field(default_factory=utc_now)
    updated_at: AwareDatetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def valid_episode(self) -> Self:
        if self.updated_at < self.created_at:
            raise ValueError("updated_at cannot precede created_at")
        node_ids = {item.node_id for item in self.graph.nodes}
        evidence_ids = [item.evidence_id for item in self.evidence]
        hypothesis_ids = [item.hypothesis_id for item in self.hypotheses]
        attempt_ids = [item.attempt_id for item in self.attempts]
        observation_ids = [item.observation_id for item in self.attempts]
        expansion_ids = [item.expansion_id for item in self.expansions]
        _unique(evidence_ids, "episode evidence ids")
        _unique(hypothesis_ids, "episode hypothesis ids")
        _unique(attempt_ids, "episode attempt ids")
        _unique(observation_ids, "episode observation ids")
        _unique(expansion_ids, "episode expansion ids")
        evidence_known = set(evidence_ids)
        hypothesis_known = set(hypothesis_ids)
        for node in self.graph.nodes:
            if not set(node.evidence_ids) <= evidence_known:
                raise ValueError(f"node {node.node_id} references unknown evidence")
        for edge in self.graph.edges:
            if not set(edge.evidence_ids) <= evidence_known:
                raise ValueError(f"edge {edge.edge_id} references unknown evidence")
            if not set(edge.hypothesis_ids) <= hypothesis_known:
                raise ValueError(f"edge {edge.edge_id} references unknown hypotheses")
        for hypothesis in self.hypotheses:
            if not set(hypothesis.anchor_node_ids) <= node_ids:
                raise ValueError(f"hypothesis {hypothesis.hypothesis_id} has unknown anchor nodes")
            if not set(hypothesis.target_node_ids) <= node_ids:
                raise ValueError(f"hypothesis {hypothesis.hypothesis_id} has unknown target nodes")
            if not set(hypothesis.dependency_ids) <= hypothesis_known:
                raise ValueError(f"hypothesis {hypothesis.hypothesis_id} has unknown dependencies")
            if not set(hypothesis.evidence_ids) <= evidence_known:
                raise ValueError(f"hypothesis {hypothesis.hypothesis_id} references unknown evidence")
        dependency_map = {item.hypothesis_id: item.dependency_ids for item in self.hypotheses}
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(hypothesis_id: str) -> None:
            if hypothesis_id in visiting:
                raise ValueError(f"hypothesis dependency cycle includes {hypothesis_id}")
            if hypothesis_id in visited:
                return
            visiting.add(hypothesis_id)
            for dependency_id in dependency_map[hypothesis_id]:
                visit(dependency_id)
            visiting.remove(hypothesis_id)
            visited.add(hypothesis_id)

        for hypothesis_id in hypothesis_ids:
            visit(hypothesis_id)
        for attempt in self.attempts:
            if attempt.hypothesis_id not in hypothesis_known:
                raise ValueError(f"attempt {attempt.attempt_id} references an unknown hypothesis")
            if not set(attempt.evidence_ids) <= evidence_known:
                raise ValueError(f"attempt {attempt.attempt_id} references unknown evidence")
        for expansion in self.expansions:
            if not set(expansion.hypothesis_ids) <= hypothesis_known:
                raise ValueError(f"expansion {expansion.expansion_id} references unknown hypotheses")
        return self

    def digest(self) -> str:
        return stable_digest(self)


class RankedHypothesis(StrictModel):
    hypothesis_id: str
    family: HypothesisFamily
    score: float
    reward_score: UnitScore
    penalty_score: UnitScore
    bonuses: dict[str, float] = Field(default_factory=dict)
    reasons: list[str] = Field(default_factory=list)


class BlockedHypothesis(StrictModel):
    hypothesis_id: str
    reasons: list[str] = Field(min_length=1)


class DiscoveryPlan(StrictModel):
    plan_id: str
    episode_id: str
    episode_digest: Sha256
    graph_revision: int = Field(ge=1)
    mode: PlanMode
    plateau_detected: bool
    selected: list[RankedHypothesis] = Field(default_factory=list)
    blocked: list[BlockedHypothesis] = Field(default_factory=list)
    effective_goal_weights: GoalWeights
    rationale: list[str] = Field(default_factory=list)


class CausalVerificationInput(StrictModel):
    verification_id: str
    hypothesis_id: str
    target_effect_observed: bool
    intended_path_observed: bool
    primitive_observed: bool
    vulnerable_variant_succeeds: bool
    fixed_variant_rejects: bool
    neutralization_removes_effect: bool
    shortcuts_excluded: bool
    reproducible_runs: int = Field(ge=0)
    independent_evidence_families: list[EvidenceKind] = Field(default_factory=list)
    conclusive_negative: bool = False
    notes: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def unique_families(self) -> Self:
        _unique([item.value for item in self.independent_evidence_families], "evidence families")
        return self


class CausalVerificationReport(StrictModel):
    report_id: str
    verification_id: str
    hypothesis_id: str
    verdict: CausalVerdict
    proof_tier: ProofTier
    confidence: UnitScore
    satisfied_checks: list[str]
    failed_checks: list[str]
    next_experiments: list[str]
