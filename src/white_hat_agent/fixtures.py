from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .adapters import ReplayRule, ReplayTranscript
from .expansion import ReplayExpansionTranscript
from .models import (
    AttemptOutcome,
    DiscoveryBudget,
    DiscoveryEpisode,
    DiscoveryObjective,
    DiscoveryObservation,
    EvidenceKind,
    EvidenceRecord,
    ExecutionMode,
    ExpansionTrigger,
    Hypothesis,
    HypothesisExpansionBatch,
    HypothesisFamily,
    HypothesisMeasures,
    MutationLevel,
    ProbeSpec,
    Relation,
    SurfaceEdge,
    SurfaceGraph,
    SurfaceKind,
    SurfaceNode,
    TargetIdentity,
)
from .schemas import _atomic_write

FIXTURE_TIME = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _measures(**overrides: float) -> HypothesisMeasures:
    values = {
        "objective_alignment": 0.90,
        "impact": 0.70,
        "reachability": 0.70,
        "evidence_strength": 0.55,
        "information_gain": 0.75,
        "novelty": 0.70,
        "causal_verifiability": 0.75,
        "transferability": 0.65,
        "cost": 0.10,
        "blast_radius": 0.02,
        "redundancy": 0.10,
    }
    values.update(overrides)
    return HypothesisMeasures(**values)


def _probe(action: str, expected: str, falsifier: str) -> ProbeSpec:
    return ProbeSpec(
        adapter_id="fixture-replay",
        action=action,
        parameters={"fixture": "active-data-pipeline"},
        expected_observations=[expected],
        falsifiers=[falsifier],
        required_capabilities=["artifact.read"],
        mode=ExecutionMode.OFFLINE,
        mutation_level=MutationLevel.NONE,
        max_steps=10,
        max_seconds=60,
        cost_units=1.0,
    )


def build_active_data_episode() -> DiscoveryEpisode:
    target = TargetIdentity(
        target_id="synthetic-active-data-pipeline",
        build_id="fixture-build-1",
        artifacts={"bundle.bin": _sha("fixture-bundle-v1")},
        environment_fingerprint=_sha("python-replay-environment-v1"),
    )
    objective = DiscoveryObjective(
        objective_id="discover-active-data-boundary",
        statement="Identify and causally verify an unexpected active-data execution boundary",
        success_criteria=[
            "observe the intended execution path",
            "reproduce the effect",
            "reject the same probe on a neutralized variant",
        ],
        target=target,
        allowed_capabilities=["artifact.read"],
        allowed_modes=[ExecutionMode.OFFLINE],
        maximum_mutation_level=MutationLevel.NONE,
    )
    graph = SurfaceGraph(
        revision=1,
        nodes=[
            SurfaceNode(
                node_id="n-bundle",
                kind=SurfaceKind.ARTIFACT,
                label="serialized analysis bundle",
                confidence=1.0,
                authority=0.1,
                tags=["fixture"],
            ),
            SurfaceNode(
                node_id="n-input",
                kind=SurfaceKind.INPUT,
                label="embedded active-data field",
                confidence=0.9,
                authority=0.2,
                tags=["attacker-influenced"],
            ),
            SurfaceNode(
                node_id="n-parser",
                kind=SurfaceKind.PARSER,
                label="bundle parser",
                confidence=0.8,
                authority=0.5,
            ),
        ],
        edges=[
            SurfaceEdge(
                edge_id="edge-input-parser",
                source="n-input",
                target="n-parser",
                relation=Relation.FLOWS_TO,
                confidence=0.75,
            )
        ],
    )
    hypotheses = [
        Hypothesis(
            hypothesis_id="h-external-reference",
            title="External reference resolution",
            statement="The parser resolves an embedded external reference while opening the bundle",
            family=HypothesisFamily.ACTIVE_DATA,
            anchor_node_ids=["n-input", "n-parser"],
            target_node_ids=["n-bundle"],
            measures=_measures(
                impact=0.92,
                reachability=0.90,
                evidence_strength=0.66,
                information_gain=0.90,
                novelty=0.82,
                causal_verifiability=0.88,
                redundancy=0.03,
            ),
            probe=_probe(
                "inspect-external-reference",
                "a resolver invocation tied to the embedded field",
                "no resolver path is reachable from the parser",
            ),
        ),
        Hypothesis(
            hypothesis_id="h-template-expression",
            title="Template expression evaluation",
            statement="The active-data field crosses from parsing into expression evaluation",
            family=HypothesisFamily.ACTIVE_DATA,
            anchor_node_ids=["n-input", "n-parser"],
            target_node_ids=["n-bundle"],
            measures=_measures(
                impact=0.88,
                reachability=0.86,
                evidence_strength=0.70,
                information_gain=0.87,
                novelty=0.76,
                causal_verifiability=0.94,
            ),
            probe=_probe(
                "trace-template-expression",
                "a parser-correlated evaluator trace",
                "the field remains inert data through the complete load path",
            ),
        ),
        Hypothesis(
            hypothesis_id="h-sibling-variant",
            title="Sibling parser variant",
            statement="A sibling bundle parser preserves the same active-data behavior",
            family=HypothesisFamily.VARIANT_ANALYSIS,
            anchor_node_ids=["n-parser"],
            target_node_ids=["n-bundle"],
            measures=_measures(
                impact=0.72,
                reachability=0.60,
                evidence_strength=0.48,
                information_gain=0.80,
                novelty=0.96,
                causal_verifiability=0.82,
                cost=0.16,
            ),
            probe=_probe(
                "compare-sibling-parser",
                "a structurally similar active-data sink",
                "the sibling parser never handles the field",
            ),
        ),
        Hypothesis(
            hypothesis_id="h-envelope-offset",
            title="Envelope offset confusion",
            statement="A message-envelope offset redirects parsing to an unintended active field",
            family=HypothesisFamily.PROTOCOL,
            anchor_node_ids=["n-input"],
            target_node_ids=["n-parser"],
            measures=_measures(
                impact=0.66,
                reachability=0.58,
                evidence_strength=0.40,
                information_gain=0.74,
                novelty=0.84,
                causal_verifiability=0.68,
                cost=0.20,
            ),
            probe=_probe(
                "analyze-envelope-offsets",
                "an offset discrepancy reaching the active field",
                "all envelope offsets resolve to canonical field boundaries",
            ),
        ),
    ]
    return DiscoveryEpisode(
        episode_id="episode-active-data-001",
        objective=objective,
        graph=graph,
        hypotheses=hypotheses,
        budget=DiscoveryBudget(max_attempts=12, max_iterations=12, max_cost_units=12.0),
        created_at=FIXTURE_TIME,
        updated_at=FIXTURE_TIME,
    )


def build_active_data_transcript(episode: DiscoveryEpisode | None = None) -> ReplayTranscript:
    episode = episode or build_active_data_episode()
    by_id = {item.hypothesis_id: item for item in episode.hypotheses}
    external = by_id["h-external-reference"]
    template = by_id["h-template-expression"]
    sibling = by_id["h-sibling-variant"]
    envelope = by_id["h-envelope-offset"]

    external_observation = DiscoveryObservation(
        observation_id="obs-external-negative",
        hypothesis_id=external.hypothesis_id,
        hypothesis_revision=external.revision,
        outcome=AttemptOutcome.NEGATIVE,
        summary="No resolver path was reachable; the exact external-reference hypothesis is refuted",
        progress_delta=0.02,
        conclusive=True,
        new_evidence=[
            EvidenceRecord(
                evidence_id="ev-external-negative",
                kind=EvidenceKind.STATIC,
                source_ref="fixture://bundle/parser/reference-walk",
                content_sha256=_sha("no-external-resolver-path"),
                summary="Complete reference walk contains no external resolver",
                confidence=0.96,
                captured_at=FIXTURE_TIME + timedelta(seconds=1),
            )
        ],
        cost_units=1.0,
        started_at=FIXTURE_TIME,
        observed_at=FIXTURE_TIME + timedelta(seconds=1),
    )

    causal_hypothesis = Hypothesis(
        hypothesis_id="h-template-causal-differential",
        title="Template evaluator causal differential",
        statement="Expression evaluation is the necessary cause of the observed active-data effect",
        family=HypothesisFamily.FORENSICS,
        anchor_node_ids=["n-evaluator"],
        target_node_ids=["n-bundle"],
        dependency_ids=[template.hypothesis_id],
        evidence_ids=["ev-template-trace"],
        measures=_measures(
            impact=0.90,
            reachability=0.94,
            evidence_strength=0.86,
            information_gain=0.92,
            novelty=0.74,
            causal_verifiability=1.0,
            transferability=0.82,
            cost=0.08,
            redundancy=0.02,
        ),
        probe=_probe(
            "differential-template-evaluator",
            "the effect disappears only when evaluator dispatch is neutralized",
            "the effect persists when evaluator dispatch is removed",
        ),
    )
    template_observation = DiscoveryObservation(
        observation_id="obs-template-supported",
        hypothesis_id=template.hypothesis_id,
        hypothesis_revision=template.revision,
        outcome=AttemptOutcome.SUCCEEDED,
        summary=(
            "A trace ties parsing of the field to evaluator dispatch; a causal differential is now testable"
        ),
        progress_delta=0.45,
        conclusive=True,
        new_evidence=[
            EvidenceRecord(
                evidence_id="ev-template-trace",
                kind=EvidenceKind.TRACE,
                source_ref="fixture://trace/parser-to-evaluator",
                content_sha256=_sha("parser-invokes-evaluator"),
                summary="The field reaches evaluator dispatch during bundle load",
                confidence=0.94,
                captured_at=FIXTURE_TIME + timedelta(seconds=3),
            )
        ],
        new_nodes=[
            SurfaceNode(
                node_id="n-evaluator",
                kind=SurfaceKind.INTERPRETER,
                label="template evaluator",
                confidence=0.94,
                authority=0.72,
                evidence_ids=["ev-template-trace"],
                tags=["active-data-sink"],
            )
        ],
        new_edges=[
            SurfaceEdge(
                edge_id="edge-parser-evaluator",
                source="n-parser",
                target="n-evaluator",
                relation=Relation.INVOKES,
                confidence=0.94,
                evidence_ids=["ev-template-trace"],
                hypothesis_ids=[template.hypothesis_id],
            )
        ],
        adjacent_hypotheses=[causal_hypothesis],
        cost_units=1.0,
        started_at=FIXTURE_TIME + timedelta(seconds=2),
        observed_at=FIXTURE_TIME + timedelta(seconds=3),
    )

    causal_observation = DiscoveryObservation(
        observation_id="obs-template-causal-confirmed",
        hypothesis_id=causal_hypothesis.hypothesis_id,
        hypothesis_revision=causal_hypothesis.revision,
        outcome=AttemptOutcome.SUCCEEDED,
        summary=(
            "The effect reproduces on the original and disappears when only evaluator dispatch is neutralized"
        ),
        progress_delta=0.65,
        conclusive=True,
        new_evidence=[
            EvidenceRecord(
                evidence_id="ev-template-differential",
                kind=EvidenceKind.DIFFERENTIAL,
                source_ref="fixture://differential/original-vs-neutralized",
                content_sha256=_sha("original-succeeds-neutralized-rejects"),
                summary="Matched-run differential isolates evaluator dispatch as necessary",
                confidence=0.99,
                captured_at=FIXTURE_TIME + timedelta(seconds=5),
            )
        ],
        cost_units=1.0,
        started_at=FIXTURE_TIME + timedelta(seconds=4),
        observed_at=FIXTURE_TIME + timedelta(seconds=5),
    )

    sibling_observation = DiscoveryObservation(
        observation_id="obs-sibling-negative",
        hypothesis_id=sibling.hypothesis_id,
        hypothesis_revision=sibling.revision,
        outcome=AttemptOutcome.NEGATIVE,
        summary="The sibling parser does not deserialize the active field",
        progress_delta=0.02,
        conclusive=True,
        cost_units=1.0,
        started_at=FIXTURE_TIME + timedelta(seconds=6),
        observed_at=FIXTURE_TIME + timedelta(seconds=7),
    )
    envelope_observation = DiscoveryObservation(
        observation_id="obs-envelope-negative",
        hypothesis_id=envelope.hypothesis_id,
        hypothesis_revision=envelope.revision,
        outcome=AttemptOutcome.NEGATIVE,
        summary="All envelope offsets resolve to canonical field boundaries",
        progress_delta=0.01,
        conclusive=True,
        cost_units=1.0,
        started_at=FIXTURE_TIME + timedelta(seconds=8),
        observed_at=FIXTURE_TIME + timedelta(seconds=9),
    )

    observations = [
        (external, external_observation),
        (template, template_observation),
        (causal_hypothesis, causal_observation),
        (sibling, sibling_observation),
        (envelope, envelope_observation),
    ]
    return ReplayTranscript(
        transcript_id="transcript-active-data-001",
        adapter_id="fixture-replay",
        target=episode.objective.target,
        capabilities=["artifact.read"],
        modes=[ExecutionMode.OFFLINE],
        rules=[
            ReplayRule(
                hypothesis_id=hypothesis.hypothesis_id,
                hypothesis_revision=hypothesis.revision,
                probe_digest=hypothesis.probe.digest(),
                observation=observation,
            )
            for hypothesis, observation in observations
        ],
    )


def build_stalled_recovery_fixture() -> tuple[DiscoveryEpisode, ReplayTranscript, ReplayExpansionTranscript]:
    base = build_active_data_episode()
    payload = base.model_dump(mode="python")
    payload["episode_id"] = "episode-frontier-recovery-001"
    payload["hypotheses"] = []
    stalled = DiscoveryEpisode.model_validate(payload)
    frontier = Hypothesis(
        hypothesis_id="h-parser-frontier",
        title="Unmapped parser dispatch frontier",
        statement="The highest-authority untested parser node dispatches into an unmodeled processing stage",
        family=HypothesisFamily.FORENSICS,
        anchor_node_ids=["n-parser"],
        target_node_ids=["n-bundle"],
        measures=_measures(
            impact=0.78,
            reachability=0.88,
            evidence_strength=0.62,
            information_gain=0.96,
            novelty=0.92,
            causal_verifiability=0.82,
            redundancy=0.01,
        ),
        probe=_probe(
            "map-parser-dispatch-frontier",
            "a previously unmapped parser dispatch boundary",
            "the parser has no unmodeled outgoing dispatch",
        ),
    )
    batch = HypothesisExpansionBatch(
        generator_id="fixture-frontier-generator",
        episode_id=stalled.episode_id,
        base_episode_digest=stalled.digest(),
        trigger=ExpansionTrigger.STALLED,
        hypotheses=[frontier],
        rationale=[
            "the portfolio is empty",
            "n-parser is the highest-confidence untested processing frontier",
        ],
        generated_at=FIXTURE_TIME + timedelta(seconds=1),
    )
    observation = DiscoveryObservation(
        observation_id="obs-parser-frontier-supported",
        hypothesis_id=frontier.hypothesis_id,
        hypothesis_revision=frontier.revision,
        outcome=AttemptOutcome.SUCCEEDED,
        summary="The frontier probe mapped a deterministic dispatch into a new processing stage",
        progress_delta=0.55,
        conclusive=True,
        new_evidence=[
            EvidenceRecord(
                evidence_id="ev-parser-frontier",
                kind=EvidenceKind.TRACE,
                source_ref="fixture://trace/parser-frontier",
                content_sha256=_sha("parser-frontier-dispatch"),
                summary="A bounded trace identifies the next parser dispatch",
                confidence=0.95,
                captured_at=FIXTURE_TIME + timedelta(seconds=3),
            )
        ],
        cost_units=frontier.probe.cost_units,
        started_at=FIXTURE_TIME + timedelta(seconds=2),
        observed_at=FIXTURE_TIME + timedelta(seconds=3),
    )
    replay = ReplayTranscript(
        transcript_id="transcript-frontier-recovery-001",
        adapter_id="fixture-replay",
        target=stalled.objective.target,
        capabilities=["artifact.read"],
        modes=[ExecutionMode.OFFLINE],
        rules=[
            ReplayRule(
                hypothesis_id=frontier.hypothesis_id,
                hypothesis_revision=frontier.revision,
                probe_digest=frontier.probe.digest(),
                observation=observation,
            )
        ],
    )
    expansions = ReplayExpansionTranscript(
        transcript_id="expansions-frontier-recovery-001",
        generator_id=batch.generator_id,
        batches=[batch],
    )
    return stalled, replay, expansions


def write_active_data_fixture(output_dir: Path) -> tuple[Path, Path]:
    episode = build_active_data_episode()
    transcript = build_active_data_transcript(episode)
    output_dir.mkdir(parents=True, exist_ok=True)
    episode_path = output_dir / "active-data-episode.json"
    replay_path = output_dir / "active-data-replay.json"
    _atomic_write(
        episode_path,
        json.dumps(episode.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
    )
    _atomic_write(
        replay_path,
        json.dumps(transcript.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
    )
    return episode_path, replay_path


def write_stalled_recovery_fixture(output_dir: Path) -> tuple[Path, Path, Path]:
    episode, replay, expansions = build_stalled_recovery_fixture()
    output_dir.mkdir(parents=True, exist_ok=True)
    episode_path = output_dir / "frontier-recovery-episode.json"
    replay_path = output_dir / "frontier-recovery-replay.json"
    expansion_path = output_dir / "frontier-recovery-expansions.json"
    for path, model in (
        (episode_path, episode),
        (replay_path, replay),
        (expansion_path, expansions),
    ):
        _atomic_write(
            path,
            json.dumps(model.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        )
    return episode_path, replay_path, expansion_path
