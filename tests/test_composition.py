from __future__ import annotations

from pathlib import Path

import yaml

from white_hat_agent.knowledge.compose import CompositionRequest, compose_playbooks
from white_hat_agent.knowledge.corpus import Corpus
from white_hat_agent.knowledge.models import ExecutionClass, ReviewState

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
HTTP_AND_VERIFICATION_CAPABILITIES = [
    "http.request",
    "http.capture",
    "data.diff",
    "evidence.write",
    "experiment.replay",
    "evidence.capture",
    "trace.capture",
    "experiment.intervene",
    "finding.write",
]


def _corpus() -> Corpus:
    corpus = Corpus(REPOSITORY_ROOT / "corpus" / "playbooks")
    assert corpus.load().valid
    return corpus


def test_composer_chains_surface_mapping_into_causal_verification() -> None:
    request = CompositionRequest(
        objective="Map an HTTP surface and causally verify any finding",
        target_kind="url",
        domains=["web"],
        technologies=["http"],
        available_capabilities=HTTP_AND_VERIFICATION_CAPABILITIES,
        desired_artifacts=["finding/verified"],
        execution_ceiling=ExecutionClass.STATE_CHANGING,
    )

    result = compose_playbooks(_corpus(), request)

    assert result.complete
    assert [item.playbook_id for item in result.selected] == [
        "http-response-surface-map",
        "causal-differential-verification",
    ]
    assert "finding/verified" in result.available_artifacts
    assert [step.sequence for step in result.steps] == list(range(1, len(result.steps) + 1))


def test_composer_exposes_missing_capability_as_unresolved_frontier() -> None:
    request = CompositionRequest(
        objective="Verify a candidate",
        target_kind="url",
        available_capabilities=["http.request"],
        desired_artifacts=["finding/verified"],
        execution_ceiling=ExecutionClass.STATE_CHANGING,
    )

    result = compose_playbooks(_corpus(), request)

    assert not result.complete
    assert result.selected == []
    assert result.unresolved_artifacts == ["finding/verified"]
    assert "missing artifact producers" in " ".join(result.rationale)


def test_unreviewed_playbook_requires_explicit_non_campaign_composition(tmp_path) -> None:
    source = _corpus().get("http-response-surface-map")
    payload = source.model_dump(mode="json")
    payload["metadata"]["review_state"] = "draft"
    payload["validation"] = {}
    (tmp_path / "draft.yaml").write_text(
        yaml.safe_dump(payload, sort_keys=False),
        encoding="utf-8",
    )
    corpus = Corpus(tmp_path)
    assert corpus.load().valid
    base = dict(
        objective="Map an HTTP surface",
        target_kind="url",
        available_capabilities=["http.request", "http.capture", "data.diff", "evidence.write"],
        desired_artifacts=["finding/candidate"],
        execution_ceiling=ExecutionClass.CONTROLLED_ACTIVE,
    )

    default_result = compose_playbooks(corpus, CompositionRequest(**base))
    review_result = compose_playbooks(
        corpus,
        CompositionRequest(**base, allowed_review_states=[ReviewState.DRAFT]),
    )

    assert not default_result.complete and default_result.selected == []
    assert review_result.complete and review_result.selected[0].playbook_id == source.metadata.playbook_id
