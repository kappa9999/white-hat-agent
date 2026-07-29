from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest
from conftest import build_scope

from white_hat_agent.campaign.contracts import validate_campaign_manifest
from white_hat_agent.campaign.models import CampaignObjective, ScopeManifest
from white_hat_agent.campaign.planning import (
    CampaignPlanningRequest,
    CampaignTarget,
    plan_campaign,
)
from white_hat_agent.knowledge.corpus import Corpus
from white_hat_agent.knowledge.models import ExecutionClass

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
FULL_CAPABILITIES = [
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
    corpus = Corpus(REPOSITORY_ROOT / "corpus/playbooks")
    assert corpus.load().valid
    return corpus


def _request(scope: ScopeManifest) -> CampaignPlanningRequest:
    return CampaignPlanningRequest(
        campaign_id="planned-http-campaign",
        name="Planned HTTP verification",
        scope=scope,
        objective=CampaignObjective(
            statement="Map an HTTP surface and causally verify candidate mechanisms",
            success_criteria=["Produce a finding with differential evidence"],
            desired_artifacts=["finding/verified"],
            priority_domains=["web", "api"],
        ),
        targets=[
            CampaignTarget(
                target_id="example-api",
                kind="url",
                value="https://api.example.test/v1",
                technologies=["http"],
            )
        ],
        available_capabilities=FULL_CAPABILITIES,
        execution_ceiling=ExecutionClass.STATE_CHANGING,
    )


def test_campaign_planner_builds_scope_checked_staged_blueprint() -> None:
    scope_payload = build_scope().model_dump(mode="json")
    scope_payload["allowed_execution_classes"].append(ExecutionClass.STATE_CHANGING.value)
    scope_payload["allowed_capabilities"] = FULL_CAPABILITIES
    scope = ScopeManifest.model_validate(scope_payload)

    blueprint = plan_campaign(_corpus(), _request(scope))

    assert blueprint.complete
    assert blueprint.manifest.corpus_manifest_digest == _corpus().manifest().manifest_digest
    assert blueprint.manifest.selected_playbooks == [
        "causal-differential-verification",
        "http-response-surface-map",
    ]
    stages = blueprint.targets[0].stages
    assert [stage.playbook_id for stage in stages] == [
        "http-response-surface-map",
        "causal-differential-verification",
    ]
    assert stages[0].depends_on == []
    assert stages[1].depends_on == [stages[0].stage_id]
    assert all(stage.scope_decision.allowed for stage in stages)


def test_campaign_planner_exposes_scope_and_capability_blockers() -> None:
    blueprint = plan_campaign(_corpus(), _request(build_scope()))

    assert not blueprint.complete
    assert blueprint.blockers
    assert any("execution class" in blocker for blocker in blueprint.blockers)
    assert any("capabilities" in blocker for blocker in blueprint.blockers)


def test_blueprint_identity_includes_the_exact_evaluation_time() -> None:
    scope_payload = build_scope().model_dump(mode="json")
    scope_payload["allowed_execution_classes"].append(ExecutionClass.STATE_CHANGING.value)
    scope_payload["allowed_capabilities"] = FULL_CAPABILITIES
    scope = ScopeManifest.model_validate(scope_payload)
    request = _request(scope)

    first = plan_campaign(_corpus(), request)
    repeated = plan_campaign(_corpus(), request)
    later = plan_campaign(
        _corpus(),
        request.model_copy(update={"requested_at": request.requested_at + timedelta(seconds=1)}),
    )

    assert first.blueprint_id == repeated.blueprint_id
    assert first.blueprint_id != later.blueprint_id


def test_campaign_contract_snapshot_must_match_the_exact_corpus_playbook() -> None:
    scope_payload = build_scope().model_dump(mode="json")
    scope_payload["allowed_execution_classes"].append(ExecutionClass.STATE_CHANGING.value)
    scope_payload["allowed_capabilities"] = FULL_CAPABILITIES
    request = _request(ScopeManifest.model_validate(scope_payload))
    corpus = _corpus()
    manifest = plan_campaign(corpus, request).manifest
    validate_campaign_manifest(corpus, manifest)

    manifest.playbook_contracts[0].capabilities = []
    with pytest.raises(ValueError, match="does not match corpus"):
        validate_campaign_manifest(corpus, manifest)
