from __future__ import annotations

import tempfile
from pathlib import Path

import yaml

from white_hat_agent.campaign.contracts import validate_campaign_manifest
from white_hat_agent.campaign.fleet import FleetStore
from white_hat_agent.campaign.models import (
    AgentRegistration,
    CampaignManifest,
    Opportunity,
    ProbeIntent,
    ScopeManifest,
)
from white_hat_agent.campaign.planning import CampaignPlanningRequest, plan_campaign
from white_hat_agent.campaign.scope import evaluate_scope
from white_hat_agent.evidence.models import EvidenceDescriptor
from white_hat_agent.knowledge.compose import CompositionRequest, compose_playbooks
from white_hat_agent.knowledge.corpus import Corpus


def load(path: Path) -> dict:
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"example is not a mapping: {path}")
    return payload


if __name__ == "__main__":
    root = Path(__file__).resolve().parents[1]
    examples = root / "examples"
    scope = ScopeManifest.model_validate(load(examples / "campaigns/lab-scope.yaml"))
    intent = ProbeIntent.model_validate(load(examples / "campaigns/http-intent.yaml"))
    campaign = CampaignManifest.model_validate(load(examples / "campaigns/lab-campaign.yaml"))
    AgentRegistration.model_validate(load(examples / "agents/http-agent.yaml"))
    Opportunity.model_validate(load(examples / "opportunities/example-program.yaml"))
    EvidenceDescriptor.model_validate(load(examples / "evidence/http-descriptor.yaml"))
    request = CompositionRequest.model_validate(load(examples / "composition/web-to-verified.yaml"))
    planning_request = CampaignPlanningRequest.model_validate(
        load(examples / "campaigns/planning-request.yaml")
    )

    corpus = Corpus(root / "corpus/playbooks")
    report = corpus.load()
    if not report.valid:
        raise ValueError(report)
    validate_campaign_manifest(corpus, campaign)
    if not evaluate_scope(scope, intent).allowed:
        raise ValueError("example intent is not allowed by example scope")
    if not compose_playbooks(corpus, request).complete:
        raise ValueError("example composition is incomplete")
    blueprint = plan_campaign(corpus, planning_request)
    if not blueprint.complete:
        raise ValueError(f"example campaign plan is incomplete: {blueprint.blockers}")
    if len(blueprint.targets) != 1 or len(blueprint.targets[0].stages) != 2:
        raise ValueError("example campaign plan should contain one target and two stages")
    with tempfile.TemporaryDirectory(prefix="white-hat-agent-examples-") as temporary:
        fleet = FleetStore(Path(temporary) / "fleet.db")
        fleet.initialize()
        fleet.create_campaign(campaign)
        if not fleet.enqueue_intent(campaign.campaign_id, intent).accepted:
            raise ValueError("example intent was not accepted by its campaign contract")
    print("examples validate")
