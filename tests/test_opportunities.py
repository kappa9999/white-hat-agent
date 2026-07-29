from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from white_hat_agent.campaign.fleet import FleetStore
from white_hat_agent.campaign.models import (
    Opportunity,
    OpportunityState,
    ProgramKind,
    TargetKind,
)
from white_hat_agent.campaign.opportunities import rank_opportunities
from white_hat_agent.knowledge.corpus import Corpus
from white_hat_agent.knowledge.models import ExecutionClass

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 7, 29, 12, tzinfo=UTC)


def _opportunity(**changes) -> Opportunity:
    values = {
        "opportunity_id": "example-public-program",
        "program_kind": ProgramKind.CUSTOM,
        "title": "Example public program",
        "program_url": "https://example.test/security",
        "scope_reference": "https://example.test/security/scope",
        "scope_snapshot_digest": "2" * 64,
        "automation_permitted": True,
        "target_kinds": [TargetKind.URL, TargetKind.API],
        "domains": ["web", "api"],
        "required_capabilities": ["http.request", "http.capture"],
        "allowed_execution_classes": [ExecutionClass.CONTROLLED_ACTIVE],
        "strategic_priority": 0.8,
        "discovered_at": NOW - timedelta(days=1),
        "last_verified_at": NOW,
        "expires_at": NOW + timedelta(days=30),
    }
    values.update(changes)
    return Opportunity(**values)


def test_opportunity_ranking_explains_fit_and_blocks_expired_items() -> None:
    corpus = Corpus(REPOSITORY_ROOT / "corpus" / "playbooks")
    assert corpus.load().valid
    strong = _opportunity()
    incomplete = _opportunity(
        opportunity_id="uncaptured-program",
        scope_snapshot_digest=None,
        automation_permitted=False,
        domains=["hardware"],
        required_capabilities=["hardware.debug"],
        strategic_priority=0.2,
    )
    expired = _opportunity(
        opportunity_id="expired-program",
        discovered_at=NOW - timedelta(days=10),
        expires_at=NOW - timedelta(days=1),
    )

    ranked = rank_opportunities(
        [incomplete, expired, strong],
        corpus,
        ["http.request", "http.capture"],
        evaluated_at=NOW,
    )

    assert ranked[0].opportunity.opportunity_id == strong.opportunity_id
    assert ranked[0].capability_coverage == 1
    assert ranked[-1].opportunity.opportunity_id == expired.opportunity_id
    assert ranked[-1].score == 0
    assert "opportunity has expired" in ranked[-1].blockers
    assert any("scope rules" in blocker for blocker in ranked[1].blockers)


def test_opportunity_store_is_idempotent_and_stateful(tmp_path) -> None:
    store = FleetStore(tmp_path / "fleet.db")
    store.initialize()
    opportunity = _opportunity()

    store.add_opportunity(opportunity)
    store.add_opportunity(opportunity)
    triaged = store.set_opportunity_state(opportunity.opportunity_id, OpportunityState.TRIAGED)

    assert triaged.state == OpportunityState.TRIAGED
    assert store.get_opportunity(opportunity.opportunity_id).state == OpportunityState.TRIAGED
    assert store.list_opportunities(OpportunityState.TRIAGED) == [triaged]
