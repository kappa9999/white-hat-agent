from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta

import pytest
from conftest import build_campaign

from white_hat_agent.campaign.fleet import FleetError, FleetStore
from white_hat_agent.campaign.models import (
    AgentRegistration,
    CampaignState,
    ProbeIntent,
    TargetKind,
    TaskResult,
)
from white_hat_agent.knowledge.learning import submission_from_learning
from white_hat_agent.knowledge.models import ExecutionClass, ReviewState, RightsDeclaration


def _intent(*, cost: float = 1.0) -> ProbeIntent:
    return ProbeIntent(
        intent_id="intent-http-map",
        scope_id="example-lab-scope",
        target_kind=TargetKind.DOMAIN,
        target="api.example.test",
        playbook_id="http-response-surface-map",
        playbook_version="1.0.0",
        playbook_digest="2" * 64,
        execution_class=ExecutionClass.CONTROLLED_ACTIVE,
        capabilities=["http.request", "http.capture", "data.diff", "evidence.write"],
        action_tags=["active-probing"],
        estimated_requests=4,
        estimated_cost_units=cost,
    )


def test_scope_bound_deduplicated_lease_and_result_lifecycle(tmp_path) -> None:
    store = FleetStore(tmp_path / "fleet.db")
    store.initialize()
    store.create_campaign(build_campaign())

    first = store.enqueue_intent("example-lab-campaign", _intent())
    duplicate = store.enqueue_intent("example-lab-campaign", _intent())
    assert first.accepted and first.task is not None
    assert duplicate.duplicate and not duplicate.accepted
    assert duplicate.task == first.task
    assert first.task.intent_digest == first.decision.intent_digest
    assert first.task.scope_decision_id == first.decision.decision_id

    store.register_agent(
        AgentRegistration(
            agent_id="incompatible-agent",
            display_name="No HTTP adapter",
            provider="fixture",
            capabilities=["evidence.write"],
            max_execution_class=ExecutionClass.READ_ONLY,
        )
    )
    store.register_agent(
        AgentRegistration(
            agent_id="http-agent",
            display_name="HTTP fixture adapter",
            provider="fixture",
            capabilities=["http.request", "http.capture", "data.diff", "evidence.write"],
            max_execution_class=ExecutionClass.CONTROLLED_ACTIVE,
        )
    )

    assert store.claim_task("http-agent") is None
    store.set_campaign_state("example-lab-campaign", CampaignState.READY)
    assert store.claim_task("http-agent") is None
    store.set_campaign_state("example-lab-campaign", CampaignState.RUNNING)
    assert store.claim_task("incompatible-agent") is None

    lease = store.claim_task("http-agent", lease_seconds=60)
    assert lease is not None
    assert lease.task.task_id == first.task.task_id

    with sqlite3.connect(store.database) as connection:
        token_hash, decision_json, intent_json = connection.execute(
            "SELECT lease_token_sha256, scope_decision_json, intent_json FROM tasks"
        ).fetchone()
    assert lease.lease_token not in token_hash
    assert first.decision.intent_digest in decision_json
    assert _intent().intent_id in intent_json

    state = store.complete_task(
        "http-agent",
        TaskResult(
            task_id=lease.task.task_id,
            lease_token=lease.lease_token,
            outcome="completed",
            summary="Synthetic HTTP surface captured",
            evidence_ids=["evidence-fixture-http"],
            reusable_learning={
                "title": "Normalize volatile response identifiers",
                "method": "Remove only fields proven volatile across clean baselines.",
            },
        ),
    )
    assert state.value == "completed"
    stats = store.stats()
    assert stats.completed == 1 and stats.leased == 0
    candidates = store.learning_candidates(campaign_id="example-lab-campaign")
    assert len(candidates) == 1
    assert candidates[0].learning["title"] == "Normalize volatile response identifiers"
    submission = submission_from_learning(
        candidates[0],
        rights=RightsDeclaration.ORIGINAL,
        contributor="fixture-contributor",
    )
    assert submission.submission_id.startswith("submission-")
    assert "Remove only fields" in submission.original_text


def test_campaign_budget_and_transition_invariants(tmp_path) -> None:
    store = FleetStore(tmp_path / "fleet.db")
    store.initialize()
    store.create_campaign(build_campaign(max_tasks=1, max_cost=1.5))
    assert store.enqueue_intent("example-lab-campaign", _intent(cost=1.0)).accepted

    second = _intent(cost=1.0).model_copy(
        update={"intent_id": "intent-http-second", "target": "other.example.test"}
    )
    with pytest.raises(FleetError, match="task budget"):
        store.enqueue_intent("example-lab-campaign", second)

    with pytest.raises(FleetError, match="invalid campaign transition"):
        store.set_campaign_state("example-lab-campaign", CampaignState.COMPLETED)


def test_rejected_scope_intent_is_never_persisted(tmp_path) -> None:
    store = FleetStore(tmp_path / "fleet.db")
    store.initialize()
    store.create_campaign(build_campaign())
    rejected = _intent().model_copy(update={"target": "outside.invalid"})

    outcome = store.enqueue_intent("example-lab-campaign", rejected)

    assert not outcome.accepted and not outcome.duplicate and not outcome.decision.allowed
    assert store.stats().queued == 0


def test_expired_lease_cannot_be_bypassed_with_reported_completion_time(tmp_path) -> None:
    store = FleetStore(tmp_path / "fleet.db")
    store.initialize()
    store.create_campaign(build_campaign())
    outcome = store.enqueue_intent("example-lab-campaign", _intent())
    store.register_agent(
        AgentRegistration(
            agent_id="http-agent",
            display_name="HTTP fixture adapter",
            provider="fixture",
            capabilities=["http.request", "http.capture", "data.diff", "evidence.write"],
            max_execution_class=ExecutionClass.CONTROLLED_ACTIVE,
        )
    )
    store.set_campaign_state("example-lab-campaign", CampaignState.READY)
    store.set_campaign_state("example-lab-campaign", CampaignState.RUNNING)
    lease = store.claim_task("http-agent", lease_seconds=60)
    assert lease is not None and outcome.task is not None
    expired_at = datetime.now(UTC) - timedelta(seconds=1)
    with sqlite3.connect(store.database) as connection:
        connection.execute(
            "UPDATE tasks SET lease_expires_at = ? WHERE task_id = ?",
            (expired_at.isoformat(), lease.task.task_id),
        )

    with pytest.raises(FleetError, match="expired"):
        store.complete_task(
            "http-agent",
            TaskResult(
                task_id=lease.task.task_id,
                lease_token=lease.lease_token,
                outcome="completed",
                summary="A stale reported timestamp must not revive the lease.",
                completed_at=expired_at - timedelta(seconds=10),
            ),
        )


def test_campaign_rejects_under_declared_or_unselected_playbooks(tmp_path) -> None:
    store = FleetStore(tmp_path / "fleet.db")
    store.initialize()
    store.create_campaign(build_campaign())

    under_declared = _intent().model_copy(update={"capabilities": ["http.request"]})
    with pytest.raises(FleetError, match="omits playbook capabilities"):
        store.enqueue_intent("example-lab-campaign", under_declared)

    unselected = _intent().model_copy(
        update={
            "intent_id": "intent-unselected-playbook",
            "playbook_id": "different-playbook",
            "playbook_digest": "3" * 64,
        }
    )
    with pytest.raises(FleetError, match="not selected"):
        store.enqueue_intent("example-lab-campaign", unselected)
    assert store.stats().queued == 0


def test_new_campaign_must_start_draft_and_wall_budget_starts_on_first_run(tmp_path) -> None:
    store = FleetStore(tmp_path / "fleet.db")
    store.initialize()
    running = build_campaign().model_copy(update={"state": CampaignState.RUNNING})
    with pytest.raises(FleetError, match="start in draft"):
        store.create_campaign(running)

    draft_contract = build_campaign()
    draft_contract.playbook_contracts[0].review_state = ReviewState.DRAFT
    with pytest.raises(FleetError, match="not reviewed"):
        store.create_campaign(draft_contract)

    old_manifest = build_campaign().model_copy(update={"created_at": datetime.now(UTC) - timedelta(days=30)})
    store.create_campaign(old_manifest)
    assert store.enqueue_intent("example-lab-campaign", _intent()).accepted
    store.set_campaign_state("example-lab-campaign", CampaignState.READY)
    store.set_campaign_state("example-lab-campaign", CampaignState.RUNNING)
    with sqlite3.connect(store.database) as connection:
        connection.execute(
            "UPDATE campaigns SET started_at = ? WHERE campaign_id = ?",
            (
                (datetime.now(UTC) - timedelta(hours=2)).isoformat(),
                "example-lab-campaign",
            ),
        )
    second = _intent().model_copy(
        update={"intent_id": "intent-after-wall-budget", "target": "later.example.test"}
    )
    with pytest.raises(FleetError, match="wall-time budget"):
        store.enqueue_intent("example-lab-campaign", second)


def test_agent_max_concurrency_is_enforced(tmp_path) -> None:
    store = FleetStore(tmp_path / "fleet.db")
    store.initialize()
    store.create_campaign(build_campaign())
    first = store.enqueue_intent("example-lab-campaign", _intent())
    second_intent = _intent().model_copy(
        update={"intent_id": "intent-http-second", "target": "other.example.test"}
    )
    second = store.enqueue_intent("example-lab-campaign", second_intent)
    assert first.accepted and second.accepted
    store.register_agent(
        AgentRegistration(
            agent_id="bounded-agent",
            display_name="Bounded HTTP adapter",
            provider="fixture",
            capabilities=["http.request", "http.capture", "data.diff", "evidence.write"],
            max_execution_class=ExecutionClass.CONTROLLED_ACTIVE,
            max_concurrency=1,
        )
    )
    store.set_campaign_state("example-lab-campaign", CampaignState.READY)
    store.set_campaign_state("example-lab-campaign", CampaignState.RUNNING)

    assert store.claim_task("bounded-agent", lease_seconds=60) is not None
    assert store.claim_task("bounded-agent", lease_seconds=60) is None
