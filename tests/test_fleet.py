from __future__ import annotations

import hashlib
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
    TaskState,
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


def test_heartbeat_never_shortens_an_active_lease(tmp_path) -> None:
    store = FleetStore(tmp_path / "fleet.db")
    store.initialize()
    store.create_campaign(build_campaign())
    store.enqueue_intent("example-lab-campaign", _intent())
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
    lease = store.claim_task("http-agent", lease_seconds=600)
    assert lease is not None and lease.task.lease_expires_at is not None

    retained = store.heartbeat(
        lease.task.task_id,
        "http-agent",
        lease.lease_token,
        extend_seconds=10,
    )

    assert retained == lease.task.lease_expires_at


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


def test_active_lease_accessor_returns_current_task_and_fails_closed(tmp_path) -> None:
    store = FleetStore(tmp_path / "fleet.db")
    store.initialize()
    store.create_campaign(build_campaign())
    outcome = store.enqueue_intent("example-lab-campaign", _intent())
    assert outcome.task is not None
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
    assert lease is not None

    active = store.assert_active_lease(lease.task.task_id, "http-agent", lease.lease_token)

    assert active == store.get_task(lease.task.task_id)
    assert active.state == TaskState.LEASED
    assert active.lease_owner == "http-agent"
    assert lease.lease_token not in active.model_dump_json()
    with sqlite3.connect(store.database) as connection:
        token_digest, task_json = connection.execute(
            "SELECT lease_token_sha256, task_json FROM tasks WHERE task_id = ?",
            (lease.task.task_id,),
        ).fetchone()
    assert token_digest == hashlib.sha256(lease.lease_token.encode()).hexdigest()
    assert lease.lease_token not in task_json

    with pytest.raises(FleetError, match="invalid lease token"):
        store.assert_active_lease(lease.task.task_id, "http-agent", "wrong-token")
    with pytest.raises(FleetError, match="not leased by this agent"):
        store.assert_active_lease(lease.task.task_id, "different-agent", lease.lease_token)

    with sqlite3.connect(store.database) as connection:
        connection.execute(
            "UPDATE tasks SET lease_expires_at = ? WHERE task_id = ?",
            ((datetime.now(UTC) - timedelta(seconds=1)).isoformat(), lease.task.task_id),
        )
    with pytest.raises(FleetError, match="expired"):
        store.assert_active_lease(lease.task.task_id, "http-agent", lease.lease_token)

    with sqlite3.connect(store.database) as connection:
        connection.execute(
            "UPDATE tasks SET lease_expires_at = ? WHERE task_id = ?",
            ((datetime.now(UTC) + timedelta(seconds=60)).isoformat(), lease.task.task_id),
        )
        connection.execute(
            "UPDATE campaigns SET state = ? WHERE campaign_id = ?",
            (CampaignState.PAUSED.value, "example-lab-campaign"),
        )
    with pytest.raises(FleetError, match="campaign is not running"):
        store.assert_active_lease(lease.task.task_id, "http-agent", lease.lease_token)


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


def test_pause_revokes_leases_and_resume_issues_a_fresh_token(tmp_path) -> None:
    store = FleetStore(tmp_path / "fleet.db")
    store.initialize()
    store.create_campaign(build_campaign())
    leased_outcome = store.enqueue_intent("example-lab-campaign", _intent(), priority=100)
    queued_outcome = store.enqueue_intent(
        "example-lab-campaign",
        _intent().model_copy(update={"intent_id": "intent-http-queued", "target": "queued.example.test"}),
        priority=10,
    )
    assert leased_outcome.task is not None and queued_outcome.task is not None
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
    original_lease = store.claim_task("http-agent", lease_seconds=60)
    assert original_lease is not None
    assert original_lease.task.task_id == leased_outcome.task.task_id
    assert original_lease.task.attempts == 1

    store.set_campaign_state("example-lab-campaign", CampaignState.PAUSED)
    store.set_campaign_state("example-lab-campaign", CampaignState.PAUSED)

    requeued = store.get_task(original_lease.task.task_id)
    untouched = store.get_task(queued_outcome.task.task_id)
    assert requeued.state == TaskState.QUEUED
    assert requeued.attempts == 0
    assert requeued.lease_owner is None and requeued.lease_expires_at is None
    assert untouched.state == TaskState.QUEUED and untouched.attempts == 0
    with sqlite3.connect(store.database) as connection:
        lease_material = connection.execute(
            "SELECT lease_owner, lease_token_sha256, lease_expires_at FROM tasks WHERE task_id = ?",
            (original_lease.task.task_id,),
        ).fetchone()
        agent_status = connection.execute(
            "SELECT status FROM agents WHERE agent_id = 'http-agent'"
        ).fetchone()[0]
    assert lease_material == (None, None, None)
    assert agent_status == "online"

    with pytest.raises(FleetError, match="campaign is not running"):
        store.heartbeat(
            original_lease.task.task_id,
            "http-agent",
            original_lease.lease_token,
        )
    with pytest.raises(FleetError, match="campaign is not running"):
        store.complete_task(
            "http-agent",
            TaskResult(
                task_id=original_lease.task.task_id,
                lease_token=original_lease.lease_token,
                outcome="completed",
                summary="A revoked lease must not report while the campaign is paused.",
            ),
        )

    store.set_campaign_state("example-lab-campaign", CampaignState.RUNNING)
    resumed_lease = store.claim_task("http-agent", lease_seconds=60)
    assert resumed_lease is not None
    assert resumed_lease.task.task_id == original_lease.task.task_id
    assert resumed_lease.lease_token != original_lease.lease_token
    assert resumed_lease.task.attempts == 1
    assert (
        store.complete_task(
            "http-agent",
            TaskResult(
                task_id=resumed_lease.task.task_id,
                lease_token=resumed_lease.lease_token,
                outcome="completed",
                summary="The resumed task completed under a fresh lease.",
            ),
        )
        == TaskState.COMPLETED
    )


def test_cancel_terminalizes_queued_and_leased_tasks_but_preserves_terminal_tasks(tmp_path) -> None:
    store = FleetStore(tmp_path / "fleet.db")
    store.initialize()
    store.create_campaign(build_campaign())
    completed_outcome = store.enqueue_intent("example-lab-campaign", _intent(), priority=100)
    leased_outcome = store.enqueue_intent(
        "example-lab-campaign",
        _intent().model_copy(update={"intent_id": "intent-http-leased", "target": "leased.example.test"}),
        priority=90,
    )
    queued_outcome = store.enqueue_intent(
        "example-lab-campaign",
        _intent().model_copy(update={"intent_id": "intent-http-queued", "target": "queued.example.test"}),
        priority=80,
    )
    assert completed_outcome.task and leased_outcome.task and queued_outcome.task
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

    completed_lease = store.claim_task("http-agent", lease_seconds=60)
    assert completed_lease is not None
    store.complete_task(
        "http-agent",
        TaskResult(
            task_id=completed_lease.task.task_id,
            lease_token=completed_lease.lease_token,
            outcome="completed",
            summary="This terminal result must survive campaign cancellation.",
        ),
    )
    active_lease = store.claim_task("http-agent", lease_seconds=60)
    assert active_lease is not None
    assert active_lease.task.task_id == leased_outcome.task.task_id

    store.set_campaign_state("example-lab-campaign", CampaignState.CANCELLED)
    store.set_campaign_state("example-lab-campaign", CampaignState.CANCELLED)

    assert store.get_task(completed_outcome.task.task_id).state == TaskState.COMPLETED
    assert store.get_task(leased_outcome.task.task_id).state == TaskState.CANCELLED
    assert store.get_task(queued_outcome.task.task_id).state == TaskState.CANCELLED
    assert store.stats().cancelled == 2
    with sqlite3.connect(store.database) as connection:
        cancelled_rows = connection.execute(
            """
            SELECT lease_owner, lease_token_sha256, lease_expires_at FROM tasks
            WHERE task_id IN (?, ?) ORDER BY task_id
            """,
            (leased_outcome.task.task_id, queued_outcome.task.task_id),
        ).fetchall()
        agent_status = connection.execute(
            "SELECT status FROM agents WHERE agent_id = 'http-agent'"
        ).fetchone()[0]
        result_count = connection.execute("SELECT COUNT(*) FROM task_results").fetchone()[0]
    assert cancelled_rows == [(None, None, None), (None, None, None)]
    assert agent_status == "online"
    assert result_count == 1

    with pytest.raises(FleetError, match="campaign is not running"):
        store.heartbeat(active_lease.task.task_id, "http-agent", active_lease.lease_token)
    with pytest.raises(FleetError, match="campaign is not running"):
        store.complete_task(
            "http-agent",
            TaskResult(
                task_id=active_lease.task.task_id,
                lease_token=active_lease.lease_token,
                outcome="completed",
                summary="A cancelled lease must not report.",
            ),
        )


def test_lease_operations_fail_if_campaign_state_drifts_outside_lifecycle_api(tmp_path) -> None:
    store = FleetStore(tmp_path / "fleet.db")
    store.initialize()
    store.create_campaign(build_campaign())
    outcome = store.enqueue_intent("example-lab-campaign", _intent())
    assert outcome.task is not None
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
    assert lease is not None

    with sqlite3.connect(store.database) as connection:
        connection.execute(
            "UPDATE campaigns SET state = ? WHERE campaign_id = ?",
            (CampaignState.PAUSED.value, "example-lab-campaign"),
        )

    with pytest.raises(FleetError, match="campaign is not running"):
        store.heartbeat(lease.task.task_id, "http-agent", lease.lease_token)
    with pytest.raises(FleetError, match="campaign is not running"):
        store.complete_task(
            "http-agent",
            TaskResult(
                task_id=lease.task.task_id,
                lease_token=lease.lease_token,
                outcome="completed",
                summary="Direct state drift must fail closed.",
            ),
        )
    assert store.get_task(lease.task.task_id).state == TaskState.LEASED
    with sqlite3.connect(store.database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM task_results").fetchone()[0] == 0

    store.set_campaign_state("example-lab-campaign", CampaignState.RUNNING)
    repaired = store.get_task(lease.task.task_id)
    assert repaired.state == TaskState.QUEUED and repaired.attempts == 0
    replacement = store.claim_task("http-agent", lease_seconds=60)
    assert replacement is not None
    assert replacement.lease_token != lease.lease_token


def test_claim_refuses_legacy_queued_task_at_attempt_limit(tmp_path) -> None:
    store = FleetStore(tmp_path / "fleet.db")
    store.initialize()
    store.create_campaign(build_campaign())
    outcome = store.enqueue_intent("example-lab-campaign", _intent())
    assert outcome.task is not None
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
    with sqlite3.connect(store.database) as connection:
        connection.execute(
            "UPDATE tasks SET attempts = max_attempts WHERE task_id = ?",
            (outcome.task.task_id,),
        )

    assert store.claim_task("http-agent", lease_seconds=60) is None
    assert store.get_task(outcome.task.task_id).state == TaskState.FAILED


def test_cancelling_one_campaign_does_not_disturb_another_campaign_lease(tmp_path) -> None:
    store = FleetStore(tmp_path / "fleet.db")
    store.initialize()
    store.create_campaign(build_campaign())
    other_campaign = build_campaign().model_copy(
        update={"campaign_id": "other-lab-campaign", "name": "Other synthetic campaign"}
    )
    store.create_campaign(other_campaign)
    first = store.enqueue_intent("example-lab-campaign", _intent(), priority=100)
    other = store.enqueue_intent("other-lab-campaign", _intent(), priority=90)
    assert first.task is not None and other.task is not None
    store.register_agent(
        AgentRegistration(
            agent_id="shared-agent",
            display_name="Shared HTTP fixture adapter",
            provider="fixture",
            capabilities=["http.request", "http.capture", "data.diff", "evidence.write"],
            max_execution_class=ExecutionClass.CONTROLLED_ACTIVE,
            max_concurrency=2,
        )
    )
    for campaign_id in ("example-lab-campaign", "other-lab-campaign"):
        store.set_campaign_state(campaign_id, CampaignState.READY)
        store.set_campaign_state(campaign_id, CampaignState.RUNNING)
    first_lease = store.claim_task("shared-agent", lease_seconds=60)
    other_lease = store.claim_task("shared-agent", lease_seconds=60)
    assert first_lease is not None and other_lease is not None
    assert first_lease.task.task_id == first.task.task_id
    assert other_lease.task.task_id == other.task.task_id

    store.set_campaign_state("example-lab-campaign", CampaignState.CANCELLED)

    assert store.get_task(first.task.task_id).state == TaskState.CANCELLED
    unaffected = store.get_task(other.task.task_id)
    assert unaffected.state == TaskState.LEASED
    assert unaffected.lease_owner == "shared-agent"
    with sqlite3.connect(store.database) as connection:
        assert (
            connection.execute("SELECT status FROM agents WHERE agent_id = 'shared-agent'").fetchone()[0]
            == "busy"
        )
    assert store.heartbeat(other_lease.task.task_id, "shared-agent", other_lease.lease_token)
