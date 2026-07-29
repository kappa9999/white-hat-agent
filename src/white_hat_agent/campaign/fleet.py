from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

from ..knowledge.models import EXECUTION_CLASS_RANK, ReviewState
from ..models import StrictModel, stable_digest, stable_id
from .models import (
    AgentRegistration,
    CampaignManifest,
    CampaignPlaybookContract,
    CampaignState,
    EnqueueOutcome,
    FleetTask,
    LearningCandidate,
    Opportunity,
    OpportunityState,
    ProbeIntent,
    ScopeDecision,
    TaskLease,
    TaskResult,
    TaskState,
)
from .scope import evaluate_scope


class FleetError(RuntimeError):
    """Fleet state or lease invariant failed."""


_CAMPAIGN_TRANSITIONS: dict[CampaignState, set[CampaignState]] = {
    CampaignState.DRAFT: {CampaignState.READY, CampaignState.CANCELLED},
    CampaignState.READY: {CampaignState.RUNNING, CampaignState.PAUSED, CampaignState.CANCELLED},
    CampaignState.RUNNING: {
        CampaignState.PAUSED,
        CampaignState.COMPLETED,
        CampaignState.CANCELLED,
    },
    CampaignState.PAUSED: {
        CampaignState.READY,
        CampaignState.RUNNING,
        CampaignState.CANCELLED,
    },
    CampaignState.COMPLETED: set(),
    CampaignState.CANCELLED: set(),
}


class FleetStats(StrictModel):
    campaigns: int
    agents: int
    queued: int
    leased: int
    completed: int
    failed: int
    blocked: int
    cancelled: int


class FleetStore:
    """Small SQLite coordination plane with atomic leases and deduplication."""

    def __init__(self, database: Path) -> None:
        self.database = database.resolve()

    def initialize(self) -> None:
        self.database.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS campaigns (
                    campaign_id TEXT PRIMARY KEY,
                    state TEXT NOT NULL,
                    manifest_json TEXT NOT NULL,
                    manifest_digest TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    started_at TEXT
                );
                CREATE TABLE IF NOT EXISTS agents (
                    agent_id TEXT PRIMARY KEY,
                    registration_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS opportunities (
                    opportunity_id TEXT PRIMARY KEY,
                    state TEXT NOT NULL,
                    opportunity_json TEXT NOT NULL,
                    opportunity_digest TEXT NOT NULL,
                    discovered_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_opportunities_state
                    ON opportunities(state, updated_at DESC);
                CREATE TABLE IF NOT EXISTS tasks (
                    task_id TEXT PRIMARY KEY,
                    campaign_id TEXT NOT NULL REFERENCES campaigns(campaign_id),
                    task_json TEXT NOT NULL,
                    intent_json TEXT NOT NULL,
                    scope_decision_json TEXT NOT NULL,
                    dedup_key TEXT NOT NULL UNIQUE,
                    state TEXT NOT NULL,
                    priority INTEGER NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    max_attempts INTEGER NOT NULL DEFAULT 3,
                    estimated_cost_units REAL NOT NULL DEFAULT 0,
                    lease_owner TEXT,
                    lease_token_sha256 TEXT,
                    lease_expires_at TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_tasks_claim
                    ON tasks(state, priority DESC, created_at ASC);
                CREATE TABLE IF NOT EXISTS task_results (
                    result_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_id TEXT NOT NULL REFERENCES tasks(task_id),
                    agent_id TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    completed_at TEXT NOT NULL
                );
                """
            )
            self._migrate(connection)

    def add_opportunity(self, opportunity: Opportunity) -> None:
        payload = json.dumps(opportunity.model_dump(mode="json"), sort_keys=True)
        now = _iso(datetime.now(UTC))
        with self._connect() as connection:
            existing = connection.execute(
                "SELECT opportunity_digest FROM opportunities WHERE opportunity_id = ?",
                (opportunity.opportunity_id,),
            ).fetchone()
            if existing:
                if existing["opportunity_digest"] != opportunity.digest():
                    raise FleetError("opportunity id already exists with different content")
                return
            connection.execute(
                """
                INSERT INTO opportunities(
                    opportunity_id, state, opportunity_json, opportunity_digest,
                    discovered_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    opportunity.opportunity_id,
                    opportunity.state.value,
                    payload,
                    opportunity.digest(),
                    _iso(opportunity.discovered_at),
                    now,
                ),
            )

    def set_opportunity_state(self, opportunity_id: str, state: OpportunityState) -> Opportunity:
        with self._connect() as connection:
            changed = connection.execute(
                "UPDATE opportunities SET state = ?, updated_at = ? WHERE opportunity_id = ?",
                (state.value, _iso(datetime.now(UTC)), opportunity_id),
            ).rowcount
            if changed != 1:
                raise FleetError(f"unknown opportunity: {opportunity_id}")
        return self.get_opportunity(opportunity_id)

    def get_opportunity(self, opportunity_id: str) -> Opportunity:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT opportunity_json, state FROM opportunities WHERE opportunity_id = ?",
                (opportunity_id,),
            ).fetchone()
        if not row:
            raise FleetError(f"unknown opportunity: {opportunity_id}")
        opportunity = Opportunity.model_validate_json(row["opportunity_json"])
        opportunity.state = OpportunityState(row["state"])
        return opportunity

    def list_opportunities(
        self,
        state: OpportunityState | None = None,
        *,
        limit: int = 100,
    ) -> list[Opportunity]:
        if limit < 1 or limit > 1000:
            raise ValueError("limit must be between 1 and 1000")
        query = "SELECT opportunity_json, state FROM opportunities"
        parameters: list[str | int] = []
        if state is not None:
            query += " WHERE state = ?"
            parameters.append(state.value)
        query += " ORDER BY updated_at DESC, opportunity_id LIMIT ?"
        parameters.append(limit)
        with self._connect() as connection:
            rows = connection.execute(query, parameters).fetchall()
        opportunities = []
        for row in rows:
            opportunity = Opportunity.model_validate_json(row["opportunity_json"])
            opportunity.state = OpportunityState(row["state"])
            opportunities.append(opportunity)
        return opportunities

    def create_campaign(self, manifest: CampaignManifest) -> None:
        if manifest.state != CampaignState.DRAFT:
            raise FleetError("new campaigns must start in draft state")
        unreviewed = [
            item.playbook_id
            for item in manifest.playbook_contracts
            if item.review_state not in {ReviewState.REVIEWED, ReviewState.VALIDATED}
        ]
        if unreviewed:
            raise FleetError(f"campaign playbooks are not reviewed: {sorted(unreviewed)}")
        payload = json.dumps(manifest.model_dump(mode="json"), sort_keys=True)
        with self._connect() as connection:
            existing = connection.execute(
                "SELECT manifest_digest FROM campaigns WHERE campaign_id = ?",
                (manifest.campaign_id,),
            ).fetchone()
            if existing:
                if existing["manifest_digest"] != manifest.digest():
                    raise FleetError("campaign id already exists with a different manifest")
                return
            connection.execute(
                "INSERT INTO campaigns("
                "campaign_id, state, manifest_json, manifest_digest, created_at, started_at"
                ") VALUES (?, ?, ?, ?, ?, NULL)",
                (
                    manifest.campaign_id,
                    manifest.state.value,
                    payload,
                    manifest.digest(),
                    _iso(manifest.created_at),
                ),
            )

    def set_campaign_state(self, campaign_id: str, state: CampaignState) -> None:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT state FROM campaigns WHERE campaign_id = ?",
                (campaign_id,),
            ).fetchone()
            if not row:
                raise FleetError(f"unknown campaign: {campaign_id}")
            current = CampaignState(row["state"])
            if state == current:
                now = datetime.now(UTC)
                affected_agents: set[str] = set()
                if state == CampaignState.PAUSED:
                    affected_agents = self._requeue_campaign_leases(
                        connection,
                        campaign_id,
                        now,
                    )
                elif state == CampaignState.CANCELLED:
                    affected_agents = self._cancel_campaign_work(
                        connection,
                        campaign_id,
                        now,
                    )
                self._release_idle_agents(connection, affected_agents, now)
                return
            allowed = _CAMPAIGN_TRANSITIONS[current]
            if state not in allowed:
                raise FleetError(f"invalid campaign transition: {current.value} -> {state.value}")
            if state == CampaignState.COMPLETED:
                active = connection.execute(
                    "SELECT COUNT(*) AS count FROM tasks WHERE campaign_id = ? AND state IN (?, ?)",
                    (campaign_id, TaskState.QUEUED.value, TaskState.LEASED.value),
                ).fetchone()["count"]
                if active:
                    raise FleetError("cannot complete a campaign with queued or leased tasks")
            now = datetime.now(UTC)
            affected_agents: set[str] = set()
            if state in {CampaignState.PAUSED, CampaignState.RUNNING}:
                # An operator pause revokes, rather than consumes, the active attempt. Sweeping
                # again before resume also repairs legacy or externally drifted paused state.
                affected_agents = self._requeue_campaign_leases(connection, campaign_id, now)
            elif state == CampaignState.CANCELLED:
                affected_agents = self._cancel_campaign_work(connection, campaign_id, now)
            if state == CampaignState.RUNNING:
                changed = connection.execute(
                    "UPDATE campaigns SET state = ?, started_at = COALESCE(started_at, ?) "
                    "WHERE campaign_id = ?",
                    (state.value, _iso(now), campaign_id),
                ).rowcount
            else:
                changed = connection.execute(
                    "UPDATE campaigns SET state = ? WHERE campaign_id = ?",
                    (state.value, campaign_id),
                ).rowcount
            if changed != 1:  # pragma: no cover - guarded above
                raise FleetError(f"campaign state update failed: {campaign_id}")
            self._release_idle_agents(connection, affected_agents, now)

    def get_campaign(self, campaign_id: str) -> CampaignManifest:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT manifest_json, state FROM campaigns WHERE campaign_id = ?",
                (campaign_id,),
            ).fetchone()
        if not row:
            raise FleetError(f"unknown campaign: {campaign_id}")
        manifest = CampaignManifest.model_validate_json(row["manifest_json"])
        manifest.state = CampaignState(row["state"])
        return manifest

    def get_task(self, task_id: str) -> FleetTask:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT task_json, state, attempts, lease_owner, lease_expires_at
                FROM tasks WHERE task_id = ?
                """,
                (task_id,),
            ).fetchone()
        if not row:
            raise FleetError(f"unknown task: {task_id}")
        task = FleetTask.model_validate_json(row["task_json"])
        task.state = TaskState(row["state"])
        task.attempts = int(row["attempts"])
        task.lease_owner = row["lease_owner"]
        task.lease_expires_at = (
            datetime.fromisoformat(row["lease_expires_at"]) if row["lease_expires_at"] else None
        )
        return task

    def register_agent(self, registration: AgentRegistration) -> None:
        now = _iso(datetime.now(UTC))
        payload = json.dumps(registration.model_dump(mode="json"), sort_keys=True)
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO agents(agent_id, registration_json, status, last_seen_at)
                VALUES (?, ?, 'online', ?)
                ON CONFLICT(agent_id) DO UPDATE SET
                    registration_json = excluded.registration_json,
                    status = 'online',
                    last_seen_at = excluded.last_seen_at
                """,
                (registration.agent_id, payload, now),
            )

    def enqueue_intent(
        self,
        campaign_id: str,
        intent: ProbeIntent,
        *,
        priority: int = 50,
        payload: dict | None = None,
    ) -> EnqueueOutcome:
        """Evaluate and persist one intent without trusting a caller-supplied decision."""

        campaign = self.get_campaign(campaign_id)
        if campaign.state in {CampaignState.COMPLETED, CampaignState.CANCELLED}:
            raise FleetError(f"cannot enqueue work for a {campaign.state.value} campaign")
        decision = evaluate_scope(campaign.scope, intent)
        if not decision.allowed:
            return EnqueueOutcome(accepted=False, duplicate=False, decision=decision)
        task = FleetTask.create(
            campaign_id=campaign_id,
            intent=intent,
            decision=decision,
            max_attempts=campaign.budget.max_attempts_per_task,
            priority=priority,
            payload=payload or {},
        )
        accepted = self._enqueue_task(task, intent, decision, campaign)
        persisted_task = task if accepted else self.get_task(task.task_id)
        return EnqueueOutcome(
            accepted=accepted,
            duplicate=not accepted,
            decision=decision,
            task=persisted_task,
        )

    def _enqueue_task(
        self,
        task: FleetTask,
        intent: ProbeIntent,
        decision: ScopeDecision,
        campaign: CampaignManifest,
    ) -> bool:
        self._assert_enqueue_binding(task, intent, decision, campaign)
        now = _iso(datetime.now(UTC))
        payload = json.dumps(task.model_dump(mode="json"), sort_keys=True)
        intent_payload = json.dumps(intent.model_dump(mode="json"), sort_keys=True)
        decision_payload = json.dumps(decision.model_dump(mode="json"), sort_keys=True)
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                campaign_row = connection.execute(
                    "SELECT state, manifest_digest, started_at FROM campaigns WHERE campaign_id = ?",
                    (task.campaign_id,),
                ).fetchone()
                if not campaign_row:
                    raise FleetError(f"unknown campaign: {task.campaign_id}")
                if campaign_row["manifest_digest"] != campaign.digest():
                    raise FleetError("campaign manifest changed before task persistence")
                current_state = CampaignState(campaign_row["state"])
                if current_state in {CampaignState.COMPLETED, CampaignState.CANCELLED}:
                    raise FleetError(f"cannot enqueue work for a {current_state.value} campaign")
                if _wall_budget_exhausted(campaign_row["started_at"], campaign.budget.max_wall_seconds):
                    raise FleetError("campaign wall-time budget is exhausted")
                duplicate = connection.execute(
                    "SELECT task_id FROM tasks WHERE dedup_key = ?",
                    (task.dedup_key,),
                ).fetchone()
                if duplicate:
                    return False
                counts = connection.execute(
                    """
                    SELECT COUNT(*) AS task_count,
                           COALESCE(SUM(estimated_cost_units), 0) AS cost_units
                    FROM tasks WHERE campaign_id = ?
                    """,
                    (task.campaign_id,),
                ).fetchone()
                if counts["task_count"] >= campaign.budget.max_tasks:
                    raise FleetError("campaign task budget is exhausted")
                if counts["cost_units"] + task.estimated_cost_units > campaign.budget.max_cost_units:
                    raise FleetError("campaign cost budget would be exceeded")
                connection.execute(
                    """
                    INSERT INTO tasks(
                        task_id, campaign_id, task_json, intent_json, scope_decision_json, dedup_key,
                        state, priority, attempts, max_attempts, estimated_cost_units, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?)
                    """,
                    (
                        task.task_id,
                        task.campaign_id,
                        payload,
                        intent_payload,
                        decision_payload,
                        task.dedup_key,
                        task.state.value,
                        task.priority,
                        task.max_attempts,
                        task.estimated_cost_units,
                        now,
                        now,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            if "dedup_key" in str(exc) or "task_id" in str(exc):
                return False
            raise
        return True

    def claim_task(self, agent_id: str, *, lease_seconds: int = 300) -> TaskLease | None:
        if lease_seconds < 10 or lease_seconds > 86400:
            raise ValueError("lease_seconds must be between 10 and 86400")
        now = datetime.now(UTC)
        expires = now + timedelta(seconds=lease_seconds)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._requeue_expired(connection, now)
            connection.execute(
                """
                UPDATE tasks SET state = ?, updated_at = ?
                WHERE state = ? AND attempts >= max_attempts
                """,
                (TaskState.FAILED.value, _iso(now), TaskState.QUEUED.value),
            )
            registration = self._agent(connection, agent_id)
            active_leases = connection.execute(
                "SELECT COUNT(*) AS count FROM tasks WHERE state = ? AND lease_owner = ?",
                (TaskState.LEASED.value, agent_id),
            ).fetchone()["count"]
            if active_leases >= registration.max_concurrency:
                connection.commit()
                return None
            rows = connection.execute(
                """
                SELECT t.*, c.manifest_json, c.started_at FROM tasks t
                JOIN campaigns c ON c.campaign_id = t.campaign_id
                WHERE t.state = ? AND c.state = ? AND t.attempts < t.max_attempts
                ORDER BY t.priority DESC, t.created_at ASC, t.task_id ASC
                """,
                (TaskState.QUEUED.value, CampaignState.RUNNING.value),
            ).fetchall()
            selected: sqlite3.Row | None = None
            for row in rows:
                campaign = CampaignManifest.model_validate_json(row["manifest_json"])
                if _wall_budget_exhausted(row["started_at"], campaign.budget.max_wall_seconds, now):
                    continue
                task = FleetTask.model_validate_json(row["task_json"])
                if not set(task.required_capabilities).issubset(registration.capabilities):
                    continue
                if (
                    EXECUTION_CLASS_RANK[task.execution_class]
                    > EXECUTION_CLASS_RANK[registration.max_execution_class]
                ):
                    continue
                selected = row
                break
            if selected is None:
                connection.commit()
                return None

            token = secrets.token_urlsafe(32)
            token_digest = hashlib.sha256(token.encode()).hexdigest()
            changed = connection.execute(
                """
                UPDATE tasks SET
                    state = ?, attempts = attempts + 1, lease_owner = ?,
                    lease_token_sha256 = ?, lease_expires_at = ?, updated_at = ?
                WHERE task_id = ? AND state = ?
                """,
                (
                    TaskState.LEASED.value,
                    agent_id,
                    token_digest,
                    _iso(expires),
                    _iso(now),
                    selected["task_id"],
                    TaskState.QUEUED.value,
                ),
            ).rowcount
            if changed != 1:
                connection.rollback()
                raise FleetError("task lease race detected")
            connection.execute(
                "UPDATE agents SET last_seen_at = ?, status = 'busy' WHERE agent_id = ?",
                (_iso(now), agent_id),
            )
            connection.commit()
            leased = FleetTask.model_validate_json(selected["task_json"])
            leased.state = TaskState.LEASED
            leased.attempts = int(selected["attempts"]) + 1
            leased.lease_owner = agent_id
            leased.lease_expires_at = expires
            return TaskLease(task=leased, lease_token=token, leased_at=now)

    def heartbeat(
        self, task_id: str, agent_id: str, lease_token: str, *, extend_seconds: int = 300
    ) -> datetime:
        if extend_seconds < 10 or extend_seconds > 86400:
            raise ValueError("extend_seconds must be between 10 and 86400")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            now = datetime.now(UTC)
            expires = now + timedelta(seconds=extend_seconds)
            self._assert_lease(connection, task_id, agent_id, lease_token, now)
            connection.execute(
                "UPDATE tasks SET lease_expires_at = ?, updated_at = ? WHERE task_id = ?",
                (_iso(expires), _iso(now), task_id),
            )
            connection.execute(
                "UPDATE agents SET last_seen_at = ? WHERE agent_id = ?",
                (_iso(now), agent_id),
            )
        return expires

    def complete_task(self, agent_id: str, result: TaskResult) -> TaskState:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            now = datetime.now(UTC)
            self._assert_lease(connection, result.task_id, agent_id, result.lease_token, now)
            campaign_row = connection.execute(
                """
                SELECT c.manifest_json
                FROM tasks t JOIN campaigns c ON c.campaign_id = t.campaign_id
                WHERE t.task_id = ?
                """,
                (result.task_id,),
            ).fetchone()
            campaign = CampaignManifest.model_validate_json(campaign_row["manifest_json"])
            existing_rows = connection.execute(
                """
                SELECT r.result_json
                FROM task_results r JOIN tasks t ON t.task_id = r.task_id
                WHERE t.campaign_id = ?
                """,
                (campaign.campaign_id,),
            ).fetchall()
            existing_findings = sum(
                len(json.loads(row["result_json"]).get("findings", [])) for row in existing_rows
            )
            if existing_findings + len(result.findings) > campaign.budget.max_findings:
                raise FleetError("campaign finding budget would be exceeded")
            terminal_state = _terminal_state(result.outcome)
            stored = result.model_dump(mode="json", exclude={"lease_token"})
            stored["completed_at"] = _iso(now)
            connection.execute(
                """
                UPDATE tasks SET
                    state = ?, lease_owner = NULL, lease_token_sha256 = NULL,
                    lease_expires_at = NULL, updated_at = ?
                WHERE task_id = ?
                """,
                (terminal_state.value, _iso(now), result.task_id),
            )
            connection.execute(
                "INSERT INTO task_results(task_id, agent_id, result_json, completed_at) VALUES (?, ?, ?, ?)",
                (result.task_id, agent_id, json.dumps(stored, sort_keys=True), _iso(now)),
            )
            self._release_idle_agents(connection, {agent_id}, now)
        return terminal_state

    def stats(self) -> FleetStats:
        with self._connect() as connection:
            counts = {
                row["state"]: row["count"]
                for row in connection.execute("SELECT state, COUNT(*) AS count FROM tasks GROUP BY state")
            }
            campaigns = connection.execute("SELECT COUNT(*) AS count FROM campaigns").fetchone()["count"]
            agents = connection.execute("SELECT COUNT(*) AS count FROM agents").fetchone()["count"]
        return FleetStats(
            campaigns=campaigns,
            agents=agents,
            queued=counts.get(TaskState.QUEUED.value, 0),
            leased=counts.get(TaskState.LEASED.value, 0),
            completed=counts.get(TaskState.COMPLETED.value, 0),
            failed=counts.get(TaskState.FAILED.value, 0),
            blocked=counts.get(TaskState.BLOCKED.value, 0),
            cancelled=counts.get(TaskState.CANCELLED.value, 0),
        )

    def learning_candidates(
        self,
        *,
        campaign_id: str | None = None,
        limit: int = 100,
    ) -> list[LearningCandidate]:
        if limit < 1 or limit > 1000:
            raise ValueError("limit must be between 1 and 1000")
        query = """
            SELECT r.task_id, r.agent_id, r.result_json, t.campaign_id
            FROM task_results r
            JOIN tasks t ON t.task_id = r.task_id
        """
        parameters: list[str | int] = []
        if campaign_id is not None:
            query += " WHERE t.campaign_id = ?"
            parameters.append(campaign_id)
        query += " ORDER BY r.result_id DESC"
        with self._connect() as connection:
            rows = connection.execute(query, parameters).fetchall()
        candidates: list[LearningCandidate] = []
        for row in rows:
            payload = json.loads(row["result_json"])
            learning = payload.get("reusable_learning")
            if not isinstance(learning, dict) or not learning:
                continue
            result_digest = stable_digest(payload)
            candidates.append(
                LearningCandidate(
                    candidate_id=stable_id(
                        "learning",
                        {"task_id": row["task_id"], "result_digest": result_digest},
                    ),
                    campaign_id=row["campaign_id"],
                    task_id=row["task_id"],
                    agent_id=row["agent_id"],
                    outcome=payload["outcome"],
                    summary=payload["summary"],
                    evidence_ids=payload.get("evidence_ids", []),
                    learning=learning,
                    completed_at=payload["completed_at"],
                    result_digest=result_digest,
                )
            )
            if len(candidates) >= limit:
                break
        return candidates

    def _campaign_scope_id(self, campaign_id: str) -> str:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT manifest_json FROM campaigns WHERE campaign_id = ?",
                (campaign_id,),
            ).fetchone()
        if not row:
            raise FleetError(f"unknown campaign: {campaign_id}")
        manifest = CampaignManifest.model_validate_json(row["manifest_json"])
        return manifest.scope.scope_id

    @staticmethod
    def _assert_enqueue_binding(
        task: FleetTask,
        intent: ProbeIntent,
        decision: ScopeDecision,
        campaign: CampaignManifest,
    ) -> None:
        if task.state != TaskState.QUEUED:
            raise FleetError("new tasks must be queued")
        if task.campaign_id != campaign.campaign_id:
            raise FleetError("task does not belong to the supplied campaign")
        if intent.scope_id != campaign.scope.scope_id:
            raise FleetError("intent does not belong to the task campaign scope")
        if not decision.allowed:
            raise FleetError("cannot enqueue a task rejected by its scope decision")
        if decision.scope_id != campaign.scope.scope_id or decision.scope_digest != campaign.scope.digest():
            raise FleetError("scope decision is not bound to the campaign scope snapshot")
        if decision.intent_id != intent.intent_id or decision.intent_digest != intent.digest():
            raise FleetError("scope decision is not bound to the supplied intent")
        if task.intent_id != intent.intent_id or task.intent_digest != intent.digest():
            raise FleetError("task is not bound to the supplied intent")
        if task.scope_decision_id != decision.decision_id:
            raise FleetError("task is not bound to the supplied scope decision")
        contracts = {item.playbook_id: item for item in campaign.playbook_contracts}
        contract = contracts.get(intent.playbook_id)
        if contract is None:
            raise FleetError("intent playbook is not selected by the campaign")
        FleetStore._assert_playbook_contract(intent, contract)

    @staticmethod
    def _assert_playbook_contract(intent: ProbeIntent, contract: CampaignPlaybookContract) -> None:
        if intent.playbook_version != contract.version or intent.playbook_digest != contract.digest:
            raise FleetError("intent is not bound to the campaign playbook version and digest")
        if (
            EXECUTION_CLASS_RANK[intent.execution_class]
            < EXECUTION_CLASS_RANK[contract.minimum_execution_class]
        ):
            raise FleetError("intent under-declares the playbook execution class")
        missing_capabilities = sorted(set(contract.capabilities) - set(intent.capabilities))
        if missing_capabilities:
            raise FleetError(f"intent omits playbook capabilities: {missing_capabilities}")
        missing_actions = sorted(set(contract.action_tags) - set(intent.action_tags))
        if missing_actions:
            raise FleetError(f"intent omits playbook action tags: {missing_actions}")
        missing_effects = sorted(set(contract.side_effects) - set(intent.side_effects))
        if missing_effects:
            raise FleetError(f"intent omits playbook side effects: {missing_effects}")
        if intent.estimated_requests < contract.minimum_request_budget:
            raise FleetError("intent under-declares the playbook request budget")

    @contextmanager
    def _connect(self):
        connection = sqlite3.connect(self.database, timeout=30, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        try:
            yield connection
            if connection.in_transaction:
                connection.commit()
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    @staticmethod
    def _requeue_expired(connection: sqlite3.Connection, now: datetime) -> None:
        owners = {
            row["lease_owner"]
            for row in connection.execute(
                """
                SELECT DISTINCT lease_owner FROM tasks
                WHERE state = ? AND lease_expires_at < ? AND lease_owner IS NOT NULL
                """,
                (TaskState.LEASED.value, _iso(now)),
            ).fetchall()
        }
        connection.execute(
            """
            UPDATE tasks SET
                state = CASE WHEN attempts >= max_attempts THEN ? ELSE ? END,
                lease_owner = NULL, lease_token_sha256 = NULL,
                lease_expires_at = NULL, updated_at = ?
            WHERE state = ? AND lease_expires_at < ?
            """,
            (
                TaskState.FAILED.value,
                TaskState.QUEUED.value,
                _iso(now),
                TaskState.LEASED.value,
                _iso(now),
            ),
        )
        FleetStore._release_idle_agents(connection, owners, now)

    @staticmethod
    def _campaign_lease_owners(connection: sqlite3.Connection, campaign_id: str) -> set[str]:
        return {
            row["lease_owner"]
            for row in connection.execute(
                """
                SELECT DISTINCT lease_owner FROM tasks
                WHERE campaign_id = ? AND state = ? AND lease_owner IS NOT NULL
                """,
                (campaign_id, TaskState.LEASED.value),
            ).fetchall()
        }

    @staticmethod
    def _requeue_campaign_leases(
        connection: sqlite3.Connection,
        campaign_id: str,
        now: datetime,
    ) -> set[str]:
        owners = FleetStore._campaign_lease_owners(connection, campaign_id)
        connection.execute(
            """
            UPDATE tasks SET
                state = ?, attempts = CASE WHEN attempts > 0 THEN attempts - 1 ELSE 0 END,
                lease_owner = NULL, lease_token_sha256 = NULL,
                lease_expires_at = NULL, updated_at = ?
            WHERE campaign_id = ? AND state = ?
            """,
            (
                TaskState.QUEUED.value,
                _iso(now),
                campaign_id,
                TaskState.LEASED.value,
            ),
        )
        return owners

    @staticmethod
    def _cancel_campaign_work(
        connection: sqlite3.Connection,
        campaign_id: str,
        now: datetime,
    ) -> set[str]:
        owners = FleetStore._campaign_lease_owners(connection, campaign_id)
        connection.execute(
            """
            UPDATE tasks SET
                state = ?, lease_owner = NULL, lease_token_sha256 = NULL,
                lease_expires_at = NULL, updated_at = ?
            WHERE campaign_id = ? AND state IN (?, ?)
            """,
            (
                TaskState.CANCELLED.value,
                _iso(now),
                campaign_id,
                TaskState.QUEUED.value,
                TaskState.LEASED.value,
            ),
        )
        return owners

    @staticmethod
    def _release_idle_agents(
        connection: sqlite3.Connection,
        agent_ids: set[str],
        now: datetime,
    ) -> None:
        for agent_id in agent_ids:
            remaining = connection.execute(
                "SELECT COUNT(*) AS count FROM tasks WHERE state = ? AND lease_owner = ?",
                (TaskState.LEASED.value, agent_id),
            ).fetchone()["count"]
            if remaining == 0:
                connection.execute(
                    "UPDATE agents SET status = 'online', last_seen_at = ? WHERE agent_id = ?",
                    (_iso(now), agent_id),
                )

    @staticmethod
    def _migrate(connection: sqlite3.Connection) -> None:
        columns = {row["name"] for row in connection.execute("PRAGMA table_info(tasks)")}
        migrations = {
            "intent_json": "ALTER TABLE tasks ADD COLUMN intent_json TEXT NOT NULL DEFAULT '{}'",
            "max_attempts": "ALTER TABLE tasks ADD COLUMN max_attempts INTEGER NOT NULL DEFAULT 3",
            "estimated_cost_units": (
                "ALTER TABLE tasks ADD COLUMN estimated_cost_units REAL NOT NULL DEFAULT 0"
            ),
        }
        for column, statement in migrations.items():
            if column not in columns:
                connection.execute(statement)
        campaign_columns = {row["name"] for row in connection.execute("PRAGMA table_info(campaigns)")}
        if "started_at" not in campaign_columns:
            connection.execute("ALTER TABLE campaigns ADD COLUMN started_at TEXT")
            connection.execute(
                "UPDATE campaigns SET started_at = created_at WHERE state IN (?, ?, ?)",
                (
                    CampaignState.RUNNING.value,
                    CampaignState.PAUSED.value,
                    CampaignState.COMPLETED.value,
                ),
            )

    @staticmethod
    def _agent(connection: sqlite3.Connection, agent_id: str) -> AgentRegistration:
        row = connection.execute(
            "SELECT registration_json FROM agents WHERE agent_id = ?",
            (agent_id,),
        ).fetchone()
        if not row:
            raise FleetError(f"agent is not registered: {agent_id}")
        return AgentRegistration.model_validate_json(row["registration_json"])

    @staticmethod
    def _assert_lease(
        connection: sqlite3.Connection,
        task_id: str,
        agent_id: str,
        lease_token: str,
        now: datetime,
    ) -> None:
        row = connection.execute(
            """
            SELECT t.state, t.lease_owner, t.lease_token_sha256, t.lease_expires_at,
                   c.state AS campaign_state
            FROM tasks t JOIN campaigns c ON c.campaign_id = t.campaign_id
            WHERE t.task_id = ?
            """,
            (task_id,),
        ).fetchone()
        if not row:
            raise FleetError(f"unknown task: {task_id}")
        if row["campaign_state"] != CampaignState.RUNNING.value:
            raise FleetError("task campaign is not running")
        if row["state"] != TaskState.LEASED.value or row["lease_owner"] != agent_id:
            raise FleetError("task is not leased by this agent")
        expected = row["lease_token_sha256"]
        supplied = hashlib.sha256(lease_token.encode()).hexdigest()
        if not expected or not secrets.compare_digest(expected, supplied):
            raise FleetError("invalid lease token")
        if not row["lease_expires_at"]:
            raise FleetError("task lease has no expiration")
        expires = datetime.fromisoformat(row["lease_expires_at"])
        if expires < now:
            raise FleetError("task lease has expired")


def _terminal_state(outcome: str) -> TaskState:
    normalized = outcome.lower()
    if normalized in {"completed", "succeeded", "supported", "confirmed"}:
        return TaskState.COMPLETED
    if normalized in {"blocked", "out-of-scope"}:
        return TaskState.BLOCKED
    return TaskState.FAILED


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat()


def _wall_budget_exhausted(
    started_at: str | None,
    max_wall_seconds: int,
    now: datetime | None = None,
) -> bool:
    if started_at is None:
        return False
    current = now or datetime.now(UTC)
    return current > datetime.fromisoformat(started_at) + timedelta(seconds=max_wall_seconds)
