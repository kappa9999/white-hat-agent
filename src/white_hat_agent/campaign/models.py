from __future__ import annotations

from enum import StrEnum
from typing import Self

from pydantic import AwareDatetime, Field, JsonValue, model_validator

from ..knowledge.models import CapabilityId, ExecutionClass, ReviewState, SemVer, Slug
from ..models import Sha256, StrictModel, stable_digest, stable_id, utc_now


class ProgramKind(StrEnum):
    HACKERONE = "hackerone"
    BUGCROWD = "bugcrowd"
    INTIGRITI = "intigriti"
    YESWEHACK = "yeswehack"
    OPEN_SOURCE = "open-source"
    PRIVATE = "private"
    LAB = "lab"
    CUSTOM = "custom"


class TargetKind(StrEnum):
    DOMAIN = "domain"
    URL = "url"
    IP = "ip"
    CIDR = "cidr"
    REPOSITORY = "repository"
    PACKAGE = "package"
    MOBILE_APP = "mobile-app"
    BINARY = "binary"
    PACKET_CAPTURE = "packet-capture"
    CLOUD_ACCOUNT = "cloud-account"
    API = "api"
    GENERIC = "generic"


class TaskState(StrEnum):
    QUEUED = "queued"
    LEASED = "leased"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"
    CANCELLED = "cancelled"


class CampaignState(StrEnum):
    DRAFT = "draft"
    READY = "ready"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


class OpportunityState(StrEnum):
    DISCOVERED = "discovered"
    TRIAGED = "triaged"
    ACTIVE = "active"
    SUBMITTED = "submitted"
    RESOLVED = "resolved"
    CLOSED = "closed"


class TargetRule(StrictModel):
    rule_id: Slug
    kind: TargetKind
    pattern: str = Field(min_length=1)
    in_scope: bool = True
    environment: str | None = None
    notes: list[str] = Field(default_factory=list)


class RateLimits(StrictModel):
    requests_per_second: float = Field(default=1.0, gt=0)
    burst: int = Field(default=2, ge=1)
    max_requests_per_task: int = Field(default=100, ge=1)
    max_concurrency: int = Field(default=1, ge=1)


class DisclosurePolicy(StrictModel):
    channel: str = Field(min_length=1)
    encryption_required: bool = False
    embargo_days: int | None = Field(default=None, ge=0)
    duplicate_policy: str | None = None
    public_disclosure_allowed: bool = False
    instructions: list[str] = Field(default_factory=list)


class ScopeManifest(StrictModel):
    schema_version: str = "1.0"
    scope_id: Slug
    program_kind: ProgramKind
    program_name: str = Field(min_length=1)
    program_url: str | None = None
    rules_url: str | None = None
    rules_sha256: Sha256 | None = None
    authorization_reference: str = Field(min_length=1)
    valid_from: AwareDatetime | None = None
    valid_until: AwareDatetime | None = None
    targets: list[TargetRule] = Field(min_length=1)
    allowed_execution_classes: list[ExecutionClass] = Field(min_length=1)
    allowed_capabilities: list[CapabilityId] = Field(default_factory=list)
    allow_unlisted_capabilities: bool = False
    prohibited_capabilities: list[CapabilityId] = Field(default_factory=list)
    prohibited_action_tags: list[Slug] = Field(default_factory=list)
    rate_limits: RateLimits = Field(default_factory=RateLimits)
    data_handling: list[str] = Field(default_factory=list)
    disclosure: DisclosurePolicy
    emergency_contact: str | None = None
    captured_at: AwareDatetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def valid_scope(self) -> Self:
        if self.valid_from and self.valid_until and self.valid_until <= self.valid_from:
            raise ValueError("valid_until must follow valid_from")
        rule_ids = [item.rule_id for item in self.targets]
        if len(rule_ids) != len(set(rule_ids)):
            raise ValueError("target rule ids must be unique")
        for label, values in (
            ("allowed_execution_classes", [item.value for item in self.allowed_execution_classes]),
            ("allowed_capabilities", self.allowed_capabilities),
            ("prohibited_capabilities", self.prohibited_capabilities),
            ("prohibited_action_tags", self.prohibited_action_tags),
        ):
            if len(values) != len(set(values)):
                raise ValueError(f"{label} must be unique")
        overlap = set(self.allowed_capabilities).intersection(self.prohibited_capabilities)
        if overlap:
            raise ValueError(f"capabilities cannot be both allowed and prohibited: {sorted(overlap)}")
        return self

    def digest(self) -> str:
        return stable_digest(self)


class ProbeIntent(StrictModel):
    intent_id: Slug
    scope_id: Slug
    target_kind: TargetKind
    target: str = Field(min_length=1)
    playbook_id: Slug
    playbook_version: SemVer
    playbook_digest: Sha256
    execution_class: ExecutionClass
    capabilities: list[CapabilityId] = Field(default_factory=list)
    action_tags: list[Slug] = Field(default_factory=list)
    estimated_requests: int = Field(default=0, ge=0)
    concurrency: int = Field(default=1, ge=1)
    side_effects: list[str] = Field(default_factory=list)
    estimated_cost_units: float = Field(default=0.0, ge=0)
    proposed_at: AwareDatetime = Field(default_factory=utc_now)

    def digest(self) -> str:
        return stable_digest(self.model_dump(mode="json", exclude={"proposed_at"}))


class ScopeDecision(StrictModel):
    decision_id: str
    scope_id: str
    scope_digest: Sha256
    intent_id: str
    intent_digest: Sha256
    evaluated_at: AwareDatetime
    allowed: bool
    matched_rule_id: str | None = None
    reasons: list[str]
    warnings: list[str] = Field(default_factory=list)
    effective_limits: RateLimits


class CampaignBudget(StrictModel):
    max_tasks: int = Field(default=1000, ge=1)
    max_cost_units: float = Field(default=1000.0, gt=0)
    max_findings: int = Field(default=100, ge=1)
    max_wall_seconds: int = Field(default=86400, ge=1)
    max_attempts_per_task: int = Field(default=3, ge=1, le=100)


class CampaignObjective(StrictModel):
    statement: str = Field(min_length=1)
    success_criteria: list[str] = Field(min_length=1)
    desired_artifacts: list[str] = Field(default_factory=lambda: ["finding/verified"])
    priority_domains: list[str] = Field(default_factory=list)


class CampaignPlaybookContract(StrictModel):
    playbook_id: Slug
    version: SemVer
    digest: Sha256
    review_state: ReviewState
    minimum_execution_class: ExecutionClass
    capabilities: list[CapabilityId] = Field(default_factory=list)
    action_tags: list[Slug] = Field(default_factory=list)
    side_effects: list[str] = Field(default_factory=list)
    minimum_request_budget: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def unique_contract_lists(self) -> Self:
        for label, values in (
            ("capabilities", self.capabilities),
            ("action_tags", self.action_tags),
            ("side_effects", self.side_effects),
        ):
            if len(values) != len(set(values)):
                raise ValueError(f"playbook contract {label} must be unique")
        return self


class CampaignManifest(StrictModel):
    schema_version: str = "1.0"
    campaign_id: Slug
    name: str = Field(min_length=1)
    scope: ScopeManifest
    objective: CampaignObjective
    corpus_manifest_digest: Sha256
    selected_playbooks: list[Slug] = Field(default_factory=list)
    playbook_contracts: list[CampaignPlaybookContract] = Field(default_factory=list)
    budget: CampaignBudget = Field(default_factory=CampaignBudget)
    state: CampaignState = CampaignState.DRAFT
    created_at: AwareDatetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def valid_playbook_snapshot(self) -> Self:
        if len(self.selected_playbooks) != len(set(self.selected_playbooks)):
            raise ValueError("selected_playbooks must be unique")
        contract_ids = [contract.playbook_id for contract in self.playbook_contracts]
        if len(contract_ids) != len(set(contract_ids)):
            raise ValueError("playbook contract ids must be unique")
        if set(contract_ids) != set(self.selected_playbooks):
            raise ValueError("playbook contracts must exactly match selected_playbooks")
        return self

    def digest(self) -> str:
        return stable_digest(self.model_dump(mode="json", exclude={"state"}))


class Opportunity(StrictModel):
    opportunity_id: Slug
    program_kind: ProgramKind
    title: str = Field(min_length=1)
    program_url: str | None = None
    scope_reference: str = Field(min_length=1)
    scope_snapshot_digest: Sha256 | None = None
    automation_permitted: bool = False
    target_kinds: list[TargetKind] = Field(default_factory=list)
    domains: list[Slug] = Field(default_factory=list)
    required_capabilities: list[CapabilityId] = Field(default_factory=list)
    allowed_execution_classes: list[ExecutionClass] = Field(default_factory=list)
    reward_hint: str | None = None
    reward_max: float | None = Field(default=None, ge=0)
    reward_currency: str | None = Field(default=None, pattern=r"^[A-Z]{3}$")
    strategic_priority: float = Field(default=0.5, ge=0, le=1)
    state: OpportunityState = OpportunityState.DISCOVERED
    discovered_at: AwareDatetime = Field(default_factory=utc_now)
    last_verified_at: AwareDatetime | None = None
    expires_at: AwareDatetime | None = None
    metadata: dict[str, JsonValue] = Field(default_factory=dict)

    @model_validator(mode="after")
    def valid_opportunity(self) -> Self:
        if (self.reward_max is None) != (self.reward_currency is None):
            raise ValueError("reward_max and reward_currency must be supplied together")
        if self.expires_at and self.expires_at <= self.discovered_at:
            raise ValueError("expires_at must follow discovered_at")
        for label, values in (
            ("target_kinds", [item.value for item in self.target_kinds]),
            ("domains", self.domains),
            ("required_capabilities", self.required_capabilities),
            ("allowed_execution_classes", [item.value for item in self.allowed_execution_classes]),
        ):
            if len(values) != len(set(values)):
                raise ValueError(f"{label} must be unique")
        return self

    def digest(self) -> str:
        return stable_digest(self.model_dump(mode="json", exclude={"state"}))


class AgentRegistration(StrictModel):
    agent_id: Slug
    display_name: str = Field(min_length=1)
    provider: str = Field(min_length=1)
    model: str | None = None
    capabilities: list[CapabilityId] = Field(default_factory=list)
    max_execution_class: ExecutionClass = ExecutionClass.ANALYSIS
    max_concurrency: int = Field(default=1, ge=1, le=1000)
    metadata: dict[str, JsonValue] = Field(default_factory=dict)


class FleetTask(StrictModel):
    task_id: str
    campaign_id: Slug
    target_kind: TargetKind
    target: str
    intent_id: Slug
    intent_digest: Sha256
    scope_decision_id: str
    playbook_id: Slug
    playbook_version: SemVer
    playbook_digest: Sha256
    required_capabilities: list[CapabilityId] = Field(default_factory=list)
    execution_class: ExecutionClass
    priority: int = Field(default=50, ge=0, le=100)
    estimated_cost_units: float = Field(default=0.0, ge=0)
    payload: dict[str, JsonValue] = Field(default_factory=dict)
    dedup_key: str
    state: TaskState = TaskState.QUEUED
    attempts: int = Field(default=0, ge=0)
    max_attempts: int = Field(default=3, ge=1, le=100)
    lease_owner: str | None = None
    lease_expires_at: AwareDatetime | None = None

    @classmethod
    def create(
        cls,
        *,
        campaign_id: str,
        intent: ProbeIntent,
        decision: ScopeDecision,
        max_attempts: int,
        priority: int = 50,
        payload: dict[str, JsonValue] | None = None,
    ) -> FleetTask:
        dedup_payload = {
            "campaign_id": campaign_id,
            "intent_digest": intent.digest(),
            "payload": payload or {},
        }
        dedup_key = stable_id("dedup", dedup_payload)
        return cls(
            task_id=stable_id("task", dedup_payload),
            campaign_id=campaign_id,
            target_kind=intent.target_kind,
            target=intent.target,
            intent_id=intent.intent_id,
            intent_digest=intent.digest(),
            scope_decision_id=decision.decision_id,
            playbook_id=intent.playbook_id,
            playbook_version=intent.playbook_version,
            playbook_digest=intent.playbook_digest,
            required_capabilities=intent.capabilities,
            execution_class=intent.execution_class,
            priority=priority,
            estimated_cost_units=intent.estimated_cost_units,
            payload=payload or {},
            dedup_key=dedup_key,
            max_attempts=max_attempts,
        )


class TaskLease(StrictModel):
    task: FleetTask
    lease_token: str
    leased_at: AwareDatetime


class EnqueueOutcome(StrictModel):
    accepted: bool
    duplicate: bool
    decision: ScopeDecision
    task: FleetTask | None = None


class TaskResult(StrictModel):
    task_id: str
    lease_token: str
    outcome: str = Field(min_length=1)
    summary: str = Field(min_length=1)
    evidence_ids: list[str] = Field(default_factory=list)
    findings: list[dict[str, JsonValue]] = Field(default_factory=list)
    adjacent_hypotheses: list[dict[str, JsonValue]] = Field(default_factory=list)
    reusable_learning: dict[str, JsonValue] | None = None
    completed_at: AwareDatetime = Field(default_factory=utc_now)


class LearningCandidate(StrictModel):
    candidate_id: str
    campaign_id: Slug
    task_id: str
    agent_id: Slug
    outcome: str
    summary: str
    evidence_ids: list[str]
    learning: dict[str, JsonValue]
    completed_at: AwareDatetime
    result_digest: Sha256
