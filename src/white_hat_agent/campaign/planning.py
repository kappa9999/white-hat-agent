from __future__ import annotations

from pydantic import AwareDatetime, Field, model_validator

from ..knowledge.compose import CompositePlaybook, CompositionRequest, compose_playbooks
from ..knowledge.corpus import Corpus
from ..knowledge.models import ExecutionClass, SemanticType, Slug
from ..models import StrictModel, stable_id, utc_now
from .contracts import contract_from_playbook
from .models import (
    CampaignBudget,
    CampaignManifest,
    CampaignObjective,
    CampaignState,
    ProbeIntent,
    ScopeDecision,
    ScopeManifest,
    TargetKind,
)
from .scope import evaluate_scope


class CampaignTarget(StrictModel):
    target_id: Slug
    kind: TargetKind
    value: str = Field(min_length=1)
    platforms: list[str] = Field(default_factory=list)
    technologies: list[str] = Field(default_factory=list)
    initial_artifacts: list[SemanticType] = Field(default_factory=lambda: ["target/context"])


class CampaignPlanningRequest(StrictModel):
    campaign_id: Slug
    name: str = Field(min_length=1)
    scope: ScopeManifest
    objective: CampaignObjective
    targets: list[CampaignTarget] = Field(min_length=1)
    available_capabilities: list[str] = Field(default_factory=list)
    execution_ceiling: ExecutionClass = ExecutionClass.READ_ONLY
    budget: CampaignBudget = Field(default_factory=CampaignBudget)
    max_playbooks_per_target: int = Field(default=8, ge=1, le=100)
    requested_at: AwareDatetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def unique_inputs(self):
        target_ids = [target.target_id for target in self.targets]
        if len(target_ids) != len(set(target_ids)):
            raise ValueError("campaign target ids must be unique")
        if len(self.available_capabilities) != len(set(self.available_capabilities)):
            raise ValueError("available_capabilities must be unique")
        return self


class CampaignPlanStage(StrictModel):
    stage_id: str
    sequence: int = Field(ge=1)
    target_id: Slug
    playbook_id: Slug
    playbook_version: str
    depends_on: list[str]
    consumes: list[str]
    provides: list[str]
    intent: ProbeIntent
    scope_decision: ScopeDecision


class TargetCampaignPlan(StrictModel):
    target: CampaignTarget
    composition: CompositePlaybook
    stages: list[CampaignPlanStage]
    complete: bool
    blockers: list[str]


class CampaignBlueprint(StrictModel):
    blueprint_id: str
    manifest: CampaignManifest
    targets: list[TargetCampaignPlan]
    complete: bool
    blockers: list[str]


def plan_campaign(corpus: Corpus, request: CampaignPlanningRequest) -> CampaignBlueprint:
    target_plans: list[TargetCampaignPlan] = []
    selected_ids: set[str] = set()
    selected_contracts = {}
    global_blockers: list[str] = []
    for target in request.targets:
        composition = compose_playbooks(
            corpus,
            CompositionRequest(
                objective=request.objective.statement,
                target_kind=target.kind.value,
                domains=request.objective.priority_domains,
                platforms=target.platforms,
                technologies=target.technologies,
                available_capabilities=request.available_capabilities,
                initial_artifacts=target.initial_artifacts,
                desired_artifacts=request.objective.desired_artifacts,
                execution_ceiling=request.execution_ceiling,
                max_playbooks=request.max_playbooks_per_target,
            ),
        )
        stages: list[CampaignPlanStage] = []
        blockers = list(composition.unresolved_artifacts)
        previous_stage_id: str | None = None
        for sequence, selection in enumerate(composition.selected, start=1):
            playbook = corpus.get(selection.playbook_id, selection.version)
            intent_payload = {
                "campaign_id": request.campaign_id,
                "target_id": target.target_id,
                "target": target.value,
                "playbook_id": selection.playbook_id,
                "playbook_version": selection.version,
            }
            intent = ProbeIntent(
                intent_id=stable_id("intent", intent_payload),
                scope_id=request.scope.scope_id,
                target_kind=target.kind,
                target=target.value,
                playbook_id=selection.playbook_id,
                playbook_version=selection.version,
                playbook_digest=playbook.digest(),
                execution_class=playbook.scope.minimum_execution_class,
                capabilities=sorted(playbook.capabilities()),
                action_tags=sorted(playbook.scope.action_tags),
                estimated_requests=playbook.scope.minimum_request_budget,
                concurrency=min(
                    playbook.scope.recommended_concurrency,
                    request.scope.rate_limits.max_concurrency,
                ),
                side_effects=sorted({effect for step in playbook.steps for effect in step.side_effects}),
                estimated_cost_units=float(len(playbook.steps)),
                proposed_at=request.requested_at,
            )
            decision = evaluate_scope(request.scope, intent, evaluated_at=request.requested_at)
            stage_id = stable_id("stage", intent_payload)
            stages.append(
                CampaignPlanStage(
                    stage_id=stage_id,
                    sequence=sequence,
                    target_id=target.target_id,
                    playbook_id=selection.playbook_id,
                    playbook_version=selection.version,
                    depends_on=[previous_stage_id] if previous_stage_id else [],
                    consumes=selection.consumed,
                    provides=selection.provided,
                    intent=intent,
                    scope_decision=decision,
                )
            )
            previous_stage_id = stage_id
            selected_ids.add(selection.playbook_id)
            selected_contracts[selection.playbook_id] = contract_from_playbook(playbook)
            if not decision.allowed:
                blockers.extend(decision.reasons)
        blockers = sorted(set(blockers))
        if blockers:
            global_blockers.extend(f"{target.target_id}: {blocker}" for blocker in blockers)
        target_plans.append(
            TargetCampaignPlan(
                target=target,
                composition=composition,
                stages=stages,
                complete=composition.complete and not blockers,
                blockers=blockers,
            )
        )

    manifest = CampaignManifest(
        campaign_id=request.campaign_id,
        name=request.name,
        scope=request.scope,
        objective=request.objective,
        corpus_manifest_digest=corpus.manifest().manifest_digest,
        selected_playbooks=sorted(selected_ids),
        playbook_contracts=[selected_contracts[item] for item in sorted(selected_contracts)],
        budget=request.budget,
        state=CampaignState.DRAFT,
        created_at=request.requested_at,
    )
    payload = {
        "request": request.model_dump(mode="json"),
        "corpus_manifest_digest": manifest.corpus_manifest_digest,
        "targets": [plan.model_dump(mode="json") for plan in target_plans],
    }
    blockers = sorted(set(global_blockers))
    return CampaignBlueprint(
        blueprint_id=stable_id("blueprint", payload),
        manifest=manifest,
        targets=target_plans,
        complete=all(plan.complete for plan in target_plans),
        blockers=blockers,
    )
