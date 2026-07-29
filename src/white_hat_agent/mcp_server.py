from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal

from fastmcp import FastMCP
from fastmcp.server.middleware.response_limiting import ResponseLimitingMiddleware
from fastmcp.server.middleware.timing import TimingMiddleware
from pydantic import Field, ValidationError

from ._version import __version__
from .campaign.contracts import validate_campaign_manifest
from .campaign.models import (
    AgentRegistration,
    CampaignManifest,
    CampaignState,
    EnqueueOutcome,
    LearningCandidate,
    Opportunity,
    OpportunityState,
    ProbeIntent,
    ScopeDecision,
    ScopeManifest,
    TaskLease,
    TaskResult,
)
from .campaign.opportunities import OpportunityScore, rank_opportunities
from .campaign.planning import CampaignBlueprint, CampaignPlanningRequest, plan_campaign
from .campaign.scope import evaluate_scope
from .capabilities.catalog import (
    CapabilityCompatibilityReport,
    CapabilityGapReport,
    CapabilitySearchHit,
)
from .capabilities.models import CapabilityDefinition
from .episode import apply_observation
from .evidence.models import EvidenceDescriptor, EvidenceRecord, FindingRecord
from .intelligence import (
    IntelligenceService,
    IntelligenceSource,
    IntelligenceStatus,
    IntelligenceSyncReport,
    NormalizedAdvisory,
    RankedAdvisory,
)
from .knowledge.compiler import compile_heuristic, compiler_prompt
from .knowledge.compose import CompositePlaybook, CompositionRequest, compose_playbooks
from .knowledge.corpus import CorpusSearchHit
from .knowledge.learning import submission_from_learning
from .knowledge.models import (
    KnowledgeSubmission,
    Playbook,
    RightsDeclaration,
)
from .models import (
    CausalVerificationInput,
    CausalVerificationReport,
    DiscoveryEpisode,
    DiscoveryObservation,
    DiscoveryPlan,
    StrictModel,
    stable_id,
)
from .planner import AdaptivePlanner
from .schemas import _atomic_write
from .verification import verify_causality
from .workspace import Workspace


class PlaybookValidationResult(StrictModel):
    valid: bool
    playbook_id: str | None = None
    version: str | None = None
    digest: str | None = None
    errors: list[str] = Field(default_factory=list)


class IntakeResult(StrictModel):
    submission_id: str
    submission_digest: str
    draft_playbook: Playbook
    unresolved_fields: list[str]
    warnings: list[str]
    persisted_path: str | None = None


def create_server(workspace_root: str | Path | None = None) -> FastMCP:
    workspace = _workspace(workspace_root)
    fleet = workspace.fleet
    fleet.initialize()

    root = FastMCP(
        name="White Hat Agent Core",
        version=__version__,
        instructions=(
            "Model-neutral cyber knowledge and campaign brain. Search and compose the corpus "
            "before inventing a new method. Every campaign operation uses exact scope, target, "
            "task, lease, and evidence identities."
        ),
        middleware=[
            TimingMiddleware(),
            ResponseLimitingMiddleware(max_size=workspace.config.max_tool_response_bytes),
        ],
        strict_input_validation=True,
        mask_error_details=True,
        list_page_size=100,
    )
    root.mount(_knowledge_server(workspace), namespace="knowledge")
    root.mount(_capability_server(workspace), namespace="capability")
    root.mount(_campaign_server(workspace), namespace="campaign")
    root.mount(_intelligence_server(workspace), namespace="intelligence")
    root.mount(_opportunity_server(workspace), namespace="opportunity")
    root.mount(_fleet_server(workspace), namespace="fleet")
    root.mount(_evidence_server(workspace), namespace="evidence")
    root.mount(_discovery_server(), namespace="discovery")

    @root.resource(
        "whitehat://status",
        name="workspace_status",
        description="Current workspace and validation health",
        mime_type="application/json",
    )
    def workspace_status() -> str:
        return workspace.doctor().model_dump_json(indent=2)

    return root


def _intelligence_server(workspace: Workspace) -> FastMCP:
    server = FastMCP(
        "White Hat Agent Intelligence",
        strict_input_validation=True,
        mask_error_details=True,
    )
    store = workspace.intelligence
    store.initialize()
    service = IntelligenceService(store)

    @server.tool(
        name="sync",
        version="1.0",
        description=(
            "Synchronize fixed official public advisory sources into immutable local snapshots. "
            "This contacts the CVE Program, CISA, OSV, and optionally FIRST EPSS; "
            "it never contacts affected targets or advisory reference URLs."
        ),
        annotations={"readOnlyHint": False, "idempotentHint": False, "openWorldHint": True},
        tags={"intelligence", "network", "write"},
    )
    def sync(
        sources: list[Literal["cisa-kev", "cve-list-v5", "osv"]] | None = None,
        since_hours: float = 24.0,
        ecosystems: list[str] | None = None,
        limit_per_source: int = 1000,
        enrich_epss: bool = False,
    ) -> IntelligenceSyncReport:
        return service.sync(
            sources=sources,
            since_hours=since_hours,
            ecosystems=ecosystems,
            limit_per_source=limit_per_source,
            enrich_epss=enrich_epss,
        )

    @server.tool(
        name="get",
        version="1.0",
        description="Resolve one locally stored advisory through its source-native ID or any known alias.",
        annotations={"readOnlyHint": True, "idempotentHint": True, "openWorldHint": False},
        tags={"intelligence", "read"},
    )
    def get(advisory_id: str) -> NormalizedAdvisory:
        return service.get(advisory_id)

    @server.tool(
        name="list",
        version="1.0",
        description=(
            "Rank locally stored advisories with inspectable KEV, EPSS, recency, severity, "
            "and evidence factors."
        ),
        annotations={"readOnlyHint": True, "idempotentHint": True, "openWorldHint": False},
        tags={"intelligence", "planning", "read"},
    )
    def list_items(
        sources: list[IntelligenceSource] | None = None,
        ecosystems: list[str] | None = None,
        known_exploited: bool | None = None,
        include_withdrawn: bool = False,
        include_rejected: bool = False,
        limit: int = 20,
    ) -> list[RankedAdvisory]:
        return service.list(
            sources=sources,
            ecosystems=ecosystems,
            known_exploited=known_exploited,
            withdrawn=None if include_withdrawn else False,
            rejected=None if include_rejected else False,
            limit=limit,
        )

    @server.tool(
        name="status",
        version="1.0",
        description="Return local source freshness, record counts, and the latest sync result.",
        annotations={"readOnlyHint": True, "idempotentHint": True, "openWorldHint": False},
        tags={"intelligence", "read", "status"},
    )
    def status() -> IntelligenceStatus:
        return service.status()

    @server.tool(
        name="brief",
        version="1.0",
        description="Render a deterministic Markdown brief from locally stored ranked advisories.",
        annotations={"readOnlyHint": True, "idempotentHint": True, "openWorldHint": False},
        tags={"intelligence", "read", "report"},
    )
    def brief(
        sources: list[IntelligenceSource] | None = None,
        ecosystems: list[str] | None = None,
        known_exploited: bool | None = None,
        include_withdrawn: bool = False,
        include_rejected: bool = False,
        limit: int = 20,
    ) -> str:
        return service.brief(
            sources=sources,
            ecosystems=ecosystems,
            known_exploited=known_exploited,
            withdrawn=None if include_withdrawn else False,
            rejected=None if include_rejected else False,
            limit=limit,
        )

    return server


def _opportunity_server(workspace: Workspace) -> FastMCP:
    server = FastMCP(
        "White Hat Agent Opportunities",
        strict_input_validation=True,
        mask_error_details=True,
    )
    fleet = workspace.fleet

    @server.tool(
        name="add",
        version="1.0",
        description="Persist a normalized bug-bounty, open-source, lab, or private-program opportunity.",
        annotations={"readOnlyHint": False, "idempotentHint": True, "openWorldHint": False},
        tags={"opportunity", "write"},
    )
    def add(opportunity: Opportunity) -> Opportunity:
        fleet.add_opportunity(opportunity)
        return opportunity

    @server.tool(
        name="get",
        version="1.0",
        description="Return one exact opportunity record.",
        annotations={"readOnlyHint": True, "idempotentHint": True, "openWorldHint": False},
        tags={"opportunity", "read"},
    )
    def get(opportunity_id: str) -> Opportunity:
        return fleet.get_opportunity(opportunity_id)

    @server.tool(
        name="list",
        version="1.0",
        description="List normalized opportunities, optionally filtered by lifecycle state.",
        annotations={"readOnlyHint": True, "idempotentHint": True, "openWorldHint": False},
        tags={"opportunity", "read"},
    )
    def list_items(state: OpportunityState | None = None, limit: int = 100) -> list[Opportunity]:
        return fleet.list_opportunities(state, limit=limit)

    @server.tool(
        name="set_state",
        version="1.0",
        description="Update an opportunity lifecycle after triage, submission, or closure.",
        annotations={"readOnlyHint": False, "idempotentHint": True, "openWorldHint": False},
        tags={"opportunity", "write"},
    )
    def set_state(opportunity_id: str, state: OpportunityState) -> Opportunity:
        return fleet.set_opportunity_state(opportunity_id, state)

    @server.tool(
        name="rank",
        version="1.0",
        description="Rank opportunities by capability, corpus, scope, freshness, and strategic fit.",
        annotations={"readOnlyHint": True, "idempotentHint": True, "openWorldHint": False},
        tags={"opportunity", "planning"},
    )
    def rank(available_capabilities: list[str], limit: int = 100) -> list[OpportunityScore]:
        return rank_opportunities(
            fleet.list_opportunities(limit=1000),
            workspace.corpus,
            available_capabilities,
            limit=limit,
        )

    @server.prompt(
        name="normalize",
        version="1.0",
        description=(
            "Normalize discovered program information without inventing scope or automation permission."
        ),
        tags={"opportunity", "intake"},
    )
    def normalize(source_text: str, source_url: str | None = None) -> str:
        return (
            "Convert the following source into one Opportunity JSON object. Preserve the source "
            "URL and exact "
            "scope reference. Set automation_permitted=true only when the source explicitly permits it. "
            "Do not infer target scope, authorization, reward, expiration, or a scope digest. "
            "Use metadata for "
            "unmapped source facts and list only capability identifiers actually implied by the work.\n\n"
            f"Source URL: {source_url or 'not supplied'}\n\n{source_text}"
        )

    return server


def _capability_server(workspace: Workspace) -> FastMCP:
    server = FastMCP(
        "White Hat Agent Capabilities",
        strict_input_validation=True,
        mask_error_details=True,
    )

    @server.tool(
        name="search",
        version="1.0",
        description="Search the shared capability and adapter-contract vocabulary.",
        annotations={"readOnlyHint": True, "idempotentHint": True, "openWorldHint": False},
        tags={"capability", "read"},
    )
    def search(query: str = "", limit: int = 20) -> list[CapabilitySearchHit]:
        return workspace.capability_catalog.search(query, limit=limit)

    @server.tool(
        name="get",
        version="1.0",
        description="Return one exact capability definition and its adapter contract.",
        annotations={"readOnlyHint": True, "idempotentHint": True, "openWorldHint": False},
        tags={"capability", "read"},
    )
    def get(capability_id: str) -> CapabilityDefinition:
        return workspace.capability_catalog.get(capability_id)

    @server.tool(
        name="gaps",
        version="1.0",
        description="Compare selected playbook requirements with an agent's capability inventory.",
        annotations={"readOnlyHint": True, "idempotentHint": True, "openWorldHint": False},
        tags={"capability", "planning"},
    )
    def gaps(playbook_ids: list[str], available_capabilities: list[str]) -> CapabilityGapReport:
        playbooks = [workspace.corpus.get(playbook_id) for playbook_id in playbook_ids]
        return workspace.capability_catalog.gaps(playbooks, available_capabilities)

    @server.tool(
        name="validate_playbooks",
        version="1.0",
        description="Check capability references and execution classifications across the corpus.",
        annotations={"readOnlyHint": True, "idempotentHint": True, "openWorldHint": False},
        tags={"capability", "validation"},
    )
    def validate_playbooks() -> CapabilityCompatibilityReport:
        return workspace.capability_catalog.validate_playbooks(workspace.corpus.all())

    @server.resource(
        "whitehat://capabilities/catalog",
        name="capability_catalog",
        description="Provider-neutral adapter capability definitions",
        mime_type="application/json",
    )
    def catalog_resource() -> str:
        payload = [item.model_dump(mode="json") for item in workspace.capability_catalog.all()]
        return json.dumps(payload, indent=2, sort_keys=True)

    return server


def run_server(
    *,
    workspace_root: str | Path | None = None,
    transport: str = "stdio",
    host: str = "127.0.0.1",
    port: int = 8000,
) -> None:
    server = create_server(workspace_root)
    if transport == "stdio":
        server.run(transport="stdio", show_banner=False)
        return
    if transport != "http":
        raise ValueError("transport must be stdio or http")
    server.run(
        transport="http",
        host=host,
        port=port,
        path="/mcp",
        stateless_http=True,
        show_banner=False,
    )


def _knowledge_server(workspace: Workspace) -> FastMCP:
    server = FastMCP(
        "White Hat Agent Knowledge",
        strict_input_validation=True,
        mask_error_details=True,
    )

    @server.tool(
        name="search",
        version="1.0",
        description=(
            "Search the validated cyber playbook corpus by concepts, domains, and available capabilities."
        ),
        annotations={"readOnlyHint": True, "idempotentHint": True, "openWorldHint": False},
        tags={"corpus", "read"},
    )
    def search(
        query: str,
        domains: list[str] | None = None,
        available_capabilities: list[str] | None = None,
        limit: int = 10,
    ) -> list[CorpusSearchHit]:
        return workspace.corpus.search(
            query,
            domains=domains,
            capabilities=available_capabilities,
            limit=limit,
        )

    @server.tool(
        name="get",
        version="1.0",
        description="Return one exact playbook version, or the latest version when omitted.",
        annotations={"readOnlyHint": True, "idempotentHint": True, "openWorldHint": False},
        tags={"corpus", "read"},
    )
    def get(playbook_id: str, version: str | None = None) -> Playbook:
        return workspace.corpus.get(playbook_id, version)

    @server.tool(
        name="intake",
        version="1.0",
        description=(
            "Losslessly ingest plain-language cyber knowledge in any language and produce "
            "a reviewable playbook draft."
        ),
        annotations={"readOnlyHint": False, "idempotentHint": True, "openWorldHint": False},
        tags={"contribution", "compiler"},
    )
    def intake(
        text: str,
        language: str = "und",
        title: str | None = None,
        domains: list[str] | None = None,
        contributor: str | None = None,
        rights: str = "original-contribution",
        persist: bool = False,
    ) -> IntakeResult:
        identity_payload = {
            "text": text,
            "language": language,
            "title": title,
            "domains": domains or [],
            "contributor": contributor,
        }
        submission = KnowledgeSubmission(
            submission_id=stable_id("submission", identity_payload),
            title_hint=title,
            original_language=language,
            original_text=text,
            domain_hints=domains or [],
            contributor_handle=contributor,
            rights=RightsDeclaration(rights),
        )
        draft = compile_heuristic(submission)
        persisted_path: str | None = None
        if persist:
            path = workspace.submissions_dir / f"{submission.submission_id}.json"
            payload = json.dumps(draft.model_dump(mode="json"), indent=2, sort_keys=True) + "\n"
            _atomic_write(path, payload)
            persisted_path = str(path)
        return IntakeResult(
            submission_id=submission.submission_id,
            submission_digest=submission.digest(),
            draft_playbook=draft.playbook,
            unresolved_fields=draft.unresolved_fields,
            warnings=draft.warnings,
            persisted_path=persisted_path,
        )

    @server.tool(
        name="learning_candidates",
        version="1.0",
        description="List evidence-linked reusable learning proposed by completed fleet tasks.",
        annotations={"readOnlyHint": True, "idempotentHint": True, "openWorldHint": False},
        tags={"learning", "read"},
    )
    def learning_candidates(
        campaign_id: str | None = None,
        limit: int = 100,
    ) -> list[LearningCandidate]:
        return workspace.fleet.learning_candidates(campaign_id=campaign_id, limit=limit)

    @server.tool(
        name="intake_learning",
        version="1.0",
        description="Convert one fleet learning candidate into a lossless draft without auto-promoting it.",
        annotations={"readOnlyHint": False, "idempotentHint": True, "openWorldHint": False},
        tags={"learning", "compiler"},
    )
    def intake_learning(
        candidate_id: str,
        rights: str,
        contributor: str | None = None,
        language: str = "und",
        persist: bool = False,
    ) -> IntakeResult:
        matches = [
            candidate
            for candidate in workspace.fleet.learning_candidates(limit=1000)
            if candidate.candidate_id == candidate_id
        ]
        if not matches:
            raise KeyError(f"unknown learning candidate: {candidate_id}")
        submission = submission_from_learning(
            matches[0],
            rights=RightsDeclaration(rights),
            contributor=contributor,
            language=language,
        )
        draft = compile_heuristic(submission)
        persisted_path: str | None = None
        if persist:
            path = workspace.submissions_dir / f"{submission.submission_id}.json"
            payload = json.dumps(draft.model_dump(mode="json"), indent=2, sort_keys=True) + "\n"
            _atomic_write(path, payload)
            persisted_path = str(path)
        return IntakeResult(
            submission_id=submission.submission_id,
            submission_digest=submission.digest(),
            draft_playbook=draft.playbook,
            unresolved_fields=draft.unresolved_fields,
            warnings=draft.warnings,
            persisted_path=persisted_path,
        )

    @server.tool(
        name="validate",
        version="1.0",
        description="Validate an agent- or contributor-produced playbook against the strict public schema.",
        annotations={"readOnlyHint": True, "idempotentHint": True, "openWorldHint": False},
        tags={"contribution", "validation"},
    )
    def validate(playbook: dict[str, Any]) -> PlaybookValidationResult:
        try:
            parsed = Playbook.model_validate(playbook)
        except ValidationError as exc:
            return PlaybookValidationResult(valid=False, errors=[str(exc)])
        return PlaybookValidationResult(
            valid=True,
            playbook_id=parsed.metadata.playbook_id,
            version=parsed.metadata.version,
            digest=parsed.digest(),
        )

    @server.tool(
        name="compose",
        version="1.0",
        description=(
            "Chain compatible corpus playbooks by semantic inputs, outputs, objective, and capabilities."
        ),
        annotations={"readOnlyHint": True, "idempotentHint": True, "openWorldHint": False},
        tags={"corpus", "planning"},
    )
    def compose(request: CompositionRequest) -> CompositePlaybook:
        return compose_playbooks(workspace.corpus, request)

    @server.resource(
        "whitehat://corpus/manifest",
        name="corpus_manifest",
        description="Deterministic index and digests for every loaded playbook",
        mime_type="application/json",
    )
    def corpus_manifest() -> str:
        return workspace.corpus.manifest().model_dump_json(indent=2)

    @server.resource(
        "whitehat://playbook/{playbook_id}",
        name="playbook",
        description="Latest version of a corpus playbook",
        mime_type="application/json",
    )
    def playbook_resource(playbook_id: str) -> str:
        return workspace.corpus.get(playbook_id).model_dump_json(indent=2)

    @server.prompt(
        name="compile_submission",
        version="1.0",
        description="Compile multilingual community knowledge into a lossless Playbook v1 draft.",
        tags={"contribution", "compiler"},
    )
    def compile_submission_prompt(
        text: str,
        language: str = "und",
        title: str | None = None,
        rights: str = "original-contribution",
    ) -> str:
        submission = KnowledgeSubmission(
            submission_id=stable_id("submission", {"text": text, "language": language, "title": title}),
            title_hint=title,
            original_language=language,
            original_text=text,
            rights=RightsDeclaration(rights),
        )
        return compiler_prompt(submission)

    return server


def _campaign_server(workspace: Workspace) -> FastMCP:
    fleet = workspace.fleet
    server = FastMCP(
        "White Hat Agent Campaigns",
        strict_input_validation=True,
        mask_error_details=True,
    )

    @server.tool(
        name="plan",
        version="1.0",
        description=(
            "Build a deterministic staged blueprint from exact scope, targets, desired artifacts, "
            "and adapter capabilities."
        ),
        annotations={"readOnlyHint": True, "idempotentHint": True, "openWorldHint": False},
        tags={"campaign", "planning"},
    )
    def plan(request: CampaignPlanningRequest) -> CampaignBlueprint:
        return plan_campaign(workspace.corpus, request)

    @server.tool(
        name="scope_check",
        version="1.0",
        description="Evaluate a typed probe intent against an exact captured program scope.",
        annotations={"readOnlyHint": True, "idempotentHint": True, "openWorldHint": False},
        tags={"scope", "planning"},
    )
    def scope_check(scope: ScopeManifest, intent: ProbeIntent) -> ScopeDecision:
        return evaluate_scope(scope, intent)

    @server.tool(
        name="create",
        version="1.0",
        description="Persist a campaign manifest with exact scope and corpus identities.",
        annotations={"readOnlyHint": False, "idempotentHint": True, "openWorldHint": False},
        tags={"campaign", "write"},
    )
    def create(manifest: CampaignManifest) -> CampaignManifest:
        validate_campaign_manifest(workspace.corpus, manifest)
        fleet.create_campaign(manifest)
        return manifest

    @server.tool(
        name="set_state",
        version="1.0",
        description="Move a campaign to an explicit lifecycle state.",
        annotations={"readOnlyHint": False, "idempotentHint": True, "openWorldHint": False},
        tags={"campaign", "write"},
    )
    def set_state(campaign_id: str, state: CampaignState) -> CampaignManifest:
        fleet.set_campaign_state(campaign_id, state)
        return fleet.get_campaign(campaign_id)

    @server.tool(
        name="enqueue",
        version="1.0",
        description="Scope-check and atomically deduplicate one fleet task for a persisted campaign.",
        annotations={"readOnlyHint": False, "idempotentHint": True, "openWorldHint": False},
        tags={"campaign", "fleet", "write"},
    )
    def enqueue(
        campaign_id: str,
        intent: ProbeIntent,
        payload: dict[str, Any] | None = None,
        priority: int = 50,
    ) -> EnqueueOutcome:
        return fleet.enqueue_intent(
            campaign_id,
            intent,
            priority=priority,
            payload=payload or {},
        )

    @server.prompt(
        name="plan_campaign",
        version="1.0",
        description="Plan a campaign from scope, corpus, capabilities, evidence goals, and budgets.",
        tags={"campaign", "planning"},
    )
    def plan_campaign_prompt(scope_json: str, objective: str, capabilities: list[str]) -> str:
        return (
            "Plan a White Hat Agent campaign. Treat the supplied scope JSON as authoritative. "
            "Search the knowledge corpus before proposing new methods. Produce typed ProbeIntent records, "
            "deduplicate target/playbook pairs, state required evidence, and keep client and "
            "server claims separate.\n\n"
            f"Objective: {objective}\nCapabilities: {capabilities}\nScope JSON:\n{scope_json}"
        )

    return server


def _fleet_server(workspace: Workspace) -> FastMCP:
    fleet = workspace.fleet
    server = FastMCP(
        "White Hat Agent Fleet",
        strict_input_validation=True,
        mask_error_details=True,
    )

    @server.tool(
        name="register",
        version="1.0",
        description="Register or refresh an agent and its exact capability inventory.",
        annotations={"readOnlyHint": False, "idempotentHint": True, "openWorldHint": False},
        tags={"fleet", "write"},
    )
    def register(registration: AgentRegistration) -> AgentRegistration:
        fleet.register_agent(registration)
        return registration

    @server.tool(
        name="claim",
        version="1.0",
        description="Atomically lease the highest-priority compatible task to a registered agent.",
        annotations={"readOnlyHint": False, "idempotentHint": False, "openWorldHint": False},
        tags={"fleet", "lease"},
    )
    def claim(agent_id: str, lease_seconds: int = 300) -> TaskLease | None:
        return fleet.claim_task(agent_id, lease_seconds=lease_seconds)

    @server.tool(
        name="heartbeat",
        version="1.0",
        description="Extend an active task lease owned by the calling agent.",
        annotations={"readOnlyHint": False, "idempotentHint": False, "openWorldHint": False},
        tags={"fleet", "lease"},
    )
    def heartbeat(task_id: str, agent_id: str, lease_token: str, extend_seconds: int = 300) -> dict[str, str]:
        expires = fleet.heartbeat(task_id, agent_id, lease_token, extend_seconds=extend_seconds)
        return {"task_id": task_id, "lease_expires_at": expires.isoformat()}

    @server.tool(
        name="report",
        version="1.0",
        description=(
            "Complete a leased task and preserve findings, evidence, adjacent hypotheses, and learning."
        ),
        annotations={"readOnlyHint": False, "idempotentHint": False, "openWorldHint": False},
        tags={"fleet", "write"},
    )
    def report(agent_id: str, result: TaskResult) -> dict[str, str]:
        task = fleet.get_task(result.task_id)
        workspace.evidence.assert_evidence_exists(
            result.evidence_ids,
            campaign_id=task.campaign_id,
        )
        state = fleet.complete_task(agent_id, result)
        return {"task_id": result.task_id, "state": state.value}

    @server.tool(
        name="stats",
        version="1.0",
        description="Return fleet campaign, agent, queue, lease, and terminal-task counts.",
        annotations={"readOnlyHint": True, "idempotentHint": True, "openWorldHint": False},
        tags={"fleet", "read"},
    )
    def stats():
        return fleet.stats()

    return server


def _evidence_server(workspace: Workspace) -> FastMCP:
    server = FastMCP(
        "White Hat Agent Evidence",
        strict_input_validation=True,
        mask_error_details=True,
    )
    store = workspace.evidence
    store.initialize()

    @server.tool(
        name="import_file",
        version="1.0",
        description="Import a bounded local file into immutable content-addressed evidence storage.",
        annotations={"readOnlyHint": False, "idempotentHint": True, "openWorldHint": False},
        tags={"evidence", "write"},
    )
    def import_file(
        path: str,
        descriptor: EvidenceDescriptor,
        media_type: str = "application/octet-stream",
    ) -> EvidenceRecord:
        return store.import_file(Path(path), descriptor, media_type=media_type)

    @server.tool(
        name="register_external",
        version="1.0",
        description="Register immutable evidence stored outside the workspace by digest and URI.",
        annotations={"readOnlyHint": False, "idempotentHint": True, "openWorldHint": False},
        tags={"evidence", "write"},
    )
    def register_external(
        descriptor: EvidenceDescriptor,
        content_sha256: str,
        byte_length: int,
        media_type: str,
        external_uri: str,
    ) -> EvidenceRecord:
        return store.register_external(
            descriptor,
            content_sha256=content_sha256,
            byte_length=byte_length,
            media_type=media_type,
            external_uri=external_uri,
        )

    @server.tool(
        name="get",
        version="1.0",
        description="Return one exact immutable evidence record.",
        annotations={"readOnlyHint": True, "idempotentHint": True, "openWorldHint": False},
        tags={"evidence", "read"},
    )
    def get(evidence_id: str) -> EvidenceRecord:
        return store.get_evidence(evidence_id)

    @server.tool(
        name="list",
        version="1.0",
        description="List evidence identities for one campaign or task.",
        annotations={"readOnlyHint": True, "idempotentHint": True, "openWorldHint": False},
        tags={"evidence", "read"},
    )
    def list_records(campaign_id: str, task_id: str | None = None, limit: int = 100) -> list[EvidenceRecord]:
        return store.list_evidence(campaign_id=campaign_id, task_id=task_id, limit=limit)

    @server.tool(
        name="add_finding",
        version="1.0",
        description="Persist a finding whose evidence identities belong to the same campaign and task.",
        annotations={"readOnlyHint": False, "idempotentHint": True, "openWorldHint": False},
        tags={"finding", "write"},
    )
    def add_finding(finding: FindingRecord) -> FindingRecord:
        return store.add_finding(finding)

    @server.tool(
        name="get_finding",
        version="1.0",
        description="Return one exact finding record.",
        annotations={"readOnlyHint": True, "idempotentHint": True, "openWorldHint": False},
        tags={"finding", "read"},
    )
    def get_finding(finding_id: str) -> FindingRecord:
        return store.get_finding(finding_id)

    @server.tool(
        name="list_findings",
        version="1.0",
        description="List all finding records for a campaign.",
        annotations={"readOnlyHint": True, "idempotentHint": True, "openWorldHint": False},
        tags={"finding", "read"},
    )
    def list_findings(campaign_id: str, limit: int = 100) -> list[FindingRecord]:
        return store.list_findings(campaign_id=campaign_id, limit=limit)

    @server.tool(
        name="finding_history",
        version="1.0",
        description="Return the digest-linked immutable revision history for one finding.",
        annotations={"readOnlyHint": True, "idempotentHint": True, "openWorldHint": False},
        tags={"finding", "read"},
    )
    def finding_history(finding_id: str, limit: int = 100) -> list[FindingRecord]:
        return store.finding_history(finding_id, limit=limit)

    return server


def _discovery_server() -> FastMCP:
    server = FastMCP(
        "White Hat Agent Discovery",
        strict_input_validation=True,
        mask_error_details=True,
    )
    planner = AdaptivePlanner()

    @server.tool(
        name="plan",
        version="1.0",
        description="Rank the next evidence-producing probes for one resumable discovery episode.",
        annotations={"readOnlyHint": True, "idempotentHint": True, "openWorldHint": False},
        tags={"discovery", "planning"},
    )
    def plan(episode: DiscoveryEpisode, limit: int = 3) -> DiscoveryPlan:
        return planner.plan(episode, limit=limit)

    @server.tool(
        name="observe",
        version="1.0",
        description="Apply one normalized observation to an exact episode revision.",
        annotations={"readOnlyHint": False, "idempotentHint": True, "openWorldHint": False},
        tags={"discovery", "write"},
    )
    def observe(episode: DiscoveryEpisode, observation: DiscoveryObservation) -> DiscoveryEpisode:
        return apply_observation(episode, observation)

    @server.tool(
        name="verify",
        version="1.0",
        description=(
            "Classify causal evidence without crediting alternate success paths to the intended mechanism."
        ),
        annotations={"readOnlyHint": True, "idempotentHint": True, "openWorldHint": False},
        tags={"discovery", "verification"},
    )
    def verify(facts: CausalVerificationInput) -> CausalVerificationReport:
        return verify_causality(facts)

    return server


def _workspace(root: str | Path | None) -> Workspace:
    if root is None:
        return Workspace.discover()
    return Workspace.load(Path(root))


if __name__ == "__main__":
    run_server()
