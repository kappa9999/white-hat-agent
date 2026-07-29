from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ValidationError

from .adapters import ReplayAdapter, ReplayTranscript
from .campaign.contracts import validate_campaign_manifest
from .campaign.fleet import FleetError
from .campaign.models import (
    AgentRegistration,
    CampaignManifest,
    CampaignState,
    Opportunity,
    OpportunityState,
    ProbeIntent,
    ScopeManifest,
    TaskResult,
)
from .campaign.opportunities import rank_opportunities
from .campaign.planning import CampaignPlanningRequest, plan_campaign
from .campaign.scope import evaluate_scope
from .capabilities.catalog import CapabilityCatalog
from .episode import apply_observation
from .evaluation import evaluate_simulation
from .evidence.models import EvidenceDescriptor, FindingRecord
from .evidence.store import EvidenceError
from .expansion import ReplayExpansionTranscript, ReplayHypothesisGenerator
from .intelligence import (
    IntelligenceError,
    IntelligenceService,
    IntelligenceSource,
    SyncStatus,
)
from .knowledge.compiler import compile_heuristic
from .knowledge.compose import CompositionRequest, compose_playbooks
from .knowledge.corpus import Corpus, dump_playbook
from .knowledge.learning import submission_from_learning
from .knowledge.models import KnowledgeSubmission, RightsDeclaration
from .mcp_server import run_server
from .models import CausalVerificationInput, DiscoveryEpisode, DiscoveryObservation, stable_id
from .planner import AdaptivePlanner, PlannerConfig
from .schemas import _atomic_write, export_schemas
from .simulator import SimulationResult, run_simulation
from .verification import verify_causality
from .workspace import Workspace


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wha",
        description=(
            "White Hat Agent Core: public intelligence, cyber knowledge, campaigns, fleets, and discovery"
        ),
    )
    parser.add_argument("--version", action="version", version="White Hat Agent Core 0.2.0")
    commands = parser.add_subparsers(dest="command", required=True)

    initialize = commands.add_parser("init", help="initialize an approachable local workspace")
    initialize.add_argument("path", type=Path, nargs="?", default=Path.cwd())
    initialize.add_argument("--no-builtin-corpus", action="store_true")

    doctor = commands.add_parser("doctor", help="verify workspace, corpus, and fleet state")
    _workspace_option(doctor)

    serve = commands.add_parser("serve", help="serve namespaced MCP tools, resources, and prompts")
    _workspace_option(serve)
    serve.add_argument("--transport", choices=["stdio", "http"], default="stdio")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)

    corpus = commands.add_parser("corpus", help="validate, index, search, or inspect the cyber corpus")
    corpus_commands = corpus.add_subparsers(dest="corpus_command", required=True)
    corpus_validate = corpus_commands.add_parser("validate", help="validate every playbook")
    _workspace_option(corpus_validate)
    corpus_index = corpus_commands.add_parser("index", help="write a deterministic corpus manifest")
    _workspace_option(corpus_index)
    corpus_index.add_argument("--out", type=Path)
    corpus_search = corpus_commands.add_parser("search", help="search playbooks by concepts and domains")
    _workspace_option(corpus_search)
    corpus_search.add_argument("query", nargs="?", default="")
    corpus_search.add_argument("--domain", action="append", default=[])
    corpus_search.add_argument("--capability", action="append", default=[])
    corpus_search.add_argument("--limit", type=int, default=10)
    corpus_show = corpus_commands.add_parser("show", help="show one playbook as JSON")
    _workspace_option(corpus_show)
    corpus_show.add_argument("playbook_id")
    corpus_show.add_argument("--version")

    capability = commands.add_parser(
        "capability", help="inspect adapter contracts and calculate capability gaps"
    )
    capability_commands = capability.add_subparsers(dest="capability_command", required=True)
    capability_list = capability_commands.add_parser("list", help="list or search capabilities")
    _workspace_option(capability_list)
    capability_list.add_argument("query", nargs="?", default="")
    capability_list.add_argument("--limit", type=int, default=20)
    capability_show = capability_commands.add_parser("show", help="show one capability definition")
    _workspace_option(capability_show)
    capability_show.add_argument("capability_id")
    capability_validate = capability_commands.add_parser(
        "validate", help="validate corpus capability references and execution classes"
    )
    _workspace_option(capability_validate)
    capability_gaps = capability_commands.add_parser(
        "gaps", help="compare playbooks with available adapter capabilities"
    )
    _workspace_option(capability_gaps)
    capability_gaps.add_argument("--playbook", action="append", required=True)
    capability_gaps.add_argument("--available", action="append", default=[])

    knowledge = commands.add_parser("knowledge", help="turn plain-language knowledge into a playbook draft")
    knowledge_commands = knowledge.add_subparsers(dest="knowledge_command", required=True)
    ingest = knowledge_commands.add_parser(
        "ingest", help="losslessly ingest any-language procedural knowledge"
    )
    _workspace_option(ingest)
    source = ingest.add_mutually_exclusive_group(required=True)
    source.add_argument("--file", type=Path)
    source.add_argument("--text")
    ingest.add_argument("--language", default="und")
    ingest.add_argument("--title")
    ingest.add_argument("--domain", action="append", default=[])
    ingest.add_argument("--contributor")
    ingest.add_argument(
        "--rights",
        choices=[item.value for item in RightsDeclaration],
        default=RightsDeclaration.ORIGINAL.value,
    )
    ingest.add_argument("--persist", action="store_true")
    ingest.add_argument("--out", type=Path)
    ingest.add_argument("--playbook-yaml", type=Path)
    learning_candidates = knowledge_commands.add_parser(
        "candidates", help="list reusable learning from completed fleet tasks"
    )
    _workspace_option(learning_candidates)
    learning_candidates.add_argument("--campaign-id")
    learning_candidates.add_argument("--limit", type=int, default=100)
    learning_ingest = knowledge_commands.add_parser(
        "ingest-result", help="compile one fleet learning candidate into a draft"
    )
    _workspace_option(learning_ingest)
    learning_ingest.add_argument("candidate_id")
    learning_ingest.add_argument(
        "--rights",
        choices=[item.value for item in RightsDeclaration],
        required=True,
    )
    learning_ingest.add_argument("--contributor")
    learning_ingest.add_argument("--language", default="und")
    learning_ingest.add_argument("--persist", action="store_true")
    learning_ingest.add_argument("--out", type=Path)

    playbook = commands.add_parser("playbook", help="compose reusable playbooks into a typed workflow")
    playbook_commands = playbook.add_subparsers(dest="playbook_command", required=True)
    compose = playbook_commands.add_parser("compose", help="compose by semantic artifacts and capabilities")
    _workspace_option(compose)
    compose.add_argument("--request", type=Path, required=True)
    compose.add_argument("--out", type=Path)

    scope = commands.add_parser("scope", help="evaluate an exact operation against captured program scope")
    scope_commands = scope.add_subparsers(dest="scope_command", required=True)
    scope_check = scope_commands.add_parser("check", help="evaluate one typed probe intent")
    scope_check.add_argument("--scope", type=Path, required=True)
    scope_check.add_argument("--intent", type=Path, required=True)
    scope_check.add_argument("--out", type=Path)

    campaign = commands.add_parser("campaign", help="create and operate a scoped campaign")
    campaign_commands = campaign.add_subparsers(dest="campaign_command", required=True)
    campaign_plan = campaign_commands.add_parser(
        "plan", help="build a staged blueprint from scope, targets, and capabilities"
    )
    _workspace_option(campaign_plan)
    campaign_plan.add_argument("--request", type=Path, required=True)
    campaign_plan.add_argument("--out", type=Path)
    campaign_create = campaign_commands.add_parser("create", help="persist a campaign manifest")
    _workspace_option(campaign_create)
    campaign_create.add_argument("--manifest", type=Path, required=True)
    campaign_state = campaign_commands.add_parser("state", help="change campaign lifecycle state")
    _workspace_option(campaign_state)
    campaign_state.add_argument("campaign_id")
    campaign_state.add_argument("state", choices=[item.value for item in CampaignState])
    campaign_enqueue = campaign_commands.add_parser(
        "enqueue", help="scope-check and deduplicate one typed intent"
    )
    _workspace_option(campaign_enqueue)
    campaign_enqueue.add_argument("campaign_id")
    campaign_enqueue.add_argument("--intent", type=Path, required=True)
    campaign_enqueue.add_argument("--payload", type=Path)
    campaign_enqueue.add_argument("--priority", type=int, default=50)

    intelligence = commands.add_parser(
        "intelligence",
        help="synchronize, rank, and inspect bounded public vulnerability intelligence",
    )
    intelligence_commands = intelligence.add_subparsers(
        dest="intelligence_command",
        required=True,
    )
    intelligence_sync = intelligence_commands.add_parser(
        "sync",
        help="synchronize fixed official sources into immutable local state",
    )
    _workspace_option(intelligence_sync)
    intelligence_sync.add_argument(
        "--source",
        action="append",
        choices=[IntelligenceSource.CISA_KEV.value, IntelligenceSource.OSV.value],
    )
    intelligence_sync.add_argument("--since-hours", type=float, default=24.0)
    intelligence_sync.add_argument("--ecosystem", action="append", default=[])
    intelligence_sync.add_argument(
        "--limit-per-source",
        type=int,
        default=1000,
        help="OSV/EPSS selection ceiling; CISA always diffs the complete bounded catalog",
    )
    intelligence_sync.add_argument("--enrich-epss", action="store_true")
    intelligence_sync.add_argument(
        "--require-success",
        action="store_true",
        help="return a failure after writing the report unless every requested primary source succeeds",
    )
    intelligence_sync.add_argument("--out", type=Path)

    intelligence_get = intelligence_commands.add_parser(
        "get",
        help="resolve one advisory by native ID or alias",
    )
    _workspace_option(intelligence_get)
    intelligence_get.add_argument("advisory_id")
    intelligence_get.add_argument("--out", type=Path)

    intelligence_list = intelligence_commands.add_parser(
        "list",
        help="list locally stored advisories by transparent priority",
    )
    _add_intelligence_filters(intelligence_list)
    intelligence_list.add_argument("--out", type=Path)

    intelligence_status = intelligence_commands.add_parser(
        "status",
        help="show source freshness, record counts, and the latest sync result",
    )
    _workspace_option(intelligence_status)
    intelligence_status.add_argument("--out", type=Path)

    intelligence_brief = intelligence_commands.add_parser(
        "brief",
        help="render a deterministic Markdown intelligence brief",
    )
    _add_intelligence_filters(intelligence_brief)
    intelligence_brief.add_argument("--out", type=Path)

    opportunity = commands.add_parser(
        "opportunity", help="intake and rank bug-bounty, open-source, lab, or private targets"
    )
    opportunity_commands = opportunity.add_subparsers(dest="opportunity_command", required=True)
    opportunity_add = opportunity_commands.add_parser("add", help="add a normalized opportunity")
    _workspace_option(opportunity_add)
    opportunity_add.add_argument("--record", type=Path, required=True)
    opportunity_get = opportunity_commands.add_parser("get", help="get one opportunity")
    _workspace_option(opportunity_get)
    opportunity_get.add_argument("opportunity_id")
    opportunity_list = opportunity_commands.add_parser("list", help="list opportunities")
    _workspace_option(opportunity_list)
    opportunity_list.add_argument("--state", choices=[item.value for item in OpportunityState])
    opportunity_list.add_argument("--limit", type=int, default=100)
    opportunity_state = opportunity_commands.add_parser("state", help="change opportunity state")
    _workspace_option(opportunity_state)
    opportunity_state.add_argument("opportunity_id")
    opportunity_state.add_argument("state", choices=[item.value for item in OpportunityState])
    opportunity_rank = opportunity_commands.add_parser("rank", help="rank opportunities for a fleet")
    _workspace_option(opportunity_rank)
    opportunity_rank.add_argument("--capability", action="append", default=[])
    opportunity_rank.add_argument("--limit", type=int, default=100)

    fleet = commands.add_parser("fleet", help="register agents and lease/report campaign tasks")
    fleet_commands = fleet.add_subparsers(dest="fleet_command", required=True)
    fleet_register = fleet_commands.add_parser("register", help="register an agent capability profile")
    _workspace_option(fleet_register)
    fleet_register.add_argument("--registration", type=Path, required=True)
    fleet_claim = fleet_commands.add_parser("claim", help="claim the next compatible task")
    _workspace_option(fleet_claim)
    fleet_claim.add_argument("agent_id")
    fleet_claim.add_argument("--lease-seconds", type=int, default=300)
    fleet_heartbeat = fleet_commands.add_parser("heartbeat", help="extend an active task lease")
    _workspace_option(fleet_heartbeat)
    fleet_heartbeat.add_argument("agent_id")
    fleet_heartbeat.add_argument("task_id")
    fleet_heartbeat.add_argument("lease_token")
    fleet_heartbeat.add_argument("--extend-seconds", type=int, default=300)
    fleet_report = fleet_commands.add_parser("report", help="report a leased task result")
    _workspace_option(fleet_report)
    fleet_report.add_argument("agent_id")
    fleet_report.add_argument("--result", type=Path, required=True)
    fleet_stats = fleet_commands.add_parser("stats", help="show campaign fleet state")
    _workspace_option(fleet_stats)

    evidence = commands.add_parser("evidence", help="store immutable artifacts and findings")
    evidence_commands = evidence.add_subparsers(dest="evidence_command", required=True)
    evidence_import = evidence_commands.add_parser("import", help="import a local evidence file")
    _workspace_option(evidence_import)
    evidence_import.add_argument("--file", type=Path, required=True)
    evidence_import.add_argument("--descriptor", type=Path, required=True)
    evidence_import.add_argument("--media-type", default="application/octet-stream")
    evidence_get = evidence_commands.add_parser("get", help="get one evidence record")
    _workspace_option(evidence_get)
    evidence_get.add_argument("evidence_id")
    evidence_list = evidence_commands.add_parser("list", help="list campaign evidence")
    _workspace_option(evidence_list)
    evidence_list.add_argument("campaign_id")
    evidence_list.add_argument("--task-id")
    evidence_list.add_argument("--limit", type=int, default=100)

    finding = commands.add_parser("finding", help="persist and inspect evidence-bound findings")
    finding_commands = finding.add_subparsers(dest="finding_command", required=True)
    finding_add = finding_commands.add_parser("add", help="add an evidence-bound finding")
    _workspace_option(finding_add)
    finding_add.add_argument("--record", type=Path, required=True)
    finding_get = finding_commands.add_parser("get", help="get one finding")
    _workspace_option(finding_get)
    finding_get.add_argument("finding_id")
    finding_list = finding_commands.add_parser("list", help="list campaign findings")
    _workspace_option(finding_list)
    finding_list.add_argument("campaign_id")
    finding_list.add_argument("--limit", type=int, default=100)
    finding_history = finding_commands.add_parser("history", help="show finding revision history")
    _workspace_option(finding_history)
    finding_history.add_argument("finding_id")
    finding_history.add_argument("--limit", type=int, default=100)

    discovery = commands.add_parser("discovery", help="adaptive hypothesis planning and causal verification")
    discovery_commands = discovery.add_subparsers(dest="discovery_command", required=True)
    plan = discovery_commands.add_parser("plan", help="rank the next typed probes")
    plan.add_argument("--episode", type=Path, required=True)
    plan.add_argument("--limit", type=int, default=3)
    plan.add_argument("--out", type=Path)
    _add_planner_options(plan)
    observe = discovery_commands.add_parser("observe", help="apply one normalized observation")
    observe.add_argument("--episode", type=Path, required=True)
    observe.add_argument("--observation", type=Path, required=True)
    observe.add_argument("--out", type=Path, required=True)
    verify = discovery_commands.add_parser("verify", help="evaluate exact causal evidence")
    verify.add_argument("--input", type=Path, required=True)
    verify.add_argument("--out", type=Path)
    simulate = discovery_commands.add_parser("simulate", help="run a deterministic replay episode")
    simulate.add_argument("--episode", type=Path, required=True)
    simulate.add_argument("--replay", type=Path, required=True)
    simulate.add_argument("--expansions", type=Path)
    simulate.add_argument("--max-cycles", type=int, default=100)
    simulate.add_argument("--max-expansions", type=int, default=8)
    simulate.add_argument("--expansion-batch-limit", type=int, default=8)
    simulate.add_argument("--continue-after-complete", action="store_true")
    simulate.add_argument("--out", type=Path)
    _add_planner_options(simulate)
    evaluate = discovery_commands.add_parser("evaluate", help="score a completed discovery simulation")
    evaluate.add_argument("--simulation", type=Path, required=True)
    evaluate.add_argument("--out", type=Path)

    schema = commands.add_parser("schema", help="export all public JSON schemas")
    schema.add_argument("--out-dir", type=Path, required=True)
    return parser


def _workspace_option(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--workspace", type=Path)


def _add_intelligence_filters(parser: argparse.ArgumentParser) -> None:
    _workspace_option(parser)
    parser.add_argument(
        "--source",
        action="append",
        choices=[item.value for item in IntelligenceSource],
    )
    parser.add_argument("--ecosystem", action="append", default=[])
    exploited = parser.add_mutually_exclusive_group()
    exploited.add_argument(
        "--known-exploited",
        dest="known_exploited",
        action="store_true",
    )
    exploited.add_argument(
        "--not-known-exploited",
        dest="known_exploited",
        action="store_false",
    )
    parser.set_defaults(known_exploited=None)
    parser.add_argument(
        "--include-withdrawn",
        action="store_true",
        help="include withdrawn advisories instead of returning active records only",
    )
    parser.add_argument("--limit", type=int, default=20)


def _add_planner_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--plateau-window", type=int, default=3)
    parser.add_argument("--plateau-progress-threshold", type=float, default=0.08)
    parser.add_argument("--productive-progress-threshold", type=float, default=0.20)
    parser.add_argument("--recent-family-window", type=int, default=6)
    parser.add_argument("--penalty-scale", type=float, default=0.55)


def _planner_from_args(args: argparse.Namespace) -> AdaptivePlanner:
    return AdaptivePlanner(
        PlannerConfig(
            plateau_window=args.plateau_window,
            plateau_progress_threshold=args.plateau_progress_threshold,
            productive_progress_threshold=args.productive_progress_threshold,
            recent_family_window=args.recent_family_window,
            penalty_scale=args.penalty_scale,
        )
    )


def _read_model(path: Path, model: type[BaseModel]) -> Any:
    return model.model_validate(_read_data(path))


def _read_data(path: Path) -> Any:
    content = path.read_text(encoding="utf-8")
    if path.suffix.lower() in {".yaml", ".yml"}:
        return yaml.safe_load(content)
    return json.loads(content)


def _jsonable(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", exclude_none=True)
    if isinstance(value, dict):
        return {str(key): _jsonable(child) for key, child in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(child) for child in value]
    return value


def _render(value: BaseModel | dict[str, Any] | list[Any]) -> str:
    payload = _jsonable(value)
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _emit(value: BaseModel | dict[str, Any] | list[Any], output: Path | None = None) -> None:
    payload = _render(value)
    if output is None:
        sys.stdout.write(payload)
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write(output, payload)
    sys.stdout.write(f"wrote {output}\n")


def _emit_text(value: str, output: Path | None = None) -> None:
    if output is None:
        sys.stdout.write(value)
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write(output, value)
    sys.stdout.write(f"wrote {output}\n")


def _workspace(args: argparse.Namespace) -> Workspace:
    root = getattr(args, "workspace", None)
    return Workspace.load(root) if root else Workspace.discover()


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "init":
            workspace = Workspace.initialize(
                args.path,
                copy_builtin_corpus=not args.no_builtin_corpus,
            )
            _emit(workspace.doctor())
        elif args.command == "doctor":
            _emit(_workspace(args).doctor())
        elif args.command == "serve":
            workspace = _workspace(args)
            run_server(
                workspace_root=workspace.root,
                transport=args.transport,
                host=args.host,
                port=args.port,
            )
        elif args.command == "corpus":
            _run_corpus(args)
        elif args.command == "capability":
            _run_capability(args)
        elif args.command == "knowledge":
            _run_knowledge(args)
        elif args.command == "playbook":
            workspace = _workspace(args)
            request = _read_model(args.request, CompositionRequest)
            _emit(compose_playbooks(workspace.corpus, request), args.out)
        elif args.command == "scope":
            scope = _read_model(args.scope, ScopeManifest)
            intent = _read_model(args.intent, ProbeIntent)
            _emit(evaluate_scope(scope, intent), args.out)
        elif args.command == "campaign":
            _run_campaign(args)
        elif args.command == "intelligence":
            _run_intelligence(args)
        elif args.command == "opportunity":
            _run_opportunity(args)
        elif args.command == "fleet":
            _run_fleet(args)
        elif args.command == "evidence":
            _run_evidence(args)
        elif args.command == "finding":
            _run_finding(args)
        elif args.command == "discovery":
            _run_discovery(args)
        elif args.command == "schema":
            paths = export_schemas(args.out_dir)
            sys.stdout.write("\n".join(str(path) for path in paths) + "\n")
        else:  # pragma: no cover - argparse enforces command choices
            raise AssertionError(f"unknown command: {args.command}")
    except (
        FileNotFoundError,
        EvidenceError,
        FleetError,
        IntelligenceError,
        KeyError,
        OSError,
        json.JSONDecodeError,
        yaml.YAMLError,
        ValidationError,
        ValueError,
    ) as exc:
        sys.stderr.write(f"wha: {exc}\n")
        return 2
    except KeyboardInterrupt:
        return 130
    return 0


def _run_corpus(args: argparse.Namespace) -> None:
    workspace = _workspace(args)
    corpus = Corpus(workspace.corpus_dir)
    report = corpus.load()
    if args.corpus_command == "validate":
        _emit(report)
    elif args.corpus_command == "index":
        if not report.valid:
            raise ValueError("cannot index an invalid corpus")
        output = args.out or workspace.corpus_dir.parent / "manifest.json"
        corpus.write_manifest(output)
        _emit(corpus.manifest(), output)
    elif args.corpus_command == "search":
        if not report.valid:
            raise ValueError("cannot search an invalid corpus")
        _emit(
            corpus.search(
                args.query,
                domains=args.domain,
                capabilities=args.capability,
                limit=args.limit,
            )
        )
    elif args.corpus_command == "show":
        if not report.valid:
            raise ValueError("cannot read an invalid corpus")
        _emit(corpus.get(args.playbook_id, args.version))


def _run_capability(args: argparse.Namespace) -> None:
    workspace = _workspace(args)
    catalog = CapabilityCatalog(workspace.capability_catalog_path)
    report = catalog.load()
    if not report.valid:
        raise ValueError(f"invalid capability catalog: {report.issues}")
    if args.capability_command == "list":
        _emit(catalog.search(args.query, limit=args.limit))
    elif args.capability_command == "show":
        _emit(catalog.get(args.capability_id))
    elif args.capability_command == "validate":
        _emit(catalog.validate_playbooks(workspace.corpus.all()))
    elif args.capability_command == "gaps":
        playbooks = [workspace.corpus.get(playbook_id) for playbook_id in args.playbook]
        _emit(catalog.gaps(playbooks, args.available))


def _run_knowledge(args: argparse.Namespace) -> None:
    workspace = _workspace(args)
    if args.knowledge_command == "candidates":
        _emit(
            workspace.fleet.learning_candidates(
                campaign_id=args.campaign_id,
                limit=args.limit,
            )
        )
        return
    if args.knowledge_command == "ingest-result":
        matches = [
            candidate
            for candidate in workspace.fleet.learning_candidates(limit=1000)
            if candidate.candidate_id == args.candidate_id
        ]
        if not matches:
            raise KeyError(f"unknown learning candidate: {args.candidate_id}")
        submission = submission_from_learning(
            matches[0],
            rights=RightsDeclaration(args.rights),
            contributor=args.contributor,
            language=args.language,
        )
        draft = compile_heuristic(submission)
        output = args.out
        if args.persist:
            output = output or workspace.submissions_dir / f"{submission.submission_id}.json"
        _emit(draft, output)
        return
    text = args.text if args.text is not None else args.file.read_text(encoding="utf-8")
    submission_payload = {
        "text": text,
        "language": args.language,
        "title": args.title,
        "domains": args.domain,
        "contributor": args.contributor,
    }
    submission = KnowledgeSubmission(
        submission_id=stable_id("submission", submission_payload),
        title_hint=args.title,
        original_language=args.language,
        original_text=text,
        domain_hints=args.domain,
        contributor_handle=args.contributor,
        rights=RightsDeclaration(args.rights),
    )
    draft = compile_heuristic(submission)
    output = args.out
    if args.persist:
        output = output or workspace.submissions_dir / f"{submission.submission_id}.json"
    _emit(draft, output)
    if args.playbook_yaml:
        args.playbook_yaml.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write(args.playbook_yaml, dump_playbook(draft.playbook))
        sys.stdout.write(f"wrote {args.playbook_yaml}\n")


def _run_campaign(args: argparse.Namespace) -> None:
    workspace = _workspace(args)
    fleet = workspace.fleet
    fleet.initialize()
    if args.campaign_command == "plan":
        request = _read_model(args.request, CampaignPlanningRequest)
        _emit(plan_campaign(workspace.corpus, request), args.out)
    elif args.campaign_command == "create":
        manifest = _read_model(args.manifest, CampaignManifest)
        validate_campaign_manifest(workspace.corpus, manifest)
        fleet.create_campaign(manifest)
        _emit(manifest)
    elif args.campaign_command == "state":
        fleet.set_campaign_state(args.campaign_id, CampaignState(args.state))
        _emit(fleet.get_campaign(args.campaign_id))
    elif args.campaign_command == "enqueue":
        intent = _read_model(args.intent, ProbeIntent)
        payload = _read_data(args.payload) if args.payload else {}
        if not isinstance(payload, dict):
            raise ValueError("task payload must be a JSON or YAML mapping")
        _emit(
            fleet.enqueue_intent(
                args.campaign_id,
                intent,
                priority=args.priority,
                payload=payload,
            )
        )


def _run_intelligence(args: argparse.Namespace) -> None:
    workspace = _workspace(args)
    store = workspace.intelligence
    store.initialize()
    service = IntelligenceService(store)
    if args.intelligence_command == "sync":
        report = service.sync(
            sources=args.source,
            since_hours=args.since_hours,
            ecosystems=args.ecosystem,
            limit_per_source=args.limit_per_source,
            enrich_epss=args.enrich_epss,
        )
        _emit(report, args.out)
        if args.require_success:
            required = set(report.requested_sources)
            unsuccessful = [
                result.source.value
                for result in report.results
                if result.source in required and result.status != SyncStatus.SUCCESS
            ]
            if unsuccessful:
                raise IntelligenceError(
                    "required intelligence source did not synchronize successfully: "
                    + ", ".join(unsuccessful)
                )
    elif args.intelligence_command == "get":
        _emit(service.get(args.advisory_id), args.out)
    elif args.intelligence_command == "list":
        _emit(
            service.list(
                sources=args.source,
                ecosystems=args.ecosystem,
                known_exploited=args.known_exploited,
                withdrawn=None if args.include_withdrawn else False,
                limit=args.limit,
            ),
            args.out,
        )
    elif args.intelligence_command == "status":
        _emit(service.status(), args.out)
    elif args.intelligence_command == "brief":
        _emit_text(
            service.brief(
                sources=args.source,
                ecosystems=args.ecosystem,
                known_exploited=args.known_exploited,
                withdrawn=None if args.include_withdrawn else False,
                limit=args.limit,
            ),
            args.out,
        )
    else:  # pragma: no cover - argparse enforces command choices
        raise AssertionError(f"unknown intelligence command: {args.intelligence_command}")


def _run_opportunity(args: argparse.Namespace) -> None:
    workspace = _workspace(args)
    fleet = workspace.fleet
    fleet.initialize()
    if args.opportunity_command == "add":
        opportunity = _read_model(args.record, Opportunity)
        fleet.add_opportunity(opportunity)
        _emit(opportunity)
    elif args.opportunity_command == "get":
        _emit(fleet.get_opportunity(args.opportunity_id))
    elif args.opportunity_command == "list":
        state = OpportunityState(args.state) if args.state else None
        _emit(fleet.list_opportunities(state, limit=args.limit))
    elif args.opportunity_command == "state":
        _emit(fleet.set_opportunity_state(args.opportunity_id, OpportunityState(args.state)))
    elif args.opportunity_command == "rank":
        _emit(
            rank_opportunities(
                fleet.list_opportunities(limit=1000),
                workspace.corpus,
                args.capability,
                limit=args.limit,
            )
        )


def _run_fleet(args: argparse.Namespace) -> None:
    fleet = _workspace(args).fleet
    fleet.initialize()
    if args.fleet_command == "register":
        registration = _read_model(args.registration, AgentRegistration)
        fleet.register_agent(registration)
        _emit(registration)
    elif args.fleet_command == "claim":
        lease = fleet.claim_task(args.agent_id, lease_seconds=args.lease_seconds)
        _emit(lease or {"task": None})
    elif args.fleet_command == "heartbeat":
        expires = fleet.heartbeat(
            args.task_id,
            args.agent_id,
            args.lease_token,
            extend_seconds=args.extend_seconds,
        )
        _emit({"task_id": args.task_id, "lease_expires_at": expires.isoformat()})
    elif args.fleet_command == "report":
        result = _read_model(args.result, TaskResult)
        task = fleet.get_task(result.task_id)
        _workspace(args).evidence.assert_evidence_exists(
            result.evidence_ids,
            campaign_id=task.campaign_id,
        )
        state = fleet.complete_task(args.agent_id, result)
        _emit({"task_id": result.task_id, "state": state.value})
    elif args.fleet_command == "stats":
        _emit(fleet.stats())


def _run_evidence(args: argparse.Namespace) -> None:
    store = _workspace(args).evidence
    store.initialize()
    if args.evidence_command == "import":
        descriptor = _read_model(args.descriptor, EvidenceDescriptor)
        _emit(store.import_file(args.file, descriptor, media_type=args.media_type))
    elif args.evidence_command == "get":
        _emit(store.get_evidence(args.evidence_id))
    elif args.evidence_command == "list":
        _emit(
            store.list_evidence(
                campaign_id=args.campaign_id,
                task_id=args.task_id,
                limit=args.limit,
            )
        )


def _run_finding(args: argparse.Namespace) -> None:
    store = _workspace(args).evidence
    store.initialize()
    if args.finding_command == "add":
        _emit(store.add_finding(_read_model(args.record, FindingRecord)))
    elif args.finding_command == "get":
        _emit(store.get_finding(args.finding_id))
    elif args.finding_command == "list":
        _emit(store.list_findings(campaign_id=args.campaign_id, limit=args.limit))
    elif args.finding_command == "history":
        _emit(store.finding_history(args.finding_id, limit=args.limit))


def _run_discovery(args: argparse.Namespace) -> None:
    if args.discovery_command == "plan":
        episode = _read_model(args.episode, DiscoveryEpisode)
        _emit(_planner_from_args(args).plan(episode, limit=args.limit), args.out)
    elif args.discovery_command == "observe":
        episode = _read_model(args.episode, DiscoveryEpisode)
        observation = _read_model(args.observation, DiscoveryObservation)
        _emit(apply_observation(episode, observation), args.out)
    elif args.discovery_command == "verify":
        facts = _read_model(args.input, CausalVerificationInput)
        _emit(verify_causality(facts), args.out)
    elif args.discovery_command == "simulate":
        episode = _read_model(args.episode, DiscoveryEpisode)
        transcript = _read_model(args.replay, ReplayTranscript)
        generator = None
        if args.expansions is not None:
            expansion_transcript = _read_model(args.expansions, ReplayExpansionTranscript)
            generator = ReplayHypothesisGenerator(expansion_transcript)
        result = run_simulation(
            episode,
            ReplayAdapter(transcript),
            planner=_planner_from_args(args),
            generator=generator,
            max_cycles=args.max_cycles,
            max_expansions=args.max_expansions,
            expansion_batch_limit=args.expansion_batch_limit,
            continue_after_complete=args.continue_after_complete,
        )
        _emit(result, args.out)
    elif args.discovery_command == "evaluate":
        simulation = _read_model(args.simulation, SimulationResult)
        _emit(evaluate_simulation(simulation), args.out)


if __name__ == "__main__":
    raise SystemExit(main())
