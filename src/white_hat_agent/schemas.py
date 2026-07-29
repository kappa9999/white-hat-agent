from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from pydantic import BaseModel

from .adapters import ReplayTranscript
from .campaign.models import (
    AgentRegistration,
    CampaignManifest,
    CampaignPlaybookContract,
    EnqueueOutcome,
    FleetTask,
    LearningCandidate,
    Opportunity,
    ProbeIntent,
    ScopeDecision,
    ScopeManifest,
    TaskLease,
    TaskResult,
)
from .campaign.opportunities import OpportunityScore
from .campaign.planning import CampaignBlueprint, CampaignPlanningRequest
from .capabilities.catalog import CapabilityCompatibilityReport, CapabilityGapReport
from .capabilities.models import CapabilityCatalogManifest, CapabilityDefinition
from .evaluation import SimulationEvaluation
from .evidence.models import EvidenceDescriptor, EvidenceRecord, FindingRecord
from .expansion import ReplayExpansionTranscript
from .knowledge.compose import CompositePlaybook, CompositionRequest
from .knowledge.models import CompilationDraft, CorpusManifest, KnowledgeSubmission, Playbook
from .models import (
    CausalVerificationInput,
    CausalVerificationReport,
    DiscoveryEpisode,
    DiscoveryObservation,
    DiscoveryPlan,
    HypothesisExpansionBatch,
)
from .simulator import SimulationResult

SCHEMA_MODELS: dict[str, type[BaseModel]] = {
    "agent-registration": AgentRegistration,
    "capability-catalog": CapabilityCatalogManifest,
    "capability-compatibility-report": CapabilityCompatibilityReport,
    "capability-definition": CapabilityDefinition,
    "capability-gap-report": CapabilityGapReport,
    "campaign-manifest": CampaignManifest,
    "campaign-playbook-contract": CampaignPlaybookContract,
    "campaign-blueprint": CampaignBlueprint,
    "campaign-planning-request": CampaignPlanningRequest,
    "causal-verification-input": CausalVerificationInput,
    "causal-verification-report": CausalVerificationReport,
    "compilation-draft": CompilationDraft,
    "composite-playbook": CompositePlaybook,
    "composition-request": CompositionRequest,
    "corpus-manifest": CorpusManifest,
    "discovery-episode": DiscoveryEpisode,
    "discovery-observation": DiscoveryObservation,
    "discovery-plan": DiscoveryPlan,
    "evidence-descriptor": EvidenceDescriptor,
    "evidence-record": EvidenceRecord,
    "finding-record": FindingRecord,
    "hypothesis-expansion": HypothesisExpansionBatch,
    "knowledge-submission": KnowledgeSubmission,
    "learning-candidate": LearningCandidate,
    "opportunity": Opportunity,
    "opportunity-score": OpportunityScore,
    "playbook": Playbook,
    "probe-intent": ProbeIntent,
    "replay-expansion-transcript": ReplayExpansionTranscript,
    "replay-transcript": ReplayTranscript,
    "scope-decision": ScopeDecision,
    "scope-manifest": ScopeManifest,
    "task-enqueue-outcome": EnqueueOutcome,
    "task-lease": TaskLease,
    "task-result": TaskResult,
    "fleet-task": FleetTask,
    "simulation-result": SimulationResult,
    "simulation-evaluation": SimulationEvaluation,
}


def export_schemas(output_dir: Path) -> list[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for name, model in sorted(SCHEMA_MODELS.items()):
        path = output_dir / f"{name}.schema.json"
        payload = json.dumps(model.model_json_schema(), indent=2, sort_keys=True) + "\n"
        _atomic_write(path, payload)
        written.append(path)
    return written


def _atomic_write(path: Path, payload: str) -> None:
    file_descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent, text=True)
    try:
        with os.fdopen(file_descriptor, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    except BaseException:
        Path(temporary_name).unlink(missing_ok=True)
        raise
