"""White Hat Agent Core: a model-neutral cyber knowledge and orchestration brain."""

from .campaign.contracts import contract_from_playbook, validate_campaign_manifest
from .campaign.fleet import FleetStore
from .campaign.models import CampaignManifest, CampaignPlaybookContract, ProbeIntent, ScopeManifest
from .campaign.planning import CampaignBlueprint, CampaignPlanningRequest, CampaignTarget, plan_campaign
from .campaign.scope import evaluate_scope
from .episode import apply_observation
from .evidence.store import EvidenceStore
from .expansion import HypothesisGenerator, apply_expansion
from .knowledge.compose import compose_playbooks
from .knowledge.corpus import Corpus
from .mcp_server import create_server
from .models import DiscoveryEpisode, DiscoveryObservation, DiscoveryPlan
from .planner import AdaptivePlanner, PlannerConfig
from .verification import verify_causality
from .workspace import Workspace

__all__ = [
    "AdaptivePlanner",
    "CampaignBlueprint",
    "CampaignManifest",
    "CampaignPlanningRequest",
    "CampaignPlaybookContract",
    "CampaignTarget",
    "Corpus",
    "DiscoveryEpisode",
    "DiscoveryObservation",
    "DiscoveryPlan",
    "EvidenceStore",
    "FleetStore",
    "HypothesisGenerator",
    "PlannerConfig",
    "ProbeIntent",
    "ScopeManifest",
    "Workspace",
    "apply_expansion",
    "apply_observation",
    "compose_playbooks",
    "contract_from_playbook",
    "create_server",
    "evaluate_scope",
    "plan_campaign",
    "validate_campaign_manifest",
    "verify_causality",
]

__version__ = "0.1.0"
