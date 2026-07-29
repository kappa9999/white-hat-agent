"""Scope-aware campaigns and lease-based multi-agent coordination."""

from .contracts import contract_from_playbook, validate_campaign_manifest
from .fleet import FleetStore
from .models import CampaignManifest, CampaignPlaybookContract, ProbeIntent, ScopeManifest
from .planning import CampaignBlueprint, CampaignPlanningRequest, CampaignTarget, plan_campaign
from .scope import evaluate_scope

__all__ = [
    "CampaignBlueprint",
    "CampaignManifest",
    "CampaignPlanningRequest",
    "CampaignPlaybookContract",
    "CampaignTarget",
    "FleetStore",
    "ProbeIntent",
    "ScopeManifest",
    "contract_from_playbook",
    "evaluate_scope",
    "plan_campaign",
    "validate_campaign_manifest",
]
