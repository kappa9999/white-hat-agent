from __future__ import annotations

from datetime import UTC, datetime, timedelta

from white_hat_agent.campaign.models import (
    CampaignBudget,
    CampaignManifest,
    CampaignObjective,
    CampaignPlaybookContract,
    DisclosurePolicy,
    ProgramKind,
    RateLimits,
    ScopeManifest,
    TargetKind,
    TargetRule,
)
from white_hat_agent.knowledge.models import ExecutionClass, ReviewState


def build_scope(*, max_requests: int = 20) -> ScopeManifest:
    now = datetime.now(UTC)
    return ScopeManifest(
        scope_id="example-lab-scope",
        program_kind=ProgramKind.LAB,
        program_name="Example local lab",
        rules_url="https://example.test/security/scope",
        rules_sha256="0" * 64,
        authorization_reference="Local synthetic fixture owned by the test suite",
        valid_from=now - timedelta(hours=1),
        valid_until=now + timedelta(hours=1),
        targets=[
            TargetRule(
                rule_id="apex",
                kind=TargetKind.DOMAIN,
                pattern="example.test",
            ),
            TargetRule(
                rule_id="subdomains",
                kind=TargetKind.DOMAIN,
                pattern="*.example.test",
            ),
            TargetRule(
                rule_id="excluded-admin",
                kind=TargetKind.DOMAIN,
                pattern="admin.example.test",
                in_scope=False,
            ),
            TargetRule(
                rule_id="lab-network",
                kind=TargetKind.CIDR,
                pattern="192.0.2.0/28",
            ),
            TargetRule(
                rule_id="repository",
                kind=TargetKind.REPOSITORY,
                pattern="https://github.com/example/project",
            ),
        ],
        allowed_execution_classes=[
            ExecutionClass.ANALYSIS,
            ExecutionClass.READ_ONLY,
            ExecutionClass.CONTROLLED_ACTIVE,
        ],
        allowed_capabilities=["http.request", "http.capture", "data.diff", "evidence.write"],
        prohibited_capabilities=["account.delete"],
        prohibited_action_tags=["denial-of-service"],
        rate_limits=RateLimits(
            requests_per_second=1,
            burst=2,
            max_requests_per_task=max_requests,
            max_concurrency=2,
        ),
        data_handling=["Synthetic test data only"],
        disclosure=DisclosurePolicy(channel="local-test-report"),
    )


def build_campaign(*, max_tasks: int = 10, max_cost: float = 20.0) -> CampaignManifest:
    return CampaignManifest(
        campaign_id="example-lab-campaign",
        name="Example synthetic campaign",
        scope=build_scope(),
        objective=CampaignObjective(
            statement="Map and verify the synthetic HTTP surface",
            success_criteria=["Store one evidence-backed result"],
        ),
        corpus_manifest_digest="1" * 64,
        selected_playbooks=["http-response-surface-map"],
        playbook_contracts=[
            CampaignPlaybookContract(
                playbook_id="http-response-surface-map",
                version="1.0.0",
                digest="2" * 64,
                review_state=ReviewState.VALIDATED,
                minimum_execution_class=ExecutionClass.CONTROLLED_ACTIVE,
                capabilities=["data.diff", "evidence.write", "http.capture", "http.request"],
                action_tags=["active-probing"],
                minimum_request_budget=4,
            )
        ],
        budget=CampaignBudget(
            max_tasks=max_tasks,
            max_cost_units=max_cost,
            max_findings=5,
            max_wall_seconds=3600,
            max_attempts_per_task=2,
        ),
    )
