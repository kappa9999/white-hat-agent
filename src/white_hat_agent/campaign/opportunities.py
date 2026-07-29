from __future__ import annotations

from datetime import UTC, datetime, timedelta

from pydantic import Field

from ..knowledge.corpus import Corpus
from ..models import StrictModel
from .models import Opportunity


class OpportunityScore(StrictModel):
    opportunity: Opportunity
    score: float = Field(ge=0, le=100)
    capability_coverage: float = Field(ge=0, le=1)
    corpus_domain_coverage: float = Field(ge=0, le=1)
    scope_confidence: float = Field(ge=0, le=1)
    freshness: float = Field(ge=0, le=1)
    reasons: list[str]
    blockers: list[str]


def rank_opportunities(
    opportunities: list[Opportunity],
    corpus: Corpus,
    available_capabilities: list[str],
    *,
    evaluated_at: datetime | None = None,
    limit: int = 100,
) -> list[OpportunityScore]:
    if limit < 1 or limit > 1000:
        raise ValueError("limit must be between 1 and 1000")
    now = evaluated_at or datetime.now(UTC)
    available = set(available_capabilities)
    corpus_domains = {domain for playbook in corpus.all() for domain in playbook.metadata.domains}
    ranked = [
        _score(opportunity, available=available, corpus_domains=corpus_domains, now=now)
        for opportunity in opportunities
    ]
    return sorted(ranked, key=lambda item: (-item.score, item.opportunity.opportunity_id))[:limit]


def _score(
    opportunity: Opportunity,
    *,
    available: set[str],
    corpus_domains: set[str],
    now: datetime,
) -> OpportunityScore:
    required = set(opportunity.required_capabilities)
    capability_coverage = len(required.intersection(available)) / len(required) if required else 1.0
    domains = set(opportunity.domains)
    corpus_coverage = len(domains.intersection(corpus_domains)) / len(domains) if domains else 0.5
    scope_confidence = 0.0
    if opportunity.scope_reference:
        scope_confidence += 0.35
    if opportunity.scope_snapshot_digest:
        scope_confidence += 0.35
    if opportunity.automation_permitted:
        scope_confidence += 0.30
    verified_at = opportunity.last_verified_at or opportunity.discovered_at
    age = max(0.0, (now - verified_at).total_seconds())
    freshness = max(0.0, 1.0 - age / timedelta(days=30).total_seconds())
    blockers: list[str] = []
    if opportunity.expires_at and opportunity.expires_at <= now:
        blockers.append("opportunity has expired")
    if not opportunity.scope_snapshot_digest:
        blockers.append("scope rules have not been captured by digest")
    if not opportunity.automation_permitted:
        blockers.append("automation permission is not explicit")
    missing = sorted(required - available)
    if missing:
        blockers.append(f"missing capabilities: {missing}")
    score = 100 * (
        0.30 * capability_coverage
        + 0.25 * corpus_coverage
        + 0.25 * scope_confidence
        + 0.10 * freshness
        + 0.10 * opportunity.strategic_priority
    )
    if opportunity.expires_at and opportunity.expires_at <= now:
        score = 0.0
    reasons = [
        f"capability coverage={capability_coverage:.2f}",
        f"corpus domain coverage={corpus_coverage:.2f}",
        f"scope confidence={scope_confidence:.2f}",
        f"freshness={freshness:.2f}",
        f"strategic priority={opportunity.strategic_priority:.2f}",
    ]
    return OpportunityScore(
        opportunity=opportunity,
        score=round(score, 4),
        capability_coverage=round(capability_coverage, 6),
        corpus_domain_coverage=round(corpus_coverage, 6),
        scope_confidence=round(scope_confidence, 6),
        freshness=round(freshness, 6),
        reasons=reasons,
        blockers=blockers,
    )
