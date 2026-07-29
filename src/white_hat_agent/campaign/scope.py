from __future__ import annotations

import fnmatch
import ipaddress
from datetime import UTC, datetime
from urllib.parse import urlsplit

from ..knowledge.models import EXECUTION_CLASS_RANK
from ..models import stable_id
from .models import ProbeIntent, ScopeDecision, ScopeManifest, TargetKind, TargetRule


def evaluate_scope(
    scope: ScopeManifest,
    intent: ProbeIntent,
    *,
    evaluated_at: datetime | None = None,
) -> ScopeDecision:
    now = evaluated_at or datetime.now(UTC)
    reasons: list[str] = []
    warnings: list[str] = []
    matched_rule: TargetRule | None = None

    if intent.scope_id != scope.scope_id:
        reasons.append("intent scope identity does not match the manifest")
    if scope.valid_from and now < scope.valid_from:
        reasons.append("scope validity window has not started")
    if scope.valid_until and now > scope.valid_until:
        reasons.append("scope validity window has expired")

    matches = [rule for rule in scope.targets if _matches(rule, intent.target_kind, intent.target)]
    exclusions = [rule for rule in matches if not rule.in_scope]
    inclusions = [rule for rule in matches if rule.in_scope]
    if exclusions:
        matched_rule = exclusions[0]
        reasons.append(f"target matches exclusion rule {matched_rule.rule_id}")
    elif inclusions:
        matched_rule = inclusions[0]
    else:
        reasons.append("target does not match an in-scope rule")

    if intent.execution_class not in scope.allowed_execution_classes:
        reasons.append(f"execution class is not allowed: {intent.execution_class.value}")
    if not scope.allow_unlisted_capabilities:
        missing = sorted(set(intent.capabilities) - set(scope.allowed_capabilities))
        if missing:
            reasons.append(f"capabilities are not declared by scope: {missing}")
    prohibited = sorted(set(intent.capabilities).intersection(scope.prohibited_capabilities))
    if prohibited:
        reasons.append(f"prohibited capabilities requested: {prohibited}")
    prohibited_actions = sorted(set(intent.action_tags).intersection(scope.prohibited_action_tags))
    if prohibited_actions:
        reasons.append(f"prohibited action tags requested: {prohibited_actions}")
    if intent.estimated_requests > scope.rate_limits.max_requests_per_task:
        reasons.append("estimated request count exceeds the per-task limit")
    if intent.concurrency > scope.rate_limits.max_concurrency:
        reasons.append("requested concurrency exceeds the scope limit")
    if intent.side_effects and EXECUTION_CLASS_RANK[intent.execution_class] <= 1:
        warnings.append("intent declares side effects despite an analysis or read-only execution class")
    if not scope.rules_sha256:
        warnings.append("program rules do not have a captured content digest")
    if not scope.valid_until:
        warnings.append("scope has no expiry; refresh program rules before each campaign")

    payload = {
        "scope": scope.scope_id,
        "intent": intent.model_dump(mode="json"),
        "evaluated_at": now.isoformat(),
        "matched_rule": matched_rule.rule_id if matched_rule else None,
        "reasons": reasons,
    }
    return ScopeDecision(
        decision_id=stable_id("scope", payload),
        scope_id=scope.scope_id,
        scope_digest=scope.digest(),
        intent_id=intent.intent_id,
        intent_digest=intent.digest(),
        evaluated_at=now,
        allowed=not reasons,
        matched_rule_id=matched_rule.rule_id if matched_rule else None,
        reasons=reasons or ["intent matches the captured scope and execution profile"],
        warnings=warnings,
        effective_limits=scope.rate_limits,
    )


def _matches(rule: TargetRule, candidate_kind: TargetKind, candidate: str) -> bool:
    compatible = (
        rule.kind in {candidate_kind, TargetKind.GENERIC}
        or (rule.kind == TargetKind.DOMAIN and candidate_kind in {TargetKind.URL, TargetKind.API})
        or (rule.kind == TargetKind.CIDR and candidate_kind == TargetKind.IP)
    )
    if not compatible:
        return False
    if rule.kind == TargetKind.CIDR:
        try:
            network = ipaddress.ip_network(rule.pattern, strict=False)
            if candidate_kind == TargetKind.CIDR:
                return ipaddress.ip_network(candidate, strict=False).subnet_of(network)
            return ipaddress.ip_address(candidate) in network
        except ValueError:
            return False
    if rule.kind == TargetKind.IP:
        try:
            return ipaddress.ip_address(candidate) == ipaddress.ip_address(rule.pattern)
        except ValueError:
            return False
    if rule.kind == TargetKind.DOMAIN:
        if "://" in candidate:
            try:
                hostname = urlsplit(candidate).hostname
            except ValueError:
                return False
        else:
            hostname = candidate.split(":", 1)[0]
        return bool(hostname) and _domain_match(rule.pattern, hostname)
    if rule.kind in {TargetKind.URL, TargetKind.API}:
        normalized_candidate = _normalize_url(candidate)
        normalized_pattern = _normalize_url(rule.pattern)
        return bool(normalized_candidate and normalized_pattern) and fnmatch.fnmatchcase(
            normalized_candidate, normalized_pattern
        )
    if rule.kind == TargetKind.REPOSITORY:
        return fnmatch.fnmatchcase(
            candidate.lower().removesuffix(".git"), rule.pattern.lower().removesuffix(".git")
        )
    return fnmatch.fnmatchcase(candidate, rule.pattern)


def _domain_match(pattern: str, hostname: str) -> bool:
    normalized_pattern = pattern.lower().rstrip(".")
    normalized_host = hostname.lower().rstrip(".")
    if normalized_pattern.startswith("*."):
        suffix = normalized_pattern[1:]
        return normalized_host.endswith(suffix) and normalized_host != normalized_pattern[2:]
    return normalized_host == normalized_pattern


def _normalize_url(value: str) -> str:
    try:
        split = urlsplit(value if "://" in value else f"https://{value}")
        host = (split.hostname or "").lower()
        port = f":{split.port}" if split.port else ""
        path = split.path or "/"
        return f"{split.scheme.lower()}://{host}{port}{path}"
    except ValueError:
        return ""
