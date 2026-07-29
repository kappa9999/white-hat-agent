from __future__ import annotations

from datetime import UTC, datetime, timedelta

from conftest import build_scope

from white_hat_agent.campaign.models import ProbeIntent, TargetKind, TargetRule
from white_hat_agent.campaign.scope import evaluate_scope
from white_hat_agent.knowledge.models import ExecutionClass


def _intent(target: str, *, kind: TargetKind = TargetKind.DOMAIN, **changes) -> ProbeIntent:
    values = {
        "intent_id": "intent-http-map",
        "scope_id": "example-lab-scope",
        "target_kind": kind,
        "target": target,
        "playbook_id": "http-response-surface-map",
        "playbook_version": "1.0.0",
        "playbook_digest": "2" * 64,
        "execution_class": ExecutionClass.READ_ONLY,
        "capabilities": ["http.request", "http.capture"],
        "estimated_requests": 4,
        "concurrency": 1,
    }
    values.update(changes)
    return ProbeIntent(**values)


def test_exact_inclusion_and_exclusion_precedence() -> None:
    scope = build_scope()

    allowed = evaluate_scope(scope, _intent("api.example.test"))
    excluded = evaluate_scope(scope, _intent("admin.example.test"))
    apex = evaluate_scope(scope, _intent("example.test"))

    assert allowed.allowed and allowed.matched_rule_id == "subdomains"
    assert apex.allowed and apex.matched_rule_id == "apex"
    assert not excluded.allowed and excluded.matched_rule_id == "excluded-admin"
    assert allowed.scope_digest == scope.digest()
    assert allowed.intent_digest == _intent("api.example.test").digest()


def test_domain_rule_matches_url_host_but_not_lookalike() -> None:
    scope = build_scope()

    allowed = evaluate_scope(scope, _intent("https://api.example.test/v1", kind=TargetKind.URL))
    lookalike = evaluate_scope(
        scope,
        _intent("https://api.example.test.attacker.invalid/v1", kind=TargetKind.URL),
    )

    assert allowed.allowed
    assert not lookalike.allowed


def test_cidr_repository_expiry_and_limits() -> None:
    scope = build_scope(max_requests=5)
    cidr = evaluate_scope(scope, _intent("192.0.2.4", kind=TargetKind.IP))
    subnet = evaluate_scope(scope, _intent("192.0.2.0/30", kind=TargetKind.CIDR))
    repository = evaluate_scope(
        scope,
        _intent("https://github.com/example/project.git", kind=TargetKind.REPOSITORY),
    )
    over_budget = evaluate_scope(scope, _intent("api.example.test", estimated_requests=6))
    expired = evaluate_scope(
        scope,
        _intent("api.example.test"),
        evaluated_at=datetime.now(UTC) + timedelta(days=2),
    )

    assert cidr.allowed
    assert subnet.allowed
    assert repository.allowed
    assert not over_budget.allowed
    assert not expired.allowed


def test_prohibited_capability_action_and_execution_class_are_rejected() -> None:
    decision = evaluate_scope(
        build_scope(),
        _intent(
            "api.example.test",
            execution_class=ExecutionClass.HIGH_IMPACT,
            capabilities=["account.delete"],
            action_tags=["denial-of-service"],
        ),
    )

    joined = " ".join(decision.reasons)
    assert not decision.allowed
    assert "execution class" in joined
    assert "prohibited capabilities" in joined
    assert "prohibited action tags" in joined


def test_malformed_url_candidate_is_rejected_without_crashing() -> None:
    decision = evaluate_scope(
        build_scope(),
        _intent("https://[malformed.example.test:bad/v1", kind=TargetKind.URL),
    )

    assert not decision.allowed
    assert "does not match" in " ".join(decision.reasons)

    malformed_rule = build_scope().model_copy(
        update={
            "targets": [
                TargetRule(
                    rule_id="malformed-url-rule",
                    kind=TargetKind.URL,
                    pattern="https://[malformed.example.test:bad/v1",
                )
            ]
        }
    )
    invalid_to_invalid = evaluate_scope(
        malformed_rule,
        _intent("https://[malformed.example.test:bad/v1", kind=TargetKind.URL),
    )
    assert not invalid_to_invalid.allowed


def test_empty_capability_allowlist_is_deny_by_default() -> None:
    scope = build_scope().model_copy(update={"allowed_capabilities": []})
    denied = evaluate_scope(scope, _intent("api.example.test"))
    open_scope = scope.model_copy(update={"allow_unlisted_capabilities": True})
    allowed = evaluate_scope(open_scope, _intent("api.example.test"))

    assert not denied.allowed
    assert "not declared" in " ".join(denied.reasons)
    assert allowed.allowed
