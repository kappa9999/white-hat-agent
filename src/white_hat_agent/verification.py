from __future__ import annotations

from .models import (
    CausalVerdict,
    CausalVerificationInput,
    CausalVerificationReport,
    ProofTier,
    stable_id,
)


def verify_causality(facts: CausalVerificationInput) -> CausalVerificationReport:
    checks = {
        "target effect observed": facts.target_effect_observed,
        "intended path observed": facts.intended_path_observed,
        "candidate primitive observed": facts.primitive_observed,
        "vulnerable variant succeeds": facts.vulnerable_variant_succeeds,
        "fixed variant rejects": facts.fixed_variant_rejects,
        "neutralization removes effect": facts.neutralization_removes_effect,
        "shortcuts excluded": facts.shortcuts_excluded,
        "reproduced at least twice": facts.reproducible_runs >= 2,
        "two independent evidence families": len(facts.independent_evidence_families) >= 2,
    }
    satisfied = [name for name, value in checks.items() if value]
    failed = [name for name, value in checks.items() if not value]

    causal_intervention = facts.fixed_variant_rejects or facts.neutralization_removes_effect
    confirmed = (
        facts.target_effect_observed
        and facts.intended_path_observed
        and facts.primitive_observed
        and facts.vulnerable_variant_succeeds
        and causal_intervention
        and facts.shortcuts_excluded
        and facts.reproducible_runs >= 2
        and len(facts.independent_evidence_families) >= 2
    )
    supported = (
        facts.target_effect_observed
        and facts.intended_path_observed
        and facts.primitive_observed
        and facts.reproducible_runs >= 1
        and bool(facts.independent_evidence_families)
    )

    if facts.target_effect_observed and not facts.intended_path_observed:
        verdict = CausalVerdict.ALTERNATE_FINDING
    elif confirmed:
        verdict = CausalVerdict.CONFIRMED
    elif supported:
        verdict = CausalVerdict.SUPPORTED
    elif facts.conclusive_negative and not facts.target_effect_observed:
        verdict = CausalVerdict.REFUTED
    else:
        verdict = CausalVerdict.INCONCLUSIVE

    if confirmed and facts.fixed_variant_rejects and facts.neutralization_removes_effect:
        tier = ProofTier.REGRESSION_CLOSED
    elif confirmed and facts.fixed_variant_rejects:
        tier = ProofTier.DIFFERENTIAL
    elif confirmed:
        tier = ProofTier.CAUSAL
    elif supported and facts.reproducible_runs >= 2:
        tier = ProofTier.REPRODUCED
    else:
        tier = ProofTier.SIGNAL

    next_experiments = _next_experiments(facts, verdict)
    confidence = round(sum(checks.values()) / len(checks), 6)
    payload = {
        "input": facts.model_dump(mode="json"),
        "verdict": verdict.value,
        "tier": tier.value,
        "checks": checks,
    }
    return CausalVerificationReport(
        report_id=stable_id("causal", payload),
        verification_id=facts.verification_id,
        hypothesis_id=facts.hypothesis_id,
        verdict=verdict,
        proof_tier=tier,
        confidence=confidence,
        satisfied_checks=satisfied,
        failed_checks=failed,
        next_experiments=next_experiments,
    )


def _next_experiments(facts: CausalVerificationInput, verdict: CausalVerdict) -> list[str]:
    if verdict == CausalVerdict.ALTERNATE_FINDING:
        return [
            "preserve the observed effect as an adjacent hypothesis with its own identity",
            "instrument the intended path and repeat without the alternate path",
        ]
    if verdict == CausalVerdict.REFUTED:
        return ["revise the hypothesis only if new evidence changes its assumptions or probe"]

    actions: list[str] = []
    if not facts.intended_path_observed:
        actions.append("capture direct evidence that the intended path executes")
    if not facts.primitive_observed:
        actions.append("instrument the candidate primitive at the causal boundary")
    if not facts.vulnerable_variant_succeeds:
        actions.append("reproduce on the exact vulnerable build identity")
    if not facts.fixed_variant_rejects:
        actions.append("run the identical probe against the fixed or patched variant")
    if not facts.neutralization_removes_effect:
        actions.append("neutralize only the candidate primitive and repeat")
    if not facts.shortcuts_excluded:
        actions.append("remove alternate success paths and repeat")
    if facts.reproducible_runs < 2:
        actions.append("repeat until at least two clean reproductions exist")
    if len(facts.independent_evidence_families) < 2:
        actions.append("add an independent evidence family such as a trace or differential artifact")
    return actions
