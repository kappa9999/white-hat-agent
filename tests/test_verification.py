from __future__ import annotations

from white_hat_agent.models import (
    CausalVerdict,
    CausalVerificationInput,
    EvidenceKind,
    ProofTier,
)
from white_hat_agent.verification import verify_causality


def _facts(**overrides):
    values = {
        "verification_id": "verify-001",
        "hypothesis_id": "h-template-causal-differential",
        "target_effect_observed": True,
        "intended_path_observed": True,
        "primitive_observed": True,
        "vulnerable_variant_succeeds": True,
        "fixed_variant_rejects": True,
        "neutralization_removes_effect": True,
        "shortcuts_excluded": True,
        "reproducible_runs": 3,
        "independent_evidence_families": [EvidenceKind.TRACE, EvidenceKind.DIFFERENTIAL],
    }
    values.update(overrides)
    return CausalVerificationInput(**values)


def test_complete_intervention_evidence_closes_regression() -> None:
    facts = _facts()

    first = verify_causality(facts)
    second = verify_causality(facts)

    assert first == second
    assert first.verdict == CausalVerdict.CONFIRMED
    assert first.proof_tier == ProofTier.REGRESSION_CLOSED
    assert first.confidence == 1.0
    assert not first.next_experiments


def test_visible_success_on_wrong_path_is_preserved_as_alternate_finding() -> None:
    report = verify_causality(
        _facts(
            intended_path_observed=False,
            primitive_observed=False,
            fixed_variant_rejects=False,
            neutralization_removes_effect=False,
            shortcuts_excluded=False,
            independent_evidence_families=[EvidenceKind.RUNTIME],
        )
    )

    assert report.verdict == CausalVerdict.ALTERNATE_FINDING
    assert report.proof_tier == ProofTier.SIGNAL
    assert "preserve the observed effect" in report.next_experiments[0]


def test_reproduced_mechanism_without_intervention_is_supported_not_confirmed() -> None:
    report = verify_causality(
        _facts(
            fixed_variant_rejects=False,
            neutralization_removes_effect=False,
        )
    )

    assert report.verdict == CausalVerdict.SUPPORTED
    assert report.proof_tier == ProofTier.REPRODUCED
    assert any("fixed" in action for action in report.next_experiments)


def test_conclusive_absence_refutes_hypothesis() -> None:
    report = verify_causality(
        _facts(
            target_effect_observed=False,
            intended_path_observed=False,
            primitive_observed=False,
            vulnerable_variant_succeeds=False,
            fixed_variant_rejects=False,
            neutralization_removes_effect=False,
            shortcuts_excluded=True,
            reproducible_runs=0,
            independent_evidence_families=[],
            conclusive_negative=True,
        )
    )

    assert report.verdict == CausalVerdict.REFUTED
    assert "new evidence" in report.next_experiments[0]
