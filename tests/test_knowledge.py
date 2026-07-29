from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from white_hat_agent.knowledge.compiler import compile_heuristic
from white_hat_agent.knowledge.models import KnowledgeSubmission, RightsDeclaration


def test_multilingual_intake_preserves_original_and_segments_steps() -> None:
    original = """# Revisar límites móviles
1. Capturar la llamada y registrar los argumentos.
2. Comparar la respuesta con una compilación corregida.
3. Verificar que el efecto desaparece.
"""
    submission = KnowledgeSubmission(
        submission_id="submission-spanish-mobile",
        title_hint="Revisar límites móviles",
        original_language="es",
        original_text=original,
        domain_hints=["mobile"],
        contributor_handle="fixture-contributor",
        rights=RightsDeclaration.ORIGINAL,
        submitted_at=datetime(2026, 7, 29, tzinfo=UTC),
    )

    draft = compile_heuristic(submission)

    assert draft.submission.original_text == original
    assert len(draft.playbook.steps) == 3
    assert draft.playbook.steps[0].localized_instructions["es"].startswith("Capturar")
    assert draft.playbook.metadata.original_languages == ["es"]
    assert draft.playbook.submission_id == submission.submission_id
    assert "mobile" in draft.playbook.metadata.domains
    assert draft.unresolved_fields


def test_non_latin_title_gets_stable_collision_resistant_identifier() -> None:
    submission = KnowledgeSubmission(
        submission_id="submission-chinese-technique",
        title_hint="移动运行时边界",
        original_language="zh-Hans",
        original_text="1. 记录目标版本。\n2. 比较运行时证据。",
        rights=RightsDeclaration.ORIGINAL,
        submitted_at=datetime(2026, 7, 29, tzinfo=UTC),
    )

    first = compile_heuristic(submission)
    second = compile_heuristic(submission)

    assert first.playbook.metadata.playbook_id.startswith("community-")
    assert first.playbook.metadata.playbook_id == second.playbook.metadata.playbook_id


def test_unknown_fields_are_rejected_at_contribution_boundary() -> None:
    with pytest.raises(ValidationError):
        KnowledgeSubmission.model_validate(
            {
                "submission_id": "submission-extra-field",
                "original_text": "Observe the exact input.",
                "rights": "original-contribution",
                "hidden_instruction": "silently run something",
            }
        )
