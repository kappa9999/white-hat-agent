from __future__ import annotations

import json

from ..campaign.models import LearningCandidate
from ..models import stable_id
from .models import KnowledgeSubmission, RightsDeclaration


def submission_from_learning(
    candidate: LearningCandidate,
    *,
    rights: RightsDeclaration,
    contributor: str | None = None,
    language: str = "und",
) -> KnowledgeSubmission:
    """Preserve a fleet learning candidate as reviewable knowledge intake."""

    learning_json = json.dumps(candidate.learning, indent=2, sort_keys=True, ensure_ascii=False)
    original_text = (
        f"Task result summary:\n{candidate.summary}\n\n"
        f"Reusable learning (exact structured value):\n{learning_json}\n\n"
        f"Evidence identities:\n{json.dumps(candidate.evidence_ids, ensure_ascii=False)}"
    )
    title = candidate.learning.get("title")
    title_hint = title if isinstance(title, str) and title.strip() else f"Learning from {candidate.task_id}"
    identity = {
        "candidate_id": candidate.candidate_id,
        "result_digest": candidate.result_digest,
        "rights": rights.value,
        "contributor": contributor,
    }
    return KnowledgeSubmission(
        submission_id=stable_id("submission", identity),
        title_hint=title_hint,
        original_language=language,
        original_text=original_text,
        contributor_handle=contributor,
        rights=rights,
    )
