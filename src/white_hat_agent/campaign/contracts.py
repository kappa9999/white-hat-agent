from __future__ import annotations

from ..knowledge.corpus import Corpus
from ..knowledge.models import Playbook, ReviewState
from .models import CampaignManifest, CampaignPlaybookContract


def contract_from_playbook(playbook: Playbook) -> CampaignPlaybookContract:
    return CampaignPlaybookContract(
        playbook_id=playbook.metadata.playbook_id,
        version=playbook.metadata.version,
        digest=playbook.digest(),
        review_state=playbook.metadata.review_state,
        minimum_execution_class=playbook.scope.minimum_execution_class,
        capabilities=sorted(playbook.capabilities()),
        action_tags=sorted(playbook.scope.action_tags),
        side_effects=sorted({effect for step in playbook.steps for effect in step.side_effects}),
        minimum_request_budget=playbook.scope.minimum_request_budget,
    )


def validate_campaign_manifest(corpus: Corpus, manifest: CampaignManifest) -> None:
    current_digest = corpus.manifest().manifest_digest
    if manifest.corpus_manifest_digest != current_digest:
        raise ValueError("campaign corpus digest does not match the current workspace corpus")
    for declared in manifest.playbook_contracts:
        if declared.review_state not in {ReviewState.REVIEWED, ReviewState.VALIDATED}:
            raise ValueError(f"campaign playbook is not reviewed: {declared.playbook_id}@{declared.version}")
        playbook = corpus.get(declared.playbook_id, declared.version)
        expected = contract_from_playbook(playbook)
        if declared != expected:
            raise ValueError(
                f"campaign playbook contract does not match corpus: {declared.playbook_id}@{declared.version}"
            )
