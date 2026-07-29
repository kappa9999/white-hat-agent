from __future__ import annotations

import re

from pydantic import Field, model_validator

from ..models import StrictModel, stable_id
from .corpus import Corpus
from .models import (
    EXECUTION_CLASS_RANK,
    ExecutionClass,
    Playbook,
    ReviewState,
    SemanticType,
    semver_key,
)


class CompositionRequest(StrictModel):
    objective: str = Field(min_length=1)
    target_kind: str = Field(min_length=1)
    domains: list[str] = Field(default_factory=list)
    platforms: list[str] = Field(default_factory=list)
    technologies: list[str] = Field(default_factory=list)
    available_capabilities: list[str] = Field(default_factory=list)
    initial_artifacts: list[SemanticType] = Field(default_factory=lambda: ["target/context"])
    desired_artifacts: list[SemanticType] = Field(min_length=1)
    execution_ceiling: ExecutionClass = ExecutionClass.READ_ONLY
    allowed_review_states: list[ReviewState] = Field(
        default_factory=lambda: [ReviewState.REVIEWED, ReviewState.VALIDATED]
    )
    max_playbooks: int = Field(default=8, ge=1, le=100)

    @model_validator(mode="after")
    def unique_review_states(self):
        if not self.allowed_review_states:
            raise ValueError("allowed_review_states must not be empty")
        if len(self.allowed_review_states) != len(set(self.allowed_review_states)):
            raise ValueError("allowed_review_states must be unique")
        return self


class ComposedStep(StrictModel):
    sequence: int = Field(ge=1)
    playbook_id: str
    playbook_version: str
    step_id: str
    title: str
    instruction: str
    required_capabilities: list[str]


class CompositionSelection(StrictModel):
    playbook_id: str
    version: str
    score: float
    consumed: list[str]
    provided: list[str]
    rationale: list[str]


class CompositePlaybook(StrictModel):
    composition_id: str
    request: CompositionRequest
    selected: list[CompositionSelection]
    steps: list[ComposedStep]
    available_artifacts: list[str]
    unresolved_artifacts: list[str]
    unused_capabilities: list[str]
    complete: bool
    rationale: list[str]


def compose_playbooks(corpus: Corpus, request: CompositionRequest) -> CompositePlaybook:
    """Greedily chain typed playbooks by semantic inputs and outputs.

    The result is deterministic and explains every selection. A future search
    strategy can replace the scorer without changing the corpus contract.
    """

    candidates = _latest_by_id(corpus.all())
    artifacts = set(request.initial_artifacts)
    desired = set(request.desired_artifacts)
    available_capabilities = set(request.available_capabilities)
    selected: list[CompositionSelection] = []
    selected_playbooks: list[Playbook] = []
    excluded: list[str] = []

    while len(selected) < request.max_playbooks and not desired.issubset(artifacts):
        ranked: list[tuple[float, str, Playbook, list[str]]] = []
        selected_ids = {item.metadata.playbook_id for item in selected_playbooks}
        for playbook in candidates:
            playbook_id = playbook.metadata.playbook_id
            if playbook_id in selected_ids:
                continue
            eligibility = _eligibility_reasons(playbook, request, artifacts, available_capabilities)
            if eligibility:
                excluded.append(f"{playbook_id}: {'; '.join(eligibility)}")
                continue
            reverse_conflict = any(
                playbook_id in selected_playbook.composition.conflicts_with
                for selected_playbook in selected_playbooks
            )
            if set(playbook.composition.conflicts_with).intersection(selected_ids) or reverse_conflict:
                excluded.append(f"{playbook_id}: conflicts with a selected playbook")
                continue
            score, reasons = _score(playbook, request, artifacts, desired, selected_ids)
            ranked.append((score, playbook_id, playbook, reasons))
        if not ranked:
            break
        score, _, chosen, reasons = max(ranked, key=lambda item: (item[0], item[1]))
        if score <= 0:
            break
        before = set(artifacts)
        artifacts.update(chosen.composition.provides)
        selected_playbooks.append(chosen)
        selected.append(
            CompositionSelection(
                playbook_id=chosen.metadata.playbook_id,
                version=chosen.metadata.version,
                score=round(score, 6),
                consumed=sorted(set(chosen.composition.consumes).intersection(before)),
                provided=sorted(set(chosen.composition.provides) - before),
                rationale=reasons,
            )
        )

    steps: list[ComposedStep] = []
    sequence = 1
    used_capabilities: set[str] = set()
    for playbook in selected_playbooks:
        for step in playbook.steps:
            used_capabilities.update(step.required_capabilities)
            steps.append(
                ComposedStep(
                    sequence=sequence,
                    playbook_id=playbook.metadata.playbook_id,
                    playbook_version=playbook.metadata.version,
                    step_id=step.step_id,
                    title=step.title,
                    instruction=step.instruction,
                    required_capabilities=step.required_capabilities,
                )
            )
            sequence += 1

    unresolved = sorted(desired - artifacts)
    rationale = [
        f"selected {len(selected)} playbooks from {len(candidates)} latest-version candidates",
        f"resolved {len(desired) - len(unresolved)} of {len(desired)} desired artifact types",
    ]
    if unresolved:
        rationale.append("missing artifact producers require a new or revised corpus contribution")
    if excluded:
        rationale.append(f"{len(set(excluded))} candidate eligibility or conflict exclusions were observed")
    payload = {
        "request": request.model_dump(mode="json"),
        "selected": [item.model_dump(mode="json") for item in selected],
        "artifacts": sorted(artifacts),
    }
    return CompositePlaybook(
        composition_id=stable_id("composition", payload),
        request=request,
        selected=selected,
        steps=steps,
        available_artifacts=sorted(artifacts),
        unresolved_artifacts=unresolved,
        unused_capabilities=sorted(available_capabilities - used_capabilities),
        complete=not unresolved,
        rationale=rationale,
    )


def _latest_by_id(playbooks: list[Playbook]) -> list[Playbook]:
    latest: dict[str, Playbook] = {}
    for playbook in playbooks:
        current = latest.get(playbook.metadata.playbook_id)
        if current is None or semver_key(playbook.metadata.version) > semver_key(current.metadata.version):
            latest[playbook.metadata.playbook_id] = playbook
    return [latest[key] for key in sorted(latest)]


def _eligibility_reasons(
    playbook: Playbook,
    request: CompositionRequest,
    artifacts: set[str],
    available_capabilities: set[str],
) -> list[str]:
    reasons: list[str] = []
    if playbook.metadata.review_state not in request.allowed_review_states:
        reasons.append(f"review state is not eligible: {playbook.metadata.review_state.value}")
    if request.target_kind not in playbook.applicability.target_kinds and "generic-asset" not in (
        playbook.applicability.target_kinds
    ):
        reasons.append("target kind does not match")
    if (
        playbook.applicability.platforms
        and request.platforms
        and not set(playbook.applicability.platforms).intersection(request.platforms)
    ):
        reasons.append("platform does not match")
    if (
        EXECUTION_CLASS_RANK[playbook.scope.minimum_execution_class]
        > EXECUTION_CLASS_RANK[request.execution_ceiling]
    ):
        reasons.append("execution class exceeds request ceiling")
    missing_capabilities = playbook.capabilities() - available_capabilities
    if missing_capabilities:
        reasons.append(f"missing capabilities {sorted(missing_capabilities)}")
    missing_inputs = set(playbook.composition.consumes) - artifacts
    if missing_inputs:
        reasons.append(f"missing artifacts {sorted(missing_inputs)}")
    return reasons


def _score(
    playbook: Playbook,
    request: CompositionRequest,
    artifacts: set[str],
    desired: set[str],
    selected_ids: set[str],
) -> tuple[float, list[str]]:
    new_outputs = set(playbook.composition.provides) - artifacts
    desired_outputs = new_outputs.intersection(desired)
    objective_terms = _terms(request.objective)
    playbook_terms = _terms(
        " ".join(
            [
                playbook.metadata.title,
                playbook.metadata.summary,
                *playbook.metadata.domains,
                *playbook.metadata.tags,
            ]
        )
    )
    overlap = len(objective_terms.intersection(playbook_terms))
    domain_overlap = len(set(request.domains).intersection(playbook.metadata.domains))
    technology_overlap = len(set(request.technologies).intersection(playbook.applicability.technologies))
    compatibility = len(set(playbook.composition.compatible_after).intersection(selected_ids))
    score = (
        10.0 * len(desired_outputs)
        + 3.0 * len(new_outputs)
        + 2.0 * overlap
        + 2.0 * domain_overlap
        + technology_overlap
        + compatibility
    )
    reasons = [
        f"adds {len(new_outputs)} new artifact types",
        f"directly resolves {len(desired_outputs)} desired artifact types",
        f"objective term overlap={overlap}",
    ]
    if domain_overlap:
        reasons.append(f"domain overlap={domain_overlap}")
    if compatibility:
        reasons.append(f"explicit compatibility links={compatibility}")
    return score, reasons


def _terms(value: str) -> set[str]:
    return {item for item in re.findall(r"[\w.-]+", value.lower(), flags=re.UNICODE) if len(item) > 1}
