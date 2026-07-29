from __future__ import annotations

import re
from collections.abc import Iterable

from .models import (
    Applicability,
    CompilationDraft,
    CompositionContract,
    ExecutionClass,
    KnowledgeSubmission,
    Playbook,
    PlaybookMetadata,
    PlaybookStep,
    ReviewState,
    ScopeRequirements,
    StepKind,
    ValueSpec,
    slugify,
)

COMPILER_ID = "white-hat-agent.heuristic-v1"
MAX_DRAFT_STEPS = 500
MAX_STEP_CHARACTERS = 20_000

_LIST_PREFIX = re.compile(r"^\s*(?:[-*+]\s+|\d+[.)]\s+|[a-zA-Z][.)]\s+|[①-⑳]\s*)")
_DOMAIN_KEYWORDS: dict[str, tuple[str, ...]] = {
    "api": ("api", "graphql", "grpc", "rest", "endpoint"),
    "binary": ("binary", "binario", "disassembly", "decompile", "ida", "ghidra", "patch diff"),
    "cloud": ("cloud", "nube", "aws", "azure", "gcp", "iam", "kubernetes", "container"),
    "incident-response": ("incident", "incidente", "forensic", "forense", "timeline", "log", "triage"),
    "mobile": ("mobile", "móvil", "android", "ios", "frida", "apk", "ipa"),
    "network": ("network", "red", "packet", "paquete", "pcap", "dns", "tcp", "udp"),
    "supply-chain": ("supply chain", "dependency", "package", "ci/cd", "sbom"),
    "web": ("web", "http", "browser", "navegador", "cookie", "html", "javascript"),
}


def compile_heuristic(submission: KnowledgeSubmission) -> CompilationDraft:
    """Losslessly turn free-form community knowledge into a reviewable draft.

    This baseline compiler deliberately does not pretend to understand every
    language. It preserves the original text, segments likely steps, infers
    broad domains, and marks semantic fields that an attached agent or human
    must resolve before promotion.
    """

    lines = [line.strip() for line in submission.original_text.splitlines() if line.strip()]
    title = submission.title_hint or _title_from_lines(lines)
    domains = submission.domain_hints or _infer_domains(submission.original_text)
    extracted_steps = list(_extract_steps(lines))
    step_texts = extracted_steps[:MAX_DRAFT_STEPS] or [submission.original_text.strip()]
    localized = submission.original_language != "en"
    steps: list[PlaybookStep] = []
    for index, text in enumerate(step_texts, start=1):
        bounded_text = text[:MAX_STEP_CHARACTERS]
        instruction = (
            bounded_text
            if not localized
            else f"Preserve the contributor instruction for review: {bounded_text}"
        )
        localized_instructions = {submission.original_language: bounded_text} if localized else {}
        steps.append(
            PlaybookStep(
                step_id=f"step-{index:02d}",
                kind=_infer_step_kind(bounded_text, index, len(step_texts)),
                title=_short_title(bounded_text, index),
                instruction=instruction,
                localized_instructions=localized_instructions,
                depends_on=[f"step-{index - 1:02d}"] if index > 1 else [],
                required_capabilities=[],
                success_signals=["A reviewer-defined success signal is observed and captured as evidence"],
                failure_signals=["The expected state or evidence is absent, ambiguous, or contradicted"],
                evidence=[],
            )
        )

    created_at = submission.submitted_at
    playbook = Playbook(
        metadata=PlaybookMetadata(
            playbook_id=slugify(
                title,
                fallback=f"community-{submission.digest()[:16]}",
            ),
            version="0.1.0",
            title=title,
            summary=_summary(submission.original_text),
            domains=domains,
            tags=["community-draft", "needs-review"],
            original_languages=[submission.original_language],
            contributors=[submission.contributor_handle] if submission.contributor_handle else [],
            review_state=ReviewState.DRAFT,
            created_at=created_at,
            updated_at=created_at,
        ),
        applicability=Applicability(target_kinds=["generic-asset"]),
        scope=ScopeRequirements(
            minimum_execution_class=ExecutionClass.ANALYSIS,
            requires_scope_manifest=True,
            requires_target_match=True,
            authorization_evidence_required=True,
        ),
        inputs=[
            ValueSpec(
                name="target-context",
                semantic_type="target/context",
                description="Exact target identity, environment, and available evidence",
            )
        ],
        outputs=[
            ValueSpec(
                name="technique-result",
                semantic_type="finding/candidate",
                description="Evidence-backed result produced by the contributed technique",
            )
        ],
        steps=steps,
        composition=CompositionContract(
            consumes=["target/context"],
            provides=["finding/candidate"],
        ),
        failure_modes=["The free-form source omitted a prerequisite or environment assumption"],
        sources=submission.sources,
        submission_id=submission.submission_id,
    )
    unresolved = [
        "Confirm the exact target kinds, platforms, technologies, and preconditions",
        "Map every step to concrete adapter capability identifiers",
        "Replace generic success and failure signals with observable facts",
        "Define evidence requirements and causal or differential verification",
        "Classify execution level, side effects, request budget, concurrency, and cleanup",
        "Map relevant CWE, CAPEC, ATT&CK, CVE, OWASP, or domain-specific taxonomy identifiers",
        "Add a replay, fixture, or reproducible validation case",
    ]
    warnings = []
    if not submission.sources:
        warnings.append(
            "No external source was supplied; retain as first-hand knowledge until independently reviewed"
        )
    if localized:
        warnings.append(
            "Canonical English instructions are placeholders; use an agent or bilingual reviewer "
            "to translate without deleting the original-language text"
        )
    if len(step_texts) == 1:
        warnings.append(
            "Only one procedural segment was detected; review whether the source contains implicit steps"
        )
    if len(extracted_steps) > MAX_DRAFT_STEPS:
        warnings.append(
            f"Draft step extraction was bounded at {MAX_DRAFT_STEPS}; the exact original text is retained"
        )
    if any(len(text) > MAX_STEP_CHARACTERS for text in step_texts):
        warnings.append(
            f"Draft step text was bounded at {MAX_STEP_CHARACTERS} characters; "
            "the exact original text is retained"
        )
    return CompilationDraft(
        compiler_id=COMPILER_ID,
        submission=submission,
        playbook=playbook,
        unresolved_fields=unresolved,
        warnings=warnings,
    )


def compiler_prompt(submission: KnowledgeSubmission) -> str:
    """Prompt any capable host model to refine a lossless draft."""

    return f"""You are compiling community cyber knowledge into a White Hat Agent Playbook v1.

Non-negotiable rules:
1. Preserve the contributor's original language and meaning. Never discard the raw submission.
2. Separate facts, assumptions, hypotheses, actions, success signals, failure signals, evidence, and cleanup.
3. Use open namespaced capability IDs instead of vendor-specific command prose where possible.
4. Identify exact inputs and outputs using semantic artifact types so playbooks can compose.
5. Map relevant public taxonomies only when supported by the source.
6. Mark unknowns explicitly. Do not invent a successful result, authorization, citation, or validation.
7. A visible effect is not causal proof; add differential or intervention verification when applicable.
8. Return one JSON object matching the Playbook schema. Set review_state to draft.

Submission ID: {submission.submission_id}
Language: {submission.original_language}
Declared rights: {submission.rights.value}
Domain hints: {", ".join(submission.domain_hints) or "none"}

Original text:
---
{submission.original_text}
---
"""


def _title_from_lines(lines: list[str]) -> str:
    if not lines:
        return "Community technique"
    title = re.sub(r"^#{1,6}\s*", "", lines[0]).strip()
    title = _LIST_PREFIX.sub("", title)
    return title[:120] or "Community technique"


def _extract_steps(lines: Iterable[str]) -> Iterable[str]:
    for line in lines:
        if _LIST_PREFIX.match(line):
            cleaned = _LIST_PREFIX.sub("", line).strip()
            if cleaned:
                yield cleaned


def _infer_domains(text: str) -> list[str]:
    lowered = text.lower()
    domains = [
        domain for domain, keywords in _DOMAIN_KEYWORDS.items() if any(term in lowered for term in keywords)
    ]
    return domains or ["cross-domain"]


def _infer_step_kind(text: str, index: int, total: int) -> StepKind:
    lowered = text.lower()
    if any(term in lowered for term in ("verify", "confirm", "validate", "comprobar", "verificar")):
        return StepKind.VERIFY
    if any(term in lowered for term in ("document", "report", "record", "documentar", "registrar")):
        return StepKind.DOCUMENT
    if any(term in lowered for term in ("clean", "restore", "rollback", "limpiar", "restaurar")):
        return StepKind.CLEANUP
    if any(term in lowered for term in ("inspect", "observe", "capture", "observar", "capturar")):
        return StepKind.OBSERVE
    if any(term in lowered for term in ("analyze", "compare", "trace", "analizar", "comparar")):
        return StepKind.ANALYZE
    if index == total:
        return StepKind.VERIFY
    return StepKind.EXECUTE


def _short_title(text: str, index: int) -> str:
    words = text.split()
    candidate = " ".join(words[:10]).rstrip(".:;,")
    return candidate[:100] or f"Step {index}"


def _summary(text: str) -> str:
    compact = " ".join(text.split())
    if len(compact) <= 240:
        return compact
    return compact[:237].rstrip() + "..."
