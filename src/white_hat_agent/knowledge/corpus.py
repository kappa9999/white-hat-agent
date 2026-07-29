from __future__ import annotations

import json
import os
import re
import tempfile
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

import yaml
from pydantic import Field, ValidationError

from ..models import StrictModel, stable_digest
from .models import CorpusEntry, CorpusManifest, Playbook, semver_key


class CorpusValidationIssue(StrictModel):
    path: str
    code: str
    message: str


class CorpusValidationReport(StrictModel):
    root: str
    valid: bool
    playbook_count: int = Field(ge=0)
    issues: list[CorpusValidationIssue] = Field(default_factory=list)
    manifest_digest: str | None = None


class CorpusSearchHit(StrictModel):
    playbook_id: str
    version: str
    title: str
    summary: str
    domains: list[str]
    tags: list[str]
    score: float
    matched_terms: list[str]
    digest: str


class Corpus:
    """Strict, deterministic loader for community playbook YAML."""

    def __init__(
        self,
        root: Path,
        *,
        max_playbook_bytes: int = 1_048_576,
        max_playbooks: int = 10_000,
    ) -> None:
        self.root = root.resolve()
        self.max_playbook_bytes = max_playbook_bytes
        self.max_playbooks = max_playbooks
        self._playbooks: dict[tuple[str, str], Playbook] = {}
        self._paths: dict[tuple[str, str], Path] = {}

    def load(self) -> CorpusValidationReport:
        self._playbooks.clear()
        self._paths.clear()
        issues: list[CorpusValidationIssue] = []
        if not self.root.exists():
            return CorpusValidationReport(
                root=str(self.root),
                valid=False,
                playbook_count=0,
                issues=[
                    CorpusValidationIssue(
                        path=".",
                        code="corpus.missing",
                        message="corpus root does not exist",
                    )
                ],
            )

        paths = sorted([*self.root.rglob("*.yaml"), *self.root.rglob("*.yml")])
        if len(paths) > self.max_playbooks:
            return CorpusValidationReport(
                root=str(self.root),
                valid=False,
                playbook_count=0,
                issues=[
                    CorpusValidationIssue(
                        path=".",
                        code="corpus.too-many-playbooks",
                        message=f"corpus contains {len(paths)} files; maximum is {self.max_playbooks}",
                    )
                ],
            )
        for path in paths:
            relative = str(path.relative_to(self.root))
            if path.is_symlink():
                issues.append(
                    CorpusValidationIssue(
                        path=relative,
                        code="corpus.symlink",
                        message="symlinked playbooks are not loaded",
                    )
                )
                continue
            try:
                byte_length = path.stat().st_size
                if byte_length > self.max_playbook_bytes:
                    raise ValueError(f"playbook is {byte_length} bytes; maximum is {self.max_playbook_bytes}")
                raw = _bounded_yaml_load(path.read_text(encoding="utf-8"))
                if not isinstance(raw, dict):
                    raise ValueError("playbook document must be a YAML mapping")
                playbook = Playbook.model_validate(raw)
            except (OSError, UnicodeError, yaml.YAMLError, ValidationError, ValueError) as exc:
                issues.append(
                    CorpusValidationIssue(
                        path=relative,
                        code="playbook.invalid",
                        message=str(exc),
                    )
                )
                continue
            key = (playbook.metadata.playbook_id, playbook.metadata.version)
            if key in self._playbooks:
                first_path = self._paths[key].relative_to(self.root)
                issues.append(
                    CorpusValidationIssue(
                        path=relative,
                        code="playbook.duplicate",
                        message=f"duplicate playbook/version also defined at {first_path}",
                    )
                )
                continue
            self._playbooks[key] = playbook
            self._paths[key] = path

        manifest = self.manifest() if self._playbooks else None
        return CorpusValidationReport(
            root=str(self.root),
            valid=not issues,
            playbook_count=len(self._playbooks),
            issues=issues,
            manifest_digest=manifest.manifest_digest if manifest else None,
        )

    def all(self) -> list[Playbook]:
        return [self._playbooks[key] for key in sorted(self._playbooks)]

    def get(self, playbook_id: str, version: str | None = None) -> Playbook:
        matches = [(key, item) for key, item in self._playbooks.items() if key[0] == playbook_id]
        if not matches:
            raise KeyError(f"unknown playbook: {playbook_id}")
        if version is not None:
            key = (playbook_id, version)
            if key not in self._playbooks:
                raise KeyError(f"unknown playbook version: {playbook_id}@{version}")
            return self._playbooks[key]
        return max(matches, key=lambda pair: semver_key(pair[0][1]))[1]

    def search(
        self,
        query: str,
        *,
        domains: list[str] | None = None,
        capabilities: list[str] | None = None,
        limit: int = 10,
    ) -> list[CorpusSearchHit]:
        if limit < 1 or limit > 100:
            raise ValueError("limit must be between 1 and 100")
        query_terms = _terms(query)
        domain_filter = set(domains or [])
        capability_filter = set(capabilities or [])
        hits: list[CorpusSearchHit] = []
        for playbook in self._playbooks.values():
            if domain_filter and not domain_filter.intersection(playbook.metadata.domains):
                continue
            available_capabilities = playbook.capabilities()
            if capability_filter and not capability_filter.issuperset(available_capabilities):
                continue
            weighted = _weighted_terms(playbook)
            matched = sorted(query_terms.intersection(weighted))
            if query_terms and not matched:
                continue
            score = sum(weighted[term] for term in matched)
            if not query_terms:
                score = 1.0
            hits.append(
                CorpusSearchHit(
                    playbook_id=playbook.metadata.playbook_id,
                    version=playbook.metadata.version,
                    title=playbook.metadata.title,
                    summary=playbook.metadata.summary,
                    domains=playbook.metadata.domains,
                    tags=playbook.metadata.tags,
                    score=round(score, 6),
                    matched_terms=matched,
                    digest=playbook.digest(),
                )
            )
        return sorted(hits, key=lambda item: (-item.score, item.playbook_id, item.version))[:limit]

    def manifest(self) -> CorpusManifest:
        entries: list[CorpusEntry] = []
        for key in sorted(self._playbooks):
            playbook = self._playbooks[key]
            entries.append(
                CorpusEntry(
                    playbook_id=playbook.metadata.playbook_id,
                    version=playbook.metadata.version,
                    digest=playbook.digest(),
                    relative_path=str(self._paths[key].relative_to(self.root)),
                    title=playbook.metadata.title,
                    summary=playbook.metadata.summary,
                    domains=playbook.metadata.domains,
                    tags=playbook.metadata.tags,
                    review_state=playbook.metadata.review_state,
                    capabilities=sorted(playbook.capabilities()),
                    consumes=playbook.composition.consumes,
                    provides=playbook.composition.provides,
                )
            )
        content_digest = stable_digest([item.model_dump(mode="json") for item in entries])
        generated_at = max(
            (item.metadata.updated_at for item in self._playbooks.values()),
            default=datetime(1970, 1, 1, tzinfo=UTC),
        )
        manifest = CorpusManifest(
            corpus_version=f"sha256:{content_digest[:16]}",
            generated_at=generated_at,
            entries=entries,
        )
        manifest.manifest_digest = manifest.computed_digest()
        return manifest

    def write_manifest(self, path: Path) -> Path:
        manifest = self.manifest()
        payload = json.dumps(manifest.model_dump(mode="json"), indent=2, sort_keys=True) + "\n"
        _atomic_write(path, payload)
        return path


def dump_playbook(playbook: Playbook) -> str:
    return yaml.safe_dump(
        playbook.model_dump(mode="json", exclude_none=True),
        sort_keys=False,
        allow_unicode=True,
        width=100,
    )


def _weighted_terms(playbook: Playbook) -> Counter[str]:
    weighted: Counter[str] = Counter()
    for value, weight in (
        (playbook.metadata.title, 5),
        (playbook.metadata.summary, 3),
        (" ".join(playbook.metadata.domains), 5),
        (" ".join(playbook.metadata.tags), 4),
        (" ".join(item.identifier for item in playbook.taxonomies), 4),
        (" ".join(playbook.capabilities()), 3),
        (" ".join(step.instruction for step in playbook.steps), 1),
    ):
        for term in _terms(value):
            weighted[term] += weight
    return weighted


def _terms(value: str) -> set[str]:
    return {item for item in re.findall(r"[\w.-]+", value.lower(), flags=re.UNICODE) if len(item) > 1}


def _bounded_yaml_load(payload: str, *, max_depth: int = 100, max_events: int = 100_000):
    depth = 0
    for count, event in enumerate(yaml.parse(payload), start=1):
        if count > max_events:
            raise ValueError(f"YAML contains more than {max_events} parser events")
        if isinstance(event, yaml.events.AliasEvent):
            raise ValueError("YAML aliases are not allowed in playbooks")
        if isinstance(event, (yaml.events.MappingStartEvent, yaml.events.SequenceStartEvent)):
            depth += 1
            if depth > max_depth:
                raise ValueError(f"YAML nesting exceeds {max_depth} levels")
        elif isinstance(event, (yaml.events.MappingEndEvent, yaml.events.SequenceEndEvent)):
            depth -= 1
    return yaml.safe_load(payload)


def _atomic_write(path: Path, payload: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent, text=True)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    except BaseException:
        Path(temporary_name).unlink(missing_ok=True)
        raise
