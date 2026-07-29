from __future__ import annotations

import re
from enum import StrEnum
from typing import Annotated, Literal, Self
from urllib.parse import unquote, urlsplit

from pydantic import AwareDatetime, Field, TypeAdapter, ValidationError, model_validator

from ..knowledge.models import SemVer, Slug, semver_key
from ..models import Sha256, StrictModel, stable_digest, stable_id
from .models import AffectedPackage, AffectedRange, CveRecordState, NormalizedAdvisory, RangeType

GitCommit = Annotated[str, Field(pattern=r"^[0-9a-fA-F]{40}(?:[0-9a-fA-F]{24})?$")]
_SEMVER = TypeAdapter(SemVer)


class ApplicabilityStatus(StrEnum):
    APPLICABLE = "applicable"
    NOT_APPLICABLE = "not-applicable"
    INDETERMINATE = "indeterminate"


class ApplicabilityBasis(StrEnum):
    EXACT_VERSION = "exact-version"
    SEMVER_RANGE = "semver-range"
    GIT_RANGE = "git-range"
    UNRESOLVED = "unresolved"


class ApplicabilitySubject(StrictModel):
    """Exact identity facts for one artifact; authorization is evaluated separately."""

    schema_version: Literal["1.0"] = "1.0"
    subject_id: Slug
    package_name: str | None = Field(default=None, min_length=1)
    ecosystem: str | None = None
    vendor: str | None = None
    purl: str | None = None
    version: str | None = None
    repository: str | None = None
    commit_sha: GitCommit | None = None
    git_ancestor_commits: list[GitCommit] = Field(default_factory=list)
    git_ancestry_complete: bool = False
    build_id: str | None = None
    artifact_sha256: Sha256 | None = None
    observed_at: AwareDatetime

    @model_validator(mode="after")
    def exact_identity(self) -> Self:
        purl = _parse_purl(self.purl)
        if self.purl is not None and purl is None:
            raise ValueError("purl must be a valid pkg: URL")
        pair_supplied = self.ecosystem is not None or self.package_name is not None
        if self.purl is not None and (pair_supplied or self.vendor is not None):
            raise ValueError("use either purl identity or ecosystem/package fields, not both")
        if self.purl is None and (self.ecosystem is None or self.package_name is None):
            raise ValueError("package identity requires a purl or an ecosystem/package pair")
        purl_version = purl[1] if purl else None
        if purl_version and self.version and purl_version != self.version:
            raise ValueError("purl and explicit version disagree")
        if not any((self.version, purl_version, self.commit_sha, self.build_id, self.artifact_sha256)):
            raise ValueError("subject requires an exact version, commit, build, or artifact digest")
        if self.commit_sha is not None and self.repository is None:
            raise ValueError("commit identity requires a repository")
        ancestors = [item.casefold() for item in self.git_ancestor_commits]
        if len(ancestors) != len(set(ancestors)):
            raise ValueError("git ancestor commits must be unique")
        if ancestors and self.commit_sha is None:
            raise ValueError("git ancestors require a subject commit")
        if self.git_ancestry_complete and not ancestors:
            raise ValueError("complete Git ancestry requires ancestor commits")
        if ancestors and self.commit_sha.casefold() not in ancestors:
            raise ValueError("git ancestors must include the subject commit")
        return self

    def digest(self) -> str:
        return stable_digest(self)


class AdvisoryApplicabilityRequest(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    advisory: NormalizedAdvisory
    subject: ApplicabilitySubject
    evaluated_at: AwareDatetime


class ApplicabilityTrace(StrictModel):
    package_index: int = Field(ge=0)
    range_index: int | None = Field(default=None, ge=0)
    basis: ApplicabilityBasis
    status: ApplicabilityStatus
    reason: str = Field(min_length=1)


class AdvisoryApplicabilityDecision(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    decision_id: str
    status: ApplicabilityStatus
    advisory_id: str
    advisory_digest: Sha256
    source_snapshot_ids: list[str]
    subject_id: Slug
    subject_digest: Sha256
    traces: list[ApplicabilityTrace]
    reasons: list[str] = Field(min_length=1)
    blockers: list[str] = Field(default_factory=list)
    evaluated_at: AwareDatetime


def assess_advisory_applicability(
    request: AdvisoryApplicabilityRequest,
) -> AdvisoryApplicabilityDecision:
    """Match one advisory to one exact artifact without granting execution authority."""

    advisory = request.advisory
    traces: list[ApplicabilityTrace] = []
    reasons: list[str] = []

    if advisory.cve_record_state == CveRecordState.REJECTED:
        reasons.append("rejected CVE records do not establish artifact applicability")
    elif advisory.withdrawn_at is not None:
        reasons.append("withdrawn advisories do not establish current artifact applicability")
    else:
        matched_packages = [
            (index, package)
            for index, package in enumerate(advisory.affected)
            if _package_matches(request.subject, package)
        ]
        for index, package in matched_packages:
            traces.extend(_evaluate_package(request.subject, package, index))
        if not matched_packages:
            reasons.append("no affected-package fact exactly matches the subject coordinates")

    if any(trace.status == ApplicabilityStatus.APPLICABLE for trace in traces):
        status = ApplicabilityStatus.APPLICABLE
        reasons.append("at least one exact version or supported range includes the subject")
    elif traces and all(trace.status == ApplicabilityStatus.NOT_APPLICABLE for trace in traces):
        status = ApplicabilityStatus.NOT_APPLICABLE
        reasons.append("all matched, supported ranges exclude the subject")
    else:
        status = ApplicabilityStatus.INDETERMINATE
        reasons.append("available normalized facts do not support a definitive applicability result")

    reasons.append("execution authorization remains the responsibility of the existing scope evaluator")

    blockers = []
    if status == ApplicabilityStatus.INDETERMINATE:
        blockers = [trace.reason for trace in traces if trace.status == status]
        if not blockers:
            blockers.append(reasons[0])
    advisory_digest = stable_digest(advisory)
    subject_digest = request.subject.digest()
    identity = {
        "advisory_digest": advisory_digest,
        "subject_digest": subject_digest,
    }
    return AdvisoryApplicabilityDecision(
        decision_id=stable_id("applicability", identity),
        status=status,
        advisory_id=advisory.advisory_id,
        advisory_digest=advisory_digest,
        source_snapshot_ids=sorted({item.snapshot_id for item in advisory.provenance}),
        subject_id=request.subject.subject_id,
        subject_digest=subject_digest,
        traces=traces,
        reasons=_unique(reasons),
        blockers=_unique(blockers),
        evaluated_at=request.evaluated_at,
    )


def _evaluate_package(
    subject: ApplicabilitySubject,
    package: AffectedPackage,
    package_index: int,
) -> list[ApplicabilityTrace]:
    traces: list[ApplicabilityTrace] = []
    version = _subject_version(subject)
    if version is not None and version in package.versions:
        traces.append(
            ApplicabilityTrace(
                package_index=package_index,
                basis=ApplicabilityBasis.EXACT_VERSION,
                status=ApplicabilityStatus.APPLICABLE,
                reason=f"subject version {version!r} is explicitly enumerated as affected",
            )
        )
    for range_index, affected_range in enumerate(package.ranges):
        if affected_range.type == RangeType.SEMVER:
            status, reason = _semver_status(version, affected_range)
            basis = ApplicabilityBasis.SEMVER_RANGE
        elif affected_range.type == RangeType.GIT:
            status, reason = _git_status(subject, affected_range)
            basis = ApplicabilityBasis.GIT_RANGE
        else:
            status = ApplicabilityStatus.INDETERMINATE
            label = affected_range.raw_type or affected_range.type.value
            reason = f"range type {label!r} requires an ecosystem-specific adapter"
            basis = ApplicabilityBasis.UNRESOLVED
        traces.append(
            ApplicabilityTrace(
                package_index=package_index,
                range_index=range_index,
                basis=basis,
                status=status,
                reason=reason,
            )
        )
    if not traces:
        reason = (
            "absence from an affected-version list is not sufficient negative evidence"
            if package.versions
            else "matched package has no normalized affected versions or ranges"
        )
        traces.append(
            ApplicabilityTrace(
                package_index=package_index,
                basis=ApplicabilityBasis.UNRESOLVED,
                status=ApplicabilityStatus.INDETERMINATE,
                reason=reason,
            )
        )
    return traces


def _semver_status(version: str | None, affected_range: AffectedRange) -> tuple[ApplicabilityStatus, str]:
    if version is None:
        return ApplicabilityStatus.INDETERMINATE, "subject has no version for SemVer matching"
    subject_key = _semver(version)
    if subject_key is None:
        return ApplicabilityStatus.INDETERMINATE, f"subject version {version!r} is not strict SemVer"
    events = [next(iter(event.model_dump(exclude_none=True).items())) for event in affected_range.events]
    kinds = {kind for kind, _ in events}
    if "introduced" not in kinds:
        return ApplicabilityStatus.INDETERMINATE, "SemVer range has no introduced event"
    if "limit" in kinds:
        return ApplicabilityStatus.INDETERMINATE, "SemVer limit events require a dedicated adapter"
    if {"fixed", "last_affected"}.issubset(kinds):
        return ApplicabilityStatus.INDETERMINATE, "SemVer range mixes fixed and last_affected events"

    parsed: list[tuple[str, str, tuple | None]] = []
    for kind, boundary in events:
        if kind == "introduced" and boundary == "0":
            parsed.append((kind, boundary, None))
            continue
        boundary_key = _semver(boundary)
        if boundary_key is None:
            return (
                ApplicabilityStatus.INDETERMINATE,
                f"range boundary {boundary!r} is not strict SemVer",
            )
        parsed.append((kind, boundary, boundary_key))

    # OSV defines evaluation in version order; source ordering is only recommended.
    timeline = sorted(
        parsed,
        key=lambda item: (-1,) if item[2] is None else item[2],
    )
    structural_state = False
    boundaries: set[tuple | None] = set()
    for kind, _, boundary_key in timeline:
        if boundary_key in boundaries:
            return ApplicabilityStatus.INDETERMINATE, "SemVer range repeats a boundary"
        boundaries.add(boundary_key)
        if kind == "introduced":
            if structural_state:
                return ApplicabilityStatus.INDETERMINATE, "SemVer range repeats an introduced transition"
            structural_state = True
        else:
            if not structural_state:
                return ApplicabilityStatus.INDETERMINATE, "SemVer range closes an inactive interval"
            structural_state = False
    affected = False
    for kind, _, boundary_key in timeline:
        comparison = (
            1 if boundary_key is None else (subject_key > boundary_key) - (subject_key < boundary_key)
        )
        if kind == "introduced" and comparison >= 0:
            affected = True
        elif (kind == "fixed" and comparison >= 0) or (kind == "last_affected" and comparison > 0):
            affected = False
    status = ApplicabilityStatus.APPLICABLE if affected else ApplicabilityStatus.NOT_APPLICABLE
    return status, f"SemVer events evaluate version {version!r} as {status.value}"


def _git_status(
    subject: ApplicabilitySubject,
    affected_range: AffectedRange,
) -> tuple[ApplicabilityStatus, str]:
    if subject.commit_sha is None or subject.repository is None:
        return ApplicabilityStatus.INDETERMINATE, "subject has no repository commit for Git matching"
    if affected_range.repository is None or not _same_repository(
        subject.repository,
        affected_range.repository,
    ):
        return ApplicabilityStatus.INDETERMINATE, "subject and affected Git repositories do not exactly match"
    if not subject.git_ancestry_complete:
        return ApplicabilityStatus.INDETERMINATE, "Git range requires explicitly complete subject ancestry"
    events = [next(iter(event.model_dump(exclude_none=True).items())) for event in affected_range.events]
    kinds = {kind for kind, _ in events}
    if "introduced" not in kinds:
        return ApplicabilityStatus.INDETERMINATE, "Git range has no introduced event"
    if kinds.intersection({"last_affected", "limit"}):
        return (
            ApplicabilityStatus.INDETERMINATE,
            "Git last_affected and limit events require graph reachability",
        )
    invalid_boundary = any(
        boundary != "0" and re.fullmatch(r"[0-9a-fA-F]{40}(?:[0-9a-fA-F]{24})?", boundary) is None
        for _, boundary in events
    )
    if invalid_boundary:
        return ApplicabilityStatus.INDETERMINATE, "Git range contains a non-canonical commit boundary"

    ancestors = {item.casefold() for item in subject.git_ancestor_commits}
    affected = False
    for kind, boundary in events:
        on_subject_history = boundary == "0" or boundary.casefold() in ancestors
        if kind == "introduced" and on_subject_history:
            affected = True
        elif kind == "fixed" and on_subject_history:
            affected = False
    status = ApplicabilityStatus.APPLICABLE if affected else ApplicabilityStatus.NOT_APPLICABLE
    return status, f"complete Git ancestry evaluates commit {subject.commit_sha!r} as {status.value}"


def _package_matches(subject: ApplicabilitySubject, package: AffectedPackage) -> bool:
    subject_purl = _parse_purl(subject.purl)
    package_purl = _parse_purl(package.purl)
    if subject_purl or package_purl:
        return subject_purl is not None and package_purl is not None and subject_purl[0] == package_purl[0]
    if package.ecosystem is None:
        return False
    if subject.ecosystem.casefold() != package.ecosystem.casefold() or subject.package_name != package.name:
        return False
    return not (subject.vendor and package.vendor and subject.vendor.casefold() != package.vendor.casefold())


def _subject_version(subject: ApplicabilitySubject) -> str | None:
    parsed = _parse_purl(subject.purl)
    return subject.version or (parsed[1] if parsed else None)


def _parse_purl(value: str | None) -> tuple[str, str | None] | None:
    if value is None or not value.startswith("pkg:"):
        return None
    without_fragment, fragment_separator, fragment = value[4:].partition("#")
    base, qualifier_separator, qualifiers = without_fragment.partition("?")
    coordinate, separator, version = base.rpartition("@")
    if not separator or "/" not in coordinate:
        coordinate, version = base, None
    if "/" not in coordinate:
        return None
    package_type, name = coordinate.split("/", 1)
    if not package_type or not name:
        return None
    identity = f"{package_type.casefold()}/{unquote(name)}"
    if qualifier_separator:
        identity += f"?{qualifiers}"
    if fragment_separator:
        identity += f"#{fragment}"
    return identity, unquote(version) if version else None


def _semver(value: str) -> tuple | None:
    try:
        validated = _SEMVER.validate_python(value)
    except ValidationError:
        return None
    prerelease = validated.split("+", 1)[0].partition("-")[2]
    if any(part.isdigit() and len(part) > 1 and part.startswith("0") for part in prerelease.split(".")):
        return None
    return semver_key(validated)


def _same_repository(left: str, right: str) -> bool:
    return _normalize_repository(left) == _normalize_repository(right)


def _normalize_repository(value: str) -> tuple[str, str]:
    normalized = value.rstrip("/")
    if normalized.endswith(".git"):
        normalized = normalized[:-4]
    parsed = urlsplit(normalized)
    if parsed.hostname:
        return parsed.hostname.casefold(), parsed.path.rstrip("/")
    if "@" in normalized and ":" in normalized:
        host, path = normalized.split(":", 1)
        return host.rsplit("@", 1)[-1].casefold(), path.rstrip("/")
    return "", normalized


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))
