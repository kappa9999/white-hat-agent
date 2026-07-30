from __future__ import annotations

import hashlib
import os
import re
import shutil
import tempfile
from collections import Counter
from collections.abc import Callable
from contextlib import suppress
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Literal, Self

import yaml
from pydantic import AwareDatetime, Field, ValidationError, model_validator

from .knowledge.models import (
    EXECUTION_CLASS_RANK,
    CapabilityId,
    ExecutionClass,
    SemanticType,
    SemVer,
    Slug,
)
from .models import ExecutionMode, Sha256, StrictModel, stable_digest, utc_now


class AdapterRegistryError(RuntimeError):
    """Raised when a concrete adapter cannot be resolved or verified safely."""


class AdapterKind(StrEnum):
    TOOL = "tool"
    KNOWLEDGE = "knowledge"


VersionArguments = tuple[Literal["--version"]] | tuple[Literal["-version"]] | tuple[()]


class ProbeDefinition(StrictModel):
    executable_names: dict[str, list[str]]
    version_args: VersionArguments = ("--version",)
    version_pattern: str | None = None
    version_file: str | None = None
    version_property: str | None = None
    minimum_version: str | None = None
    managed_adapter_id: Slug | None = None
    timeout_seconds: float = Field(default=10.0, gt=0, le=60)

    @model_validator(mode="after")
    def valid_probe(self) -> Self:
        if not self.executable_names or any(not names for names in self.executable_names.values()):
            raise ValueError("probe executable_names must contain non-empty platform entries")
        if self.version_file:
            path = Path(self.version_file)
            if path.is_absolute() or ".." in path.parts:
                raise ValueError("probe version_file must be a contained relative path")
            if not self.version_property:
                raise ValueError("probe version_file requires version_property")
            if self.version_args:
                raise ValueError("file probes cannot invoke a version command")
        else:
            if not self.version_pattern:
                raise ValueError("command probes require version_pattern")
            if not self.version_args:
                raise ValueError("command probes require a fixed version strategy")
        if self.version_pattern:
            re.compile(self.version_pattern)
        return self


class GitHubReleaseProvisioner(StrictModel):
    kind: Literal["github-release"] = "github-release"
    repository: str = Field(pattern=r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
    asset_patterns: dict[str, list[str]]
    entrypoints: dict[str, list[str]] = Field(default_factory=dict)
    strip_single_directory: bool = True
    max_download_bytes: int = Field(ge=1, le=2_147_483_648)
    max_install_bytes: int = Field(ge=1, le=8_589_934_592)

    @model_validator(mode="after")
    def valid_patterns(self) -> Self:
        if not self.asset_patterns or any(not patterns for patterns in self.asset_patterns.values()):
            raise ValueError("GitHub release provisioner requires platform asset patterns")
        for patterns in self.asset_patterns.values():
            for pattern in patterns:
                re.compile(pattern)
        for paths in self.entrypoints.values():
            for value in paths:
                if ("{" in value or "}" in value) and (
                    value.count("{version}") != 1
                    or "{" in value.replace("{version}", "")
                    or "}" in value.replace("{version}", "")
                ):
                    raise ValueError("adapter entrypoints only support one {version} placeholder")
                path = Path(value.replace("{version}", "0"))
                if path.is_absolute() or ".." in path.parts:
                    raise ValueError("adapter entrypoints must be contained relative paths")
        return self


class AdoptiumProvisioner(StrictModel):
    kind: Literal["adoptium-api"] = "adoptium-api"
    feature_version: int = Field(ge=21, le=99)
    image_type: Literal["jdk"] = "jdk"
    jvm_impl: Literal["hotspot"] = "hotspot"
    vendor: Literal["eclipse"] = "eclipse"
    entrypoints: dict[str, list[str]]
    strip_single_directory: bool = True
    max_download_bytes: int = Field(ge=1, le=2_147_483_648)
    max_install_bytes: int = Field(ge=1, le=8_589_934_592)

    @model_validator(mode="after")
    def valid_entrypoints(self) -> Self:
        if not self.entrypoints or any(not paths for paths in self.entrypoints.values()):
            raise ValueError("Adoptium provisioner requires platform entrypoints")
        for paths in self.entrypoints.values():
            for value in paths:
                path = Path(value)
                if path.is_absolute() or ".." in path.parts:
                    raise ValueError("Adoptium entrypoints must be contained relative paths")
        return self


class GitCheckoutProvisioner(StrictModel):
    kind: Literal["git-checkout"] = "git-checkout"
    repository: str = Field(pattern=r"^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?$")
    ref: str = Field(min_length=1, max_length=200)
    max_checkout_bytes: int = Field(ge=1, le=2_147_483_648)


class MitreCweProvisioner(StrictModel):
    kind: Literal["mitre-cwe"] = "mitre-cwe"
    max_download_bytes: int = Field(ge=1, le=2_147_483_648)
    max_install_bytes: int = Field(ge=1, le=8_589_934_592)


ProvisionerDefinition = Annotated[
    GitHubReleaseProvisioner | AdoptiumProvisioner | GitCheckoutProvisioner | MitreCweProvisioner,
    Field(discriminator="kind"),
]


class AdapterLicense(StrictModel):
    name: str = Field(min_length=1)
    url: str = Field(pattern=r"^https://")
    attribution: str = Field(min_length=1)


class OperationResourceLimits(StrictModel):
    max_input_bytes: int = Field(gt=0, le=2_147_483_648)
    max_output_bytes: int = Field(gt=0, le=2_147_483_648)
    max_files: int = Field(gt=0, le=100_000)
    max_records: int = Field(gt=0, le=10_000_000)
    wall_seconds: int = Field(gt=0, le=86_400)
    cpu_seconds: int = Field(gt=0, le=86_400)
    memory_mib: int = Field(gt=0, le=1_048_576)
    max_processes: int = Field(gt=0, le=4_096)


class AdapterOperationBinding(StrictModel):
    operation_id: Slug
    operation_version: SemVer
    capabilities: list[CapabilityId] = Field(min_length=1)
    execution_class: ExecutionClass
    modes: list[ExecutionMode] = Field(min_length=1)
    input_types: list[SemanticType] = Field(min_length=1)
    output_types: list[SemanticType] = Field(min_length=1)
    conformance_suite_id: Slug
    limits: OperationResourceLimits

    @model_validator(mode="after")
    def unique_contract_lists(self) -> Self:
        for label, values in (
            ("capabilities", self.capabilities),
            ("modes", [item.value for item in self.modes]),
            ("input_types", self.input_types),
            ("output_types", self.output_types),
        ):
            if len(values) != len(set(values)):
                raise ValueError(f"adapter operation {label} must be unique")
        return self

    def digest(self) -> str:
        return stable_digest(self)


class AdapterManifest(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    adapter_id: Slug
    adapter_version: str = Field(default="1.0.0", pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    title: str = Field(min_length=1)
    description: str = Field(min_length=1)
    kind: AdapterKind
    provider: str = Field(min_length=1)
    provider_url: str = Field(pattern=r"^https://")
    license: AdapterLicense
    capabilities: list[CapabilityId] = Field(min_length=1)
    modes: list[ExecutionMode] = Field(default_factory=lambda: [ExecutionMode.OFFLINE])
    max_execution_class: ExecutionClass = ExecutionClass.ANALYSIS
    platforms: list[str] = Field(min_length=1)
    priority: int = Field(default=50, ge=0, le=100)
    probe: ProbeDefinition | None = None
    requirements: list[ProbeDefinition] = Field(default_factory=list, max_length=32)
    operations: list[AdapterOperationBinding] = Field(default_factory=list)
    provisioner: ProvisionerDefinition | None = None
    search_globs: list[str] = Field(default_factory=list)
    updated_at: AwareDatetime

    @model_validator(mode="after")
    def valid_manifest(self) -> Self:
        for label, values in (
            ("capabilities", self.capabilities),
            ("modes", [item.value for item in self.modes]),
            ("platforms", self.platforms),
            ("search_globs", self.search_globs),
            ("operation identifiers", [item.operation_id for item in self.operations]),
        ):
            if len(values) != len(set(values)):
                raise ValueError(f"adapter {label} must be unique")
        manifest_capabilities = set(self.capabilities)
        manifest_modes = set(self.modes)
        for operation in self.operations:
            undeclared_capabilities = sorted(set(operation.capabilities) - manifest_capabilities)
            if undeclared_capabilities:
                raise ValueError(
                    f"adapter operation {operation.operation_id} has undeclared capabilities: "
                    + ", ".join(undeclared_capabilities)
                )
            undeclared_modes = sorted(
                (mode.value for mode in set(operation.modes) - manifest_modes),
            )
            if undeclared_modes:
                raise ValueError(
                    f"adapter operation {operation.operation_id} has undeclared modes: "
                    + ", ".join(undeclared_modes)
                )
            if (
                EXECUTION_CLASS_RANK[operation.execution_class]
                > EXECUTION_CLASS_RANK[self.max_execution_class]
            ):
                raise ValueError(
                    f"adapter operation {operation.operation_id} exceeds the manifest execution class"
                )
        if self.kind == AdapterKind.TOOL and self.probe is None:
            raise ValueError("tool adapters require an executable probe")
        if self.kind == AdapterKind.TOOL:
            if self.probe and self.probe.managed_adapter_id is not None:
                raise ValueError("a tool's own executable probe cannot reference another adapter")
            if isinstance(self.provisioner, GitCheckoutProvisioner):
                raise ValueError("tool adapters cannot provision executable code through Git checkout")
            if isinstance(self.provisioner, MitreCweProvisioner):
                raise ValueError("the MITRE CWE provisioner is only valid for knowledge adapters")
            if isinstance(self.provisioner, (GitHubReleaseProvisioner, AdoptiumProvisioner)):
                missing = [
                    platform
                    for platform in self.platforms
                    if not platform_values(self.provisioner.entrypoints, platform)
                ]
                if missing:
                    raise ValueError(
                        "provisioned tool adapters require entrypoints for: " + ", ".join(missing)
                    )
            if self.search_globs:
                raise ValueError("tool adapters cannot declare knowledge search globs")
        if self.kind == AdapterKind.KNOWLEDGE:
            if self.operations:
                raise ValueError("knowledge adapters cannot declare executable operations")
            if not self.search_globs:
                raise ValueError("knowledge adapters require bounded search_globs")
            if self.provisioner is None:
                raise ValueError("knowledge adapters require a trusted provisioner")
            if self.probe is not None or self.requirements:
                raise ValueError("knowledge adapters cannot declare executable probes")
        return self

    def digest(self) -> str:
        return stable_digest(self)


class AdapterCatalogManifest(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    adapters: list[AdapterManifest]

    def digest(self) -> str:
        return stable_digest(self)


class AdapterRegistryIssue(StrictModel):
    code: str
    message: str


class AdapterRegistryReport(StrictModel):
    path: str
    valid: bool
    adapter_count: int = Field(ge=0)
    digest: str | None = None
    issues: list[AdapterRegistryIssue] = Field(default_factory=list)


class AdapterSearchHit(StrictModel):
    adapter: AdapterManifest
    score: float
    matched_terms: list[str]


class AdapterCheck(StrictModel):
    name: str
    ok: bool
    detail: str


class AdapterConformanceCheck(StrictModel):
    name: str = Field(min_length=1, max_length=200)
    ok: bool
    detail: str = Field(min_length=1, max_length=16_384)


class AdapterConformanceReport(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    adapter_id: Slug
    operation_id: Slug
    operation_version: SemVer
    manifest_digest: Sha256
    operation_contract_digest: Sha256
    observed_identity_sha256: Sha256
    requirement_identity_sha256: list[Sha256 | None] = Field(max_length=32)
    tool_payload_sha256: Sha256
    tool_version: str = Field(min_length=1, max_length=200)
    driver_id: Slug
    driver_version: SemVer
    sandbox_profile_sha256: Sha256
    fixture_id: Slug
    fixture_sha256: Sha256
    started_at: AwareDatetime
    finished_at: AwareDatetime
    passed: bool
    checks: list[AdapterConformanceCheck] = Field(min_length=1)
    warnings: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def consistent_result(self) -> Self:
        if self.finished_at < self.started_at:
            raise ValueError("conformance finished_at cannot precede started_at")
        check_names = [check.name for check in self.checks]
        if len(check_names) != len(set(check_names)):
            raise ValueError("conformance check names must be unique")
        if self.passed != all(check.ok for check in self.checks):
            raise ValueError("conformance passed must match the individual checks")
        if any(not warning.strip() for warning in self.warnings):
            raise ValueError("conformance warnings must not be empty")
        if len(self.warnings) != len(set(self.warnings)):
            raise ValueError("conformance warnings must be unique")
        return self

    def digest(self) -> str:
        return stable_digest(self)


ConformanceVerifier = Callable[
    [AdapterOperationBinding, AdapterConformanceReport, list[str]],
    bool,
]


class InstalledAdapterRecord(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    adapter_id: Slug
    manifest_digest: Sha256
    version: str = Field(min_length=1)
    revision: str = Field(min_length=1)
    source_urls: list[str] = Field(min_length=1)
    artifact_sha256: list[Sha256] = Field(default_factory=list)
    content_sha256: Sha256
    entrypoints: list[str] = Field(default_factory=list)
    installed_at: AwareDatetime

    @model_validator(mode="after")
    def contained_entrypoints(self) -> Self:
        for value in self.entrypoints:
            path = Path(value)
            if path.is_absolute() or ".." in path.parts:
                raise ValueError("installed adapter entrypoints must be contained relative paths")
        return self


class AdapterStatus(StrictModel):
    adapter_id: Slug
    manifest_digest: Sha256
    observed_at: AwareDatetime
    platform: str
    supported: bool
    installed: bool
    healthy: bool
    source: Literal["system", "managed"] | None = None
    version: str | None = None
    revision: str | None = None
    entrypoints: list[str] = Field(default_factory=list)
    observed_identity_sha256: Sha256 | None = None
    conformant_operations: list[Slug] = Field(default_factory=list)
    declared_capabilities: list[CapabilityId] = Field(default_factory=list)
    available_capabilities: list[CapabilityId] = Field(default_factory=list)
    checks: list[AdapterCheck] = Field(default_factory=list)
    blockers: list[str] = Field(default_factory=list)


class AdapterSelection(StrictModel):
    required_capabilities: list[CapabilityId]
    selected_adapters: list[Slug]
    ready_adapters: list[Slug]
    provisioning_required: list[Slug]
    conformance_required: list[Slug]
    uncovered_capabilities: list[CapabilityId]
    complete: bool
    ready: bool
    reasons: list[str]


class KnowledgeSearchHit(StrictModel):
    adapter_id: Slug
    revision: str
    relative_path: str
    line: int = Field(ge=1)
    snippet: str


class KnowledgeExcerpt(StrictModel):
    adapter_id: Slug
    revision: str
    relative_path: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    text: str
    truncated: bool


class AdapterRegistry:
    def __init__(
        self,
        path: Path,
        *,
        capability_execution_classes: dict[str, ExecutionClass] | None = None,
        max_catalog_bytes: int = 4_194_304,
    ) -> None:
        self.path = path.resolve()
        self.capability_execution_classes = capability_execution_classes
        self.max_catalog_bytes = max_catalog_bytes
        self._manifest: AdapterCatalogManifest | None = None
        self._items: dict[str, AdapterManifest] = {}

    def load(self) -> AdapterRegistryReport:
        self._manifest = None
        self._items.clear()
        try:
            byte_length = self.path.stat().st_size
            if byte_length > self.max_catalog_bytes:
                raise ValueError(
                    f"adapter registry is {byte_length} bytes; maximum is {self.max_catalog_bytes}"
                )
            raw = yaml.safe_load(self.path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                raise ValueError("adapter registry must be a YAML mapping")
            manifest = AdapterCatalogManifest.model_validate(raw)
            items = {item.adapter_id: item for item in manifest.adapters}
            if len(items) != len(manifest.adapters):
                raise ValueError("adapter identifiers must be unique")
            _validate_managed_requirement_graph(items)
            if self.capability_execution_classes is not None:
                unknown = sorted(
                    {
                        capability
                        for item in manifest.adapters
                        for capability in item.capabilities
                        if capability not in self.capability_execution_classes
                    }
                )
                if unknown:
                    raise ValueError(f"adapters reference unknown capabilities: {', '.join(unknown)}")
                underclassified = [
                    (
                        f"{item.adapter_id}:{capability} requires "
                        f"{self.capability_execution_classes[capability].value}"
                    )
                    for item in manifest.adapters
                    for capability in item.capabilities
                    if (
                        EXECUTION_CLASS_RANK[item.max_execution_class]
                        < EXECUTION_CLASS_RANK[self.capability_execution_classes[capability]]
                    )
                ]
                if underclassified:
                    raise ValueError(
                        "adapters underclassify capability execution: " + ", ".join(underclassified)
                    )
        except (OSError, UnicodeError, yaml.YAMLError, ValidationError, ValueError) as exc:
            return AdapterRegistryReport(
                path=str(self.path),
                valid=False,
                adapter_count=0,
                issues=[AdapterRegistryIssue(code="adapter-registry.invalid", message=str(exc))],
            )
        self._manifest = manifest
        self._items = items
        return AdapterRegistryReport(
            path=str(self.path),
            valid=True,
            adapter_count=len(items),
            digest=manifest.digest(),
        )

    def all(self) -> list[AdapterManifest]:
        return [self._items[key] for key in sorted(self._items)]

    def get(self, adapter_id: str) -> AdapterManifest:
        try:
            return self._items[adapter_id]
        except KeyError as exc:
            raise KeyError(f"unknown adapter: {adapter_id}") from exc

    def search(
        self,
        query: str,
        *,
        kind: AdapterKind | None = None,
        limit: int = 20,
    ) -> list[AdapterSearchHit]:
        if limit < 1 or limit > 100:
            raise ValueError("limit must be between 1 and 100")
        wanted = _terms(query)
        hits: list[AdapterSearchHit] = []
        for item in self._items.values():
            if kind is not None and item.kind != kind:
                continue
            weighted: Counter[str] = Counter()
            for text, weight in (
                (item.adapter_id, 8),
                (item.title, 6),
                (item.description, 3),
                (item.provider, 2),
                (" ".join(item.capabilities), 5),
            ):
                for term in _terms(text):
                    weighted[term] += weight
            matched = sorted(wanted.intersection(weighted))
            if wanted and not matched:
                continue
            hits.append(
                AdapterSearchHit(
                    adapter=item,
                    score=float(sum(weighted[term] for term in matched) or 1),
                    matched_terms=matched,
                )
            )
        return sorted(hits, key=lambda hit: (-hit.score, hit.adapter.priority, hit.adapter.adapter_id))[
            :limit
        ]


class AdapterManager:
    def __init__(
        self,
        registry: AdapterRegistry,
        managed_root: Path,
        *,
        conformance_verifier: ConformanceVerifier | None = None,
    ) -> None:
        self.registry = registry
        self.managed_root = managed_root.resolve()
        self.conformance_verifier = conformance_verifier

    def save_conformance_report(
        self,
        report: AdapterConformanceReport,
        *,
        entrypoints: list[str] | None = None,
    ) -> Path:
        manifest = self.registry.get(report.adapter_id)
        if manifest.kind != AdapterKind.TOOL:
            raise AdapterRegistryError("conformance reports require a tool adapter")
        operation = next(
            (item for item in manifest.operations if item.operation_id == report.operation_id),
            None,
        )
        if operation is None:
            raise AdapterRegistryError(
                f"adapter does not declare operation: {report.adapter_id}:{report.operation_id}"
            )
        if report.manifest_digest != manifest.digest():
            raise AdapterRegistryError("conformance report manifest identity does not match the registry")
        if (
            report.operation_version != operation.operation_version
            or report.operation_contract_digest != operation.digest()
        ):
            raise AdapterRegistryError("conformance report operation contract does not match the registry")
        if report.fixture_id != operation.conformance_suite_id:
            raise AdapterRegistryError("conformance report fixture does not match the operation suite")
        if len(report.requirement_identity_sha256) != len(manifest.requirements):
            raise AdapterRegistryError("conformance report requirements do not match the manifest")
        current_requirement_identities = self._requirement_observations(
            manifest,
            current_platform(),
        )[1]
        if report.requirement_identity_sha256 != current_requirement_identities:
            raise AdapterRegistryError("conformance report requirement identity does not match the runtime")
        if self.conformance_verifier is not None:
            current_entrypoints = entrypoints
            if current_entrypoints is None:
                current_entrypoints = self.status(report.adapter_id).entrypoints
            if not self.conformance_verifier(operation, report, current_entrypoints):
                raise AdapterRegistryError("conformance report does not match the current runtime")
        directory = self._conformance_adapter_dir(report.adapter_id, create=True)
        path = directory / f"{report.operation_id}.json"
        payload = report.model_dump_json(indent=2) + "\n"
        file_descriptor, temporary_name = tempfile.mkstemp(
            dir=directory,
            prefix=f".{report.operation_id}.",
            suffix=".tmp",
        )
        temporary_path = Path(temporary_name)
        try:
            fchmod = getattr(os, "fchmod", None)
            if fchmod is not None:
                fchmod(file_descriptor, 0o600)
            handle = os.fdopen(file_descriptor, "w", encoding="utf-8", newline="\n")
            file_descriptor = -1
            with handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_path, path)
        except BaseException:
            if file_descriptor >= 0:
                with suppress(OSError):
                    os.close(file_descriptor)
            temporary_path.unlink(missing_ok=True)
            raise
        return path

    def conformance_reports(self, adapter_id: str) -> list[AdapterConformanceReport]:
        manifest = self.registry.get(adapter_id)
        if manifest.kind != AdapterKind.TOOL:
            return []
        status = self.status(adapter_id)
        return self._matching_conformance_reports(
            manifest,
            tool_version=status.version,
            observed_identity_sha256=status.observed_identity_sha256,
            requirement_identity_sha256=self._requirement_observations(
                manifest,
                status.platform,
            )[1],
            entrypoints=status.entrypoints,
        )

    def status(self, adapter_id: str) -> AdapterStatus:
        manifest = self.registry.get(adapter_id)
        platform = current_platform()
        supported = _platform_value(manifest.platforms, platform) is not None
        checks = [
            AdapterCheck(
                name="platform",
                ok=supported,
                detail=f"current={platform}; supported={','.join(manifest.platforms)}",
            )
        ]
        blockers: list[str] = []
        if not supported:
            blockers.append(f"adapter does not support {platform}")
        record = self._installed_record(manifest)
        if manifest.kind == AdapterKind.KNOWLEDGE:
            content_dir = self._content_dir(adapter_id)
            installed = record is not None and content_dir.is_dir() and not content_dir.is_symlink()
            checks.append(
                AdapterCheck(
                    name="managed-content",
                    ok=installed,
                    detail=str(self._content_dir(adapter_id)),
                )
            )
            if not installed:
                blockers.append("knowledge snapshot is not provisioned")
            integrity = False
            integrity_detail = "not checked"
            if installed and record:
                try:
                    observed_digest = content_tree_digest(
                        content_dir,
                        max_bytes=_managed_content_limit(manifest),
                    )
                    integrity = observed_digest == record.content_sha256
                    integrity_detail = f"observed={observed_digest}; expected={record.content_sha256}"
                except (OSError, AdapterRegistryError) as exc:
                    integrity_detail = type(exc).__name__
            checks.append(
                AdapterCheck(
                    name="content-integrity",
                    ok=integrity,
                    detail=integrity_detail,
                )
            )
            if installed and not integrity:
                blockers.append("managed knowledge snapshot integrity check failed")
            healthy = supported and installed and integrity
            return AdapterStatus(
                adapter_id=adapter_id,
                manifest_digest=manifest.digest(),
                observed_at=utc_now(),
                platform=platform,
                supported=supported,
                installed=installed,
                healthy=healthy,
                source="managed" if installed else None,
                version=record.version if record else None,
                revision=record.revision if record else None,
                entrypoints=record.entrypoints if record else [],
                declared_capabilities=manifest.capabilities,
                available_capabilities=manifest.capabilities if healthy else [],
                checks=checks,
                blockers=blockers,
            )

        managed_entrypoints = self._managed_entrypoints(record) if record else []
        executable = next((path for path in managed_entrypoints if Path(path).is_file()), None)
        source: Literal["system", "managed"] | None = "managed" if executable else None
        if executable is None and manifest.probe:
            executable = _which_probe(manifest.probe, platform)
            source = "system" if executable else None
        installed = executable is not None
        checks.append(
            AdapterCheck(
                name="executable",
                ok=installed,
                detail=executable or "not found",
            )
        )
        system_entrypoints = (
            _system_entrypoints(manifest, Path(executable), platform)
            if executable and source == "system"
            else []
        )
        entrypoints = managed_entrypoints if source == "managed" else system_entrypoints
        observed_identity_sha256: str | None = None
        if entrypoints:
            try:
                observed_identity_sha256 = observed_tool_identity_digest(entrypoints)
                checks.append(
                    AdapterCheck(
                        name="observed-identity",
                        ok=True,
                        detail=observed_identity_sha256,
                    )
                )
            except (OSError, AdapterRegistryError) as exc:
                checks.append(
                    AdapterCheck(
                        name="observed-identity",
                        ok=False,
                        detail=type(exc).__name__,
                    )
                )
                blockers.append("tool identity could not be observed")
        passive_version: str | None = None
        passive_version_check: AdapterCheck | None = None
        if installed and manifest.probe:
            if manifest.probe.version_file:
                passive_version, passive_version_check = _probe_file_version(
                    Path(executable),
                    manifest.probe,
                    name="version",
                )
            elif record is not None and source == "managed":
                passive_version = record.version
                passive_version_check = AdapterCheck(
                    name="version",
                    ok=_version_matches_probe(passive_version, manifest.probe),
                    detail=f"managed install metadata; version={passive_version}",
                )

        requirement_paths, requirement_identity_sha256 = self._requirement_observations(
            manifest,
            platform,
        )
        matching_reports = self._matching_conformance_reports(
            manifest,
            tool_version=passive_version,
            observed_identity_sha256=observed_identity_sha256,
            requirement_identity_sha256=requirement_identity_sha256,
            entrypoints=[*entrypoints, *[path for path in requirement_paths if path]],
        )
        version = passive_version
        if passive_version_check is not None:
            checks.append(passive_version_check)
            if not passive_version_check.ok:
                blockers.append("tool version did not satisfy the manifest")
        elif installed and manifest.probe:
            observed_versions = {
                report.tool_version
                for report in matching_reports
                if _report_check_ok(report, "tool-version")
                and _version_matches_probe(report.tool_version, manifest.probe)
            }
            if len(observed_versions) == 1:
                version = next(iter(observed_versions))
                checks.append(
                    AdapterCheck(
                        name="version",
                        ok=True,
                        detail=f"cached explicit conformance; version={version}",
                    )
                )
                matching_reports = [report for report in matching_reports if report.tool_version == version]
            else:
                detail = (
                    "conflicting cached conformance observations"
                    if observed_versions
                    else "command probe deferred; run adapter conform"
                )
                checks.append(AdapterCheck(name="version", ok=False, detail=detail))
                blockers.append("tool version requires explicit conformance")

        for index, (requirement, dependency, dependency_identity) in enumerate(
            zip(
                manifest.requirements,
                requirement_paths,
                requirement_identity_sha256,
                strict=True,
            ),
            start=1,
        ):
            check_name = f"requirement-{index}"
            if dependency is None:
                checks.append(AdapterCheck(name=check_name, ok=False, detail="executable not found"))
                blockers.append(f"runtime requirement {index} is missing")
                continue
            if dependency_identity is None:
                checks.append(
                    AdapterCheck(name=check_name, ok=False, detail="identity could not be observed")
                )
                blockers.append(f"runtime requirement {index} identity could not be observed")
                continue
            if requirement.version_file:
                _, requirement_check = _probe_file_version(
                    Path(dependency),
                    requirement,
                    name=check_name,
                )
            else:
                observed = any(
                    _report_check_ok(report, f"requirement-{index}-version") for report in matching_reports
                )
                requirement_check = AdapterCheck(
                    name=check_name,
                    ok=observed,
                    detail=(
                        f"cached explicit conformance; executable={dependency}"
                        if observed
                        else f"command probe deferred; executable={dependency}; run adapter conform"
                    ),
                )
            checks.append(requirement_check)
            if not requirement_check.ok:
                blockers.append(f"runtime requirement {index} is not satisfied")

        healthy = (
            supported
            and installed
            and observed_identity_sha256 is not None
            and version is not None
            and not blockers
        )
        passing_reports = {report.operation_id: report for report in matching_reports if report.passed}
        conformant_operations = (
            [
                operation.operation_id
                for operation in manifest.operations
                if operation.operation_id in passing_reports
            ]
            if healthy
            else []
        )
        conformant_capabilities = {
            capability
            for operation in manifest.operations
            if operation.operation_id in passing_reports
            for capability in operation.capabilities
        }
        available_capabilities = []
        if healthy:
            available_capabilities = (
                list(manifest.capabilities)
                if not manifest.operations
                else [
                    capability
                    for capability in manifest.capabilities
                    if capability in conformant_capabilities
                ]
            )
        return AdapterStatus(
            adapter_id=adapter_id,
            manifest_digest=manifest.digest(),
            observed_at=utc_now(),
            platform=platform,
            supported=supported,
            installed=installed,
            healthy=healthy,
            source=source,
            version=version or (record.version if record else None),
            revision=record.revision if record and source == "managed" else None,
            entrypoints=[*entrypoints, *[path for path in requirement_paths if path]],
            observed_identity_sha256=observed_identity_sha256,
            conformant_operations=conformant_operations,
            declared_capabilities=manifest.capabilities,
            available_capabilities=available_capabilities,
            checks=checks,
            blockers=blockers,
        )

    def all_statuses(self, *, kind: AdapterKind | None = None) -> list[AdapterStatus]:
        return [
            self.status(item.adapter_id) for item in self.registry.all() if kind is None or item.kind == kind
        ]

    def _requirement_observations(
        self,
        manifest: AdapterManifest,
        platform: str,
    ) -> tuple[list[str | None], list[str | None]]:
        paths: list[str | None] = []
        identities: list[str | None] = []
        for requirement in manifest.requirements:
            path: str | None = None
            if requirement.managed_adapter_id is not None:
                dependency = self.registry.get(requirement.managed_adapter_id)
                record = self._installed_record(dependency)
                if record is not None:
                    names = {
                        Path(name).name.casefold()
                        for name in platform_values(requirement.executable_names, platform) or []
                    }
                    path = next(
                        (
                            candidate
                            for candidate in self._managed_entrypoints(record)
                            if Path(candidate).name.casefold() in names
                        ),
                        None,
                    )
            if path is None:
                path = _which_probe(requirement, platform)
            paths.append(path)
            if path is None:
                identities.append(None)
                continue
            try:
                identities.append(observed_tool_identity_digest([path]))
            except (OSError, AdapterRegistryError):
                identities.append(None)
        return paths, identities

    def resolve(
        self,
        required_capabilities: list[str],
        *,
        kind: AdapterKind | None = None,
        max_execution_class: ExecutionClass | None = None,
    ) -> AdapterSelection:
        required = sorted(set(required_capabilities))
        if not required:
            raise ValueError("at least one required capability is required")
        if len(required) > 64:
            raise ValueError("adapter resolution accepts at most 64 distinct capabilities")
        if self.registry.capability_execution_classes is None:
            raise AdapterRegistryError("adapter resolution requires capability execution classes")
        candidates: list[tuple[AdapterManifest, AdapterStatus]] = []
        candidate_capabilities: dict[str, set[str]] = {}
        for manifest in self.registry.all():
            if kind is not None and manifest.kind != kind:
                continue
            if (
                manifest.kind == AdapterKind.KNOWLEDGE
                and max_execution_class is not None
                and EXECUTION_CLASS_RANK[manifest.max_execution_class]
                > EXECUTION_CLASS_RANK[max_execution_class]
            ):
                continue
            resolution_capabilities = _resolution_capabilities(manifest, max_execution_class)
            relevant_capabilities = resolution_capabilities.intersection(required)
            if not relevant_capabilities:
                continue
            status = self.status(manifest.adapter_id)
            locally_resolvable = (manifest.kind == AdapterKind.KNOWLEDGE and status.healthy) or (
                manifest.kind == AdapterKind.TOOL
                and status.installed
                and status.observed_identity_sha256 is not None
            )
            if status.supported and (locally_resolvable or manifest.provisioner is not None):
                candidates.append((manifest, status))
                candidate_capabilities[manifest.adapter_id] = relevant_capabilities
        bits = {capability: 1 << index for index, capability in enumerate(required)}
        states: dict[int, tuple[tuple[AdapterManifest, AdapterStatus], ...]] = {0: ()}
        for pair in candidates:
            coverage = 0
            for capability in candidate_capabilities[pair[0].adapter_id]:
                coverage |= bits.get(capability, 0)
            updated = dict(states)
            for mask, existing_selection in states.items():
                combined_mask = mask | coverage
                proposed = (*existing_selection, pair)
                incumbent = updated.get(combined_mask)
                if incumbent is None or _selection_cost(
                    proposed,
                    candidate_capabilities,
                ) < _selection_cost(incumbent, candidate_capabilities):
                    updated[combined_mask] = proposed
            states = updated
        covered, selected_tuple = min(
            states.items(),
            key=lambda item: (
                -item[0].bit_count(),
                *_selection_cost(item[1], candidate_capabilities),
            ),
        )
        selected = list(selected_tuple)
        uncovered = {capability for capability, bit in bits.items() if not covered & bit}
        ready = [
            manifest.adapter_id
            for manifest, status in selected
            if status.healthy
            and (
                manifest.kind == AdapterKind.KNOWLEDGE
                or candidate_capabilities[manifest.adapter_id].issubset(status.available_capabilities)
            )
        ]
        provision = [
            manifest.adapter_id
            for manifest, status in selected
            if not status.installed
            or (manifest.kind == AdapterKind.KNOWLEDGE and not status.healthy)
            or (manifest.kind == AdapterKind.TOOL and status.observed_identity_sha256 is None)
        ]
        conformance = [
            manifest.adapter_id
            for manifest, status in selected
            if manifest.kind == AdapterKind.TOOL
            and status.installed
            and status.observed_identity_sha256 is not None
            and manifest.adapter_id not in ready
        ]
        reasons = [
            (
                f"{manifest.adapter_id}: ready"
                if manifest.adapter_id in ready
                else (
                    f"{manifest.adapter_id}: conformance required"
                    if manifest.adapter_id in conformance
                    else f"{manifest.adapter_id}: provision required"
                )
            )
            for manifest, status in selected
        ]
        if uncovered:
            reasons.append(f"uncovered: {', '.join(sorted(uncovered))}")
        return AdapterSelection(
            required_capabilities=required,
            selected_adapters=[manifest.adapter_id for manifest, _ in selected],
            ready_adapters=ready,
            provisioning_required=provision,
            conformance_required=conformance,
            uncovered_capabilities=sorted(uncovered),
            complete=not uncovered,
            ready=not uncovered and not provision and not conformance,
            reasons=reasons,
        )

    def search_knowledge(
        self,
        adapter_id: str,
        query: str,
        *,
        limit: int = 20,
        max_files: int = 5_000,
        max_total_bytes: int = 268_435_456,
    ) -> list[KnowledgeSearchHit]:
        if not query.strip():
            raise ValueError("knowledge search query must not be empty")
        if limit < 1 or limit > 100:
            raise ValueError("limit must be between 1 and 100")
        manifest = self.registry.get(adapter_id)
        if manifest.kind != AdapterKind.KNOWLEDGE:
            raise ValueError("knowledge search requires a knowledge adapter")
        status = self.status(adapter_id)
        if not status.healthy or not status.revision:
            raise AdapterRegistryError(f"knowledge adapter is not ready: {adapter_id}")
        root = self._content_dir(adapter_id)
        paths: dict[str, Path] = {}
        for pattern in manifest.search_globs:
            for path in root.glob(pattern):
                if path.is_file() and not path.is_symlink():
                    paths[path.relative_to(root).as_posix()] = path
                    if len(paths) > max_files:
                        raise AdapterRegistryError("knowledge search exceeds file-count limit")
        query_text = query.strip()
        if isinstance(manifest.provisioner, MitreCweProvisioner):
            cwe_id = re.fullmatch(r"cwe-([1-9][0-9]{0,5})", query_text, flags=re.IGNORECASE)
            if cwe_id is not None:
                query_text = f'<Weakness ID="{cwe_id.group(1)}"'
        needle = query_text.casefold()
        scanned = 0
        hits: list[KnowledgeSearchHit] = []
        for relative, path in sorted(paths.items()):
            size = path.stat().st_size
            scanned += size
            if scanned > max_total_bytes:
                raise AdapterRegistryError("knowledge search exceeds byte limit")
            with path.open("rb") as handle:
                for line_number, raw_line in enumerate(handle, start=1):
                    if len(raw_line) > 65_536:
                        raw_line = raw_line[:65_536]
                    line = raw_line.decode("utf-8", errors="replace")
                    if needle not in line.casefold():
                        continue
                    hits.append(
                        KnowledgeSearchHit(
                            adapter_id=adapter_id,
                            revision=status.revision,
                            relative_path=relative,
                            line=line_number,
                            snippet=line.strip()[:1_000],
                        )
                    )
                    if len(hits) >= limit:
                        return hits
        return hits

    def read_knowledge(
        self,
        adapter_id: str,
        relative_path: str,
        *,
        start_line: int = 1,
        line_count: int = 80,
        max_bytes: int = 131_072,
    ) -> KnowledgeExcerpt:
        if start_line < 1 or line_count < 1 or line_count > 200:
            raise ValueError("knowledge excerpt requires start_line >= 1 and line_count between 1 and 200")
        manifest = self.registry.get(adapter_id)
        if manifest.kind != AdapterKind.KNOWLEDGE:
            raise ValueError("knowledge excerpts require a knowledge adapter")
        status = self.status(adapter_id)
        if not status.healthy or not status.revision:
            raise AdapterRegistryError(f"knowledge adapter is not ready: {adapter_id}")
        root = self._content_dir(adapter_id)
        relative = Path(relative_path)
        if relative.is_absolute() or ".." in relative.parts:
            raise AdapterRegistryError("knowledge path must be contained and relative")
        path = (root / relative).resolve()
        if root not in path.parents or not path.is_file() or path.is_symlink():
            raise AdapterRegistryError("knowledge path is not a regular managed file")
        allowed = any(relative.match(pattern) for pattern in manifest.search_globs)
        if not allowed:
            raise AdapterRegistryError("knowledge path is outside the adapter search contract")
        selected: list[str] = []
        byte_length = 0
        truncated = False
        with path.open("rb") as handle:
            for line_number, raw_line in enumerate(handle, start=1):
                if line_number < start_line:
                    continue
                if len(selected) >= line_count:
                    break
                if byte_length + len(raw_line) > max_bytes:
                    truncated = True
                    break
                byte_length += len(raw_line)
                selected.append(raw_line.decode("utf-8", errors="replace"))
        end_line = start_line + max(len(selected) - 1, 0)
        return KnowledgeExcerpt(
            adapter_id=adapter_id,
            revision=status.revision,
            relative_path=relative.as_posix(),
            start_line=start_line,
            end_line=end_line,
            text="".join(selected),
            truncated=truncated,
        )

    def _matching_conformance_reports(
        self,
        manifest: AdapterManifest,
        *,
        tool_version: str | None,
        observed_identity_sha256: str | None,
        requirement_identity_sha256: list[str | None],
        entrypoints: list[str],
    ) -> list[AdapterConformanceReport]:
        if manifest.kind != AdapterKind.TOOL or observed_identity_sha256 is None:
            return []
        try:
            directory = self._conformance_adapter_dir(manifest.adapter_id, create=False)
        except AdapterRegistryError:
            return []
        if not directory.is_dir() or directory.is_symlink():
            return []

        reports: list[AdapterConformanceReport] = []
        manifest_digest = manifest.digest()
        for operation in manifest.operations:
            path = directory / f"{operation.operation_id}.json"
            try:
                if path.is_symlink() or not path.is_file() or path.stat().st_size > 1_048_576:
                    continue
                report = AdapterConformanceReport.model_validate_json(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, ValidationError, ValueError):
                continue
            if (
                report.adapter_id != manifest.adapter_id
                or report.operation_id != operation.operation_id
                or report.operation_version != operation.operation_version
                or report.manifest_digest != manifest_digest
                or report.operation_contract_digest != operation.digest()
                or (tool_version is not None and report.tool_version != tool_version)
                or report.observed_identity_sha256 != observed_identity_sha256
                or report.requirement_identity_sha256 != requirement_identity_sha256
            ):
                continue
            if self.conformance_verifier is None or not self.conformance_verifier(
                operation,
                report,
                entrypoints,
            ):
                continue
            reports.append(report)
        return reports

    def _conformance_adapter_dir(self, adapter_id: str, *, create: bool) -> Path:
        root = self.managed_root / ".conformance"
        if create:
            root.mkdir(parents=True, exist_ok=True)
        if root.is_symlink() or (root.exists() and not root.is_dir()):
            raise AdapterRegistryError("adapter conformance root must be a real directory")
        directory = root / adapter_id
        if create:
            directory.mkdir(exist_ok=True)
        if directory.is_symlink() or (directory.exists() and not directory.is_dir()):
            raise AdapterRegistryError("adapter conformance directory must be a real directory")
        return directory

    def _adapter_root(self, adapter_id: str) -> Path:
        return self.managed_root / adapter_id

    def _content_dir(self, adapter_id: str) -> Path:
        return self._adapter_root(adapter_id) / "content"

    def _installed_record(self, manifest: AdapterManifest) -> InstalledAdapterRecord | None:
        path = self._adapter_root(manifest.adapter_id) / "installed.json"
        try:
            record = InstalledAdapterRecord.model_validate_json(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, ValidationError, ValueError):
            return None
        if record.adapter_id != manifest.adapter_id or record.manifest_digest != manifest.digest():
            return None
        return record

    def _managed_entrypoints(self, record: InstalledAdapterRecord) -> list[str]:
        content_dir = self._content_dir(record.adapter_id)
        if not content_dir.is_dir() or content_dir.is_symlink():
            return []
        root = content_dir.resolve()
        resolved: list[str] = []
        for relative in record.entrypoints:
            candidate = root / relative
            path = candidate.resolve()
            if candidate.is_symlink() or root not in path.parents or not path.is_file():
                continue
            resolved.append(str(path))
        return resolved


def current_platform() -> str:
    import platform as platform_module

    os_name = platform_module.system().casefold()
    operating_system = {"darwin": "macos", "windows": "windows", "linux": "linux"}.get(os_name)
    if operating_system is None:
        return f"unsupported-{os_name or 'unknown'}"
    machine = platform_module.machine().casefold()
    architecture = {
        "amd64": "x86_64",
        "x86_64": "x86_64",
        "aarch64": "arm64",
        "arm64": "arm64",
    }.get(machine, machine or "unknown")
    return f"{operating_system}-{architecture}"


def platform_values(mapping: dict[str, list[str]], platform: str) -> list[str] | None:
    for key in (platform, platform.split("-", 1)[0], "any"):
        if key in mapping:
            return mapping[key]
    return None


def _platform_value(values: list[str], platform: str) -> str | None:
    for key in (platform, platform.split("-", 1)[0], "any"):
        if key in values:
            return key
    return None


def _which_probe(probe: ProbeDefinition, platform: str) -> str | None:
    for executable in platform_values(probe.executable_names, platform) or []:
        path = shutil.which(executable)
        if path:
            return str(Path(path).resolve())
    return None


def _report_check_ok(report: AdapterConformanceReport, name: str) -> bool:
    return any(check.name == name and check.ok for check in report.checks)


def _system_entrypoints(manifest: AdapterManifest, executable: Path, platform: str) -> list[str]:
    definition = manifest.provisioner
    if isinstance(definition, (GitHubReleaseProvisioner, AdoptiumProvisioner)):
        relatives = platform_values(definition.entrypoints, platform) or []
        if relatives and Path(relatives[0]).name.casefold() == executable.name.casefold():
            root = executable.resolve()
            for _ in Path(relatives[0]).parts:
                root = root.parent
            resolved = [str((root / relative).resolve()) for relative in relatives]
            existing = [path for path in resolved if Path(path).is_file()]
            if existing:
                return existing
    return [str(executable.resolve())]


def _probe_file_version(
    executable: Path,
    probe: ProbeDefinition,
    *,
    name: str,
) -> tuple[str | None, AdapterCheck]:
    if not probe.version_file:
        raise AdapterRegistryError("passive status only supports file-backed version probes")
    try:
        property_path = executable.resolve().parent / probe.version_file
        version = _read_property(property_path, probe.version_property or "")
        detail = f"{version or 'missing'} from {property_path}"
    except (OSError, UnicodeError) as exc:
        return None, AdapterCheck(name=name, ok=False, detail=type(exc).__name__)
    ok = version is not None and _version_matches_probe(version, probe)
    if probe.minimum_version:
        detail += f"; minimum={probe.minimum_version}"
    return version, AdapterCheck(name=name, ok=ok, detail=detail)


def _version_matches_probe(version: str, probe: ProbeDefinition) -> bool:
    if re.fullmatch(r"[0-9]+(?:\.[0-9]+)*(?:[-+][A-Za-z0-9.-]+)?", version) is None:
        return False
    if probe.minimum_version and _version_key(version) < _version_key(probe.minimum_version):
        return False
    return bool(version)


def _read_property(path: Path, key: str) -> str | None:
    if not path.is_file() or path.is_symlink():
        return None
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith(f"{key}="):
            return line.split("=", 1)[1].strip() or None
    return None


def version_key(value: str) -> tuple[int, ...]:
    return _version_key(value)


def observed_tool_identity_digest(entrypoints: list[str]) -> str:
    if not entrypoints:
        raise AdapterRegistryError("tool identity requires at least one entrypoint")
    observed: list[dict[str, str | int]] = []
    for value in entrypoints:
        path = Path(value)
        if path.is_symlink():
            raise AdapterRegistryError("tool identity entrypoints cannot be symbolic links")
        try:
            resolved = path.resolve(strict=True)
            if not resolved.is_file():
                raise AdapterRegistryError("tool identity entrypoints must be regular files")
            stat = resolved.stat()
            digest = hashlib.sha256()
            with resolved.open("rb") as handle:
                while chunk := handle.read(1_048_576):
                    digest.update(chunk)
        except OSError as exc:
            raise AdapterRegistryError("tool identity could not be read") from exc
        observed.append(
            {
                "path": str(resolved),
                "size": stat.st_size,
                "sha256": digest.hexdigest(),
            }
        )
    return stable_digest(
        {
            "schema_version": "1.0",
            "entrypoints": observed,
        }
    )


def content_tree_digest(
    root: Path,
    *,
    max_entries: int = 100_000,
    max_bytes: int = 8_589_934_592,
) -> str:
    if not root.is_dir() or root.is_symlink():
        raise AdapterRegistryError("managed content root must be a real directory")
    digest = hashlib.sha256()
    digest.update(b"white-hat-agent-content-tree\0\x01")
    entries = 0
    byte_length = 0
    for current, directories, files in os.walk(root, topdown=True, followlinks=False):
        directories.sort()
        files.sort()
        current_path = Path(current)
        for directory in directories:
            path = current_path / directory
            if path.is_symlink():
                raise AdapterRegistryError("managed content contains a symbolic link")
            entries += 1
            if entries > max_entries:
                raise AdapterRegistryError("managed content exceeds entry-count limit")
            relative = path.relative_to(root).as_posix().encode()
            digest.update(b"D")
            digest.update(len(relative).to_bytes(8, "big"))
            digest.update(relative)
        for file_name in files:
            path = current_path / file_name
            if path.is_symlink() or not path.is_file():
                raise AdapterRegistryError("managed content contains a link or special file")
            entries += 1
            if entries > max_entries:
                raise AdapterRegistryError("managed content exceeds entry-count limit")
            relative = path.relative_to(root).as_posix().encode()
            file_digest = hashlib.sha256()
            file_bytes = 0
            with path.open("rb") as handle:
                while chunk := handle.read(1_048_576):
                    file_bytes += len(chunk)
                    byte_length += len(chunk)
                    if byte_length > max_bytes:
                        raise AdapterRegistryError("managed content exceeds byte limit")
                    file_digest.update(chunk)
            digest.update(b"F")
            digest.update(len(relative).to_bytes(8, "big"))
            digest.update(relative)
            digest.update(file_bytes.to_bytes(8, "big"))
            digest.update(file_digest.digest())
    digest.update(b"E")
    digest.update(entries.to_bytes(8, "big"))
    digest.update(byte_length.to_bytes(8, "big"))
    return digest.hexdigest()


def _version_key(value: str) -> tuple[int, ...]:
    numbers = tuple(int(item) for item in re.findall(r"\d+", value))
    return numbers or (0,)


def _terms(value: str) -> set[str]:
    return {item for item in re.findall(r"[\w.-]+", value.lower(), flags=re.UNICODE) if len(item) > 1}


def _managed_content_limit(manifest: AdapterManifest) -> int:
    if isinstance(
        manifest.provisioner,
        (GitHubReleaseProvisioner, AdoptiumProvisioner, MitreCweProvisioner),
    ):
        return manifest.provisioner.max_install_bytes
    if isinstance(manifest.provisioner, GitCheckoutProvisioner):
        return manifest.provisioner.max_checkout_bytes
    return 8_589_934_592


def _resolution_capabilities(
    manifest: AdapterManifest,
    max_execution_class: ExecutionClass | None,
) -> set[str]:
    if manifest.kind == AdapterKind.KNOWLEDGE:
        return set(manifest.capabilities)
    if not manifest.operations:
        if (
            max_execution_class is None
            or EXECUTION_CLASS_RANK[manifest.max_execution_class] <= EXECUTION_CLASS_RANK[max_execution_class]
        ):
            return set(manifest.capabilities)
        return set()
    return {
        capability
        for operation in manifest.operations
        if max_execution_class is None
        or EXECUTION_CLASS_RANK[operation.execution_class] <= EXECUTION_CLASS_RANK[max_execution_class]
        for capability in operation.capabilities
    }


def _validate_managed_requirement_graph(items: dict[str, AdapterManifest]) -> None:
    edges: dict[str, set[str]] = {adapter_id: set() for adapter_id in items}
    for manifest in items.values():
        for requirement in manifest.requirements:
            dependency_id = requirement.managed_adapter_id
            if dependency_id is None:
                continue
            if dependency_id == manifest.adapter_id:
                raise ValueError(f"adapter {manifest.adapter_id} cannot provide its own runtime requirement")
            dependency = items.get(dependency_id)
            if dependency is None:
                raise ValueError(
                    f"adapter {manifest.adapter_id} references unknown managed requirement: {dependency_id}"
                )
            if dependency.kind != AdapterKind.TOOL or dependency.provisioner is None:
                raise ValueError(f"managed requirement {dependency_id} must be a provisionable tool adapter")
            if dependency.probe is None:
                raise ValueError(f"managed requirement {dependency_id} has no executable probe")
            edges[manifest.adapter_id].add(dependency_id)

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(adapter_id: str) -> None:
        if adapter_id in visiting:
            raise ValueError(f"managed adapter requirements contain a cycle at {adapter_id}")
        if adapter_id in visited:
            return
        visiting.add(adapter_id)
        for dependency_id in sorted(edges[adapter_id]):
            visit(dependency_id)
        visiting.remove(adapter_id)
        visited.add(adapter_id)

    for adapter_id in sorted(items):
        visit(adapter_id)


def _selection_cost(
    selection: tuple[tuple[AdapterManifest, AdapterStatus], ...],
    candidate_capabilities: dict[str, set[str]],
) -> tuple[int, int, int, int, tuple[str, ...]]:
    return (
        sum(not status.healthy for _, status in selection),
        sum(
            manifest.kind == AdapterKind.TOOL
            and status.healthy
            and not candidate_capabilities[manifest.adapter_id].issubset(status.available_capabilities)
            for manifest, status in selection
        ),
        len(selection),
        sum(manifest.priority for manifest, _ in selection),
        tuple(manifest.adapter_id for manifest, _ in selection),
    )
