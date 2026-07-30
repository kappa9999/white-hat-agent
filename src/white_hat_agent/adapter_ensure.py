from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import Field

from .adapter_execution import AdapterExecutionBroker
from .adapter_provisioning import AdapterProvisioner, ProvisionAction
from .adapter_registry import (
    AdapterConformanceCheck,
    AdapterConformanceReport,
    AdapterKind,
    AdapterManager,
    AdapterManifest,
    AdapterRegistryError,
    AdapterSelection,
)
from .knowledge.models import EXECUTION_CLASS_RANK, ExecutionClass, Slug
from .models import Sha256, StrictModel


class AdapterEnsurePhase(StrEnum):
    DEPENDENCY = "dependency"
    PROVISION = "provision"
    CONFORMANCE = "conformance"


class AdapterEnsureOutcome(StrEnum):
    SKIPPED = "skipped"
    UNCHANGED = "unchanged"
    CHANGED = "changed"
    PASSED = "passed"
    FAILED = "failed"


class AdapterEnsureEvent(StrictModel):
    adapter_id: Slug
    phase: AdapterEnsurePhase
    outcome: AdapterEnsureOutcome
    changed: bool = False
    operation_id: Slug | None = None
    detail: str = Field(min_length=1, max_length=2_000)
    plan_digest: Sha256 | None = None
    revision: str | None = None
    content_sha256: Sha256 | None = None


class AdapterEnsureResult(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    requested_capabilities: list[str]
    update_requested: bool
    initial_selection: AdapterSelection
    events: list[AdapterEnsureEvent]
    final_selection: AdapterSelection
    failures: list[str]
    complete: bool
    ready: bool


class AdapterEnsurer:
    """Provision and conform the smallest provider set for concrete capabilities."""

    def __init__(self, manager: AdapterManager, execution: AdapterExecutionBroker) -> None:
        self.manager = manager
        self.execution = execution
        self.provisioner = AdapterProvisioner(manager)

    def ensure(
        self,
        required_capabilities: list[str],
        *,
        kind: AdapterKind | None = None,
        max_execution_class: ExecutionClass | None = None,
        update: bool = True,
    ) -> AdapterEnsureResult:
        required = sorted(set(required_capabilities))
        initial = self.manager.resolve(
            required,
            kind=kind,
            max_execution_class=max_execution_class,
        )
        events: list[AdapterEnsureEvent] = []
        failures: list[str] = []
        for adapter_id in initial.selected_adapters:
            manifest = self.manager.registry.get(adapter_id)
            relevant = _relevant_capabilities(manifest, required, max_execution_class)
            try:
                self._ensure_adapter(
                    manifest,
                    relevant,
                    update=update,
                    events=events,
                )
            except (AdapterRegistryError, OSError, RuntimeError, ValueError) as exc:
                failures.append(_bounded_detail(f"{adapter_id}: {type(exc).__name__}: {exc}"))
        final = self.manager.resolve(
            required,
            kind=kind,
            max_execution_class=max_execution_class,
        )
        return AdapterEnsureResult(
            requested_capabilities=required,
            update_requested=update,
            initial_selection=initial,
            events=events,
            final_selection=final,
            failures=failures,
            complete=final.complete,
            ready=final.ready and not failures,
        )

    def _ensure_adapter(
        self,
        manifest: AdapterManifest,
        relevant_capabilities: set[str],
        *,
        update: bool,
        events: list[AdapterEnsureEvent],
    ) -> None:
        requirement_paths, _ = self.manager._requirement_observations(
            manifest,
            self.manager.status(manifest.adapter_id).platform,
        )
        for index, requirement in enumerate(manifest.requirements):
            dependency_id = requirement.managed_adapter_id
            if dependency_id is None or requirement_paths[index] is not None:
                continue
            self._ensure_dependency(
                dependency_id,
                consumer_id=manifest.adapter_id,
                events=events,
            )

        status = self.manager.status(manifest.adapter_id)
        needs_provision = (
            not status.installed
            or (manifest.kind == AdapterKind.KNOWLEDGE and not status.healthy)
            or (manifest.kind == AdapterKind.TOOL and status.observed_identity_sha256 is None)
        )
        changed = False
        if update or needs_provision:
            changed = self._provision(manifest, events=events)
        elif manifest.provisioner is None and needs_provision:
            raise AdapterRegistryError(f"adapter has no trusted provisioner: {manifest.adapter_id}")
        else:
            events.append(
                AdapterEnsureEvent(
                    adapter_id=manifest.adapter_id,
                    phase=AdapterEnsurePhase.PROVISION,
                    outcome=AdapterEnsureOutcome.SKIPPED,
                    detail="installed provider retained because update was not requested",
                )
            )

        if manifest.kind != AdapterKind.TOOL or not manifest.operations:
            return
        operations = [
            operation
            for operation in manifest.operations
            if relevant_capabilities.intersection(operation.capabilities)
        ]
        for operation in operations:
            status = self.manager.status(manifest.adapter_id)
            if not changed and operation.operation_id in status.conformant_operations:
                events.append(
                    AdapterEnsureEvent(
                        adapter_id=manifest.adapter_id,
                        operation_id=operation.operation_id,
                        phase=AdapterEnsurePhase.CONFORMANCE,
                        outcome=AdapterEnsureOutcome.SKIPPED,
                        detail="current identity already has a passing conformance report",
                    )
                )
                continue
            report = self._conform(manifest, operation.operation_id, events=events)
            failed_dependencies = _failed_managed_requirements(manifest, report.checks)
            if not report.passed and failed_dependencies:
                for dependency_id in failed_dependencies:
                    self._ensure_dependency(
                        dependency_id,
                        consumer_id=manifest.adapter_id,
                        events=events,
                    )
                report = self._conform(manifest, operation.operation_id, events=events)
            if not report.passed:
                failed_checks = ", ".join(check.name for check in report.checks if not check.ok)
                raise AdapterRegistryError(
                    f"conformance failed for {manifest.adapter_id}:{operation.operation_id}: "
                    f"{failed_checks or 'unknown check'}"
                )

    def _ensure_dependency(
        self,
        adapter_id: str,
        *,
        consumer_id: str,
        events: list[AdapterEnsureEvent],
    ) -> None:
        dependency = self.manager.registry.get(adapter_id)
        events.append(
            AdapterEnsureEvent(
                adapter_id=adapter_id,
                phase=AdapterEnsurePhase.DEPENDENCY,
                outcome=AdapterEnsureOutcome.UNCHANGED,
                detail=f"resolving managed runtime required by {consumer_id}",
            )
        )
        self._provision(dependency, events=events)

    def _provision(
        self,
        manifest: AdapterManifest,
        *,
        events: list[AdapterEnsureEvent],
    ) -> bool:
        if manifest.provisioner is None:
            status = self.manager.status(manifest.adapter_id)
            if status.installed:
                events.append(
                    AdapterEnsureEvent(
                        adapter_id=manifest.adapter_id,
                        phase=AdapterEnsurePhase.PROVISION,
                        outcome=AdapterEnsureOutcome.UNCHANGED,
                        detail="system provider has no managed update channel",
                    )
                )
                return False
            raise AdapterRegistryError(f"adapter has no trusted provisioner: {manifest.adapter_id}")
        try:
            plan = self.provisioner.plan(manifest.adapter_id)
            result = self.provisioner.provision(plan)
        except (AdapterRegistryError, OSError, RuntimeError, ValueError) as exc:
            events.append(
                AdapterEnsureEvent(
                    adapter_id=manifest.adapter_id,
                    phase=AdapterEnsurePhase.PROVISION,
                    outcome=AdapterEnsureOutcome.FAILED,
                    detail=_bounded_detail(f"{type(exc).__name__}: {exc}"),
                )
            )
            raise
        installed = result.installed
        changed = result.action != ProvisionAction.NONE and result.changed
        events.append(
            AdapterEnsureEvent(
                adapter_id=manifest.adapter_id,
                phase=AdapterEnsurePhase.PROVISION,
                outcome=(AdapterEnsureOutcome.CHANGED if changed else AdapterEnsureOutcome.UNCHANGED),
                changed=changed,
                detail=(
                    f"{result.action.value} completed at {plan.revision}"
                    if changed
                    else f"already current at {plan.revision}"
                ),
                plan_digest=plan.digest(),
                revision=plan.revision,
                content_sha256=installed.content_sha256 if installed else None,
            )
        )
        return changed

    def _conform(
        self,
        manifest: AdapterManifest,
        operation_id: str,
        *,
        events: list[AdapterEnsureEvent],
    ) -> AdapterConformanceReport:
        try:
            report = self.execution.conform(manifest.adapter_id, operation_id)
        except (AdapterRegistryError, OSError, RuntimeError, ValueError) as exc:
            events.append(
                AdapterEnsureEvent(
                    adapter_id=manifest.adapter_id,
                    operation_id=operation_id,
                    phase=AdapterEnsurePhase.CONFORMANCE,
                    outcome=AdapterEnsureOutcome.FAILED,
                    detail=_bounded_detail(f"{type(exc).__name__}: {exc}"),
                )
            )
            raise
        events.append(
            AdapterEnsureEvent(
                adapter_id=manifest.adapter_id,
                operation_id=operation_id,
                phase=AdapterEnsurePhase.CONFORMANCE,
                outcome=(AdapterEnsureOutcome.PASSED if report.passed else AdapterEnsureOutcome.FAILED),
                detail=(
                    f"fixture {report.fixture_id} passed"
                    if report.passed
                    else "fixed conformance checks failed"
                ),
            )
        )
        return report


def _relevant_capabilities(
    manifest: AdapterManifest,
    required: list[str],
    max_execution_class: ExecutionClass | None,
) -> set[str]:
    if manifest.kind == AdapterKind.KNOWLEDGE:
        return set(manifest.capabilities).intersection(required)
    allowed: set[str] = set()
    for operation in manifest.operations:
        if (
            max_execution_class is not None
            and EXECUTION_CLASS_RANK[operation.execution_class] > EXECUTION_CLASS_RANK[max_execution_class]
        ):
            continue
        allowed.update(operation.capabilities)
    return allowed.intersection(required)


def _failed_managed_requirements(
    manifest: AdapterManifest,
    checks: list[AdapterConformanceCheck],
) -> list[str]:
    failed_names = {check.name for check in checks if not check.ok}
    dependencies: list[str] = []
    for index, requirement in enumerate(manifest.requirements, start=1):
        if f"requirement-{index}-version" in failed_names and requirement.managed_adapter_id is not None:
            dependencies.append(requirement.managed_adapter_id)
    return list(dict.fromkeys(dependencies))


def _bounded_detail(value: str) -> str:
    return value.strip()[:2_000] or "unspecified adapter failure"
