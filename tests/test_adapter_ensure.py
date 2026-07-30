from __future__ import annotations

from pathlib import Path

from white_hat_agent.adapter_ensure import (
    AdapterEnsureEvent,
    AdapterEnsureOutcome,
    AdapterEnsurePhase,
    AdapterEnsurer,
)
from white_hat_agent.adapter_registry import (
    AdapterConformanceCheck,
    AdapterConformanceReport,
    AdapterKind,
    AdapterLicense,
    AdapterManifest,
    AdapterOperationBinding,
    AdapterSelection,
    AdapterStatus,
    GitHubReleaseProvisioner,
    OperationResourceLimits,
    ProbeDefinition,
)
from white_hat_agent.knowledge.models import ExecutionClass
from white_hat_agent.models import ExecutionMode, utc_now


def _license() -> AdapterLicense:
    return AdapterLicense(
        name="Apache-2.0",
        url="https://example.test/license",
        attribution="Fixture provider",
    )


def _manifests() -> tuple[AdapterManifest, AdapterManifest]:
    runtime = AdapterManifest(
        adapter_id="fixture-jdk",
        title="Fixture JDK",
        description="Managed runtime fixture",
        kind=AdapterKind.TOOL,
        provider="Fixture",
        provider_url="https://example.test/jdk",
        license=_license(),
        capabilities=["runtime.java"],
        platforms=["any"],
        probe=ProbeDefinition(
            executable_names={"any": ["java"]},
            version_args=["-version"],
            version_pattern=r'version "(?P<version>[0-9]+(?:\.[0-9]+)*)',
        ),
        provisioner=GitHubReleaseProvisioner(
            repository="example/jdk",
            asset_patterns={"any": [r"^jdk\.zip$"]},
            entrypoints={"any": ["bin/java"]},
            max_download_bytes=1_000_000,
            max_install_bytes=2_000_000,
        ),
        updated_at=utc_now(),
    )
    requirement = ProbeDefinition(
        executable_names={"any": ["java"]},
        version_args=["-version"],
        version_pattern=r'version "(?P<version>[0-9]+(?:\.[0-9]+)*)',
        minimum_version="21",
        managed_adapter_id=runtime.adapter_id,
    )
    tool = AdapterManifest(
        adapter_id="fixture-re",
        title="Fixture reverse engineering tool",
        description="Fixture dependency fallback tool",
        kind=AdapterKind.TOOL,
        provider="Fixture",
        provider_url="https://example.test/re",
        license=_license(),
        capabilities=["binary.static-inspect"],
        modes=[ExecutionMode.OFFLINE],
        max_execution_class=ExecutionClass.ANALYSIS,
        platforms=["any"],
        probe=ProbeDefinition(
            executable_names={"any": ["fixture-re"]},
            version_args=["--version"],
            version_pattern=r"(?P<version>[0-9]+(?:\.[0-9]+)+)",
        ),
        requirements=[requirement],
        operations=[
            AdapterOperationBinding(
                operation_id="fixture.native-map",
                operation_version="1.0.0",
                capabilities=["binary.static-inspect"],
                execution_class=ExecutionClass.ANALYSIS,
                modes=[ExecutionMode.OFFLINE],
                input_types=["artifact/file"],
                output_types=["surface/native-code-map"],
                conformance_suite_id="fixture-map-v1",
                limits=OperationResourceLimits(
                    max_input_bytes=1_000_000,
                    max_output_bytes=1_000_000,
                    max_files=10,
                    max_records=100,
                    wall_seconds=30,
                    cpu_seconds=30,
                    memory_mib=512,
                    max_processes=4,
                ),
            )
        ],
        provisioner=GitHubReleaseProvisioner(
            repository="example/re",
            asset_patterns={"any": [r"^re\.zip$"]},
            entrypoints={"any": ["fixture-re"]},
            max_download_bytes=1_000_000,
            max_install_bytes=2_000_000,
        ),
        updated_at=utc_now(),
    )
    return runtime, tool


class _Registry:
    def __init__(self, manifests: list[AdapterManifest]) -> None:
        self.items = {manifest.adapter_id: manifest for manifest in manifests}

    def get(self, adapter_id: str) -> AdapterManifest:
        return self.items[adapter_id]


class _Manager:
    def __init__(self, runtime: AdapterManifest, tool: AdapterManifest, tmp_path: Path) -> None:
        self.registry = _Registry([runtime, tool])
        self.runtime = runtime
        self.tool = tool
        self.runtime_installed = False
        self.conformed = False
        self.system_java = str(tmp_path / "system-java")
        self.managed_java = str(tmp_path / "managed-java")

    def resolve(self, required, *, kind=None, max_execution_class=None) -> AdapterSelection:
        del kind, max_execution_class
        ready = [self.tool.adapter_id] if self.conformed else []
        return AdapterSelection(
            required_capabilities=sorted(set(required)),
            selected_adapters=[self.tool.adapter_id],
            ready_adapters=ready,
            provisioning_required=[],
            conformance_required=[] if self.conformed else [self.tool.adapter_id],
            uncovered_capabilities=[],
            complete=True,
            ready=self.conformed,
            reasons=[f"{self.tool.adapter_id}: " + ("ready" if self.conformed else "conformance required")],
        )

    def status(self, adapter_id: str) -> AdapterStatus:
        manifest = self.registry.get(adapter_id)
        if adapter_id == self.runtime.adapter_id:
            return AdapterStatus(
                adapter_id=adapter_id,
                manifest_digest=manifest.digest(),
                observed_at=utc_now(),
                platform="linux-x86_64",
                supported=True,
                installed=self.runtime_installed,
                healthy=self.runtime_installed,
                source="managed" if self.runtime_installed else None,
                version="21.0.12" if self.runtime_installed else None,
                entrypoints=[self.managed_java] if self.runtime_installed else [],
            )
        return AdapterStatus(
            adapter_id=adapter_id,
            manifest_digest=manifest.digest(),
            observed_at=utc_now(),
            platform="linux-x86_64",
            supported=True,
            installed=True,
            healthy=self.conformed,
            source="system",
            version="1.0.0",
            entrypoints=["/fixture/re", self.managed_java if self.runtime_installed else self.system_java],
            observed_identity_sha256="a" * 64,
            conformant_operations=["fixture.native-map"] if self.conformed else [],
            available_capabilities=["binary.static-inspect"] if self.conformed else [],
        )

    def _requirement_observations(self, manifest, platform):
        del platform
        if not manifest.requirements:
            return [], []
        path = self.managed_java if self.runtime_installed else self.system_java
        return [path], ["b" * 64]


class _Execution:
    def __init__(self, manager: _Manager) -> None:
        self.manager = manager
        self.calls = 0

    def conform(self, adapter_id: str, operation_id: str) -> AdapterConformanceReport:
        self.calls += 1
        passed = self.manager.runtime_installed
        if passed:
            self.manager.conformed = True
        operation = self.manager.tool.operations[0]
        now = utc_now()
        return AdapterConformanceReport(
            adapter_id=adapter_id,
            operation_id=operation_id,
            operation_version=operation.operation_version,
            manifest_digest=self.manager.tool.digest(),
            operation_contract_digest=operation.digest(),
            observed_identity_sha256="a" * 64,
            requirement_identity_sha256=["b" * 64],
            tool_payload_sha256="c" * 64,
            tool_version="1.0.0",
            driver_id="fixture-driver",
            driver_version="1.0.0",
            sandbox_profile_sha256="d" * 64,
            fixture_id=operation.conformance_suite_id,
            fixture_sha256="e" * 64,
            started_at=now,
            finished_at=now,
            passed=passed,
            checks=[
                AdapterConformanceCheck(name="tool-version", ok=True, detail="version=1.0.0"),
                AdapterConformanceCheck(
                    name="requirement-1-version",
                    ok=passed,
                    detail="version=21" if passed else "version=17",
                ),
            ],
        )


def test_ensure_retries_failed_host_runtime_with_managed_dependency(tmp_path, monkeypatch) -> None:
    runtime, tool = _manifests()
    manager = _Manager(runtime, tool, tmp_path)
    execution = _Execution(manager)
    ensurer = AdapterEnsurer(manager, execution)  # type: ignore[arg-type]

    def fake_provision(manifest, *, events):
        changed = manifest.adapter_id == runtime.adapter_id
        if changed:
            manager.runtime_installed = True
        events.append(
            AdapterEnsureEvent(
                adapter_id=manifest.adapter_id,
                phase=AdapterEnsurePhase.PROVISION,
                outcome=(AdapterEnsureOutcome.CHANGED if changed else AdapterEnsureOutcome.UNCHANGED),
                changed=changed,
                detail="fixture provision",
            )
        )
        return changed

    monkeypatch.setattr(ensurer, "_provision", fake_provision)

    result = ensurer.ensure(["binary.static-inspect"])

    assert result.ready
    assert result.failures == []
    assert execution.calls == 2
    assert manager.runtime_installed
    assert [event.outcome for event in result.events if event.phase == AdapterEnsurePhase.CONFORMANCE] == [
        AdapterEnsureOutcome.FAILED,
        AdapterEnsureOutcome.PASSED,
    ]
    assert any(
        event.adapter_id == runtime.adapter_id and event.phase == AdapterEnsurePhase.DEPENDENCY
        for event in result.events
    )
