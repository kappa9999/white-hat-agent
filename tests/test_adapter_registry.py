from __future__ import annotations

import io
import json
import lzma
import shutil
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest
import yaml

from white_hat_agent import adapter_provisioning
from white_hat_agent.adapter_provisioning import (
    AdapterProvisioner,
    AdapterProvisionPlan,
    CweCatalogIdentity,
    ProvisionAction,
    ResolvedArtifact,
    ResolvedOciImage,
    ResolvedOciLayer,
    _adoptium_api_url,
    _materialize_assets,
    _validate_cwe_snapshot,
)
from white_hat_agent.adapter_registry import (
    AdapterCatalogManifest,
    AdapterConformanceCheck,
    AdapterConformanceReport,
    AdapterKind,
    AdapterLicense,
    AdapterManager,
    AdapterManifest,
    AdapterOperationBinding,
    AdapterRegistry,
    AdapterRegistryError,
    AdapterStatus,
    AdoptiumProvisioner,
    GitHubReleaseProvisioner,
    InstalledAdapterRecord,
    MitreCweProvisioner,
    OciImageProvisioner,
    OperationResourceLimits,
    ProbeDefinition,
    content_tree_digest,
    current_platform,
    observed_tool_identity_digest,
)
from white_hat_agent.knowledge.models import ExecutionClass
from white_hat_agent.models import ExecutionMode, utc_now

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def _accept_fixture_conformance(*_args) -> bool:
    return True


def _license() -> AdapterLicense:
    return AdapterLicense(
        name="Apache-2.0",
        url="https://example.test/license",
        attribution="Fixture provider",
    )


def _tool_manifest(
    adapter_id: str = "fixture-tool",
    *,
    capabilities: list[str] | None = None,
    provisioner: GitHubReleaseProvisioner | None = None,
) -> AdapterManifest:
    declared_capabilities = capabilities or ["artifact.inspect"]
    return AdapterManifest(
        adapter_id=adapter_id,
        title="Fixture tool",
        description="Fixture reverse engineering tool",
        kind=AdapterKind.TOOL,
        provider="Fixture",
        provider_url="https://example.test/tool",
        license=_license(),
        capabilities=declared_capabilities,
        modes=[ExecutionMode.OFFLINE],
        max_execution_class=ExecutionClass.ANALYSIS,
        platforms=["any"],
        probe=ProbeDefinition(
            executable_names={"any": ["fixture-tool"]},
            version_args=["--version"],
            version_pattern=r"Python (?P<version>[0-9]+(?:\.[0-9]+)+)",
        ),
        operations=[
            AdapterOperationBinding(
                operation_id="inspect",
                operation_version="1.0.0",
                capabilities=declared_capabilities,
                execution_class=ExecutionClass.ANALYSIS,
                modes=[ExecutionMode.OFFLINE],
                input_types=["artifact.file"],
                output_types=["artifact.summary"],
                conformance_suite_id="fixture-inspect",
                limits=OperationResourceLimits(
                    max_input_bytes=1_000_000,
                    max_output_bytes=1_000_000,
                    max_files=10,
                    max_records=1_000,
                    wall_seconds=30,
                    cpu_seconds=30,
                    memory_mib=512,
                    max_processes=4,
                ),
            )
        ],
        provisioner=provisioner,
        updated_at=utc_now(),
    )


def _oci_tool_manifest() -> AdapterManifest:
    provisioner = OciImageProvisioner(
        image="ghcr.io/example/tool",
        release_repository="example/tool",
        platform_map={"linux-x86_64": "linux/amd64"},
        entrypoint=["tool"],
        descriptor_name="oci-image.env",
        max_download_bytes=2_000_000,
        max_install_bytes=4_096,
    )
    return AdapterManifest(
        adapter_id="fixture-oci-tool",
        title="Fixture OCI tool",
        description="Fixture digest-bound OCI tool",
        kind=AdapterKind.TOOL,
        provider="Fixture",
        provider_url="https://github.com/example/tool",
        license=_license(),
        capabilities=["artifact.inspect"],
        modes=[ExecutionMode.OFFLINE],
        max_execution_class=ExecutionClass.ANALYSIS,
        platforms=["linux-x86_64"],
        probe=ProbeDefinition(
            executable_names={"linux-x86_64": ["oci-image.env"]},
            version_args=(),
            version_file="oci-image.env",
            version_property="version",
        ),
        operations=[
            AdapterOperationBinding(
                operation_id="inspect",
                operation_version="1.0.0",
                capabilities=["artifact.inspect"],
                execution_class=ExecutionClass.ANALYSIS,
                modes=[ExecutionMode.OFFLINE],
                input_types=["artifact.file"],
                output_types=["artifact.summary"],
                conformance_suite_id="fixture-inspect",
                limits=OperationResourceLimits(
                    max_input_bytes=1_000_000,
                    max_output_bytes=1_000_000,
                    max_files=10,
                    max_records=1_000,
                    wall_seconds=30,
                    cpu_seconds=30,
                    memory_mib=512,
                    max_processes=4,
                ),
            )
        ],
        provisioner=provisioner,
        updated_at=utc_now(),
    )


def _resolved_oci_image() -> ResolvedOciImage:
    return ResolvedOciImage(
        image="ghcr.io/example/tool",
        tag="v2.0.0",
        platform="linux/amd64",
        index_sha256="a" * 64,
        manifest_sha256="b" * 64,
        config_sha256="c" * 64,
        source_revision="d" * 40,
        compressed_bytes=123,
        entrypoint=["tool"],
        layers=[
            ResolvedOciLayer(
                media_type="application/vnd.oci.image.layer.v1.tar+gzip",
                size=123,
                sha256="e" * 64,
            )
        ],
    )


def _knowledge_manifest(adapter_id: str = "fixture-knowledge") -> AdapterManifest:
    return AdapterManifest(
        adapter_id=adapter_id,
        title="Fixture knowledge",
        description="Fixture machine-readable knowledge",
        kind=AdapterKind.KNOWLEDGE,
        provider="Fixture",
        provider_url="https://example.test/data",
        license=_license(),
        capabilities=["code.search"],
        platforms=["any"],
        provisioner=GitHubReleaseProvisioner(
            repository="example/data",
            asset_patterns={"any": [r"^data\.json$"]},
            max_download_bytes=1_000_000,
            max_install_bytes=1_000_000,
        ),
        search_globs=["*.json"],
        updated_at=utc_now(),
    )


def _runtime_manifest(adapter_id: str = "fixture-jdk") -> AdapterManifest:
    return AdapterManifest(
        adapter_id=adapter_id,
        title="Fixture Java runtime",
        description="Fixture managed Java runtime dependency",
        kind=AdapterKind.TOOL,
        provider="Fixture",
        provider_url="https://example.test/runtime",
        license=_license(),
        capabilities=["runtime.java"],
        modes=[ExecutionMode.OFFLINE],
        max_execution_class=ExecutionClass.ANALYSIS,
        platforms=[
            "linux-x86_64",
            "linux-arm64",
            "macos-x86_64",
            "macos-arm64",
            "windows-x86_64",
            "windows-arm64",
        ],
        probe=ProbeDefinition(
            executable_names={"any": ["java", "java.exe"]},
            version_args=["-version"],
            version_pattern=r'version "(?P<version>[0-9]+(?:\.[0-9]+)*)',
            minimum_version="21",
        ),
        provisioner=AdoptiumProvisioner(
            feature_version=21,
            entrypoints={
                "linux": ["bin/java"],
                "macos": ["Contents/Home/bin/java"],
                "windows": ["bin/java.exe"],
            },
            max_download_bytes=400_000_000,
            max_install_bytes=1_000_000_000,
        ),
        operations=[],
        updated_at=utc_now(),
    )


def _registry(tmp_path: Path, manifests: list[AdapterManifest]) -> AdapterRegistry:
    path = tmp_path / "catalog.yaml"
    payload = json.loads(AdapterCatalogManifest(adapters=manifests).model_dump_json())
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    capability_classes = {
        capability: ExecutionClass.ANALYSIS for manifest in manifests for capability in manifest.capabilities
    }
    registry = AdapterRegistry(path, capability_execution_classes=capability_classes)
    assert registry.load().valid
    return registry


def _conformance_report(
    manifest: AdapterManifest,
    status: AdapterStatus,
    *,
    passed: bool = True,
    tool_version: str = "1.2.3",
    requirement_identity_sha256: list[str | None] | None = None,
) -> AdapterConformanceReport:
    operation = manifest.operations[0]
    assert status.observed_identity_sha256
    now = utc_now()
    return AdapterConformanceReport(
        adapter_id=manifest.adapter_id,
        operation_id=operation.operation_id,
        operation_version=operation.operation_version,
        manifest_digest=manifest.digest(),
        operation_contract_digest=operation.digest(),
        observed_identity_sha256=status.observed_identity_sha256,
        requirement_identity_sha256=requirement_identity_sha256 or [],
        tool_payload_sha256="a" * 64,
        tool_version=tool_version,
        driver_id="fixture-driver",
        driver_version="1.0.0",
        sandbox_profile_sha256="b" * 64,
        fixture_id=operation.conformance_suite_id,
        fixture_sha256="c" * 64,
        started_at=now,
        finished_at=now,
        passed=passed,
        checks=[
            AdapterConformanceCheck(
                name="tool-version",
                ok=True,
                detail=f"version={tool_version}",
            ),
            *[
                AdapterConformanceCheck(
                    name=f"requirement-{index}-version",
                    ok=identity is not None,
                    detail=f"identity={identity or 'unobserved'}",
                )
                for index, identity in enumerate(requirement_identity_sha256 or [], start=1)
            ],
            AdapterConformanceCheck(
                name="deterministic-output",
                ok=passed,
                detail="fixture result matched" if passed else "fixture result differed",
            ),
        ],
    )


def test_builtin_registry_is_nonredundant_and_searchable() -> None:
    registry = AdapterRegistry(
        REPOSITORY_ROOT / "adapters/catalog.yaml",
        capability_execution_classes={
            "artifact.inspect": ExecutionClass.ANALYSIS,
            "artifact.recursive-unpack": ExecutionClass.ANALYSIS,
            "artifact.signature-match": ExecutionClass.ANALYSIS,
            "binary.behavior-identify": ExecutionClass.ANALYSIS,
            "binary.diff": ExecutionClass.ANALYSIS,
            "binary.go-symbol-recover": ExecutionClass.ANALYSIS,
            "binary.runtime-inspect": ExecutionClass.ANALYSIS,
            "binary.static-inspect": ExecutionClass.ANALYSIS,
            "code.search": ExecutionClass.ANALYSIS,
            "experiment.design": ExecutionClass.ANALYSIS,
            "graph.reason": ExecutionClass.ANALYSIS,
            "hypothesis.generate": ExecutionClass.ANALYSIS,
            "mobile.runtime-observe": ExecutionClass.READ_ONLY,
            "mobile.static-inspect": ExecutionClass.ANALYSIS,
            "network.capture-inspect": ExecutionClass.ANALYSIS,
            "runtime.java": ExecutionClass.ANALYSIS,
            "trace.capture": ExecutionClass.READ_ONLY,
            "weakness.lookup": ExecutionClass.ANALYSIS,
        },
    )

    report = registry.load()
    reverse = registry.search("reverse")
    knowledge = registry.search("", kind=AdapterKind.KNOWLEDGE)

    assert report.valid
    assert report.adapter_count == 14
    assert reverse[0].adapter.adapter_id == "ghidra"
    assert {item.adapter.adapter_id for item in knowledge} == {
        "capa-rules",
        "mitre-attack",
        "mitre-cwe",
        "owasp-wstg",
    }
    jadx = registry.get("jadx")
    assert [operation.operation_id for operation in jadx.operations] == ["jadx.android-static-map"]
    assert jadx.operations[0].input_types == ["artifact/mobile-build"]
    assert jadx.operations[0].output_types == ["surface/static-map"]
    ghidra = registry.get("ghidra")
    assert [operation.operation_id for operation in ghidra.operations] == [
        "ghidra.binary-summary",
        "ghidra.native-code-map",
    ]
    assert ghidra.operations[1].capabilities == ["binary.static-inspect"]
    assert ghidra.operations[1].output_types == ["surface/native-code-map"]
    assert ghidra.requirements[0].managed_adapter_id == "temurin-jdk"
    temurin = registry.get("temurin-jdk")
    assert temurin.capabilities == ["runtime.java"]
    assert temurin.operations == []
    yara_x = registry.get("yara-x")
    assert yara_x.capabilities == ["artifact.signature-match"]
    assert [operation.operation_id for operation in yara_x.operations] == ["yara-x.file-scan"]
    assert yara_x.operations[0].output_types == ["evidence/signature-match"]
    tshark = registry.get("tshark")
    assert tshark.capabilities == ["network.capture-inspect"]
    assert [operation.operation_id for operation in tshark.operations] == ["tshark.packet-capture-map"]
    assert tshark.operations[0].input_types == ["artifact/packet-capture"]
    assert tshark.operations[0].output_types == ["surface/network-protocol-map"]
    goresym = registry.get("goresym")
    assert goresym.platforms == ["linux-x86_64", "macos-x86_64", "windows-x86_64"]
    assert goresym.probe and goresym.probe.version_args == ("-about",)
    assert [operation.operation_id for operation in goresym.operations] == ["goresym.symbol-map"]
    assert goresym.operations[0].capabilities == ["binary.go-symbol-recover"]
    assert goresym.operations[0].output_types == ["surface/go-symbol-map"]
    unblob = registry.get("unblob")
    assert isinstance(unblob.provisioner, OciImageProvisioner)
    assert unblob.platforms == ["linux-x86_64", "linux-arm64"]
    assert [operation.operation_id for operation in unblob.operations] == ["unblob.extraction-map"]
    assert unblob.operations[0].output_types == ["surface/extracted-file-map"]


def test_status_defers_path_execution_and_uses_cached_conformance(tmp_path, monkeypatch) -> None:
    manifest = _tool_manifest()
    registry = _registry(tmp_path, [manifest])
    manager = AdapterManager(
        registry,
        tmp_path / "managed",
        conformance_verifier=_accept_fixture_conformance,
    )
    marker = tmp_path / "executed"
    executable = tmp_path / "fixture-tool"
    executable.write_text(f"#!/bin/sh\ntouch {marker}\nprintf 'Python 1.2.3\\n'\n", encoding="utf-8")
    executable.chmod(0o755)
    monkeypatch.setattr(
        "white_hat_agent.adapter_registry.shutil.which",
        lambda name: str(executable) if name == "fixture-tool" else None,
    )

    status = manager.status("fixture-tool")

    assert not status.healthy
    assert status.source == "system"
    assert status.version is None
    assert status.entrypoints == [str(executable.resolve())]
    assert status.observed_identity_sha256
    assert status.declared_capabilities == ["artifact.inspect"]
    assert status.conformant_operations == []
    assert status.available_capabilities == []
    assert not marker.exists()

    report = _conformance_report(manifest, status)
    report_path = manager.save_conformance_report(report)
    conformed = manager.status("fixture-tool")

    assert report_path == tmp_path / "managed/.conformance/fixture-tool/inspect.json"
    assert conformed.healthy
    assert conformed.version == "1.2.3"
    assert conformed.conformant_operations == ["inspect"]
    assert conformed.available_capabilities == ["artifact.inspect"]
    reports = manager.conformance_reports(manifest.adapter_id)
    assert len(reports) == 1
    assert reports[0].digest() == report.digest()


def test_status_never_executes_a_failing_path_version_probe(tmp_path, monkeypatch) -> None:
    executable = tmp_path / "failing-version"
    executable.write_text("#!/bin/sh\nprintf '1.2.3\\n'\nexit 1\n", encoding="utf-8")
    executable.chmod(0o755)
    manifest = _tool_manifest().model_copy(
        update={
            "probe": ProbeDefinition(
                executable_names={"any": ["fixture-tool"]},
                version_args=["--version"],
                version_pattern=r"(?P<version>[0-9]+(?:\.[0-9]+)+)",
            )
        }
    )
    registry = _registry(tmp_path, [manifest])
    manager = AdapterManager(registry, tmp_path / "managed")
    monkeypatch.setattr(
        "white_hat_agent.adapter_registry.shutil.which",
        lambda name: str(executable) if name == "fixture-tool" else None,
    )

    status = manager.status(manifest.adapter_id)

    assert not status.healthy
    assert status.version is None
    assert "tool version requires explicit conformance" in status.blockers


def test_probe_rejects_arbitrary_command_arguments() -> None:
    assert ProbeDefinition(
        executable_names={"any": ["GoReSym"]},
        version_args=["-about"],
        version_pattern=r"Version: v(?P<version>[0-9.]+)",
    ).version_args == ("-about",)
    for arguments in (["-c", "print('executed')"], ["version"]):
        with pytest.raises(ValueError):
            ProbeDefinition(
                executable_names={"any": ["python3"]},
                version_args=arguments,
                version_pattern=r"(?P<version>[0-9.]+)",
            )


def test_operation_version_is_bounded_for_evidence_manifests() -> None:
    payload = _tool_manifest().model_dump(mode="json")
    payload["operations"][0]["operation_version"] = f"1.0.0-{'a' * 65}"

    with pytest.raises(ValueError):
        AdapterManifest.model_validate(payload)


def test_registry_rejects_underclassified_capability_execution(tmp_path) -> None:
    manifest = _tool_manifest(capabilities=["http.request"])
    path = tmp_path / "catalog.yaml"
    payload = json.loads(AdapterCatalogManifest(adapters=[manifest]).model_dump_json())
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    registry = AdapterRegistry(
        path,
        capability_execution_classes={"http.request": ExecutionClass.CONTROLLED_ACTIVE},
    )

    report = registry.load()

    assert not report.valid
    assert "underclassify" in report.issues[0].message


def test_operation_contract_is_strict_and_resource_bounded() -> None:
    operation = _tool_manifest().operations[0]
    payload = operation.model_dump(mode="json")
    payload["command"] = ["fixture-tool", "--unsafe"]

    with pytest.raises(ValueError, match="Extra inputs are not permitted"):
        AdapterOperationBinding.model_validate(payload)

    limits = operation.limits.model_dump(mode="json")
    limits["max_files"] = 0
    with pytest.raises(ValueError):
        OperationResourceLimits.model_validate(limits)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("duplicate-operation", "operation identifiers"),
        ("undeclared-capability", "undeclared capabilities"),
        ("undeclared-mode", "undeclared modes"),
        ("excessive-execution", "exceeds the manifest execution class"),
    ],
)
def test_manifest_validates_typed_operation_boundaries(mutation: str, message: str) -> None:
    payload = _tool_manifest().model_dump(mode="json")
    if mutation == "duplicate-operation":
        payload["operations"].append(dict(payload["operations"][0]))
    elif mutation == "undeclared-capability":
        payload["operations"][0]["capabilities"] = ["code.search"]
    elif mutation == "undeclared-mode":
        payload["operations"][0]["modes"] = ["sandbox"]
    else:
        payload["operations"][0]["execution_class"] = "read-only"

    with pytest.raises(ValueError, match=message):
        AdapterManifest.model_validate(payload)


def test_knowledge_manifest_rejects_operation_bindings() -> None:
    payload = _knowledge_manifest().model_dump(mode="json")
    operation = _tool_manifest(capabilities=["code.search"]).operations[0]
    payload["operations"] = [operation.model_dump(mode="json")]

    with pytest.raises(ValueError, match="knowledge adapters cannot declare executable operations"):
        AdapterManifest.model_validate(payload)


def test_conformance_is_invalidated_by_observed_tool_identity_drift(tmp_path, monkeypatch) -> None:
    executable = tmp_path / "fixture-tool"
    executable.write_text("#!/bin/sh\nprintf 'Python 1.2.3\\n'\n", encoding="utf-8")
    executable.chmod(0o755)
    manifest = _tool_manifest()
    manager = AdapterManager(
        _registry(tmp_path, [manifest]),
        tmp_path / "managed",
        conformance_verifier=_accept_fixture_conformance,
    )
    monkeypatch.setattr(
        "white_hat_agent.adapter_registry.shutil.which",
        lambda name: str(executable) if name == "fixture-tool" else None,
    )
    initial = manager.status(manifest.adapter_id)
    manager.save_conformance_report(_conformance_report(manifest, initial))

    conformed = manager.status(manifest.adapter_id)
    executable.write_text("#!/bin/sh\n# changed\nprintf 'Python 1.2.3\\n'\n", encoding="utf-8")
    drifted = manager.status(manifest.adapter_id)

    assert conformed.available_capabilities == ["artifact.inspect"]
    assert not drifted.healthy
    assert drifted.observed_identity_sha256 != initial.observed_identity_sha256
    assert drifted.conformant_operations == []
    assert drifted.available_capabilities == []
    assert manager.conformance_reports(manifest.adapter_id) == []


def test_conformance_is_invalidated_by_runtime_requirement_identity_drift(
    tmp_path,
    monkeypatch,
) -> None:
    executable = tmp_path / "fixture-tool"
    executable.write_bytes(b"tool")
    executable.chmod(0o755)
    dependency = tmp_path / "fixture-runtime"
    dependency.write_bytes(b"runtime-v1")
    dependency.chmod(0o755)
    requirement = ProbeDefinition(
        executable_names={"any": ["fixture-runtime"]},
        version_args=["--version"],
        version_pattern=r"(?P<version>[0-9]+(?:\.[0-9]+)+)",
        minimum_version="1.0.0",
    )
    manifest = _tool_manifest().model_copy(update={"requirements": [requirement]})
    manager = AdapterManager(
        _registry(tmp_path, [manifest]),
        tmp_path / "managed",
        conformance_verifier=_accept_fixture_conformance,
    )
    monkeypatch.setattr(
        "white_hat_agent.adapter_registry.shutil.which",
        lambda name: {
            "fixture-tool": str(executable),
            "fixture-runtime": str(dependency),
        }.get(name),
    )
    initial = manager.status(manifest.adapter_id)
    dependency_identity = observed_tool_identity_digest([str(dependency)])
    manager.save_conformance_report(
        _conformance_report(
            manifest,
            initial,
            requirement_identity_sha256=[dependency_identity],
        )
    )

    assert manager.status(manifest.adapter_id).available_capabilities == ["artifact.inspect"]
    dependency.write_bytes(b"runtime-v2")
    drifted = manager.status(manifest.adapter_id)

    assert not drifted.healthy
    assert drifted.available_capabilities == []
    assert manager.conformance_reports(manifest.adapter_id) == []


def test_conformance_save_rejects_manifest_and_operation_contract_drift(tmp_path, monkeypatch) -> None:
    manifest = _tool_manifest()
    manager = AdapterManager(
        _registry(tmp_path, [manifest]),
        tmp_path / "managed",
        conformance_verifier=_accept_fixture_conformance,
    )
    monkeypatch.setattr(
        "white_hat_agent.adapter_registry.shutil.which",
        lambda executable: sys.executable if executable == "fixture-tool" else None,
    )
    report = _conformance_report(manifest, manager.status(manifest.adapter_id))

    with pytest.raises(AdapterRegistryError, match="manifest identity"):
        manager.save_conformance_report(report.model_copy(update={"manifest_digest": "d" * 64}))
    with pytest.raises(AdapterRegistryError, match="operation contract"):
        manager.save_conformance_report(report.model_copy(update={"operation_contract_digest": "e" * 64}))


def test_only_passing_explicit_conformance_grants_capabilities(
    tmp_path,
    monkeypatch,
) -> None:
    manifest = _tool_manifest()
    manager = AdapterManager(
        _registry(tmp_path, [manifest]),
        tmp_path / "managed",
        conformance_verifier=_accept_fixture_conformance,
    )
    monkeypatch.setattr(
        "white_hat_agent.adapter_registry.shutil.which",
        lambda executable: sys.executable if executable == "fixture-tool" else None,
    )
    status = manager.status(manifest.adapter_id)
    passing = _conformance_report(manifest, status)
    manager.save_conformance_report(passing)
    assert manager.status(manifest.adapter_id).available_capabilities == ["artifact.inspect"]

    manager.save_conformance_report(_conformance_report(manifest, status, passed=False))
    failed = manager.status(manifest.adapter_id)
    assert failed.conformant_operations == []
    assert failed.available_capabilities == []
    assert manager.conformance_reports(manifest.adapter_id)[0].passed is False


def test_persisted_conformance_is_invalidated_by_manifest_operation_drift(
    tmp_path,
    monkeypatch,
) -> None:
    manifest = _tool_manifest()
    managed_root = tmp_path / "managed"
    manager = AdapterManager(
        _registry(tmp_path, [manifest]),
        managed_root,
        conformance_verifier=_accept_fixture_conformance,
    )
    monkeypatch.setattr(
        "white_hat_agent.adapter_registry.shutil.which",
        lambda executable: sys.executable if executable == "fixture-tool" else None,
    )
    status = manager.status(manifest.adapter_id)
    manager.save_conformance_report(_conformance_report(manifest, status))
    assert manager.status(manifest.adapter_id).available_capabilities == ["artifact.inspect"]

    payload = manifest.model_dump(mode="json")
    payload["operations"][0]["limits"]["max_records"] += 1
    drifted_manifest = AdapterManifest.model_validate(payload)
    drifted = AdapterManager(
        _registry(tmp_path, [drifted_manifest]),
        managed_root,
        conformance_verifier=_accept_fixture_conformance,
    )

    assert drifted.status(manifest.adapter_id).available_capabilities == []
    assert drifted.conformance_reports(manifest.adapter_id) == []


def test_tool_resolution_covers_only_bound_operation_capabilities(tmp_path) -> None:
    payload = _tool_manifest(capabilities=["artifact.inspect", "code.search"]).model_dump(mode="json")
    payload["operations"][0]["capabilities"] = ["artifact.inspect"]
    manifest = AdapterManifest.model_validate(payload)
    manager = AdapterManager(_registry(tmp_path, [manifest]), tmp_path / "managed")

    selection = manager.resolve(["code.search"], kind=AdapterKind.TOOL)

    assert not selection.complete
    assert selection.selected_adapters == []
    assert selection.uncovered_capabilities == ["code.search"]


def test_resolver_prefers_healthy_tools_then_reports_provisioning(tmp_path, monkeypatch) -> None:
    installable = GitHubReleaseProvisioner(
        repository="example/tool",
        asset_patterns={"any": [r"^tool\.zip$"]},
        entrypoints={"any": ["tool"]},
        max_download_bytes=1_000_000,
        max_install_bytes=1_000_000,
    )
    first = _tool_manifest("healthy", capabilities=["artifact.inspect"])
    second = _tool_manifest("installable", capabilities=["code.search"], provisioner=installable)
    registry = _registry(tmp_path, [first, second])
    manager = AdapterManager(registry, tmp_path / "managed")

    def fake_status(adapter_id: str) -> AdapterStatus:
        manifest = registry.get(adapter_id)
        healthy = adapter_id == "healthy"
        return AdapterStatus(
            adapter_id=adapter_id,
            manifest_digest=manifest.digest(),
            observed_at=utc_now(),
            platform=current_platform(),
            supported=True,
            installed=healthy,
            healthy=healthy,
            source="system" if healthy else None,
            version="1.0.0" if healthy else None,
            observed_identity_sha256="a" * 64 if healthy else None,
            declared_capabilities=manifest.capabilities,
            available_capabilities=[],
            blockers=[] if healthy else ["not installed"],
        )

    monkeypatch.setattr(manager, "status", fake_status)

    selection = manager.resolve(["artifact.inspect", "code.search"], kind=AdapterKind.TOOL)

    assert selection.complete
    assert not selection.ready
    assert selection.selected_adapters == ["healthy", "installable"]
    assert selection.provisioning_required == ["installable"]
    assert selection.conformance_required == ["healthy"]


def test_resolver_does_not_offer_impossible_conformance_for_unobservable_tool(
    tmp_path,
    monkeypatch,
) -> None:
    manifest = _tool_manifest()
    manager = AdapterManager(_registry(tmp_path, [manifest]), tmp_path / "managed")
    monkeypatch.setattr(
        manager,
        "status",
        lambda _adapter_id: AdapterStatus(
            adapter_id=manifest.adapter_id,
            manifest_digest=manifest.digest(),
            observed_at=utc_now(),
            platform=current_platform(),
            supported=True,
            installed=True,
            healthy=False,
            source="system",
            entrypoints=["/unobservable/tool"],
            observed_identity_sha256=None,
            declared_capabilities=manifest.capabilities,
            blockers=["tool identity could not be observed"],
        ),
    )

    selection = manager.resolve(["artifact.inspect"], kind=AdapterKind.TOOL)

    assert not selection.complete
    assert selection.selected_adapters == []
    assert selection.provisioning_required == []
    assert selection.conformance_required == []
    assert selection.uncovered_capabilities == ["artifact.inspect"]


def test_resolver_finds_exact_minimum_after_health_preference(tmp_path, monkeypatch) -> None:
    manifests = [
        _tool_manifest("wide", capabilities=["a", "b", "c", "d"]),
        _tool_manifest("left", capabilities=["a", "b", "e"]),
        _tool_manifest("right", capabilities=["c", "d", "f"]),
        _tool_manifest("e-only", capabilities=["e"]),
        _tool_manifest("f-only", capabilities=["f"]),
    ]
    registry = _registry(tmp_path, manifests)
    manager = AdapterManager(registry, tmp_path / "managed")

    def healthy_status(adapter_id: str) -> AdapterStatus:
        manifest = registry.get(adapter_id)
        return AdapterStatus(
            adapter_id=adapter_id,
            manifest_digest=manifest.digest(),
            observed_at=utc_now(),
            platform=current_platform(),
            supported=True,
            installed=True,
            healthy=True,
            source="system",
            version="1.0.0",
            observed_identity_sha256="a" * 64,
            conformant_operations=[item.operation_id for item in manifest.operations],
            declared_capabilities=manifest.capabilities,
            available_capabilities=manifest.capabilities,
        )

    monkeypatch.setattr(manager, "status", healthy_status)

    selection = manager.resolve(["a", "b", "c", "d", "e", "f"])

    assert selection.complete
    assert selection.ready
    assert selection.selected_adapters == ["left", "right"]
    assert selection.conformance_required == []


def test_release_plan_requires_exact_asset_digest_and_is_update_aware(tmp_path, monkeypatch) -> None:
    definition = GitHubReleaseProvisioner(
        repository="example/tool",
        asset_patterns={"any": [r"^tool-[0-9.]+\.zip$"]},
        entrypoints={"any": ["tool"]},
        max_download_bytes=1_000_000,
        max_install_bytes=2_000_000,
    )
    manifest = _tool_manifest(provisioner=definition)
    registry = _registry(tmp_path, [manifest])
    manager = AdapterManager(registry, tmp_path / "managed")
    monkeypatch.setattr(
        manager,
        "status",
        lambda _: AdapterStatus(
            adapter_id=manifest.adapter_id,
            manifest_digest=manifest.digest(),
            observed_at=utc_now(),
            platform=current_platform(),
            supported=True,
            installed=True,
            healthy=True,
            source="system",
            version="1.0.0",
            available_capabilities=manifest.capabilities,
        ),
    )
    monkeypatch.setattr(
        adapter_provisioning,
        "_get_json",
        lambda _: {
            "tag_name": "v2.0.0",
            "assets": [
                {
                    "name": "tool-2.0.0.zip",
                    "size": 123,
                    "digest": "sha256:" + "a" * 64,
                    "browser_download_url": (
                        "https://github.com/example/tool/releases/download/v2.0.0/tool-2.0.0.zip"
                    ),
                }
            ],
        },
    )

    plan = AdapterProvisioner(manager).plan(manifest.adapter_id)

    assert plan.action == ProvisionAction.UPDATE
    assert plan.current_version == "1.0.0"
    assert plan.target_version == "2.0.0"
    assert plan.artifacts[0].sha256 == "a" * 64
    assert len(plan.digest()) == 64
    forged = plan.model_copy(update={"revision": "v9.9.9", "target_version": "9.9.9"})
    with pytest.raises(AdapterRegistryError, match="identity"):
        AdapterProvisioner(manager).provision(forged)


def test_release_plan_resolves_one_versioned_entrypoint(tmp_path, monkeypatch) -> None:
    definition = GitHubReleaseProvisioner(
        repository="example/tool",
        asset_patterns={"any": [r"^tool-[0-9.]+\.xz$"]},
        entrypoints={"any": ["tool-{version}"]},
        strip_single_directory=False,
        max_download_bytes=1_000_000,
        max_install_bytes=2_000_000,
    )
    manifest = _tool_manifest(provisioner=definition)
    manager = AdapterManager(_registry(tmp_path, [manifest]), tmp_path / "managed")
    monkeypatch.setattr(
        manager,
        "status",
        lambda _: AdapterStatus(
            adapter_id=manifest.adapter_id,
            manifest_digest=manifest.digest(),
            observed_at=utc_now(),
            platform=current_platform(),
            supported=True,
            installed=False,
            healthy=False,
        ),
    )
    monkeypatch.setattr(
        adapter_provisioning,
        "_get_json",
        lambda _: {
            "tag_name": "2.3.4",
            "assets": [
                {
                    "name": "tool-2.3.4.xz",
                    "size": 123,
                    "digest": "sha256:" + "a" * 64,
                    "browser_download_url": (
                        "https://github.com/example/tool/releases/download/2.3.4/tool-2.3.4.xz"
                    ),
                }
            ],
        },
    )

    plan = AdapterProvisioner(manager).plan(manifest.adapter_id)

    assert plan.entrypoints == ["tool-2.3.4"]
    assert plan.target_version == "2.3.4"


def test_oci_plan_binds_release_platform_and_registry_digests(tmp_path, monkeypatch) -> None:
    manifest = _oci_tool_manifest()
    manager = AdapterManager(_registry(tmp_path, [manifest]), tmp_path / "managed")
    monkeypatch.setattr(adapter_provisioning, "current_platform", lambda: "linux-x86_64")
    monkeypatch.setattr(
        manager,
        "status",
        lambda _: AdapterStatus(
            adapter_id=manifest.adapter_id,
            manifest_digest=manifest.digest(),
            observed_at=utc_now(),
            platform="linux-x86_64",
            supported=True,
            installed=True,
            healthy=True,
            source="managed",
            version="1.0.0",
            revision="v1.0.0@sha256:" + "1" * 64 + "/sha256:" + "2" * 64,
            available_capabilities=manifest.capabilities,
        ),
    )

    def release_metadata(url: str) -> dict[str, object]:
        if url.endswith("/releases/latest"):
            return {"tag_name": "v2.0.0"}
        return {"sha": "d" * 40}

    image = _resolved_oci_image()
    monkeypatch.setattr(adapter_provisioning, "_get_json", release_metadata)
    monkeypatch.setattr(adapter_provisioning, "_resolve_oci_image", lambda *args, **kwargs: image)
    monkeypatch.setattr(adapter_provisioning, "_oci_runtime_blockers", lambda: [])

    plan = AdapterProvisioner(manager).plan(manifest.adapter_id)

    assert plan.method == "oci-image"
    assert plan.action == ProvisionAction.UPDATE
    assert plan.current_version == "1.0.0"
    assert plan.target_version == "2.0.0"
    assert plan.revision == f"v2.0.0@sha256:{'a' * 64}/sha256:{'b' * 64}"
    assert plan.oci_image == image
    assert plan.source_urls[-1].endswith("/blobs/sha256:" + "c" * 64)

    forged = plan.model_copy(update={"source_urls": plan.source_urls[:-1]})
    with pytest.raises(AdapterRegistryError, match="sources"):
        AdapterProvisioner(manager).provision(forged)


def test_oci_provision_pulls_exact_manifest_and_writes_only_descriptor(tmp_path, monkeypatch) -> None:
    manifest = _oci_tool_manifest()
    manager = AdapterManager(_registry(tmp_path, [manifest]), tmp_path / "managed")
    monkeypatch.setattr(adapter_provisioning, "current_platform", lambda: "linux-x86_64")
    monkeypatch.setattr(
        manager,
        "status",
        lambda _: AdapterStatus(
            adapter_id=manifest.adapter_id,
            manifest_digest=manifest.digest(),
            observed_at=utc_now(),
            platform="linux-x86_64",
            supported=True,
            installed=False,
            healthy=False,
        ),
    )
    image = _resolved_oci_image()
    monkeypatch.setattr(
        adapter_provisioning,
        "_get_json",
        lambda url: {"tag_name": image.tag} if url.endswith("/releases/latest") else {"sha": "d" * 40},
    )
    monkeypatch.setattr(adapter_provisioning, "_resolve_oci_image", lambda *args, **kwargs: image)
    monkeypatch.setattr(adapter_provisioning, "_oci_runtime_blockers", lambda: [])
    plan = AdapterProvisioner(manager).plan(manifest.adapter_id)
    pulled: list[ResolvedOciImage] = []
    verified: list[ResolvedOciImage] = []
    monkeypatch.setattr(adapter_provisioning, "_trusted_docker_executable", lambda: Path("/usr/bin/docker"))
    monkeypatch.setattr(adapter_provisioning, "_pull_oci_image", lambda _docker, value: pulled.append(value))
    monkeypatch.setattr(
        adapter_provisioning,
        "_verify_local_oci_image",
        lambda _docker, value: verified.append(value),
    )

    result = AdapterProvisioner(manager).provision(plan)

    assert result.changed
    assert pulled == [image]
    assert verified == [image]
    content = tmp_path / "managed/fixture-oci-tool/content"
    assert [path.name for path in content.iterdir()] == ["oci-image.env"]
    descriptor = (content / "oci-image.env").read_text()
    assert "version=v2.0.0\n" in descriptor
    assert f"manifest_sha256={'b' * 64}\n" in descriptor
    installed = InstalledAdapterRecord.model_validate_json(
        (tmp_path / "managed/fixture-oci-tool/installed.json").read_text()
    )
    assert installed.revision == plan.revision
    assert installed.artifact_sha256 == ["a" * 64, "b" * 64, "c" * 64, "e" * 64]


def test_adoptium_plan_binds_platform_package_checksum_and_release(tmp_path, monkeypatch) -> None:
    manifest = _runtime_manifest()
    manager = AdapterManager(_registry(tmp_path, [manifest]), tmp_path / "managed")
    monkeypatch.setattr(
        manager,
        "status",
        lambda _: AdapterStatus(
            adapter_id=manifest.adapter_id,
            manifest_digest=manifest.digest(),
            observed_at=utc_now(),
            platform="linux-x86_64",
            supported=True,
            installed=False,
            healthy=False,
        ),
    )
    monkeypatch.setattr(adapter_provisioning, "current_platform", lambda: "linux-x86_64")
    package_url = (
        "https://github.com/adoptium/temurin21-binaries/releases/download/"
        "jdk-21.0.12%2B8/OpenJDK21U-jdk_x64_linux_hotspot_21.0.12_8.tar.gz"
    )
    monkeypatch.setattr(
        adapter_provisioning,
        "_get_adoptium_json",
        lambda _: [
            {
                "release_name": "jdk-21.0.12+8",
                "binary": {
                    "architecture": "x64",
                    "os": "linux",
                    "image_type": "jdk",
                    "jvm_impl": "hotspot",
                    "package": {
                        "name": "OpenJDK21U-jdk_x64_linux_hotspot_21.0.12_8.tar.gz",
                        "link": package_url,
                        "size": 207_486_543,
                        "checksum": "a" * 64,
                    },
                },
            }
        ],
    )

    plan = AdapterProvisioner(manager).plan(manifest.adapter_id)

    assert plan.method == "adoptium-api"
    assert plan.target_version == "21.0.12+8"
    assert plan.revision == "jdk-21.0.12+8"
    assert plan.entrypoints == ["bin/java"]
    assert plan.artifacts == [
        ResolvedArtifact(
            name="OpenJDK21U-jdk_x64_linux_hotspot_21.0.12_8.tar.gz",
            url=package_url,
            size=207_486_543,
            sha256="a" * 64,
        )
    ]
    assert "architecture=x64" in plan.source_urls[0]

    mismatched_url = package_url.removesuffix(plan.artifacts[0].name) + "other.tar.gz"
    mismatched_artifact = plan.artifacts[0].model_copy(update={"url": mismatched_url})
    mismatched_plan = plan.model_copy(
        update={
            "artifacts": [mismatched_artifact],
            "source_urls": [plan.source_urls[0], mismatched_url],
        }
    )
    with pytest.raises(AdapterRegistryError, match="package URL"):
        AdapterProvisioner(manager).provision(mismatched_plan)

    archive = tmp_path / plan.artifacts[0].name
    with tarfile.open(archive, "w:gz") as bundle:
        payload = b"managed java"
        member = tarfile.TarInfo("jdk-21.0.12+8/bin/java")
        member.size = len(payload)
        bundle.addfile(member, io.BytesIO(payload))
    monkeypatch.setattr(
        adapter_provisioning,
        "_download_artifact",
        lambda _artifact, destination, max_bytes: shutil.copyfile(archive, destination),
    )

    result = AdapterProvisioner(manager).provision(plan)

    assert result.changed
    assert (tmp_path / "managed/fixture-jdk/content/bin/java").read_bytes() == b"managed java"


@pytest.mark.parametrize(
    ("platform", "coordinate", "entrypoint"),
    [
        ("linux-x86_64", "architecture=x64", "bin/java"),
        ("linux-arm64", "architecture=aarch64", "bin/java"),
        ("macos-x86_64", "os=mac", "Contents/Home/bin/java"),
        ("macos-arm64", "architecture=aarch64", "Contents/Home/bin/java"),
        ("windows-x86_64", "os=windows", "bin/java.exe"),
        ("windows-arm64", "architecture=aarch64", "bin/java.exe"),
    ],
)
def test_adoptium_platform_matrix_is_bounded(platform, coordinate, entrypoint) -> None:
    definition = _runtime_manifest().provisioner
    assert isinstance(definition, AdoptiumProvisioner)

    url = _adoptium_api_url(definition, platform)

    assert coordinate in url
    assert entrypoint in definition.entrypoints[platform.split("-", 1)[0]]


def test_mitre_cwe_plan_binds_official_version_counts_and_catalog(tmp_path, monkeypatch) -> None:
    manifest = AdapterManifest(
        adapter_id="fixture-cwe",
        title="Fixture CWE",
        description="Fixture canonical weakness catalog",
        kind=AdapterKind.KNOWLEDGE,
        provider="MITRE CWE",
        provider_url="https://cwe.mitre.org/",
        license=_license(),
        capabilities=["weakness.lookup"],
        platforms=["any"],
        provisioner=MitreCweProvisioner(
            max_download_bytes=8_388_608,
            max_install_bytes=67_108_864,
        ),
        search_globs=["cwec_v*.xml"],
        updated_at=utc_now(),
    )
    manager = AdapterManager(_registry(tmp_path, [manifest]), tmp_path / "managed")
    monkeypatch.setattr(
        adapter_provisioning,
        "_get_cwe_version_json",
        lambda _url: {
            "ContentVersion": "4.20",
            "ContentDate": "2026-04-30",
            "TotalWeaknesses": 969,
            "TotalCategories": 422,
            "TotalViews": 59,
        },
    )
    artifact = ResolvedArtifact(
        name="cwec_latest.xml.zip",
        url="https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
        size=2_021_351,
        sha256="a" * 64,
    )
    monkeypatch.setattr(adapter_provisioning, "_resolve_cwe_artifact", lambda _limit: artifact)

    plan = AdapterProvisioner(manager).plan(manifest.adapter_id)

    assert plan.method == "mitre-cwe"
    assert plan.target_version == "4.20"
    assert plan.revision == "cwe-4.20@2026-04-30"
    assert plan.artifacts == [artifact]
    assert plan.cwe_identity == CweCatalogIdentity(
        content_date="2026-04-30",
        total_weaknesses=969,
        total_categories=422,
        total_views=59,
    )
    forged = plan.model_copy(update={"revision": "cwe-4.21@2026-04-30"})
    with pytest.raises(AdapterRegistryError, match="catalog identity"):
        AdapterProvisioner(manager).provision(forged)


def test_mitre_cwe_provision_validates_catalog_and_supports_revision_bound_search(
    tmp_path,
    monkeypatch,
) -> None:
    manifest = AdapterManifest(
        adapter_id="fixture-cwe",
        title="Fixture CWE",
        description="Fixture canonical weakness catalog",
        kind=AdapterKind.KNOWLEDGE,
        provider="MITRE CWE",
        provider_url="https://cwe.mitre.org/",
        license=_license(),
        capabilities=["weakness.lookup"],
        platforms=["any"],
        provisioner=MitreCweProvisioner(
            max_download_bytes=1_000_000,
            max_install_bytes=2_000_000,
        ),
        search_globs=["cwec_v*.xml"],
        updated_at=utc_now(),
    )
    manager = AdapterManager(_registry(tmp_path, [manifest]), tmp_path / "managed")
    archive = tmp_path / "cwec_latest.xml.zip"
    xml = """<?xml version="1.0" encoding="UTF-8"?>
<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-7" Name="CWE" Version="4.20" Date="2026-04-30">
  <Weaknesses>
    <Weakness ID="79" Name="Cross-site Scripting">
      <Description>Neutralization failure</Description>
    </Weakness>
  </Weaknesses>
  <Categories><Category ID="1" Name="Fixture"/></Categories>
  <Views><View ID="1000" Name="Fixture"/></Views>
</Weakness_Catalog>
"""
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("cwec_v4.20.xml", xml)
    artifact = ResolvedArtifact(
        name=archive.name,
        url="https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
        size=archive.stat().st_size,
        sha256="b" * 64,
    )
    plan = AdapterProvisionPlan(
        adapter_id=manifest.adapter_id,
        manifest_digest=manifest.digest(),
        platform=current_platform(),
        method="mitre-cwe",
        action=ProvisionAction.INSTALL,
        target_version="4.20",
        revision="cwe-4.20@2026-04-30",
        source_urls=[
            "https://cwe-api.mitre.org/api/v1/cwe/version",
            artifact.url,
        ],
        artifacts=[artifact],
        max_download_bytes=1_000_000,
        max_install_bytes=2_000_000,
        cwe_identity=CweCatalogIdentity(
            content_date="2026-04-30",
            total_weaknesses=1,
            total_categories=1,
            total_views=1,
        ),
        created_at=utc_now(),
    )
    monkeypatch.setattr(
        adapter_provisioning,
        "_download_cwe_artifact",
        lambda _artifact, destination, max_bytes: shutil.copyfile(archive, destination),
    )

    result = AdapterProvisioner(manager).provision(plan)
    hits = manager.search_knowledge(manifest.adapter_id, "CWE-79")

    assert result.changed
    assert result.installed is not None
    assert result.installed.revision == "cwe-4.20@2026-04-30"
    assert len(hits) == 1
    assert hits[0].revision == result.installed.revision
    assert hits[0].relative_path == "cwec_v4.20.xml"
    assert 'Weakness ID="79"' in hits[0].snippet


def test_mitre_cwe_snapshot_rejects_version_endpoint_count_mismatch(tmp_path) -> None:
    content = tmp_path / "content"
    content.mkdir()
    (content / "cwec_v4.20.xml").write_text(
        '<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-7" Name="CWE" '
        'Version="4.20" Date="2026-04-30"><Weaknesses/></Weakness_Catalog>',
        encoding="utf-8",
    )

    with pytest.raises(AdapterRegistryError, match="counts"):
        _validate_cwe_snapshot(
            content,
            version="4.20",
            identity=CweCatalogIdentity(
                content_date="2026-04-30",
                total_weaknesses=1,
                total_categories=1,
                total_views=1,
            ),
        )


def test_managed_requirement_is_preferred_when_host_dependency_is_missing(tmp_path, monkeypatch) -> None:
    runtime = _runtime_manifest()
    requirement = ProbeDefinition(
        executable_names={"any": ["java"]},
        version_args=["-version"],
        version_pattern=r'version "(?P<version>[0-9]+(?:\.[0-9]+)*)',
        minimum_version="21",
        managed_adapter_id=runtime.adapter_id,
    )
    tool = _tool_manifest().model_copy(update={"requirements": [requirement]})
    manager = AdapterManager(_registry(tmp_path, [runtime, tool]), tmp_path / "managed")
    content = tmp_path / "managed/fixture-jdk/content"
    java = content / "bin/java"
    java.parent.mkdir(parents=True)
    java.write_bytes(b"managed java")
    record = InstalledAdapterRecord(
        adapter_id=runtime.adapter_id,
        manifest_digest=runtime.digest(),
        version="21.0.12",
        revision="jdk-21.0.12+8",
        source_urls=["https://api.adoptium.net/v3/assets/latest/21/hotspot"],
        content_sha256=content_tree_digest(content),
        entrypoints=["bin/java"],
        installed_at=utc_now(),
    )
    (content.parent / "installed.json").write_text(record.model_dump_json())
    monkeypatch.setattr("white_hat_agent.adapter_registry.shutil.which", lambda _name: None)

    paths, identities = manager._requirement_observations(tool, current_platform())

    assert paths == [str(java.resolve())]
    assert identities == [observed_tool_identity_digest([str(java.resolve())])]


def test_runtime_only_adapter_remains_resolvable_without_a_fake_operation(tmp_path) -> None:
    runtime = _runtime_manifest()
    manager = AdapterManager(_registry(tmp_path, [runtime]), tmp_path / "managed")

    selection = manager.resolve(["runtime.java"])

    assert selection.complete
    assert selection.selected_adapters == [runtime.adapter_id]


def test_release_entrypoint_rejects_unknown_or_repeated_templates() -> None:
    with pytest.raises(ValueError, match=r"one \{version\} placeholder"):
        GitHubReleaseProvisioner(
            repository="example/tool",
            asset_patterns={"any": [r"^tool\.xz$"]},
            entrypoints={"any": ["tool-{revision}"]},
            max_download_bytes=1_000,
            max_install_bytes=2_000,
        )
    with pytest.raises(ValueError, match=r"one \{version\} placeholder"):
        GitHubReleaseProvisioner(
            repository="example/tool",
            asset_patterns={"any": [r"^tool\.xz$"]},
            entrypoints={"any": ["tool-{version}-{version}"]},
            max_download_bytes=1_000,
            max_install_bytes=2_000,
        )


def test_provision_materializes_bounded_archive_atomically(tmp_path, monkeypatch) -> None:
    definition = GitHubReleaseProvisioner(
        repository="example/tool",
        asset_patterns={"any": [r"^tool\.zip$"]},
        entrypoints={"any": ["tool"]},
        max_download_bytes=1_000_000,
        max_install_bytes=2_000_000,
    )
    manifest = _tool_manifest(provisioner=definition)
    registry = _registry(tmp_path, [manifest])
    manager = AdapterManager(registry, tmp_path / "managed")
    archive = tmp_path / "fixture.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("tool-2.0.0/tool", "fixture\n")
    artifact = ResolvedArtifact(
        name="tool.zip",
        url="https://github.com/example/tool/releases/download/v2.0.0/tool.zip",
        size=archive.stat().st_size,
        sha256="a" * 64,
    )
    plan = AdapterProvisionPlan(
        adapter_id=manifest.adapter_id,
        manifest_digest=manifest.digest(),
        platform=current_platform(),
        method="github-release",
        action=ProvisionAction.INSTALL,
        target_version="2.0.0",
        revision="v2.0.0",
        source_urls=[
            "https://api.github.com/repos/example/tool/releases/latest",
            artifact.url,
        ],
        artifacts=[artifact],
        entrypoints=["tool"],
        strip_single_directory=True,
        max_download_bytes=definition.max_download_bytes,
        max_install_bytes=definition.max_install_bytes,
        created_at=utc_now(),
    )
    monkeypatch.setattr(
        adapter_provisioning,
        "_download_artifact",
        lambda _artifact, destination, max_bytes: shutil.copyfile(archive, destination),
    )

    result = AdapterProvisioner(manager).provision(plan)

    assert result.changed
    assert (tmp_path / "managed/fixture-tool/content/tool").read_text() == "fixture\n"
    installed = InstalledAdapterRecord.model_validate_json(
        (tmp_path / "managed/fixture-tool/installed.json").read_text()
    )
    assert installed.revision == "v2.0.0"


def test_provision_rejects_plan_bounds_that_do_not_match_manifest(tmp_path) -> None:
    definition = GitHubReleaseProvisioner(
        repository="example/tool",
        asset_patterns={"any": [r"^tool\.zip$"]},
        entrypoints={"any": ["tool"]},
        max_download_bytes=1_000_000,
        max_install_bytes=2_000_000,
    )
    manifest = _tool_manifest(provisioner=definition)
    manager = AdapterManager(_registry(tmp_path, [manifest]), tmp_path / "managed")
    artifact = ResolvedArtifact(
        name="tool.zip",
        url="https://github.com/example/tool/releases/download/v2.0.0/tool.zip",
        size=123,
        sha256="a" * 64,
    )
    plan = AdapterProvisionPlan(
        adapter_id=manifest.adapter_id,
        manifest_digest=manifest.digest(),
        platform=current_platform(),
        method="github-release",
        action=ProvisionAction.INSTALL,
        target_version="2.0.0",
        revision="v2.0.0",
        source_urls=["https://api.github.com/repos/example/tool/releases/latest", artifact.url],
        artifacts=[artifact],
        entrypoints=["tool"],
        strip_single_directory=True,
        max_download_bytes=definition.max_download_bytes,
        max_install_bytes=definition.max_install_bytes + 1,
        created_at=utc_now(),
    )

    with pytest.raises(AdapterRegistryError, match="install bound"):
        AdapterProvisioner(manager).provision(plan)


def test_release_artifact_name_must_not_escape_download_root() -> None:
    with pytest.raises(ValueError, match="portable file name"):
        ResolvedArtifact(
            name="../../outside.zip",
            url="https://github.com/example/tool/releases/download/v1/outside.zip",
            size=1,
            sha256="a" * 64,
        )


def test_archive_traversal_is_rejected(tmp_path) -> None:
    archive = tmp_path / "unsafe.zip"
    destination = tmp_path / "output"
    destination.mkdir()
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("../escape", "no")

    with pytest.raises(AdapterRegistryError, match="escapes"):
        _materialize_assets(
            [archive],
            destination,
            strip_single_directory=False,
            max_install_bytes=1_000_000,
        )
    assert not (tmp_path / "escape").exists()


def test_raw_xz_release_asset_is_bounded_and_materialized(tmp_path) -> None:
    archive = tmp_path / "tool-2.3.4.xz"
    archive.write_bytes(lzma.compress(b"standalone executable payload"))
    destination = tmp_path / "output"
    destination.mkdir()

    _materialize_assets(
        [archive],
        destination,
        strip_single_directory=False,
        max_install_bytes=128,
    )

    assert (destination / "tool-2.3.4").read_bytes() == b"standalone executable payload"

    bounded = tmp_path / "bounded"
    bounded.mkdir()
    with pytest.raises(AdapterRegistryError, match="extracted-byte limit"):
        _materialize_assets(
            [archive],
            bounded,
            strip_single_directory=False,
            max_install_bytes=8,
        )


def test_knowledge_search_preserves_snapshot_revision_and_locations(tmp_path) -> None:
    manifest = _knowledge_manifest()
    registry = _registry(tmp_path, [manifest])
    manager = AdapterManager(registry, tmp_path / "managed")
    root = tmp_path / "managed/fixture-knowledge"
    content = root / "content"
    content.mkdir(parents=True)
    (content / "data.json").write_text('{"name": "Command and Scripting Interpreter"}\n')
    record = InstalledAdapterRecord(
        adapter_id=manifest.adapter_id,
        manifest_digest=manifest.digest(),
        version="1.0.0",
        revision="f" * 40,
        source_urls=["https://github.com/example/data"],
        content_sha256=content_tree_digest(content),
        installed_at=utc_now(),
    )
    (root / "installed.json").write_text(record.model_dump_json())

    status = manager.status(manifest.adapter_id)
    hits = manager.search_knowledge(manifest.adapter_id, "scripting interpreter")

    assert status.healthy
    assert status.available_capabilities == manifest.capabilities
    assert status.conformant_operations == []
    assert len(hits) == 1
    assert hits[0].revision == "f" * 40
    assert hits[0].relative_path == "data.json"
    assert hits[0].line == 1
    excerpt = manager.read_knowledge(manifest.adapter_id, "data.json", line_count=10)
    assert excerpt.revision == "f" * 40
    assert "Scripting Interpreter" in excerpt.text
    with pytest.raises(AdapterRegistryError, match="relative"):
        manager.read_knowledge(manifest.adapter_id, "../outside")


def test_knowledge_search_fails_closed_after_snapshot_tampering(tmp_path) -> None:
    manifest = _knowledge_manifest()
    manager = AdapterManager(_registry(tmp_path, [manifest]), tmp_path / "managed")
    root = tmp_path / "managed/fixture-knowledge"
    content = root / "content"
    content.mkdir(parents=True)
    data = content / "data.json"
    data.write_text('{"name": "original"}\n')
    record = InstalledAdapterRecord(
        adapter_id=manifest.adapter_id,
        manifest_digest=manifest.digest(),
        version="1.0.0",
        revision="f" * 40,
        source_urls=["https://github.com/example/data"],
        content_sha256=content_tree_digest(content),
        installed_at=utc_now(),
    )
    (root / "installed.json").write_text(record.model_dump_json())
    data.write_text('{"name": "tampered"}\n')

    status = manager.status(manifest.adapter_id)

    assert not status.healthy
    assert "managed knowledge snapshot integrity check failed" in status.blockers
    with pytest.raises(AdapterRegistryError, match="not ready"):
        manager.search_knowledge(manifest.adapter_id, "tampered")


def test_content_tree_digest_is_unambiguous_across_file_boundaries(tmp_path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    (first / "a").write_bytes(b"X\0b\0Y")
    (second / "a").write_bytes(b"X")
    (second / "b").write_bytes(b"Y")

    assert content_tree_digest(first) != content_tree_digest(second)
