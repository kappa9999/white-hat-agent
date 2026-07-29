from __future__ import annotations

import json
import shutil
import sys
import zipfile
from pathlib import Path

import pytest
import yaml

from white_hat_agent import adapter_provisioning
from white_hat_agent.adapter_provisioning import (
    AdapterProvisioner,
    AdapterProvisionPlan,
    ProvisionAction,
    ResolvedArtifact,
    _materialize_assets,
)
from white_hat_agent.adapter_registry import (
    AdapterCatalogManifest,
    AdapterKind,
    AdapterLicense,
    AdapterManager,
    AdapterManifest,
    AdapterRegistry,
    AdapterRegistryError,
    AdapterStatus,
    GitHubReleaseProvisioner,
    InstalledAdapterRecord,
    ProbeDefinition,
    content_tree_digest,
    current_platform,
)
from white_hat_agent.knowledge.models import ExecutionClass
from white_hat_agent.models import ExecutionMode, utc_now

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


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
    return AdapterManifest(
        adapter_id=adapter_id,
        title="Fixture tool",
        description="Fixture reverse engineering tool",
        kind=AdapterKind.TOOL,
        provider="Fixture",
        provider_url="https://example.test/tool",
        license=_license(),
        capabilities=capabilities or ["artifact.inspect"],
        modes=[ExecutionMode.OFFLINE],
        max_execution_class=ExecutionClass.ANALYSIS,
        platforms=["any"],
        probe=ProbeDefinition(
            executable_names={"any": ["fixture-tool"]},
            version_args=["--version"],
            version_pattern=r"Python (?P<version>[0-9]+(?:\.[0-9]+)+)",
        ),
        provisioner=provisioner,
        updated_at=utc_now(),
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


def test_builtin_registry_is_nonredundant_and_searchable() -> None:
    registry = AdapterRegistry(
        REPOSITORY_ROOT / "adapters/catalog.yaml",
        capability_execution_classes={
            "artifact.inspect": ExecutionClass.ANALYSIS,
            "binary.diff": ExecutionClass.ANALYSIS,
            "code.search": ExecutionClass.ANALYSIS,
            "graph.reason": ExecutionClass.ANALYSIS,
            "hypothesis.generate": ExecutionClass.ANALYSIS,
            "mobile.runtime-observe": ExecutionClass.READ_ONLY,
            "mobile.static-inspect": ExecutionClass.ANALYSIS,
            "trace.capture": ExecutionClass.READ_ONLY,
        },
    )

    report = registry.load()
    reverse = registry.search("reverse")
    knowledge = registry.search("", kind=AdapterKind.KNOWLEDGE)

    assert report.valid
    assert report.adapter_count == 9
    assert reverse[0].adapter.adapter_id == "ghidra"
    assert {item.adapter.adapter_id for item in knowledge} == {
        "capa-rules",
        "mitre-attack",
    }


def test_status_observes_real_path_and_version_without_installing(tmp_path, monkeypatch) -> None:
    registry = _registry(tmp_path, [_tool_manifest()])
    manager = AdapterManager(registry, tmp_path / "managed")
    monkeypatch.setattr(
        "white_hat_agent.adapter_registry.shutil.which",
        lambda executable: sys.executable if executable == "fixture-tool" else None,
    )

    status = manager.status("fixture-tool")

    assert status.healthy
    assert status.source == "system"
    assert status.version
    assert status.entrypoints == [str(Path(sys.executable).resolve())]
    assert status.available_capabilities == ["artifact.inspect"]


def test_status_rejects_a_version_match_from_a_failing_probe(tmp_path, monkeypatch) -> None:
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
    assert status.version == "1.2.3"
    assert "tool version probe did not satisfy the manifest" in status.blockers


def test_probe_rejects_arbitrary_command_arguments() -> None:
    for arguments in (["-c", "print('executed')"], ["version"]):
        with pytest.raises(ValueError):
            ProbeDefinition(
                executable_names={"any": ["python3"]},
                version_args=arguments,
                version_pattern=r"(?P<version>[0-9.]+)",
            )


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
            available_capabilities=manifest.capabilities if healthy else [],
            blockers=[] if healthy else ["not installed"],
        )

    monkeypatch.setattr(manager, "status", fake_status)

    selection = manager.resolve(["artifact.inspect", "code.search"], kind=AdapterKind.TOOL)

    assert selection.complete
    assert not selection.ready
    assert selection.selected_adapters == ["healthy", "installable"]
    assert selection.provisioning_required == ["installable"]


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
            available_capabilities=manifest.capabilities,
        )

    monkeypatch.setattr(manager, "status", healthy_status)

    selection = manager.resolve(["a", "b", "c", "d", "e", "f"])

    assert selection.complete
    assert selection.ready
    assert selection.selected_adapters == ["left", "right"]


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

    hits = manager.search_knowledge(manifest.adapter_id, "scripting interpreter")

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
