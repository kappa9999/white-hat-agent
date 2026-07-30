from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from white_hat_agent.adapter_execution import (
    DRIVER_VERSION,
    MINIMUM_EVIDENCE_IMPORT_BYTES,
    SANDBOX_PROFILE_SHA256,
    AdapterExecutionBroker,
    AdapterExecutionError,
    AdapterExecutionOutcome,
    AdapterExecutionReceipt,
    AdapterExecutionRequest,
    AdapterLimitOverrides,
    LlvmObjectInspectDriver,
    LlvmObjectInspectPayload,
    OfflineSandboxSupervisor,
    SupervisedProcessResult,
    TrustedInvocation,
    _effective_limits,
    _fixture_bytes,
    _tree_usage,
    conformance_report_is_current,
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
    AdapterStatus,
    OperationResourceLimits,
    ProbeDefinition,
)
from white_hat_agent.campaign.fleet import FleetStore
from white_hat_agent.campaign.models import (
    AgentRegistration,
    CampaignManifest,
    CampaignObjective,
    CampaignPlaybookContract,
    CampaignState,
    DisclosurePolicy,
    ProbeIntent,
    ProgramKind,
    ScopeManifest,
    TargetKind,
    TargetRule,
)
from white_hat_agent.evidence.models import EvidenceDescriptor
from white_hat_agent.evidence.store import EvidenceStore
from white_hat_agent.knowledge.models import ExecutionClass, ReviewState
from white_hat_agent.models import ExecutionMode, utc_now


def _limits() -> OperationResourceLimits:
    return OperationResourceLimits(
        max_input_bytes=1_048_576,
        max_output_bytes=1_048_576,
        max_files=32,
        max_records=100,
        wall_seconds=30,
        cpu_seconds=20,
        memory_mib=512,
        max_processes=16,
    )


def _operation() -> AdapterOperationBinding:
    return AdapterOperationBinding(
        operation_id="llvm.object-inspect",
        operation_version="1.0.0",
        capabilities=["artifact.inspect"],
        execution_class=ExecutionClass.ANALYSIS,
        modes=[ExecutionMode.OFFLINE, ExecutionMode.SANDBOX],
        input_types=["artifact/file"],
        output_types=["artifact/metadata"],
        conformance_suite_id="minimal-elf64-x86-64-v1",
        limits=_limits(),
    )


def _manifest() -> AdapterManifest:
    return AdapterManifest(
        adapter_id="llvm",
        title="LLVM fixture",
        description="Fixed llvm-readobj fixture adapter",
        kind=AdapterKind.TOOL,
        provider="LLVM",
        provider_url="https://llvm.org",
        license=AdapterLicense(
            name="Apache-2.0 WITH LLVM-exception",
            url="https://llvm.org/LICENSE.txt",
            attribution="LLVM Project",
        ),
        capabilities=["artifact.inspect"],
        modes=[ExecutionMode.OFFLINE, ExecutionMode.SANDBOX],
        max_execution_class=ExecutionClass.ANALYSIS,
        platforms=["any"],
        probe=ProbeDefinition(
            executable_names={"any": ["llvm-readobj"]},
            version_args=["--version"],
            version_pattern=r"(?P<version>[0-9]+(?:\.[0-9]+)+)",
        ),
        operations=[_operation()],
        updated_at=utc_now(),
    )


def _registry(tmp_path: Path) -> AdapterRegistry:
    path = tmp_path / "catalog.yaml"
    payload = AdapterCatalogManifest(adapters=[_manifest()]).model_dump(mode="json")
    path.write_text(json.dumps(payload), encoding="utf-8")
    registry = AdapterRegistry(
        path,
        capability_execution_classes={"artifact.inspect": ExecutionClass.ANALYSIS},
    )
    assert registry.load().valid
    return registry


def _campaign() -> CampaignManifest:
    now = datetime.now(UTC)
    scope = ScopeManifest(
        scope_id="adapter-fixture-scope",
        program_kind=ProgramKind.LAB,
        program_name="Owned adapter fixture",
        authorization_reference="Synthetic test fixture owned by the test suite",
        valid_from=now - timedelta(minutes=5),
        valid_until=now + timedelta(hours=1),
        targets=[
            TargetRule(
                rule_id="fixture-binary",
                kind=TargetKind.BINARY,
                pattern="fixture.elf",
            )
        ],
        allowed_execution_classes=[ExecutionClass.ANALYSIS],
        allowed_capabilities=["artifact.inspect"],
        disclosure=DisclosurePolicy(channel="local-test"),
    )
    return CampaignManifest(
        campaign_id="adapter-fixture-campaign",
        name="Typed offline adapter fixture",
        scope=scope,
        objective=CampaignObjective(
            statement="Inspect one owned inert binary",
            success_criteria=["Persist a bounded metadata result"],
        ),
        corpus_manifest_digest="1" * 64,
        selected_playbooks=["adapter-fixture-inspect"],
        playbook_contracts=[
            CampaignPlaybookContract(
                playbook_id="adapter-fixture-inspect",
                version="1.0.0",
                digest="2" * 64,
                review_state=ReviewState.VALIDATED,
                minimum_execution_class=ExecutionClass.ANALYSIS,
                capabilities=["artifact.inspect"],
            )
        ],
    )


class _FixtureSupervisor:
    def __init__(self, *, padding_bytes: int = 0) -> None:
        self.padding_bytes = padding_bytes
        self.calls = 0

    def run(self, invocation, input_path, work_dir, limits) -> SupervisedProcessResult:
        del invocation, input_path, limits
        self.calls += 1
        stdout = work_dir / "stdout.bin"
        stderr = work_dir / "stderr.bin"
        stdout.write_text(
            json.dumps(
                [
                    {
                        "FileSummary": {
                            "File": "/input/artifact",
                            "Format": "elf64-x86-64",
                            "Arch": "x86_64",
                            "AddressSize": "64bit",
                        },
                        "ElfHeader": {"Entry": 4194536},
                        "Sections": [
                            {
                                "Section": {
                                    "Index": 1,
                                    "Name": {"Name": ".text", "Value": 1},
                                    "Size": 12,
                                    "Padding": "x" * self.padding_bytes,
                                }
                            }
                        ],
                        "Symbols": [],
                        "NeededLibraries": [],
                    }
                ]
            ),
            encoding="utf-8",
        )
        stderr.write_bytes(b"")
        return SupervisedProcessResult(
            outcome=AdapterExecutionOutcome.SUCCEEDED,
            return_code=0,
            signal_number=None,
            stdout_path=stdout,
            stderr_path=stderr,
            result_path=None,
            output_complete=True,
            warnings=(),
        )


class _VersionSupervisor:
    def run(self, invocation, input_path, work_dir, limits) -> SupervisedProcessResult:
        del invocation, input_path, limits
        stdout = work_dir / "stdout.bin"
        stderr = work_dir / "stderr.bin"
        stdout.write_text("LLVM version 18.1.3\n", encoding="utf-8")
        stderr.write_bytes(b"")
        return SupervisedProcessResult(
            outcome=AdapterExecutionOutcome.SUCCEEDED,
            return_code=0,
            signal_number=None,
            stdout_path=stdout,
            stderr_path=stderr,
            result_path=None,
            output_complete=True,
            warnings=(),
        )


def test_fixture_and_request_secret_contract() -> None:
    fixture = _fixture_bytes()
    assert len(fixture) == 784
    assert hashlib.sha256(fixture).hexdigest() == (
        "daf49381748b12d617a3c645f9932ade03d7c0cac6b804da1bd35ae80cf37cad"
    )
    request = AdapterExecutionRequest(
        agent_id="fixture-agent",
        task_id="task-fixture",
        lease_token="lease-token-that-is-long-enough",
        operation=LlvmObjectInspectPayload(operation_id="llvm.object-inspect"),
        input_evidence_ids=["evidence-fixture"],
    )
    serialized = request.model_dump_json()
    assert "lease-token-that-is-long-enough" not in serialized
    assert "lease-token-that-is-long-enough" not in request.digest()


def test_limit_overrides_can_only_reduce_contract() -> None:
    reduced = _effective_limits(_limits(), AdapterLimitOverrides(max_records=10, wall_seconds=5))
    assert reduced.max_records == 10
    assert reduced.wall_seconds == 5
    with pytest.raises(AdapterExecutionError, match="exceeds"):
        _effective_limits(_limits(), AdapterLimitOverrides(max_records=101))
    evidence_capped = _effective_limits(
        _limits(),
        AdapterLimitOverrides(),
        max_output_bytes=4096,
    )
    assert evidence_capped.max_output_bytes == 4096


def test_llvm_entrypoint_resolution_is_bounded(tmp_path) -> None:
    executable = tmp_path / "llvm-readobj"
    executable.write_bytes(b"fixture executable")
    status = AdapterStatus(
        adapter_id="llvm",
        manifest_digest="1" * 64,
        observed_at=utc_now(),
        platform="linux-x86_64",
        supported=True,
        installed=True,
        healthy=True,
        source="system",
        version="18.1.3",
        entrypoints=[str(executable)],
        observed_identity_sha256="2" * 64,
    )
    assert (
        LlvmObjectInspectDriver().tool_payload_digest(status.entrypoints)
        == hashlib.sha256(executable.read_bytes()).hexdigest()
    )


def test_llvm_normalization_uses_one_shared_record_budget(tmp_path) -> None:
    stdout = tmp_path / "stdout.bin"
    stderr = tmp_path / "stderr.bin"
    stdout.write_text(
        json.dumps(
            [
                {
                    "FileSummary": {
                        "Format": "elf64-x86-64",
                        "Arch": "x86_64",
                        "AddressSize": "64bit",
                    },
                    "ElfHeader": {},
                    "Sections": [
                        {"Section": {"Name": {"Name": ".text"}}},
                        {"Section": {"Name": {"Name": ".data"}}},
                    ],
                    "Symbols": [{"Symbol": {"Name": "entry"}}],
                    "NeededLibraries": ["libc.so.6"],
                }
            ]
        ),
        encoding="utf-8",
    )
    stderr.write_bytes(b"")
    process = SupervisedProcessResult(
        outcome=AdapterExecutionOutcome.SUCCEEDED,
        return_code=0,
        signal_number=None,
        stdout_path=stdout,
        stderr_path=stderr,
        result_path=None,
        output_complete=True,
        warnings=(),
    )

    normalized = LlvmObjectInspectDriver().normalize(
        process,
        "a" * 64,
        _limits().model_copy(update={"max_records": 2}),
    )

    assert normalized.records_returned == 2
    assert normalized.truncated
    assert len(normalized.data["sections"]) == 2
    assert normalized.data["symbols"] == []
    assert normalized.data["needed_libraries"] == []


def test_sandbox_exposes_tool_work_but_not_broker_captures(tmp_path) -> None:
    executable = tmp_path / "bwrap"
    executable.write_bytes(b"fixture")
    executable.chmod(0o700)
    input_path = tmp_path / "input"
    input_path.write_bytes(b"fixture")
    broker_root = tmp_path / "broker"
    tool_work = broker_root / "tool-work"
    tool_work.mkdir(parents=True)

    command = OfflineSandboxSupervisor(executable)._command(
        TrustedInvocation(argv=("/bin/true",), mounts=()),
        input_path.resolve(),
        tool_work.resolve(),
    )

    assert [str(tool_work), "/work"] == command[command.index("--bind") + 1 : command.index("--bind") + 3]
    assert str(broker_root) not in command


def test_explicit_version_probe_is_fixed_and_parsed_after_supervision(tmp_path) -> None:
    executable = tmp_path / "llvm-readobj"
    executable.write_bytes(b"fixture")
    fixture = tmp_path / "fixture.elf"
    fixture.write_bytes(_fixture_bytes())
    broker = object.__new__(AdapterExecutionBroker)
    broker.supervisor = _VersionSupervisor()

    version, check, warnings = broker._contained_version_probe(
        ProbeDefinition(
            executable_names={"any": ["llvm-readobj"]},
            version_args=["--version"],
            version_pattern=r"(?P<version>[0-9]+(?:\.[0-9]+)+)",
        ),
        executable,
        fixture,
        tmp_path / "probe",
        _limits(),
        name="tool-version",
    )

    assert version == "18.1.3"
    assert check.ok
    assert check.name == "tool-version"
    assert warnings == []


def test_tree_usage_counts_links_without_following_them(tmp_path) -> None:
    (tmp_path / "regular").write_bytes(b"abc")
    (tmp_path / "link").symlink_to("/etc/passwd")

    entries, byte_length = _tree_usage(
        tmp_path,
        stop_after_bytes=1024,
        stop_after_entries=10,
    )

    assert entries == 2
    assert byte_length == 3


def test_execution_requires_lease_and_persists_evidence_without_token(tmp_path, monkeypatch) -> None:
    registry = _registry(tmp_path)
    manager = AdapterManager(
        registry,
        tmp_path / "managed",
        conformance_verifier=conformance_report_is_current,
    )
    executable = tmp_path / "llvm-readobj"
    executable.write_bytes(b"reviewed llvm fixture executable")
    observed_identity = "3" * 64
    status = AdapterStatus(
        adapter_id="llvm",
        manifest_digest=registry.get("llvm").digest(),
        observed_at=utc_now(),
        platform="linux-x86_64",
        supported=True,
        installed=True,
        healthy=True,
        source="system",
        version="18.1.3",
        entrypoints=[str(executable)],
        observed_identity_sha256=observed_identity,
        conformant_operations=["llvm.object-inspect"],
        declared_capabilities=["artifact.inspect"],
        available_capabilities=["artifact.inspect"],
    )
    monkeypatch.setattr(manager, "status", lambda _: status)
    tool_digest = LlvmObjectInspectDriver().tool_payload_digest(status.entrypoints)
    report = AdapterConformanceReport(
        adapter_id="llvm",
        operation_id="llvm.object-inspect",
        operation_version="1.0.0",
        manifest_digest=registry.get("llvm").digest(),
        operation_contract_digest=_operation().digest(),
        observed_identity_sha256=observed_identity,
        requirement_identity_sha256=[],
        tool_payload_sha256=tool_digest,
        tool_version="18.1.3",
        driver_id="whitehat.llvm-readobj",
        driver_version=DRIVER_VERSION,
        sandbox_profile_sha256=SANDBOX_PROFILE_SHA256,
        fixture_id="minimal-elf64-x86-64-v1",
        fixture_sha256="daf49381748b12d617a3c645f9932ade03d7c0cac6b804da1bd35ae80cf37cad",
        started_at=utc_now(),
        finished_at=utc_now(),
        passed=True,
        checks=[AdapterConformanceCheck(name="fixture", ok=True, detail="passed")],
    )
    assert conformance_report_is_current(_operation(), report, status.entrypoints)
    assert not conformance_report_is_current(
        _operation(),
        report.model_copy(update={"driver_version": "1.0.0"}),
        status.entrypoints,
    )
    manager.save_conformance_report(report)

    fleet = FleetStore(tmp_path / "state.db")
    fleet.initialize()
    fleet.create_campaign(_campaign())
    fleet.register_agent(
        AgentRegistration(
            agent_id="fixture-agent",
            display_name="Typed fixture agent",
            provider="test",
            capabilities=["artifact.inspect"],
            max_execution_class=ExecutionClass.ANALYSIS,
        )
    )
    fleet.set_campaign_state("adapter-fixture-campaign", CampaignState.READY)
    fleet.set_campaign_state("adapter-fixture-campaign", CampaignState.RUNNING)
    enqueued = fleet.enqueue_intent(
        "adapter-fixture-campaign",
        ProbeIntent(
            intent_id="adapter-fixture-intent",
            scope_id="adapter-fixture-scope",
            target_kind=TargetKind.BINARY,
            target="fixture.elf",
            playbook_id="adapter-fixture-inspect",
            playbook_version="1.0.0",
            playbook_digest="2" * 64,
            execution_class=ExecutionClass.ANALYSIS,
            capabilities=["artifact.inspect"],
        ),
    )
    assert enqueued.accepted and enqueued.task
    lease = fleet.claim_task("fixture-agent", lease_seconds=60)
    assert lease is not None

    evidence = EvidenceStore(
        tmp_path / "state.db",
        tmp_path / "artifacts",
        max_import_bytes=80_000,
    )
    evidence.initialize()
    source = tmp_path / "fixture.elf"
    source.write_bytes(_fixture_bytes())
    input_record = evidence.import_file(
        source,
        EvidenceDescriptor(
            campaign_id="adapter-fixture-campaign",
            task_id=lease.task.task_id,
            target="fixture.elf",
            evidence_type="artifact/file",
            title="Owned inert ELF",
            description="Synthetic immutable adapter input",
            producer="test-suite",
        ),
    )
    supervisor = _FixtureSupervisor(padding_bytes=77_500)
    broker = AdapterExecutionBroker(
        manager,
        fleet,
        evidence,
        supervisor=supervisor,
    )
    request = AdapterExecutionRequest(
        agent_id="fixture-agent",
        task_id=lease.task.task_id,
        lease_token=lease.lease_token,
        operation=LlvmObjectInspectPayload(operation_id="llvm.object-inspect"),
        input_evidence_ids=[input_record.evidence_id],
    )
    wrong_type = evidence.import_file(
        source,
        input_record.descriptor.model_copy(update={"evidence_type": "adapter/execution-output"}),
    )
    before_capacity_rejection = len(
        evidence.list_evidence(
            campaign_id="adapter-fixture-campaign",
            task_id=lease.task.task_id,
            limit=20,
        )
    )
    evidence.max_import_bytes = MINIMUM_EVIDENCE_IMPORT_BYTES
    with pytest.raises(AdapterExecutionError, match="too small"):
        broker.execute(request)
    assert supervisor.calls == 0
    assert (
        len(
            evidence.list_evidence(
                campaign_id="adapter-fixture-campaign",
                task_id=lease.task.task_id,
                limit=20,
            )
        )
        == before_capacity_rejection
    )
    evidence.max_import_bytes = 80_000
    with pytest.raises(AdapterExecutionError, match="evidence type"):
        broker.execute(request.model_copy(update={"input_evidence_ids": [wrong_type.evidence_id]}))
    assert supervisor.calls == 0
    result = broker.execute(request)

    assert result.outcome == AdapterExecutionOutcome.SUCCEEDED
    assert result.normalized and result.normalized.data["format"] == "elf64-x86-64"
    assert len(json.dumps(result.model_dump(mode="json"))) > evidence.max_import_bytes
    assert supervisor.calls == 1
    assert {capture.name for capture in result.captures} == {
        "stdout",
        "stderr",
        "normalized",
        "execution-manifest",
    }
    assert len(result.evidence_ids) == 4
    receipt = AdapterExecutionReceipt.from_result(result)
    assert receipt.records_returned == result.normalized.records_returned
    assert "normalized" not in receipt.model_dump(mode="json")
    records = evidence.list_evidence(
        campaign_id="adapter-fixture-campaign",
        task_id=lease.task.task_id,
        limit=20,
    )
    manifest_record = next(
        record for record in records if record.descriptor.evidence_type == "adapter/execution-manifest"
    )
    manifest_payload = json.loads(
        (evidence.artifacts_dir / manifest_record.storage_path).read_text(encoding="utf-8")
    )
    assert "normalized" not in manifest_payload
    assert any(
        capture["name"] == "normalized" and capture["evidence_id"]
        for capture in manifest_payload["receipt"]["captures"]
    )
    assert len(json.dumps(manifest_payload)) < 10_000
    for record in records:
        if not record.storage_path:
            continue
        stored = evidence.artifacts_dir / record.storage_path
        assert lease.lease_token.encode() not in stored.read_bytes()
