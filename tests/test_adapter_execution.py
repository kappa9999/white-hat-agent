from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import white_hat_agent.adapter_execution as adapter_execution
from white_hat_agent.adapter_execution import (
    DRIVER_VERSION,
    MINIMUM_EVIDENCE_IMPORT_BYTES,
    SANDBOX_PROFILE_SHA256,
    YARA_X_CONFORMANCE_RULE_SHA256,
    AdapterExecutionBroker,
    AdapterExecutionError,
    AdapterExecutionOutcome,
    AdapterExecutionReceipt,
    AdapterExecutionRequest,
    AdapterLimitOverrides,
    FridaExecutableRuntimeMapDriver,
    FridaExecutableRuntimeMapPayload,
    GhidraNativeCodeMapDriver,
    GhidraNativeCodeMapPayload,
    JadxAndroidStaticMapDriver,
    JadxAndroidStaticMapPayload,
    LlvmObjectInspectDriver,
    LlvmObjectInspectPayload,
    OfflineSandboxSupervisor,
    SandboxInlineFile,
    SandboxMount,
    SupervisedProcessResult,
    TrustedInvocation,
    TsharkPacketCaptureMapDriver,
    TsharkPacketCaptureMapPayload,
    YaraXFileScanDriver,
    YaraXFileScanPayload,
    _effective_limits,
    _fixture_bytes,
    _frida_fixture_bytes,
    _frida_runtime_map_script_bytes,
    _ghidra_native_map_fixture_bytes,
    _jadx_fixture_bytes,
    _temporary_input_mode,
    _tree_usage,
    _tshark_fixture_bytes,
    _yara_x_conformance_rule,
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

    jadx_fixture = _jadx_fixture_bytes()
    assert len(jadx_fixture) == 904
    assert hashlib.sha256(jadx_fixture).hexdigest() == (
        "865d09fc9bc4a407c2bab2516dd2576a63d410d036f30c21b6a28b8b875ec847"
    )
    jadx_request = request.model_copy(
        update={"operation": JadxAndroidStaticMapPayload(operation_id="jadx.android-static-map")}
    )
    assert jadx_request.operation.operation_id == "jadx.android-static-map"

    native_map_fixture = _ghidra_native_map_fixture_bytes()
    assert len(native_map_fixture) == 1496
    assert hashlib.sha256(native_map_fixture).hexdigest() == (
        "160fad2a70818a93807bc01ccfff766f7c3702756e8135ee5239132de9fe56b0"
    )
    native_map_request = request.model_copy(
        update={"operation": GhidraNativeCodeMapPayload(operation_id="ghidra.native-code-map")}
    )
    assert native_map_request.operation.operation_id == "ghidra.native-code-map"

    yara_rule = _yara_x_conformance_rule()
    assert hashlib.sha256(yara_rule.encode()).hexdigest() == YARA_X_CONFORMANCE_RULE_SHA256
    yara_request = request.model_copy(
        update={
            "operation": YaraXFileScanPayload(
                operation_id="yara-x.file-scan",
                rule_source=yara_rule,
            )
        }
    )
    assert yara_request.operation.operation_id == "yara-x.file-scan"
    assert json.loads(yara_request.model_dump_json())["operation"]["rule_source"] == yara_rule
    with pytest.raises(ValueError, match="external files"):
        YaraXFileScanPayload(
            operation_id="yara-x.file-scan",
            rule_source='include "other.yar"',
        )
    with pytest.raises(ValueError, match="external files"):
        YaraXFileScanPayload(
            operation_id="yara-x.file-scan",
            rule_source='include/**/"/usr/share/other.yar"',
        )
    with pytest.raises(ValueError, match="external files"):
        YaraXFileScanPayload(
            operation_id="yara-x.file-scan",
            rule_source='rule first { condition: true }\ninclude "other.yar"',
        )
    lexical_include_text = YaraXFileScanPayload(
        operation_id="yara-x.file-scan",
        rule_source=(
            "/* include comments are inert */\n"
            "rule fixture {\n"
            '  strings: $text = "include" $regex = /include[{}]/\n'
            "  condition: $text or $regex\n"
            "}"
        ),
    )
    assert '"include"' in lexical_include_text.rule_source

    tshark_fixture = _tshark_fixture_bytes()
    assert len(tshark_fixture) == 755
    assert hashlib.sha256(tshark_fixture).hexdigest() == (
        "a932f9b0da893cc34f3ad70d9e51291896ca0c80fd68b923803364797adb619b"
    )
    tshark_request = request.model_copy(
        update={"operation": TsharkPacketCaptureMapPayload(operation_id="tshark.packet-capture-map")}
    )
    assert tshark_request.operation.operation_id == "tshark.packet-capture-map"
    with pytest.raises(ValueError, match="Extra inputs"):
        TsharkPacketCaptureMapPayload(
            operation_id="tshark.packet-capture-map",
            display_filter="http",
        )

    frida_fixture = _frida_fixture_bytes()
    assert len(frida_fixture) == 15_584
    assert hashlib.sha256(frida_fixture).hexdigest() == (
        "57312d10cbae62727393380a716ce7ef5a35502c54030bf3a3420696f85ede21"
    )
    assert b"wha_runtime_marker" in frida_fixture
    frida_request = request.model_copy(
        update={"operation": FridaExecutableRuntimeMapPayload(operation_id="frida.executable-runtime-map")}
    )
    assert frida_request.operation.operation_id == "frida.executable-runtime-map"


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


def test_yara_x_normalization_preserves_rule_identity_matches_and_limits(tmp_path) -> None:
    stdout = tmp_path / "stdout.bin"
    stderr = tmp_path / "stderr.bin"
    stdout.write_text(
        json.dumps(
            {
                "path": "/input/artifact",
                "rules": [
                    {
                        "identifier": "wha_native_marker",
                        "namespace": "default",
                        "meta": [["purpose", "White Hat Agent typed YARA-X conformance"]],
                        "tags": ["conformance"],
                        "strings": [
                            {
                                "identifier": "$marker",
                                "offset": 192,
                                "match": "WHA_NATIVE_CODE_MAP_MARKER",
                            }
                        ],
                    }
                ],
            }
        )
        + "\n",
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
    operation = YaraXFileScanPayload(
        operation_id="yara-x.file-scan",
        rule_source=_yara_x_conformance_rule(),
    )
    driver = YaraXFileScanDriver()

    normalized = driver.normalize(process, "a" * 64, _limits(), operation)

    assert normalized.records_returned == 2
    assert not normalized.truncated
    assert normalized.data["rule_source_sha256"] == YARA_X_CONFORMANCE_RULE_SHA256
    assert normalized.data["rules"][0]["strings"][0]["offset"] == 192
    assert all(check.ok for check in driver.fixture_checks(normalized))

    reduced = driver.normalize(
        process,
        "a" * 64,
        _limits().model_copy(update={"max_records": 1}),
        operation,
    )
    assert reduced.records_returned == 1
    assert reduced.truncated
    assert reduced.data["rules"][0]["strings"] == []
    assert reduced.data["rules"][0]["strings_truncated"] is True


def test_yara_x_normalization_rejects_schema_drift_and_duplicate_rules(tmp_path) -> None:
    stdout = tmp_path / "stdout.bin"
    stderr = tmp_path / "stderr.bin"
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
    operation = YaraXFileScanPayload(
        operation_id="yara-x.file-scan",
        rule_source="rule fixture { condition: true }",
    )
    driver = YaraXFileScanDriver()
    rule = {
        "identifier": "fixture",
        "namespace": "default",
        "meta": [],
        "tags": [],
        "strings": [],
    }

    stdout.write_text(
        json.dumps({"path": "/input/artifact", "rules": [], "unknown": True}) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(AdapterExecutionError, match="target result"):
        driver.normalize(process, "a" * 64, _limits(), operation)

    stdout.write_text(
        json.dumps({"path": "/input/artifact", "rules": [rule, rule]}) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(AdapterExecutionError, match="duplicate rule identities"):
        driver.normalize(process, "a" * 64, _limits(), operation)

    stdout.write_text(
        json.dumps({"path": "/input/artifact", "rules": []})
        + "\n"
        + json.dumps({"path": "/input/artifact", "rules": []})
        + "\n",
        encoding="utf-8",
    )
    with pytest.raises(AdapterExecutionError, match="exactly one"):
        driver.normalize(process, "a" * 64, _limits(), operation)


def test_yara_x_invocation_is_fixed_and_rule_source_is_inline(tmp_path) -> None:
    executable = tmp_path / "yr"
    executable.write_bytes(b"fixture YARA-X executable")
    status = AdapterStatus(
        adapter_id="yara-x",
        manifest_digest="1" * 64,
        observed_at=utc_now(),
        platform="linux-x86_64",
        supported=True,
        installed=True,
        healthy=True,
        source="system",
        version="1.19.0",
        entrypoints=[str(executable)],
        observed_identity_sha256="2" * 64,
    )
    operation = YaraXFileScanPayload(
        operation_id="yara-x.file-scan",
        rule_source="rule fixture { condition: true }",
    )
    driver = YaraXFileScanDriver()
    yara_limits = _limits().model_copy(update={"memory_mib": 2048})

    invocation = driver.prepare(status, operation, yara_limits, {})

    assert invocation.argv[-2:] == ("/input/rules.yar", "/input/artifact")
    assert invocation.argv[0:2] == ("/opt/tool/yr", "scan")
    assert "rule fixture" not in " ".join(invocation.argv)
    assert invocation.inline_files == (SandboxInlineFile("/input/rules.yar", operation.rule_source.encode()),)
    assert {mount.destination for mount in invocation.mounts} == {"/opt/tool/yr"}
    with pytest.raises(AdapterExecutionError, match="at least 8"):
        driver.prepare(
            status,
            operation,
            yara_limits.model_copy(update={"max_processes": 4}),
            {},
        )
    with pytest.raises(AdapterExecutionError, match="2048 MiB"):
        driver.prepare(
            status,
            operation,
            yara_limits.model_copy(update={"memory_mib": 1024}),
            {},
        )
    with pytest.raises(AdapterExecutionError, match="different operation"):
        driver.prepare(
            status,
            LlvmObjectInspectPayload(operation_id="llvm.object-inspect"),
            yara_limits,
            {},
        )


def test_tshark_normalization_preserves_packets_protocols_and_streams(tmp_path) -> None:
    def packet(number: int, protocols: str, fields: dict[str, list[str]]) -> dict:
        return {
            "_index": "packets-2023-11-14",
            "_type": "doc",
            "_score": None,
            "_source": {
                "layers": {
                    "frame.number": [str(number)],
                    "frame.time_epoch": [f"170000000{number}.000000000"],
                    "frame.len": ["72"],
                    "frame.cap_len": ["72"],
                    "frame.protocols": [protocols],
                    **fields,
                }
            },
        }

    packets = [
        packet(
            1,
            "eth:ethertype:ip:udp:dns",
            {
                "ip.src": ["192.0.2.10"],
                "ip.dst": ["198.51.100.53"],
                "udp.srcport": ["53000"],
                "udp.dstport": ["53"],
                "udp.stream": ["0"],
                "dns.id": ["0x1234"],
                "dns.flags.response": ["False"],
                "dns.qry.name": ["fixture.test"],
            },
        ),
        packet(
            2,
            "eth:ethertype:ip:udp:dns",
            {
                "ip.src": ["198.51.100.53"],
                "ip.dst": ["192.0.2.10"],
                "udp.srcport": ["53"],
                "udp.dstport": ["53000"],
                "udp.stream": ["0"],
                "dns.id": ["0x1234"],
                "dns.flags.response": ["True"],
                "dns.qry.name": ["fixture.test"],
                "dns.a": ["203.0.113.7"],
                "dns.flags.rcode": ["0"],
            },
        ),
        packet(
            3,
            "eth:ethertype:ip:tcp:http",
            {
                "ip.src": ["192.0.2.10"],
                "ip.dst": ["198.51.100.80"],
                "tcp.srcport": ["49152"],
                "tcp.dstport": ["80"],
                "tcp.stream": ["0"],
                "tcp.flags": ["0x0018"],
                "tcp.seq": ["1"],
                "tcp.ack": ["1"],
                "tcp.len": ["104"],
                "http.request.method": ["GET"],
                "http.host": ["fixture.test"],
                "http.request.uri": ["/status?fixture=1"],
            },
        ),
    ]
    stdout = tmp_path / "stdout.bin"
    stderr = tmp_path / "stderr.bin"
    stdout.write_text(json.dumps(packets), encoding="utf-8")
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
    operation = TsharkPacketCaptureMapPayload(operation_id="tshark.packet-capture-map")
    driver = TsharkPacketCaptureMapDriver()

    normalized = driver.normalize(process, "a" * 64, _limits(), operation)

    assert normalized.records_returned == 3
    assert not normalized.truncated
    assert normalized.data["protocol_counts"] == {
        "dns": 2,
        "eth": 3,
        "ethertype": 3,
        "http": 1,
        "ip": 3,
        "tcp": 1,
        "udp": 2,
    }
    assert normalized.data["packets"][1]["fields"]["dns_is_response"] == [True]
    assert normalized.data["packets"][2]["fields"]["tcp_source_port"] == [49152]
    assert [item["transport"] for item in normalized.data["streams"]] == ["tcp", "udp"]

    stdout.write_text(json.dumps(packets[:2]), encoding="utf-8")
    capped = driver.normalize(
        process,
        "a" * 64,
        _limits().model_copy(update={"max_records": 2}),
        operation,
    )
    assert capped.records_returned == 2
    assert capped.truncated
    assert capped.data["packet_limit_reached"] is True


def test_tshark_normalization_rejects_schema_drift_and_unordered_frames(tmp_path) -> None:
    layers = {
        "frame.number": ["1"],
        "frame.time_epoch": ["1700000000.000000000"],
        "frame.len": ["42"],
        "frame.cap_len": ["42"],
        "frame.protocols": ["eth:ethertype:arp"],
    }
    packet = {"_source": {"layers": layers}}
    stdout = tmp_path / "stdout.bin"
    stderr = tmp_path / "stderr.bin"
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
    driver = TsharkPacketCaptureMapDriver()
    operation = TsharkPacketCaptureMapPayload(operation_id="tshark.packet-capture-map")

    stdout.write_text(json.dumps([{**packet, "unexpected": True}]), encoding="utf-8")
    with pytest.raises(AdapterExecutionError, match="unexpected packet metadata"):
        driver.normalize(process, "a" * 64, _limits(), operation)

    stdout.write_text(json.dumps([packet, packet]), encoding="utf-8")
    with pytest.raises(AdapterExecutionError, match="unordered frame numbers"):
        driver.normalize(process, "a" * 64, _limits(), operation)

    stdout.write_text(
        json.dumps([{"_source": {"layers": {**layers, "caller.option": ["unsafe"]}}}]),
        encoding="utf-8",
    )
    with pytest.raises(AdapterExecutionError, match="unselected field"):
        driver.normalize(process, "a" * 64, _limits(), operation)


def test_tshark_invocation_is_fixed_and_offline(tmp_path) -> None:
    executable = tmp_path / "tshark"
    executable.write_bytes(b"fixture TShark executable")
    status = AdapterStatus(
        adapter_id="tshark",
        manifest_digest="1" * 64,
        observed_at=utc_now(),
        platform="linux-x86_64",
        supported=True,
        installed=True,
        healthy=True,
        source="system",
        version="4.2.2",
        entrypoints=[str(executable)],
        observed_identity_sha256="2" * 64,
    )
    driver = TsharkPacketCaptureMapDriver()
    operation = TsharkPacketCaptureMapPayload(operation_id="tshark.packet-capture-map")

    invocation = driver.prepare(status, operation, _limits(), {})

    assert invocation.argv[:3] == ("/opt/tool/tshark", "-r", "/input/artifact")
    assert "-n" in invocation.argv
    assert invocation.argv[invocation.argv.index("-c") + 1] == "100"
    assert invocation.argv[invocation.argv.index("--temp-dir") + 1] == "/tmp"
    assert "frame.protocols" in invocation.argv
    assert "http.request.uri" in invocation.argv
    assert "tls.handshake.extensions_server_name" in invocation.argv
    assert invocation.mounts == (SandboxMount(executable, "/opt/tool/tshark"),)
    with pytest.raises(AdapterExecutionError, match="different operation"):
        driver.prepare(
            status,
            LlvmObjectInspectPayload(operation_id="llvm.object-inspect"),
            _limits(),
            {},
        )


def _frida_output_payload() -> dict[str, object]:
    main = {
        "name": "artifact",
        "path": "/input/artifact",
        "base": "0x400000",
        "size": 15_584,
    }
    return {
        "schema_version": "1.0",
        "producer": "frida-inject",
        "execution_phase": "spawned-before-main",
        "cleanup_strategy": "eternalize-then-pid-namespace-teardown",
        "process": {
            "arch": "x64",
            "platform": "linux",
            "pointer_size": 8,
            "page_size": 4096,
            "code_signing_policy": "optional",
        },
        "main_module": main,
        "modules": {
            "total": 2,
            "returned": 2,
            "truncated": False,
            "items": [
                main,
                {
                    "name": "libc.so.6",
                    "path": "/usr/lib/libc.so.6",
                    "base": "0x70000000",
                    "size": 2_000_000,
                },
            ],
        },
        "imports": {
            "total": 1,
            "returned": 1,
            "truncated": False,
            "items": [
                {
                    "type": "function",
                    "name": "__libc_start_main",
                    "module": "libc.so.6",
                    "address": "0x70000100",
                    "slot": "0x403ff0",
                }
            ],
        },
        "exports": {
            "total": 1,
            "returned": 1,
            "truncated": False,
            "items": [
                {
                    "type": "function",
                    "name": "wha_runtime_marker",
                    "address": "0x401126",
                    "offset_from_main": "0x1126",
                }
            ],
        },
        "dependencies": {
            "total": 1,
            "returned": 1,
            "truncated": False,
            "items": [{"name": "libc.so.6", "type": "regular"}],
        },
        "collection_errors": [],
    }


def test_frida_normalization_preserves_runtime_map_and_enforces_record_budget(tmp_path) -> None:
    stdout = tmp_path / "stdout.bin"
    stderr = tmp_path / "stderr.bin"
    payload = _frida_output_payload()
    stdout.write_text(
        "WHA_FRIDA_RUNTIME_MAP_V1 " + json.dumps(payload) + "\nProcess terminated\n",
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
    operation = FridaExecutableRuntimeMapPayload(operation_id="frida.executable-runtime-map")
    driver = FridaExecutableRuntimeMapDriver()

    normalized = driver.normalize(process, "a" * 64, _limits(), operation)

    assert normalized.records_returned == 5
    assert not normalized.truncated
    assert normalized.data["main_module"] == payload["main_module"]
    collections = normalized.data["collections"]
    assert collections["exports"]["items"][0]["name"] == "wha_runtime_marker"
    assert collections["dependencies"]["items"] == [{"name": "libc.so.6", "type": "regular"}]

    capped = driver.normalize(
        process,
        "a" * 64,
        _limits().model_copy(update={"max_records": 3}),
        operation,
    )
    assert capped.records_returned == 3
    assert capped.truncated
    assert capped.data["record_limit_reached"] is True
    assert capped.data["collections"]["exports"]["observed"] == 1
    assert capped.data["collections"]["exports"]["returned"] == 0


def test_frida_normalization_rejects_marker_and_schema_drift(tmp_path) -> None:
    stdout = tmp_path / "stdout.bin"
    stderr = tmp_path / "stderr.bin"
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
    operation = FridaExecutableRuntimeMapPayload(operation_id="frida.executable-runtime-map")
    driver = FridaExecutableRuntimeMapDriver()
    encoded = json.dumps(_frida_output_payload())

    stdout.write_text(
        f"WHA_FRIDA_RUNTIME_MAP_V1 {encoded}\nWHA_FRIDA_RUNTIME_MAP_V1 {encoded}\n",
        encoding="utf-8",
    )
    with pytest.raises(AdapterExecutionError, match="exactly one marked JSON"):
        driver.normalize(process, "a" * 64, _limits(), operation)

    drifted = _frida_output_payload()
    drifted["unexpected"] = True
    stdout.write_text("WHA_FRIDA_RUNTIME_MAP_V1 " + json.dumps(drifted), encoding="utf-8")
    with pytest.raises(AdapterExecutionError, match="unexpected outer schema"):
        driver.normalize(process, "a" * 64, _limits(), operation)

    invalid_pointer = _frida_output_payload()
    invalid_pointer["main_module"] = {
        **invalid_pointer["main_module"],
        "base": "not-a-pointer",
    }
    stdout.write_text(
        "WHA_FRIDA_RUNTIME_MAP_V1 " + json.dumps(invalid_pointer),
        encoding="utf-8",
    )
    with pytest.raises(AdapterExecutionError, match="module base"):
        driver.normalize(process, "a" * 64, _limits(), operation)


def test_frida_invocation_is_fixed_local_spawn_and_binds_script(tmp_path) -> None:
    executable = tmp_path / "frida-inject-17.16.4-linux-x86_64"
    executable.write_bytes(b"fixture standalone Frida executable")
    status = AdapterStatus(
        adapter_id="frida",
        manifest_digest="1" * 64,
        observed_at=utc_now(),
        platform="linux-x86_64",
        supported=True,
        installed=True,
        healthy=True,
        source="managed",
        version="17.16.4",
        entrypoints=[str(executable)],
        observed_identity_sha256="2" * 64,
    )
    driver = FridaExecutableRuntimeMapDriver()
    operation = FridaExecutableRuntimeMapPayload(operation_id="frida.executable-runtime-map")
    limits = _limits().model_copy(update={"memory_mib": 2048})
    original_digest = driver.tool_payload_digest(status.entrypoints)

    invocation = driver.prepare(status, operation, limits, {})

    assert invocation.argv == (
        "/opt/tool/frida-inject",
        "--file=/input/artifact",
        "--script=/input/runtime-map.js",
        "--runtime=qjs",
        "--eternalize",
    )
    assert invocation.mounts == (SandboxMount(executable, "/opt/tool/frida-inject"),)
    assert invocation.executable_input
    assert len(invocation.inline_files) == 1
    assert invocation.inline_files[0].destination == "/input/runtime-map.js"
    assert invocation.inline_files[0].content == _frida_runtime_map_script_bytes()
    assert not any(flag in " ".join(invocation.argv) for flag in ("--device", "--pid", "--name"))
    executable.write_bytes(b"drifted standalone Frida executable")
    assert driver.tool_payload_digest(status.entrypoints) != original_digest
    with pytest.raises(AdapterExecutionError, match="different operation"):
        driver.prepare(
            status,
            LlvmObjectInspectPayload(operation_id="llvm.object-inspect"),
            limits,
            {},
        )


def test_executable_input_mode_is_temporary_and_never_writable(tmp_path) -> None:
    artifact = tmp_path / "artifact"
    artifact.write_bytes(b"fixture")
    artifact.chmod(0o400)

    with _temporary_input_mode(artifact, executable=True):
        assert artifact.stat().st_mode & 0o777 == 0o500

    assert artifact.stat().st_mode & 0o777 == 0o400


def test_jadx_normalization_preserves_code_graph_and_manifest(tmp_path) -> None:
    output = tmp_path / "jadx-output"
    class_directory = output / "sources/org/whitehat/fixture"
    resource_directory = output / "resources"
    class_directory.mkdir(parents=True)
    resource_directory.mkdir()
    (output / "sources/mapping.json").write_text(
        json.dumps(
            {
                "classes": [
                    {
                        "name": "org.whitehat.fixture.MinimalAndroid",
                        "alias": "org.whitehat.fixture.MinimalAndroid",
                        "json": "org/whitehat/fixture/MinimalAndroid.json",
                        "inner": False,
                        "methods": [
                            {"signature": "marker()Ljava/lang/String;", "name": "marker"},
                            {"signature": "markerLength()I", "name": "markerLength"},
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (output / "callgraph.json").write_text(
        json.dumps(
            {
                "nodes": [
                    {
                        "id": 3,
                        "method": "org.whitehat.fixture.MinimalAndroid.marker()Ljava/lang/String;",
                    },
                    {
                        "id": 4,
                        "method": "org.whitehat.fixture.MinimalAndroid.markerLength()I",
                    },
                ],
                "edges": [{"from": 4, "to": 3, "resolved": True}],
            }
        ),
        encoding="utf-8",
    )
    (class_directory / "MinimalAndroid.json").write_text(
        json.dumps(
            {
                "name": "org.whitehat.fixture.MinimalAndroid",
                "methods": [
                    {
                        "name": "marker",
                        "lines": [{"code": 'return "WHA_ANDROID_FIXTURE";'}],
                    },
                    {"name": "markerLength", "lines": [{"code": "return marker().length();"}]},
                ],
            }
        ),
        encoding="utf-8",
    )
    manifest = '<manifest package="org.whitehat.fixture" />\n'
    (resource_directory / "AndroidManifest.xml").write_text(manifest, encoding="utf-8")
    stdout = tmp_path / "stdout.bin"
    stderr = tmp_path / "stderr.bin"
    stdout.write_bytes(b"")
    stderr.write_bytes(b"")
    process = SupervisedProcessResult(
        outcome=AdapterExecutionOutcome.SUCCEEDED,
        return_code=0,
        signal_number=None,
        stdout_path=stdout,
        stderr_path=stderr,
        result_path=output,
        output_complete=True,
        warnings=(),
    )

    driver = JadxAndroidStaticMapDriver()
    normalized = driver.normalize(process, "a" * 64, _limits())

    assert normalized.records_returned == 5
    assert not normalized.truncated
    assert normalized.data["format"] == "jadx-json"
    assert normalized.data["resources"]["items"][0]["text"] == manifest
    assert all(check.ok for check in driver.fixture_checks(normalized))

    reduced = driver.normalize(
        process,
        "a" * 64,
        _limits().model_copy(update={"max_records": 2}),
    )
    assert reduced.records_returned == 2
    assert reduced.truncated


def test_ghidra_native_map_normalization_preserves_code_calls_strings_and_xrefs(
    tmp_path,
) -> None:
    output = tmp_path / "native-code-map.json"
    output.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "program": {
                    "name": "fixture.elf",
                    "format": "Executable and Linking Format (ELF)",
                    "language": "x86:LE:64:default",
                    "compiler_spec": "gcc",
                    "image_base": "00400000",
                },
                "analysis": {
                    "decompile_failures": 0,
                    "code_truncated_functions": 0,
                    "decompiled_characters": 57,
                },
                "functions": {
                    "total": 2,
                    "returned": 2,
                    "truncated": False,
                    "items": [
                        {
                            "name": "wha_marker",
                            "namespace": "Global",
                            "entry": "00401000",
                            "signature": "char * wha_marker(void)",
                            "body_addresses": 8,
                            "external": False,
                            "thunk": False,
                            "decompile_status": "completed",
                            "decompiler_message": "",
                            "code_truncated": False,
                            "code": 'return "WHA_NATIVE_CODE_MAP_MARKER";',
                        },
                        {
                            "name": "wha_marker_length",
                            "namespace": "Global",
                            "entry": "0040100f",
                            "signature": "ulong wha_marker_length(void)",
                            "body_addresses": 60,
                            "external": False,
                            "thunk": False,
                            "decompile_status": "completed",
                            "decompiler_message": "",
                            "code_truncated": False,
                            "code": "value = wha_marker();",
                        },
                    ],
                },
                "call_edges": {
                    "returned": 1,
                    "truncated": False,
                    "items": [
                        {
                            "from_entry": "0040100f",
                            "from_name": "wha_marker_length",
                            "callsite": "0040101b",
                            "to_address": "00401000",
                            "to_entry": "00401000",
                            "to_name": "wha_marker",
                            "reference_type": "UNCONDITIONAL_CALL",
                            "external": False,
                        }
                    ],
                },
                "strings": {
                    "returned": 1,
                    "truncated": False,
                    "items": [
                        {
                            "address": "00402000",
                            "data_type": "string",
                            "byte_length": 27,
                            "value_truncated": False,
                            "value": "WHA_NATIVE_CODE_MAP_MARKER",
                        }
                    ],
                },
                "string_xrefs": {
                    "returned": 1,
                    "truncated": False,
                    "items": [
                        {
                            "from_address": "00401008",
                            "to_address": "00402000",
                            "reference_type": "DATA",
                            "operand_index": 1,
                            "source_function_entry": "00401000",
                            "source_function_name": "wha_marker",
                        }
                    ],
                },
            }
        ),
        encoding="utf-8",
    )
    stdout = tmp_path / "stdout.bin"
    stderr = tmp_path / "stderr.bin"
    stdout.write_bytes(b"")
    stderr.write_bytes(b"")
    process = SupervisedProcessResult(
        outcome=AdapterExecutionOutcome.SUCCEEDED,
        return_code=0,
        signal_number=None,
        stdout_path=stdout,
        stderr_path=stderr,
        result_path=output,
        output_complete=True,
        warnings=(),
    )

    driver = GhidraNativeCodeMapDriver()
    normalized = driver.normalize(process, "a" * 64, _limits())

    assert normalized.records_returned == 5
    assert not normalized.truncated
    assert all(check.ok for check in driver.fixture_checks(normalized))

    malformed = json.loads(output.read_text(encoding="utf-8"))
    malformed["functions"]["returned"] = 1
    output.write_text(json.dumps(malformed), encoding="utf-8")
    with pytest.raises(AdapterExecutionError, match="section counters"):
        driver.normalize(process, "a" * 64, _limits())

    malformed["functions"]["returned"] = 2
    malformed["unexpected"] = True
    output.write_text(json.dumps(malformed), encoding="utf-8")
    with pytest.raises(AdapterExecutionError, match="top-level schema drifted"):
        driver.normalize(process, "a" * 64, _limits())

    del malformed["unexpected"]
    malformed["analysis"]["decompiled_characters"] = 58
    output.write_text(json.dumps(malformed), encoding="utf-8")
    with pytest.raises(AdapterExecutionError, match="counters do not match"):
        driver.normalize(process, "a" * 64, _limits())


def test_ghidra_native_map_invocation_is_fixed(tmp_path, monkeypatch) -> None:
    root = tmp_path / "ghidra"
    entrypoint = root / "support/analyzeHeadless"
    entrypoint.parent.mkdir(parents=True)
    entrypoint.write_bytes(b"reviewed launcher")
    script = tmp_path / "WhaNativeCodeMap.java"
    script.write_bytes(b"reviewed script")
    java = tmp_path / "java"
    java.mkdir()
    monkeypatch.setattr(
        adapter_execution,
        "_system_java_mounts",
        lambda: (adapter_execution.SandboxMount(java, "/opt/java"),),
    )
    status = AdapterStatus(
        adapter_id="ghidra",
        manifest_digest="1" * 64,
        observed_at=utc_now(),
        platform="linux-x86_64",
        supported=True,
        installed=True,
        healthy=True,
        source="system",
        version="12.1.2",
        entrypoints=[str(entrypoint)],
        observed_identity_sha256="2" * 64,
    )
    driver = GhidraNativeCodeMapDriver()
    invocation = driver.prepare(
        status,
        GhidraNativeCodeMapPayload(operation_id="ghidra.native-code-map"),
        _limits(),
        {"ghidra_native_map_script": script},
    )

    assert invocation.result_relative_path == "native-code-map.json"
    assert invocation.argv[0] == "/opt/tool/support/analyzeHeadless"
    assert invocation.argv[invocation.argv.index("-postScript") + 1] == "WhaNativeCodeMap.java"
    assert invocation.argv[invocation.argv.index("-import") + 1] == "/input/artifact"
    assert {mount.destination for mount in invocation.mounts} == {
        "/opt/tool",
        "/opt/java",
        "/opt/wha-assets/WhaNativeCodeMap.java",
    }
    with pytest.raises(AdapterExecutionError, match="different payload"):
        driver.prepare(
            status,
            LlvmObjectInspectPayload(operation_id="llvm.object-inspect"),
            _limits(),
            {"ghidra_native_map_script": script},
        )


def test_jadx_normalization_rejects_untrusted_output_paths(tmp_path) -> None:
    output = tmp_path / "jadx-output"
    sources = output / "sources"
    sources.mkdir(parents=True)
    (sources / "mapping.json").write_text(
        json.dumps({"classes": [{"json": "../escape.json"}]}),
        encoding="utf-8",
    )
    (output / "callgraph.json").write_text(
        json.dumps({"nodes": [], "edges": []}),
        encoding="utf-8",
    )
    stdout = tmp_path / "stdout.bin"
    stderr = tmp_path / "stderr.bin"
    stdout.write_bytes(b"")
    stderr.write_bytes(b"")
    process = SupervisedProcessResult(
        outcome=AdapterExecutionOutcome.SUCCEEDED,
        return_code=0,
        signal_number=None,
        stdout_path=stdout,
        stderr_path=stderr,
        result_path=output,
        output_complete=True,
        warnings=(),
    )

    with pytest.raises(AdapterExecutionError, match="unsafe JSON path"):
        JadxAndroidStaticMapDriver().normalize(process, "a" * 64, _limits())

    (sources / "mapping.json").write_text(json.dumps({"classes": []}), encoding="utf-8")
    (output / "link").symlink_to("/etc/passwd")
    with pytest.raises(AdapterExecutionError, match="symbolic link"):
        JadxAndroidStaticMapDriver().normalize(process, "a" * 64, _limits())


def test_jadx_invocations_bind_one_distribution_and_fixed_arguments(tmp_path, monkeypatch) -> None:
    root = tmp_path / "jadx"
    entrypoint = root / "bin/jadx"
    payload = root / "lib/jadx-1.5.6-all.jar"
    entrypoint.parent.mkdir(parents=True)
    payload.parent.mkdir()
    entrypoint.write_bytes(b"reviewed launcher")
    payload.write_bytes(b"reviewed jar")
    java = tmp_path / "java"
    java.mkdir()
    monkeypatch.setattr(
        adapter_execution,
        "_system_java_payload_digests",
        lambda: ("a" * 64, "b" * 64),
    )
    monkeypatch.setattr(
        adapter_execution,
        "_system_java_mounts",
        lambda: (adapter_execution.SandboxMount(java, "/opt/java"),),
    )
    status = AdapterStatus(
        adapter_id="jadx",
        manifest_digest="1" * 64,
        observed_at=utc_now(),
        platform="linux-x86_64",
        supported=True,
        installed=True,
        healthy=True,
        source="system",
        version="1.5.6",
        entrypoints=[str(entrypoint)],
        observed_identity_sha256="2" * 64,
    )
    driver = JadxAndroidStaticMapDriver()
    original_digest = driver.tool_payload_digest(status.entrypoints)
    payload.write_bytes(b"changed jar")
    assert driver.tool_payload_digest(status.entrypoints) != original_digest

    version = driver.version_invocation(status)
    invocation = driver.prepare(
        status,
        JadxAndroidStaticMapPayload(operation_id="jadx.android-static-map"),
        _limits(),
        {},
    )

    assert version.argv == ("/opt/tool/bin/jadx", "--version")
    assert invocation.result_relative_path == "jadx-output"
    assert invocation.argv[-2:] == ("/work/jadx-output", "/input/artifact")
    assert "--output-format" in invocation.argv
    assert "--call-graph" in invocation.argv
    assert {mount.destination for mount in invocation.mounts} == {"/opt/tool", "/opt/java"}
    with pytest.raises(AdapterExecutionError, match="different operation"):
        driver.prepare(
            status,
            LlvmObjectInspectPayload(operation_id="llvm.object-inspect"),
            _limits(),
            {},
        )


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


def test_sandbox_materializes_only_flat_read_only_inline_inputs(tmp_path) -> None:
    executable = tmp_path / "bwrap"
    executable.write_bytes(b"fixture")
    executable.chmod(0o700)
    supervisor = OfflineSandboxSupervisor(executable)
    work = tmp_path / "broker"
    work.mkdir()
    invocation = TrustedInvocation(
        argv=("/bin/true",),
        mounts=(),
        inline_files=(SandboxInlineFile("/input/rules.yar", b"rule x { condition: true }"),),
    )

    materialized = supervisor._materialize_inline_files(invocation, work, _limits())

    assert materialized.inline_files == ()
    assert len(materialized.mounts) == 1
    assert materialized.mounts[0].destination == "/input/rules.yar"
    assert materialized.mounts[0].source.read_bytes() == b"rule x { condition: true }"
    assert materialized.mounts[0].source.stat().st_mode & 0o777 == 0o400

    unsafe = invocation.__class__(
        argv=("/bin/true",),
        mounts=(),
        inline_files=(SandboxInlineFile("/etc/rules.yar", b"fixture"),),
    )
    unsafe_work = tmp_path / "unsafe"
    unsafe_work.mkdir()
    with pytest.raises(AdapterExecutionError, match="unsafe destination"):
        supervisor._materialize_inline_files(unsafe, unsafe_work, _limits())


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
    assert result.finished_at >= result.started_at
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
    assert manifest_payload["operation_payload"] == {"operation_id": "llvm.object-inspect"}
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
