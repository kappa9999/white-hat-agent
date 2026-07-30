from __future__ import annotations

import base64
import hashlib
import importlib.resources
import json
import math
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Iterator
from contextlib import ExitStack, contextmanager, suppress
from dataclasses import dataclass
from datetime import timedelta
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Annotated, ClassVar, Literal, Protocol, Self

from pydantic import AwareDatetime, Field, JsonValue, SecretStr, field_validator, model_validator

from .adapter_registry import (
    AdapterConformanceCheck,
    AdapterConformanceReport,
    AdapterManager,
    AdapterOperationBinding,
    AdapterStatus,
    OperationResourceLimits,
    ProbeDefinition,
    _probe_file_version,
    _version_matches_probe,
)
from .campaign.fleet import FleetStore
from .evidence.models import EvidenceDescriptor, EvidenceRecord
from .evidence.store import EvidenceStore
from .knowledge.models import EXECUTION_CLASS_RANK, Slug
from .models import Sha256, StrictModel, stable_digest, stable_id, utc_now

try:  # Unix-only execution dependencies; import remains portable for Windows clients.
    import pwd
    import resource
except ImportError:  # pragma: no cover - exercised by Windows packaging smoke tests
    pwd = None  # type: ignore[assignment]
    resource = None  # type: ignore[assignment]


class AdapterExecutionError(RuntimeError):
    """A typed adapter operation could not be authorized or executed safely."""


class GhidraBinarySummaryPayload(StrictModel):
    operation_id: Literal["ghidra.binary-summary"]


class GhidraNativeCodeMapPayload(StrictModel):
    operation_id: Literal["ghidra.native-code-map"]


class CapaFileAnalyzePayload(StrictModel):
    operation_id: Literal["capa.file-analyze"]
    operating_system: Literal["auto", "linux", "macos", "windows"] = "auto"


class LlvmObjectInspectPayload(StrictModel):
    operation_id: Literal["llvm.object-inspect"]


class GoReSymSymbolMapPayload(StrictModel):
    operation_id: Literal["goresym.symbol-map"]


class UnblobExtractionMapPayload(StrictModel):
    operation_id: Literal["unblob.extraction-map"]


class JadxAndroidStaticMapPayload(StrictModel):
    operation_id: Literal["jadx.android-static-map"]


class TsharkPacketCaptureMapPayload(StrictModel):
    operation_id: Literal["tshark.packet-capture-map"]


class FridaExecutableRuntimeMapPayload(StrictModel):
    operation_id: Literal["frida.executable-runtime-map"]


def _contains_yara_include_directive(source: str) -> bool:
    index = 0
    brace_depth = 0
    expect_regex = False
    while index < len(source):
        char = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if char.isspace():
            index += 1
            continue
        if char == "/" and following == "/":
            newline = source.find("\n", index + 2)
            index = len(source) if newline < 0 else newline + 1
            continue
        if char == "/" and following == "*":
            closing = source.find("*/", index + 2)
            index = len(source) if closing < 0 else closing + 2
            continue
        if char == '"':
            index += 1
            while index < len(source):
                if source[index] == "\\":
                    index += 2
                elif source[index] == '"':
                    index += 1
                    break
                else:
                    index += 1
            expect_regex = False
            continue
        if char == "/" and expect_regex:
            index += 1
            in_character_class = False
            while index < len(source):
                if source[index] == "\\":
                    index += 2
                    continue
                if source[index] == "[":
                    in_character_class = True
                elif source[index] == "]":
                    in_character_class = False
                elif source[index] == "/" and not in_character_class:
                    index += 1
                    break
                index += 1
            expect_regex = False
            continue
        if char.isalpha() or char == "_":
            end = index + 1
            while end < len(source) and (source[end].isalnum() or source[end] == "_"):
                end += 1
            token = source[index:end].casefold()
            if brace_depth == 0 and token == "include":
                return True
            expect_regex = token == "matches"
            index = end
            continue
        if char == "{":
            brace_depth += 1
            expect_regex = False
        elif char == "}":
            brace_depth = max(0, brace_depth - 1)
            expect_regex = False
        elif char == "=":
            if following == "~":
                expect_regex = True
                index += 2
                continue
            expect_regex = following != "="
        else:
            expect_regex = False
        index += 1
    return False


class YaraXFileScanPayload(StrictModel):
    operation_id: Literal["yara-x.file-scan"]
    rule_source: str = Field(min_length=1, max_length=65_536)

    @field_validator("rule_source")
    @classmethod
    def bounded_standalone_rule_source(cls, value: str) -> str:
        if "\x00" in value:
            raise ValueError("rule_source cannot contain NUL bytes")
        if len(value.encode("utf-8")) > 65_536:
            raise ValueError("rule_source exceeds the UTF-8 byte limit")
        if _contains_yara_include_directive(value):
            raise ValueError("rule_source cannot include external files")
        return value


AdapterOperationPayload = Annotated[
    GhidraBinarySummaryPayload
    | GhidraNativeCodeMapPayload
    | CapaFileAnalyzePayload
    | LlvmObjectInspectPayload
    | GoReSymSymbolMapPayload
    | UnblobExtractionMapPayload
    | JadxAndroidStaticMapPayload
    | TsharkPacketCaptureMapPayload
    | FridaExecutableRuntimeMapPayload
    | YaraXFileScanPayload,
    Field(discriminator="operation_id"),
]


class AdapterLimitOverrides(StrictModel):
    max_input_bytes: int | None = Field(default=None, ge=1)
    max_output_bytes: int | None = Field(default=None, ge=1)
    max_files: int | None = Field(default=None, ge=1)
    max_records: int | None = Field(default=None, ge=1)
    wall_seconds: int | None = Field(default=None, ge=1)
    cpu_seconds: int | None = Field(default=None, ge=1)
    memory_mib: int | None = Field(default=None, ge=64)
    max_processes: int | None = Field(default=None, ge=1)


class AdapterExecutionRequest(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    agent_id: Slug
    task_id: str = Field(min_length=1, max_length=256)
    lease_token: SecretStr
    operation: AdapterOperationPayload
    input_evidence_ids: list[str] = Field(min_length=1, max_length=1)
    limits: AdapterLimitOverrides = Field(default_factory=AdapterLimitOverrides)

    @model_validator(mode="after")
    def unique_inputs(self) -> Self:
        if len(self.input_evidence_ids) != len(set(self.input_evidence_ids)):
            raise ValueError("input_evidence_ids must be unique")
        if len(self.lease_token.get_secret_value()) < 20:
            raise ValueError("lease_token is too short")
        return self

    def digest(self) -> str:
        return stable_digest(self.model_dump(mode="json", exclude={"lease_token"}))


class AdapterExecutionOutcome(StrEnum):
    SUCCEEDED = "succeeded"
    TOOL_FAILED = "tool-failed"
    TIMED_OUT = "timed-out"
    RESOURCE_LIMITED = "resource-limited"
    INVALID_OUTPUT = "invalid-output"


class AdapterCapture(StrictModel):
    name: str
    media_type: str
    byte_length: int = Field(ge=0)
    content_sha256: Sha256
    complete: bool
    evidence_id: str | None = None


class AdapterNormalizedResult(StrictModel):
    operation_id: Slug
    artifact_sha256: Sha256
    records_returned: int = Field(ge=0)
    truncated: bool
    data: dict[str, JsonValue]


class AdapterExecutionResult(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    execution_id: str
    request_digest: Sha256
    campaign_id: Slug
    task_id: str
    target: str
    intent_id: Slug
    scope_decision_id: str
    adapter_id: Slug
    operation_id: Slug
    operation_version: str
    manifest_digest: Sha256
    operation_contract_digest: Sha256
    observed_identity_sha256: Sha256
    tool_payload_sha256: Sha256
    conformance_report_digest: Sha256
    sandbox_profile_sha256: Sha256
    input_evidence_ids: list[str]
    input_content_sha256: list[Sha256]
    effective_limits: OperationResourceLimits
    outcome: AdapterExecutionOutcome
    exit_code: int | None = None
    signal: int | None = None
    normalized: AdapterNormalizedResult | None = None
    captures: list[AdapterCapture] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    started_at: AwareDatetime
    finished_at: AwareDatetime

    @model_validator(mode="after")
    def valid_result(self) -> Self:
        if (self.outcome == AdapterExecutionOutcome.SUCCEEDED) != (self.normalized is not None):
            raise ValueError("only successful execution results contain normalized output")
        if len(self.evidence_ids) != len(set(self.evidence_ids)):
            raise ValueError("evidence_ids must be unique")
        return self


class AdapterExecutionReceipt(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    execution_id: str
    campaign_id: Slug
    task_id: str
    adapter_id: Slug
    operation_id: Slug
    outcome: AdapterExecutionOutcome
    records_returned: int = Field(ge=0)
    truncated: bool
    captures: list[AdapterCapture]
    evidence_ids: list[str]
    warnings: list[str]
    started_at: AwareDatetime
    finished_at: AwareDatetime

    @classmethod
    def from_result(cls, result: AdapterExecutionResult) -> Self:
        return cls(
            execution_id=result.execution_id,
            campaign_id=result.campaign_id,
            task_id=result.task_id,
            adapter_id=result.adapter_id,
            operation_id=result.operation_id,
            outcome=result.outcome,
            records_returned=result.normalized.records_returned if result.normalized else 0,
            truncated=result.normalized.truncated if result.normalized else False,
            captures=result.captures,
            evidence_ids=result.evidence_ids,
            warnings=result.warnings,
            started_at=result.started_at,
            finished_at=result.finished_at,
        )


class AdapterExecutionManifest(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    receipt: AdapterExecutionReceipt
    request_digest: Sha256
    intent_id: Slug
    scope_decision_id: str
    operation_version: str
    manifest_digest: Sha256
    operation_contract_digest: Sha256
    observed_identity_sha256: Sha256
    tool_payload_sha256: Sha256
    conformance_report_digest: Sha256
    sandbox_profile_sha256: Sha256
    input_evidence_ids: list[str]
    input_content_sha256: list[Sha256]
    operation_payload: dict[str, JsonValue]
    effective_limits: OperationResourceLimits
    exit_code: int | None = None
    signal: int | None = None

    @classmethod
    def from_result(
        cls,
        result: AdapterExecutionResult,
        *,
        operation_payload: dict[str, JsonValue],
    ) -> Self:
        return cls(
            receipt=AdapterExecutionReceipt.from_result(result),
            request_digest=result.request_digest,
            intent_id=result.intent_id,
            scope_decision_id=result.scope_decision_id,
            operation_version=result.operation_version,
            manifest_digest=result.manifest_digest,
            operation_contract_digest=result.operation_contract_digest,
            observed_identity_sha256=result.observed_identity_sha256,
            tool_payload_sha256=result.tool_payload_sha256,
            conformance_report_digest=result.conformance_report_digest,
            sandbox_profile_sha256=result.sandbox_profile_sha256,
            input_evidence_ids=result.input_evidence_ids,
            input_content_sha256=result.input_content_sha256,
            operation_payload=operation_payload,
            effective_limits=result.effective_limits,
            exit_code=result.exit_code,
            signal=result.signal,
        )


@dataclass(frozen=True)
class SandboxMount:
    source: Path
    destination: str


@dataclass(frozen=True)
class SandboxInlineFile:
    destination: str
    content: bytes


@dataclass(frozen=True)
class TrustedInvocation:
    argv: tuple[str, ...]
    mounts: tuple[SandboxMount, ...]
    result_relative_path: str | None = None
    inline_files: tuple[SandboxInlineFile, ...] = ()
    executable_input: bool = False


@dataclass(frozen=True)
class OciTrustedInvocation:
    image_reference: str
    platform: Literal["linux/amd64", "linux/arm64"]
    argv: tuple[str, ...]
    result_relative_path: str | None = None


AdapterInvocation = TrustedInvocation | OciTrustedInvocation


@dataclass(frozen=True)
class SupervisedProcessResult:
    outcome: AdapterExecutionOutcome
    return_code: int | None
    signal_number: int | None
    stdout_path: Path
    stderr_path: Path
    result_path: Path | None
    output_complete: bool
    warnings: tuple[str, ...]


SANDBOX_PROFILE: dict[str, JsonValue] = {
    "profile": "linux-bubblewrap-offline-v2",
    "network": "unshared",
    "environment": "cleared",
    "home": "tmpfs",
    "tmp": "tmpfs",
    "input": "single-read-only-file",
    "tools": "reviewed-read-only-mounts",
    "system_runtime": "read-only-usr-bin-and-libraries",
    "host_configuration": "not-mounted",
    "output": "tool-work-directory-with-broker-private-captures",
    "namespaces": ["network", "pid", "ipc", "uts"],
    "capabilities": "dropped",
    "stdin": "null",
}
SANDBOX_PROFILE_SHA256 = stable_digest(SANDBOX_PROFILE)
OCI_SANDBOX_PROFILE: dict[str, JsonValue] = {
    "profile": "docker-oci-offline-v1",
    "image": "release-and-platform-manifest-digest-bound",
    "pull": "never-during-execution",
    "network": "none",
    "root_filesystem": "read-only",
    "capabilities": "dropped",
    "privilege_escalation": "disabled",
    "input": "single-read-only-file",
    "output": "single-private-bind-mount",
    "temporary_filesystems": ["home", "tmp"],
    "resources": ["cpu-seconds", "memory", "pids", "wall-clock", "output-tree"],
    "stdin": "null",
}
OCI_SANDBOX_PROFILE_SHA256 = stable_digest(OCI_SANDBOX_PROFILE)


@dataclass(frozen=True)
class ConformanceFixture:
    fixture_id: str
    filename: str
    resource_name: str | None
    sha256: str | None
    source: Literal["package", "tool-entrypoint"] = "package"


ELF_FIXTURE = ConformanceFixture(
    fixture_id="minimal-elf64-x86-64-v1",
    filename="fixture.elf",
    resource_name="minimal_elf64.b64",
    sha256="daf49381748b12d617a3c645f9932ade03d7c0cac6b804da1bd35ae80cf37cad",
)
GHIDRA_NATIVE_MAP_FIXTURE = ConformanceFixture(
    fixture_id="native-code-map-elf64-x86-64-v1",
    filename="fixture.elf",
    resource_name="native_code_map_elf64.b64",
    sha256="160fad2a70818a93807bc01ccfff766f7c3702756e8135ee5239132de9fe56b0",
)
JADX_FIXTURE = ConformanceFixture(
    fixture_id="minimal-dex35-v1",
    filename="fixture.dex",
    resource_name="minimal_android_dex.b64",
    sha256="865d09fc9bc4a407c2bab2516dd2576a63d410d036f30c21b6a28b8b875ec847",
)
YARA_X_FIXTURE = ConformanceFixture(
    fixture_id="yara-x-marker-elf64-x86-64-v1",
    filename="fixture.elf",
    resource_name="native_code_map_elf64.b64",
    sha256="160fad2a70818a93807bc01ccfff766f7c3702756e8135ee5239132de9fe56b0",
)
TSHARK_FIXTURE = ConformanceFixture(
    fixture_id="protocol-map-ethernet-ipv4-v1",
    filename="fixture.pcap",
    resource_name="protocol_map_ethernet_ipv4.b64",
    sha256="a932f9b0da893cc34f3ad70d9e51291896ca0c80fd68b923803364797adb619b",
)
FRIDA_RUNTIME_MAP_FIXTURE = ConformanceFixture(
    fixture_id="frida-runtime-map-elf64-x86-64-v1",
    filename="fixture.elf",
    resource_name="frida_runtime_elf64.b64",
    sha256="57312d10cbae62727393380a716ce7ef5a35502c54030bf3a3420696f85ede21",
)
GORESYM_SELF_FIXTURE = ConformanceFixture(
    fixture_id="goresym-self-analysis-v1",
    filename="GoReSym.fixture",
    resource_name=None,
    sha256=None,
    source="tool-entrypoint",
)
UNBLOB_FIXTURE = ConformanceFixture(
    fixture_id="unblob-marker-zip-v1",
    filename="fixture.zip",
    resource_name="unblob_marker_zip.b64",
    sha256="a46bf7434ad415379cd4b5019fd96ad0766559d76bfc2e4da2195498e0f89cd3",
)
# Backward-compatible public constants for the original shared ELF fixture.
FIXTURE_ID = ELF_FIXTURE.fixture_id
FIXTURE_SHA256 = ELF_FIXTURE.sha256
GHIDRA_SCRIPT_SHA256 = "87e15c8b2368cc739e4cca74ca306c1cbbddef9cc673626737de7dbc6317a5a9"
GHIDRA_NATIVE_MAP_SCRIPT_SHA256 = "59fc8004e838a78d169db17f356a37de437397d5f244c65e0317cc30909c2e28"
YARA_X_CONFORMANCE_RULE_SHA256 = "5c79304a77695997bbaadc354626cbc447d7bd3b46f14683a45069bddc582961"
DRIVER_VERSION = "1.2.0"
GHIDRA_NATIVE_MAP_DRIVER_VERSION = "1.0.0"
JADX_DRIVER_VERSION = "1.0.0"
YARA_X_DRIVER_VERSION = "1.0.4"
TSHARK_DRIVER_VERSION = "1.0.0"
FRIDA_RUNTIME_MAP_SCRIPT_SHA256 = "810cc52ec4f789f01742f4d974419056923d07e66966f39e46c6df2a88b30ebf"
FRIDA_DRIVER_VERSION = "1.0.0"
GORESYM_DRIVER_VERSION = "1.0.0"
UNBLOB_DRIVER_VERSION = "1.0.0"
MINIMUM_EVIDENCE_IMPORT_BYTES = 65_536


class ProviderDriver(Protocol):
    adapter_id: str
    operation_id: str
    driver_id: str
    driver_version: str

    def tool_payload_digest(self, entrypoints: list[str]) -> str: ...

    def prepare(
        self,
        status: AdapterStatus,
        operation: AdapterOperationPayload,
        limits: OperationResourceLimits,
        assets: dict[str, Path],
    ) -> AdapterInvocation: ...

    def normalize(
        self,
        process: SupervisedProcessResult,
        artifact_sha256: str,
        limits: OperationResourceLimits,
        operation: AdapterOperationPayload | None = None,
    ) -> AdapterNormalizedResult: ...

    def fixture_checks(self, normalized: AdapterNormalizedResult) -> list[AdapterConformanceCheck]: ...


@contextmanager
def _temporary_input_mode(path: Path, *, executable: bool) -> Iterator[None]:
    if not executable:
        yield
        return
    original_mode = stat.S_IMODE(path.stat().st_mode)
    sandbox_mode = (original_mode | stat.S_IRUSR | stat.S_IXUSR) & ~(
        stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH
    )
    path.chmod(sandbox_mode)
    try:
        yield
    finally:
        path.chmod(original_mode)


class OfflineSandboxSupervisor:
    def __init__(self, executable: Path | None = None) -> None:
        if sys.platform != "linux":
            raise AdapterExecutionError("typed offline execution currently requires Linux or WSL")
        selected = executable
        if selected is None:
            selected = next((path for path in (Path("/usr/bin/bwrap"),) if path.is_file()), None)
        if selected is None or not selected.is_absolute() or selected.is_symlink() or not selected.is_file():
            raise AdapterExecutionError("offline adapter execution requires bubblewrap on Linux")
        resolved = selected.resolve(strict=True)
        if executable is None:
            metadata = resolved.stat()
            if metadata.st_uid != 0 or metadata.st_mode & 0o022:
                raise AdapterExecutionError(
                    "system bubblewrap must be root-owned and not group/world writable"
                )
        if not os.access(resolved, os.X_OK):
            raise AdapterExecutionError("bubblewrap is not executable")
        self.executable = resolved

    def run(
        self,
        invocation: TrustedInvocation,
        input_path: Path,
        work_dir: Path,
        limits: OperationResourceLimits,
    ) -> SupervisedProcessResult:
        input_path = input_path.resolve(strict=True)
        work_dir = work_dir.resolve(strict=True)
        tool_work_dir = work_dir / "tool-work"
        tool_work_dir.mkdir(mode=0o700)
        stdout_path = work_dir / "stdout.bin"
        stderr_path = work_dir / "stderr.bin"
        invocation = self._materialize_inline_files(invocation, work_dir, limits)
        command = self._command(invocation, input_path, tool_work_dir)
        started = time.monotonic()
        limited = False
        timed_out = False
        warnings: list[str] = []
        with (
            _temporary_input_mode(input_path, executable=invocation.executable_input),
            stdout_path.open("wb") as stdout_handle,
            stderr_path.open("wb") as stderr_handle,
        ):
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=stdout_handle,
                stderr=stderr_handle,
                close_fds=True,
                start_new_session=True,
                preexec_fn=lambda: _apply_resource_limits(limits),
                env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
            )
            try:
                while process.poll() is None:
                    elapsed = time.monotonic() - started
                    if elapsed > limits.wall_seconds:
                        timed_out = True
                        warnings.append("wall-clock limit exceeded")
                        _terminate_process_group(process)
                        break
                    entries, byte_length = _tree_usage(
                        work_dir,
                        stop_after_bytes=limits.max_output_bytes + 1,
                        stop_after_entries=limits.max_files + 1,
                    )
                    if entries > limits.max_files or byte_length > limits.max_output_bytes:
                        limited = True
                        warnings.append("workspace file or byte limit exceeded")
                        _terminate_process_group(process)
                        break
                    if _descendant_process_count(process.pid) > limits.max_processes:
                        limited = True
                        warnings.append("process-count limit exceeded")
                        _terminate_process_group(process)
                        break
                    time.sleep(0.1)
                try:
                    return_code = process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    _kill_process_group(process)
                    return_code = process.wait(timeout=5)
            finally:
                if process.poll() is None:
                    _kill_process_group(process)
                    with suppress(subprocess.TimeoutExpired):
                        process.wait(timeout=5)

        entries, byte_length = _tree_usage(
            work_dir,
            stop_after_bytes=limits.max_output_bytes + 1,
            stop_after_entries=limits.max_files + 1,
        )
        output_complete = (
            not limited and entries <= limits.max_files and byte_length <= limits.max_output_bytes
        )
        if not output_complete and not limited:
            limited = True
            warnings.append("workspace exceeded output limits at process exit")
        if timed_out:
            outcome = AdapterExecutionOutcome.TIMED_OUT
        elif limited or return_code in {-signal.SIGXCPU, -signal.SIGXFSZ}:
            outcome = AdapterExecutionOutcome.RESOURCE_LIMITED
        elif return_code != 0:
            outcome = AdapterExecutionOutcome.TOOL_FAILED
        else:
            outcome = AdapterExecutionOutcome.SUCCEEDED
        result_path = (
            tool_work_dir / invocation.result_relative_path if invocation.result_relative_path else None
        )
        return SupervisedProcessResult(
            outcome=outcome,
            return_code=return_code,
            signal_number=-return_code if return_code < 0 else None,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            result_path=result_path,
            output_complete=output_complete,
            warnings=tuple(warnings),
        )

    def _materialize_inline_files(
        self,
        invocation: TrustedInvocation,
        work_dir: Path,
        limits: OperationResourceLimits,
    ) -> TrustedInvocation:
        if not invocation.inline_files:
            return invocation
        if len(invocation.inline_files) > 16:
            raise AdapterExecutionError("adapter invocation has too many inline files")
        destinations = {mount.destination for mount in invocation.mounts}
        inline_root = work_dir / "inline-inputs"
        inline_root.mkdir(mode=0o700)
        mounts = list(invocation.mounts)
        total_bytes = 0
        for index, item in enumerate(invocation.inline_files):
            destination = PurePosixPath(item.destination)
            if (
                not destination.is_absolute()
                or destination.parent != PurePosixPath("/input")
                or destination.name in {"", "artifact"}
                or destination.as_posix() in destinations
            ):
                raise AdapterExecutionError("adapter inline file has an unsafe destination")
            total_bytes += len(item.content)
            if total_bytes > limits.max_input_bytes:
                raise AdapterExecutionError("adapter inline files exceed the input byte limit")
            source = inline_root / f"{index:02d}-{destination.name}"
            source.write_bytes(item.content)
            source.chmod(0o400)
            mounts.append(SandboxMount(source=source, destination=destination.as_posix()))
            destinations.add(destination.as_posix())
        return TrustedInvocation(
            argv=invocation.argv,
            mounts=tuple(mounts),
            result_relative_path=invocation.result_relative_path,
            executable_input=invocation.executable_input,
        )

    def _command(
        self,
        invocation: TrustedInvocation,
        input_path: Path,
        tool_work_dir: Path,
    ) -> list[str]:
        command = [
            str(self.executable),
            "--die-with-parent",
            "--new-session",
            "--unshare-net",
            "--unshare-pid",
            "--unshare-ipc",
            "--unshare-uts",
            "--clearenv",
            "--cap-drop",
            "ALL",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
        ]
        for system_path in ("/usr", "/bin", "/lib", "/lib64"):
            if Path(system_path).exists():
                command.extend(("--ro-bind", system_path, system_path))
        command.extend(
            (
                "--dir",
                "/etc",
                "--tmpfs",
                "/tmp",
                "--tmpfs",
                "/var",
                "--tmpfs",
                "/home",
                "--dir",
                "/home/wha",
                "--dir",
                "/input",
                "--ro-bind",
                str(input_path),
                "/input/artifact",
                "--dir",
                "/work",
                "--bind",
                str(tool_work_dir),
                "/work",
                "--setenv",
                "PATH",
                "/opt/java/bin:/usr/bin:/bin",
                "--setenv",
                "JAVA_HOME",
                "/opt/java",
                "--setenv",
                "HOME",
                "/home/wha",
                "--setenv",
                "USER",
                "wha",
                "--setenv",
                "LOGNAME",
                "wha",
                "--setenv",
                "LANG",
                "C.UTF-8",
                "--setenv",
                "LC_ALL",
                "C.UTF-8",
                "--chdir",
                "/work",
            )
        )
        if pwd is not None:
            account_home = Path(pwd.getpwuid(os.getuid()).pw_dir)
            if (
                account_home.is_absolute()
                and len(account_home.parts) >= 3
                and account_home.parts[1] == "home"
            ):
                command.extend(("--dir", account_home.as_posix()))
        created: set[str] = set()
        for mount in invocation.mounts:
            source = mount.source.resolve(strict=True)
            parent = str(Path(mount.destination).parent)
            if parent not in created and parent not in {
                "/",
                "/usr",
                "/bin",
                "/lib",
                "/lib64",
                "/etc",
                "/input",
                "/work",
            }:
                command.extend(("--dir", parent))
                created.add(parent)
            command.extend(("--ro-bind", str(source), mount.destination))
        command.extend(("--", *invocation.argv))
        return command


class OciSandboxSupervisor:
    def __init__(self, docker: Path | None = None) -> None:
        if sys.platform != "linux":
            raise AdapterExecutionError("OCI adapter execution currently requires Linux or WSL")
        if docker is None:
            from .adapter_provisioning import _trusted_docker_executable

            docker = _trusted_docker_executable()
        resolved = docker.resolve(strict=True)
        if not resolved.is_file() or not os.access(resolved, os.X_OK):
            raise AdapterExecutionError("Docker CLI is not an executable file")
        self.docker = resolved

    def run(
        self,
        invocation: OciTrustedInvocation,
        input_path: Path,
        work_dir: Path,
        limits: OperationResourceLimits,
    ) -> SupervisedProcessResult:
        self._validate_invocation(invocation)
        input_path = input_path.resolve(strict=True)
        work_dir = work_dir.resolve(strict=True)
        if any("," in str(path) or "\x00" in str(path) for path in (input_path, work_dir)):
            raise AdapterExecutionError("OCI bind paths contain an unsupported mount delimiter")
        tool_work_dir = work_dir / "tool-work"
        tool_work_dir.mkdir(mode=0o700)
        stdout_path = work_dir / "stdout.bin"
        stderr_path = work_dir / "stderr.bin"
        stdout_path.touch(mode=0o600)
        stderr_path.touch(mode=0o600)
        container_name = (
            "wha-"
            + hashlib.sha256(f"{os.getpid()}:{time.monotonic_ns()}:{work_dir}".encode()).hexdigest()[:24]
        )
        container_id: str | None = None
        process: subprocess.Popen[bytes] | None = None
        started = time.monotonic()
        limited = False
        timed_out = False
        warnings: list[str] = []
        state: dict[str, object] = {}
        try:
            container_id = self._create(
                invocation,
                input_path,
                tool_work_dir,
                limits,
                container_name,
            )
            with stdout_path.open("wb") as stdout_handle, stderr_path.open("wb") as stderr_handle:
                process = subprocess.Popen(
                    [str(self.docker), "container", "start", "--attach", container_id],
                    stdin=subprocess.DEVNULL,
                    stdout=stdout_handle,
                    stderr=stderr_handle,
                    close_fds=True,
                    start_new_session=True,
                )
                while process.poll() is None:
                    if time.monotonic() - started > limits.wall_seconds:
                        timed_out = True
                        warnings.append("wall-clock limit exceeded")
                        self._kill(container_id)
                        break
                    entries, byte_length = _tree_usage(
                        work_dir,
                        stop_after_bytes=limits.max_output_bytes + 1,
                        stop_after_entries=limits.max_files + 1,
                    )
                    if entries > limits.max_files or byte_length > limits.max_output_bytes:
                        limited = True
                        warnings.append("workspace file or byte limit exceeded")
                        self._kill(container_id)
                        break
                    time.sleep(0.1)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    self._kill(container_id)
                    _kill_process_group(process)
                    process.wait(timeout=5)
                state = self._state(container_id)
        finally:
            if process is not None and process.poll() is None:
                if container_id is not None:
                    self._kill(container_id)
                _kill_process_group(process)
                with suppress(subprocess.TimeoutExpired):
                    process.wait(timeout=5)
            if container_id is not None:
                self._remove(container_id)

        entries, byte_length = _tree_usage(
            work_dir,
            stop_after_bytes=limits.max_output_bytes + 1,
            stop_after_entries=limits.max_files + 1,
        )
        output_complete = (
            not limited and entries <= limits.max_files and byte_length <= limits.max_output_bytes
        )
        if not output_complete and not limited:
            limited = True
            warnings.append("workspace exceeded output limits at process exit")
        exit_code = state.get("ExitCode")
        return_code = exit_code if isinstance(exit_code, int) and not isinstance(exit_code, bool) else None
        oom_killed = state.get("OOMKilled") is True
        if timed_out:
            outcome = AdapterExecutionOutcome.TIMED_OUT
        elif limited or oom_killed or return_code in {137, 152, 153}:
            outcome = AdapterExecutionOutcome.RESOURCE_LIMITED
            if oom_killed:
                warnings.append("container memory limit exceeded")
        elif return_code != 0:
            outcome = AdapterExecutionOutcome.TOOL_FAILED
        else:
            outcome = AdapterExecutionOutcome.SUCCEEDED
        signal_number = return_code - 128 if return_code is not None and 128 < return_code < 160 else None
        result_path = (
            tool_work_dir / invocation.result_relative_path if invocation.result_relative_path else None
        )
        return SupervisedProcessResult(
            outcome=outcome,
            return_code=return_code,
            signal_number=signal_number,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            result_path=result_path,
            output_complete=output_complete,
            warnings=tuple(dict.fromkeys(warnings)),
        )

    def _validate_invocation(self, invocation: OciTrustedInvocation) -> None:
        if (
            re.fullmatch(
                r"ghcr\.io/[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)+"
                r"@sha256:[0-9a-f]{64}",
                invocation.image_reference,
            )
            is None
        ):
            raise AdapterExecutionError("OCI invocation requires an exact GHCR manifest digest")
        if (
            not invocation.argv
            or len(invocation.argv) > 64
            or any(
                not value or len(value) > 4_096 or "\x00" in value or "\r" in value or "\n" in value
                for value in invocation.argv
            )
        ):
            raise AdapterExecutionError("OCI invocation arguments are missing or unbounded")
        if invocation.result_relative_path is not None:
            result = PurePosixPath(invocation.result_relative_path)
            if result.is_absolute() or ".." in result.parts:
                raise AdapterExecutionError("OCI result path must remain in the output mount")

    def _create(
        self,
        invocation: OciTrustedInvocation,
        input_path: Path,
        tool_work_dir: Path,
        limits: OperationResourceLimits,
        container_name: str,
    ) -> str:
        tmpfs_mib = max(16, min(512, limits.memory_mib // 4))
        command = [
            str(self.docker),
            "container",
            "create",
            "--name",
            container_name,
            "--pull=never",
            "--platform",
            invocation.platform,
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges=true",
            "--pids-limit",
            str(limits.max_processes),
            "--memory",
            f"{limits.memory_mib}m",
            "--memory-swap",
            f"{limits.memory_mib}m",
            "--cpus",
            "1.0",
            "--ulimit",
            f"cpu={limits.cpu_seconds}:{limits.cpu_seconds}",
            "--ulimit",
            "nofile=1024:1024",
            "--user",
            f"{os.getuid()}:{os.getgid()}",
            "--workdir",
            "/data/output",
            "--env",
            "HOME=/tmp",
            "--env",
            "LANG=C.UTF-8",
            "--env",
            "LC_ALL=C.UTF-8",
            "--tmpfs",
            f"/tmp:rw,noexec,nosuid,nodev,size={tmpfs_mib}m",
            "--tmpfs",
            f"/home:rw,noexec,nosuid,nodev,size={tmpfs_mib}m",
            "--mount",
            f"type=bind,src={input_path},dst=/data/input/artifact,readonly",
            "--mount",
            f"type=bind,src={tool_work_dir},dst=/data/output",
            "--stop-timeout",
            "2",
            invocation.image_reference,
            *invocation.argv,
        ]
        result = self._control(command, timeout=60)
        container_id = result.strip()
        if re.fullmatch(r"[0-9a-f]{12,64}", container_id) is None:
            raise AdapterExecutionError("Docker create returned an invalid container identity")
        return container_id

    def _state(self, container_id: str) -> dict[str, object]:
        payload = self._control(
            [
                str(self.docker),
                "container",
                "inspect",
                "--format",
                "{{json .State}}",
                container_id,
            ],
            timeout=15,
        )
        try:
            state = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise AdapterExecutionError("Docker returned invalid container state") from exc
        if not isinstance(state, dict):
            raise AdapterExecutionError("Docker container state must be an object")
        return state

    def _kill(self, container_id: str) -> None:
        self._control(
            [str(self.docker), "container", "kill", container_id],
            timeout=15,
            allow_failure=True,
        )

    def _remove(self, container_id: str) -> None:
        self._control(
            [str(self.docker), "container", "rm", "--force", container_id],
            timeout=15,
            allow_failure=True,
        )

    @staticmethod
    def _control(command: list[str], *, timeout: int, allow_failure: bool = False) -> str:
        try:
            result = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            if allow_failure:
                return ""
            raise AdapterExecutionError(f"Docker control command failed: {type(exc).__name__}") from exc
        output = result.stdout.strip()
        if len(output.encode()) > 65_536:
            raise AdapterExecutionError("Docker control output exceeds its metadata limit")
        if result.returncode != 0 and not allow_failure:
            detail = " ".join((result.stderr or result.stdout).split())[:1_024]
            raise AdapterExecutionError(
                f"Docker control command failed with exit {result.returncode}: {detail}"
            )
        return output


class AdapterSandboxSupervisor:
    def __init__(self, offline: OfflineSandboxSupervisor | None = None) -> None:
        self.offline = offline or OfflineSandboxSupervisor()
        self._oci: OciSandboxSupervisor | None = None

    def run(
        self,
        invocation: AdapterInvocation,
        input_path: Path,
        work_dir: Path,
        limits: OperationResourceLimits,
    ) -> SupervisedProcessResult:
        if isinstance(invocation, OciTrustedInvocation):
            if self._oci is None:
                self._oci = OciSandboxSupervisor()
            return self._oci.run(invocation, input_path, work_dir, limits)
        return self.offline.run(invocation, input_path, work_dir, limits)


class LlvmObjectInspectDriver:
    adapter_id = "llvm"
    operation_id = "llvm.object-inspect"
    driver_id = "whitehat.llvm-readobj"
    driver_version = DRIVER_VERSION

    def _executable(self, entrypoints: list[str]) -> Path:
        candidates = [Path(path) for path in entrypoints]
        candidates.extend(path.with_name("llvm-readobj") for path in tuple(candidates))
        executable = next(
            (path.resolve() for path in candidates if path.name == "llvm-readobj" and path.is_file()),
            None,
        )
        if executable is None:
            raise AdapterExecutionError("LLVM operation requires an observed llvm-readobj entrypoint")
        return executable

    def tool_payload_digest(self, entrypoints: list[str]) -> str:
        return _hash_file(self._executable(entrypoints))

    def prepare(
        self,
        status: AdapterStatus,
        operation: AdapterOperationPayload,
        limits: OperationResourceLimits,
        assets: dict[str, Path],
    ) -> TrustedInvocation:
        del operation, limits, assets
        executable = self._executable(status.entrypoints)
        return TrustedInvocation(
            argv=(
                "/opt/tool/llvm-readobj",
                "--elf-output-style=JSON",
                "--file-header",
                "--section-headers",
                "--symbols",
                "--needed-libs",
                "/input/artifact",
            ),
            mounts=(SandboxMount(executable, "/opt/tool/llvm-readobj"),),
        )

    def normalize(
        self,
        process: SupervisedProcessResult,
        artifact_sha256: str,
        limits: OperationResourceLimits,
        operation: AdapterOperationPayload | None = None,
    ) -> AdapterNormalizedResult:
        del operation
        payload = _read_json(process.stdout_path, limits.max_output_bytes)
        if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], dict):
            raise AdapterExecutionError("llvm-readobj emitted an unexpected JSON document")
        item = payload[0]
        summary = item.get("FileSummary")
        if not isinstance(summary, dict):
            raise AdapterExecutionError("llvm-readobj output has no FileSummary")
        remaining = limits.max_records
        sections = _llvm_records(item.get("Sections"), "Section", remaining)
        remaining -= len(sections[0])
        symbols = _llvm_records(item.get("Symbols"), "Symbol", remaining)
        remaining -= len(symbols[0])
        all_libraries = item.get("NeededLibraries") if isinstance(item.get("NeededLibraries"), list) else []
        libraries = all_libraries[:remaining]
        total = len(sections[0]) + len(symbols[0]) + len(libraries)
        truncated = sections[1] or symbols[1] or len(all_libraries) > len(libraries)
        data: dict[str, JsonValue] = {
            "format": str(summary.get("Format", "")),
            "architecture": str(summary.get("Arch", "")),
            "address_size": str(summary.get("AddressSize", "")),
            "file_header": _json_value(item.get("ElfHeader", {})),
            "sections": sections[0],
            "symbols": symbols[0],
            "needed_libraries": _json_value(libraries),
        }
        return AdapterNormalizedResult(
            operation_id=self.operation_id,
            artifact_sha256=artifact_sha256,
            records_returned=total,
            truncated=truncated,
            data=data,
        )

    def fixture_checks(self, normalized: AdapterNormalizedResult) -> list[AdapterConformanceCheck]:
        sections = normalized.data.get("sections", [])
        return [
            AdapterConformanceCheck(
                name="fixture-format",
                ok=normalized.data.get("format") == "elf64-x86-64",
                detail=str(normalized.data.get("format")),
            ),
            AdapterConformanceCheck(
                name="fixture-architecture",
                ok=normalized.data.get("architecture") == "x86_64",
                detail=str(normalized.data.get("architecture")),
            ),
            AdapterConformanceCheck(
                name="fixture-text-section",
                ok=any(isinstance(item, dict) and _nested_name(item) == ".text" for item in sections),
                detail=f"returned_sections={len(sections)}",
            ),
        ]


class GoReSymSymbolMapDriver:
    adapter_id = "goresym"
    operation_id = "goresym.symbol-map"
    driver_id = "whitehat.goresym-symbol-map"
    driver_version = GORESYM_DRIVER_VERSION

    def _executable(self, entrypoints: list[str]) -> Path:
        executable = next(
            (
                Path(path).resolve()
                for path in entrypoints
                if Path(path).name.casefold() in {"goresym", "goresym.exe"} and Path(path).is_file()
            ),
            None,
        )
        if executable is None:
            raise AdapterExecutionError("GoReSym operation requires an observed GoReSym entrypoint")
        return executable

    def tool_payload_digest(self, entrypoints: list[str]) -> str:
        return _hash_file(self._executable(entrypoints))

    def prepare(
        self,
        status: AdapterStatus,
        operation: AdapterOperationPayload,
        limits: OperationResourceLimits,
        assets: dict[str, Path],
    ) -> TrustedInvocation:
        del limits, assets
        if not isinstance(operation, GoReSymSymbolMapPayload):
            raise AdapterExecutionError("GoReSym driver received a different operation payload")
        executable = self._executable(status.entrypoints)
        return TrustedInvocation(
            argv=(
                "/opt/tool/GoReSym",
                "-t",
                "-d",
                "-p",
                "-strings",
                "/input/artifact",
            ),
            mounts=(SandboxMount(executable, "/opt/tool/GoReSym"),),
        )

    def normalize(
        self,
        process: SupervisedProcessResult,
        artifact_sha256: str,
        limits: OperationResourceLimits,
        operation: AdapterOperationPayload | None = None,
    ) -> AdapterNormalizedResult:
        if operation is not None and not isinstance(operation, GoReSymSymbolMapPayload):
            raise AdapterExecutionError("GoReSym driver received a different operation payload")
        payload = _read_json(process.stdout_path, limits.max_output_bytes)
        data, records_returned, truncated = _normalize_goresym_payload(payload, limits)
        return AdapterNormalizedResult(
            operation_id=self.operation_id,
            artifact_sha256=artifact_sha256,
            records_returned=records_returned,
            truncated=truncated,
            data=data,
        )

    def fixture_checks(self, normalized: AdapterNormalizedResult) -> list[AdapterConformanceCheck]:
        build = normalized.data.get("build", {})
        functions = normalized.data.get("user_functions", {})
        types = normalized.data.get("types", {})
        files = normalized.data.get("files", {})
        function_items = functions.get("items", []) if isinstance(functions, dict) else []
        type_items = types.get("items", []) if isinstance(types, dict) else []
        file_items = files.get("items", []) if isinstance(files, dict) else []
        return [
            AdapterConformanceCheck(
                name="fixture-go-identity",
                ok=(
                    isinstance(build, dict)
                    and bool(build.get("go_version"))
                    and build.get("architecture") == "amd64"
                    and build.get("operating_system") == "linux"
                ),
                detail=(
                    f"go={build.get('go_version')}; arch={build.get('architecture')}; "
                    f"os={build.get('operating_system')}"
                    if isinstance(build, dict)
                    else "missing"
                ),
            ),
            AdapterConformanceCheck(
                name="fixture-main-function",
                ok=any(
                    isinstance(item, dict) and item.get("full_name") == "main.main" for item in function_items
                ),
                detail=f"returned_user_functions={len(function_items)}",
            ),
            AdapterConformanceCheck(
                name="fixture-metadata-type",
                ok=any(
                    isinstance(item, dict) and str(item.get("name", "")).lstrip("*") == "main.ExtractMetadata"
                    for item in type_items
                ),
                detail=f"returned_types={len(type_items)}",
            ),
            AdapterConformanceCheck(
                name="fixture-source-path",
                ok=any(
                    isinstance(item, dict)
                    and str(item.get("path", "")).replace("\\", "/").endswith("/GoReSym/main.go")
                    for item in file_items
                ),
                detail=f"returned_files={len(file_items)}",
            ),
        ]


class UnblobExtractionMapDriver:
    adapter_id = "unblob"
    operation_id = "unblob.extraction-map"
    driver_id = "whitehat.unblob-extraction-map"
    driver_version = UNBLOB_DRIVER_VERSION
    descriptor_name = "unblob-image.env"

    def _descriptor(self, entrypoints: list[str]) -> tuple[Path, dict[str, str]]:
        candidates = [
            Path(value).resolve()
            for value in entrypoints
            if Path(value).name == self.descriptor_name and Path(value).is_file()
        ]
        if len(candidates) != 1:
            raise AdapterExecutionError("unblob operation requires one managed OCI descriptor")
        path = candidates[0]
        if path.is_symlink() or path.stat().st_size > 4_096:
            raise AdapterExecutionError("unblob OCI descriptor is not a bounded regular file")
        values: dict[str, str] = {}
        for line in path.read_text(encoding="utf-8").splitlines():
            key, separator, value = line.partition("=")
            if not separator or key in values:
                raise AdapterExecutionError("unblob OCI descriptor is malformed")
            values[key] = value
        expected = {
            "schema_version",
            "version",
            "image",
            "platform",
            "index_sha256",
            "manifest_sha256",
            "config_sha256",
            "source_revision",
            "compressed_bytes",
            "entrypoint_json",
        }
        try:
            entrypoint = json.loads(values.get("entrypoint_json", ""))
            compressed_bytes = int(values.get("compressed_bytes", "0"))
        except (json.JSONDecodeError, ValueError) as exc:
            raise AdapterExecutionError("unblob OCI descriptor has invalid typed fields") from exc
        if (
            set(values) != expected
            or values["schema_version"] != "1.0"
            or values["image"] != "ghcr.io/onekey-sec/unblob"
            or values["platform"] not in {"linux/amd64", "linux/arm64"}
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,199}", values["version"]) is None
            or any(
                re.fullmatch(r"[0-9a-f]{64}", values[key]) is None
                for key in ("index_sha256", "manifest_sha256", "config_sha256")
            )
            or re.fullmatch(r"[0-9a-f]{40}", values["source_revision"]) is None
            or not 1 <= compressed_bytes <= 2_147_483_648
            or entrypoint != ["unblob"]
        ):
            raise AdapterExecutionError("unblob OCI descriptor violates its fixed image contract")
        return path, values

    def tool_payload_digest(self, entrypoints: list[str]) -> str:
        descriptor, values = self._descriptor(entrypoints)
        try:
            from .adapter_provisioning import _trusted_docker_executable

            docker = _trusted_docker_executable()
        except RuntimeError as exc:
            raise AdapterExecutionError("unblob operation requires the trusted Docker CLI") from exc
        return stable_digest(
            {
                "descriptor_sha256": _hash_file(descriptor),
                "manifest_sha256": values["manifest_sha256"],
                "docker_cli_sha256": _hash_file(docker),
                "sandbox_profile_sha256": OCI_SANDBOX_PROFILE_SHA256,
                "command_contract": "unblob-fixed-recursive-extraction-v1",
            }
        )

    def prepare(
        self,
        status: AdapterStatus,
        operation: AdapterOperationPayload,
        limits: OperationResourceLimits,
        assets: dict[str, Path],
    ) -> OciTrustedInvocation:
        del assets
        if not isinstance(operation, UnblobExtractionMapPayload):
            raise AdapterExecutionError("unblob driver received a different operation payload")
        if limits.max_processes < 16:
            raise AdapterExecutionError("unblob extraction requires a process limit of at least 16")
        _, descriptor = self._descriptor(status.entrypoints)
        return OciTrustedInvocation(
            image_reference=(f"{descriptor['image']}@sha256:{descriptor['manifest_sha256']}"),
            platform=descriptor["platform"],  # type: ignore[arg-type]
            argv=(
                "--report",
                "/data/output/report.json",
                "--log",
                "/data/output/unblob.log",
                "--extract-dir",
                "/data/output/extracted",
                "--process-num",
                "1",
                "--depth",
                "3",
                "--randomness-depth",
                "0",
                "/data/input/artifact",
            ),
            result_relative_path="report.json",
        )

    def normalize(
        self,
        process: SupervisedProcessResult,
        artifact_sha256: str,
        limits: OperationResourceLimits,
        operation: AdapterOperationPayload | None = None,
    ) -> AdapterNormalizedResult:
        if operation is not None and not isinstance(operation, UnblobExtractionMapPayload):
            raise AdapterExecutionError("unblob normalization requires its exact operation payload")
        if process.result_path is None:
            raise AdapterExecutionError("unblob execution did not expose its fixed report path")
        payload = _read_json(process.result_path, limits.max_output_bytes)
        if not isinstance(payload, list) or len(payload) > limits.max_files + 1:
            raise AdapterExecutionError("unblob report must be a bounded task list")
        extracted_root = process.result_path.parent / "extracted"
        actual_entries = _unblob_output_entries(extracted_root, limits)
        report_types: dict[str, int] = {}
        files: list[dict[str, JsonValue]] = []
        directories: list[dict[str, JsonValue]] = []
        links: list[dict[str, JsonValue]] = []
        chunks: list[dict[str, JsonValue]] = []
        errors: list[dict[str, JsonValue]] = []
        reported_paths: set[str] = set()
        input_identity: dict[str, JsonValue] | None = None
        max_depth = 0
        for raw_task in payload:
            if not isinstance(raw_task, dict) or set(raw_task) != {"task", "reports", "subtasks"}:
                raise AdapterExecutionError("unblob task has an unexpected shape")
            task = raw_task["task"]
            reports = raw_task["reports"]
            subtasks = raw_task["subtasks"]
            if (
                not isinstance(task, dict)
                or not isinstance(reports, list)
                or len(reports) > 64
                or not isinstance(subtasks, list)
                or len(subtasks) > limits.max_files
            ):
                raise AdapterExecutionError("unblob task fields are missing or unbounded")
            task_path = _unblob_task_path(task.get("path"))
            depth = task.get("depth")
            if isinstance(depth, bool) or not isinstance(depth, int) or not 0 <= depth <= 3:
                raise AdapterExecutionError("unblob task depth violates the fixed recursion bound")
            max_depth = max(max_depth, depth)
            typed: dict[str, list[dict[str, object]]] = {}
            for report in reports:
                if not isinstance(report, dict):
                    raise AdapterExecutionError("unblob report entry must be an object")
                report_type = report.get("__typename__")
                if not isinstance(report_type, str) or not 1 <= len(report_type) <= 128:
                    raise AdapterExecutionError("unblob report entry has no bounded type")
                report_types[report_type] = report_types.get(report_type, 0) + 1
                typed.setdefault(report_type, []).append(report)
            for singleton in ("StatReport", "FileMagicReport", "HashReport"):
                if len(typed.get(singleton, [])) > 1:
                    raise AdapterExecutionError(f"unblob task contains duplicate {singleton}")
            stat_report = next(iter(typed.get("StatReport", [])), None)
            hash_report = next(iter(typed.get("HashReport", [])), None)
            magic_report = next(iter(typed.get("FileMagicReport", [])), None)
            if stat_report is None:
                raise AdapterExecutionError("unblob task has no StatReport")
            stat_path = _unblob_task_path(stat_report.get("path"))
            if stat_path != task_path:
                raise AdapterExecutionError("unblob task and StatReport paths differ")
            record = _unblob_stat_record(stat_report, hash_report, magic_report, depth)
            if task_path == "input":
                if input_identity is not None:
                    raise AdapterExecutionError("unblob report contains multiple input tasks")
                if record.get("sha256") != artifact_sha256:
                    raise AdapterExecutionError("unblob input digest differs from the evidence artifact")
                input_identity = record
            else:
                if task_path in reported_paths:
                    raise AdapterExecutionError("unblob report contains duplicate extracted paths")
                reported_paths.add(task_path)
                actual = actual_entries.get(task_path)
                if actual is None or not _unblob_records_match(record, actual):
                    raise AdapterExecutionError("unblob report differs from the extracted output tree")
                kind = record["kind"]
                if kind == "file":
                    files.append(record)
                elif kind == "directory":
                    directories.append(record)
                else:
                    links.append(record)
            for chunk_report in typed.get("ChunkReport", []):
                chunks.append(_unblob_chunk_record(chunk_report, task_path))
            for report_type, items in typed.items():
                if "error" in report_type.casefold():
                    errors.extend({"path": task_path, "type": report_type} for _ in items)
        if input_identity is None:
            raise AdapterExecutionError("unblob report does not identify the input artifact")
        if reported_paths != set(actual_entries):
            raise AdapterExecutionError("unblob report does not cover the complete extracted output tree")
        files.sort(key=lambda item: str(item["path"]))
        directories.sort(key=lambda item: str(item["path"]))
        links.sort(key=lambda item: str(item["path"]))
        chunks.sort(key=lambda item: (str(item["path"]), int(item["start_offset"])))
        errors.sort(key=lambda item: (str(item["path"]), str(item["type"])))
        total_records = len(files) + len(directories) + len(links) + len(chunks) + len(errors)
        remaining = limits.max_records
        returned: list[list[dict[str, JsonValue]]] = []
        for records in (files, directories, links, chunks, errors):
            selected = records[:remaining]
            returned.append(selected)
            remaining -= len(selected)
        returned_files, returned_directories, returned_links, returned_chunks, returned_errors = returned
        handlers: dict[str, int] = {}
        for chunk in chunks:
            handler = str(chunk["handler"])
            handlers[handler] = handlers.get(handler, 0) + 1
        data: dict[str, JsonValue] = {
            "engine": "unblob",
            "input": input_identity,
            "summary": {
                "files": len(files),
                "directories": len(directories),
                "links": len(links),
                "chunks": len(chunks),
                "errors": len(errors),
                "extracted_bytes": sum(int(item["size"]) for item in files),
                "max_depth": max_depth,
                "handlers": dict(sorted(handlers.items())),
                "report_types": dict(sorted(report_types.items())),
            },
            "files": returned_files,
            "directories": returned_directories,
            "links": returned_links,
            "chunks": returned_chunks,
            "errors": returned_errors,
        }
        return AdapterNormalizedResult(
            operation_id=self.operation_id,
            artifact_sha256=artifact_sha256,
            records_returned=sum(len(records) for records in returned),
            truncated=total_records > limits.max_records,
            data=data,
        )

    def fixture_checks(self, normalized: AdapterNormalizedResult) -> list[AdapterConformanceCheck]:
        files = normalized.data.get("files")
        chunks = normalized.data.get("chunks")
        marker = (
            next(
                (
                    item
                    for item in files
                    if isinstance(item, dict) and str(item.get("path", "")).endswith("wha-unblob-marker.txt")
                ),
                None,
            )
            if isinstance(files, list)
            else None
        )
        zip_chunk = (
            next(
                (item for item in chunks if isinstance(item, dict) and item.get("handler") == "zip"),
                None,
            )
            if isinstance(chunks, list)
            else None
        )
        summary = normalized.data.get("summary")
        return [
            AdapterConformanceCheck(
                name="fixture-zip-handler",
                ok=isinstance(zip_chunk, dict) and zip_chunk.get("encrypted") is False,
                detail=f"returned_chunks={len(chunks) if isinstance(chunks, list) else 0}",
            ),
            AdapterConformanceCheck(
                name="fixture-extracted-marker",
                ok=(
                    isinstance(marker, dict)
                    and marker.get("sha256")
                    == "df5e84bcd760b28d68dff7ea622a65b3aa2178f9c23a46191d0b30ab65ee66cf"
                ),
                detail=f"returned_files={len(files) if isinstance(files, list) else 0}",
            ),
            AdapterConformanceCheck(
                name="fixture-clean-extraction",
                ok=isinstance(summary, dict) and summary.get("errors") == 0,
                detail=f"errors={summary.get('errors') if isinstance(summary, dict) else 'missing'}",
            ),
        ]


class CapaFileAnalyzeDriver:
    adapter_id = "capa"
    operation_id = "capa.file-analyze"
    driver_id = "whitehat.capa-json"
    driver_version = DRIVER_VERSION

    def _executable(self, entrypoints: list[str]) -> Path:
        executable = next(
            (Path(path).resolve() for path in entrypoints if Path(path).name == "capa"),
            None,
        )
        if executable is None or not executable.is_file():
            raise AdapterExecutionError("capa operation requires an observed capa entrypoint")
        return executable

    def tool_payload_digest(self, entrypoints: list[str]) -> str:
        return _hash_file(self._executable(entrypoints))

    def prepare(
        self,
        status: AdapterStatus,
        operation: AdapterOperationPayload,
        limits: OperationResourceLimits,
        assets: dict[str, Path],
    ) -> TrustedInvocation:
        del limits, assets
        if not isinstance(operation, CapaFileAnalyzePayload):
            raise AdapterExecutionError("capa driver received a different operation payload")
        argv = ["/opt/tool/capa", "-j"]
        if operation.operating_system != "auto":
            argv.extend(("--os", operation.operating_system))
        argv.append("/input/artifact")
        return TrustedInvocation(
            argv=tuple(argv),
            mounts=(SandboxMount(self._executable(status.entrypoints), "/opt/tool/capa"),),
        )

    def normalize(
        self,
        process: SupervisedProcessResult,
        artifact_sha256: str,
        limits: OperationResourceLimits,
        operation: AdapterOperationPayload | None = None,
    ) -> AdapterNormalizedResult:
        del operation
        payload = _read_json(process.stdout_path, limits.max_output_bytes)
        if not isinstance(payload, dict) or not isinstance(payload.get("meta"), dict):
            raise AdapterExecutionError("capa emitted an unexpected JSON document")
        meta = payload["meta"]
        sample = meta.get("sample") if isinstance(meta.get("sample"), dict) else {}
        if sample.get("sha256") != artifact_sha256:
            raise AdapterExecutionError("capa sample digest does not match the input evidence")
        analysis = meta.get("analysis") if isinstance(meta.get("analysis"), dict) else {}
        rules = payload.get("rules") if isinstance(payload.get("rules"), dict) else {}
        records: list[JsonValue] = []
        for name in sorted(rules)[: limits.max_records]:
            value = rules[name] if isinstance(rules[name], dict) else {}
            rule_meta = value.get("meta") if isinstance(value.get("meta"), dict) else {}
            matches = value.get("matches") if isinstance(value.get("matches"), list) else []
            records.append(
                {
                    "name": name,
                    "namespace": str(rule_meta.get("namespace", "")),
                    "scopes": _json_value(rule_meta.get("scopes", {})),
                    "attack": _json_value(rule_meta.get("attack", [])),
                    "mbc": _json_value(rule_meta.get("mbc", [])),
                    "match_count": len(matches),
                }
            )
        data: dict[str, JsonValue] = {
            "capa_version": str(meta.get("version", "")),
            "flavor": str(meta.get("flavor", "")),
            "format": str(analysis.get("format", "")),
            "architecture": str(analysis.get("arch", "")),
            "operating_system": str(analysis.get("os", "")),
            "extractor": str(analysis.get("extractor", "")),
            "base_address": _json_value(analysis.get("base_address", {})),
            "feature_counts": _feature_count_summary(analysis.get("feature_counts")),
            "rules": records,
            "total_rules": len(rules),
        }
        return AdapterNormalizedResult(
            operation_id=self.operation_id,
            artifact_sha256=artifact_sha256,
            records_returned=len(records),
            truncated=len(rules) > len(records),
            data=data,
        )

    def fixture_checks(self, normalized: AdapterNormalizedResult) -> list[AdapterConformanceCheck]:
        return [
            AdapterConformanceCheck(
                name="fixture-format",
                ok=normalized.data.get("format") == "elf",
                detail=str(normalized.data.get("format")),
            ),
            AdapterConformanceCheck(
                name="fixture-architecture",
                ok=normalized.data.get("architecture") == "amd64",
                detail=str(normalized.data.get("architecture")),
            ),
            AdapterConformanceCheck(
                name="fixture-os",
                ok=normalized.data.get("operating_system") == "linux",
                detail=str(normalized.data.get("operating_system")),
            ),
        ]


class YaraXFileScanDriver:
    adapter_id = "yara-x"
    operation_id = "yara-x.file-scan"
    driver_id = "whitehat.yara-x-ndjson"
    driver_version = YARA_X_DRIVER_VERSION
    max_matches_per_pattern = 32
    match_text_bytes = 64

    def _executable(self, entrypoints: list[str]) -> Path:
        executable = next(
            (Path(path).resolve() for path in entrypoints if Path(path).name.casefold() in {"yr", "yr.exe"}),
            None,
        )
        if executable is None or not executable.is_file():
            raise AdapterExecutionError("YARA-X operation requires an observed yr entrypoint")
        return executable

    def tool_payload_digest(self, entrypoints: list[str]) -> str:
        return stable_digest(
            {
                "executable_sha256": _hash_file(self._executable(entrypoints)),
                "conformance_rule_sha256": YARA_X_CONFORMANCE_RULE_SHA256,
                "output_contract": "ndjson-v1",
            }
        )

    def prepare(
        self,
        status: AdapterStatus,
        operation: AdapterOperationPayload,
        limits: OperationResourceLimits,
        assets: dict[str, Path],
    ) -> TrustedInvocation:
        del assets
        if not isinstance(operation, YaraXFileScanPayload):
            raise AdapterExecutionError("YARA-X driver received a different operation payload")
        if limits.max_processes < 8:
            raise AdapterExecutionError("YARA-X file scan requires a process/thread limit of at least 8")
        if limits.memory_mib < 2048:
            raise AdapterExecutionError("YARA-X file scan requires at least 2048 MiB of address space")
        rule_bytes = operation.rule_source.encode("utf-8")
        if not rule_bytes:
            raise AdapterExecutionError("YARA-X rule source cannot be empty")
        return TrustedInvocation(
            argv=(
                "/opt/tool/yr",
                "scan",
                "--output-format",
                "ndjson",
                "--print-meta",
                "--print-namespace",
                "--print-tags",
                f"--print-strings={self.match_text_bytes}",
                "--threads",
                "1",
                "--timeout",
                str(max(1, min(limits.wall_seconds, 86_400))),
                "--max-matches-per-pattern",
                str(self.max_matches_per_pattern),
                "--no-mmap",
                "--disable-console-logs",
                "/input/rules.yar",
                "/input/artifact",
            ),
            mounts=(SandboxMount(self._executable(status.entrypoints), "/opt/tool/yr"),),
            inline_files=(SandboxInlineFile("/input/rules.yar", rule_bytes),),
        )

    def normalize(
        self,
        process: SupervisedProcessResult,
        artifact_sha256: str,
        limits: OperationResourceLimits,
        operation: AdapterOperationPayload | None = None,
    ) -> AdapterNormalizedResult:
        if not isinstance(operation, YaraXFileScanPayload):
            raise AdapterExecutionError("YARA-X normalization requires its exact operation payload")
        payload = _read_single_ndjson(process.stdout_path, limits.max_output_bytes)
        if set(payload) != {"path", "rules"} or payload.get("path") != "/input/artifact":
            raise AdapterExecutionError("YARA-X emitted an unexpected target result")
        raw_rules = payload.get("rules")
        if not isinstance(raw_rules, list):
            raise AdapterExecutionError("YARA-X result has an invalid rules collection")

        validated = [_normalize_yara_rule(value) for value in raw_rules]
        identities = [(str(rule["namespace"]), str(rule["identifier"])) for rule in validated]
        if len(identities) != len(set(identities)):
            raise AdapterExecutionError("YARA-X result contains duplicate rule identities")
        validated.sort(key=lambda rule: (str(rule["namespace"]), str(rule["identifier"])))

        returned: list[JsonValue] = []
        remaining = limits.max_records
        total_strings = sum(len(rule["strings"]) for rule in validated)
        returned_strings = 0
        match_limit_reached = False
        for raw_rule in validated:
            if remaining == 0:
                break
            remaining -= 1
            strings = list(raw_rule["strings"])
            counts: dict[str, int] = {}
            for item in strings:
                identifier = str(item["identifier"])
                counts[identifier] = counts.get(identifier, 0) + 1
            if any(count >= self.max_matches_per_pattern for count in counts.values()):
                match_limit_reached = True
            selected_strings = strings[:remaining]
            remaining -= len(selected_strings)
            returned_strings += len(selected_strings)
            returned.append(
                {
                    "identifier": raw_rule["identifier"],
                    "namespace": raw_rule["namespace"],
                    "meta": raw_rule["meta"],
                    "tags": raw_rule["tags"],
                    "strings": selected_strings,
                    "strings_truncated": len(selected_strings) != len(strings),
                }
            )

        returned_rules = len(returned)
        rule_source_bytes = operation.rule_source.encode("utf-8")
        truncated = (
            returned_rules != len(validated) or returned_strings != total_strings or match_limit_reached
        )
        data: dict[str, JsonValue] = {
            "engine": "yara-x",
            "rule_source_sha256": hashlib.sha256(rule_source_bytes).hexdigest(),
            "rule_source_bytes": len(rule_source_bytes),
            "match_text_bytes": self.match_text_bytes,
            "max_matches_per_pattern": self.max_matches_per_pattern,
            "match_limit_reached": match_limit_reached,
            "total_rule_matches": len(validated),
            "returned_rule_matches": returned_rules,
            "total_string_matches": total_strings,
            "returned_string_matches": returned_strings,
            "rules": returned,
        }
        return AdapterNormalizedResult(
            operation_id=self.operation_id,
            artifact_sha256=artifact_sha256,
            records_returned=returned_rules + returned_strings,
            truncated=truncated,
            data=data,
        )

    def fixture_checks(self, normalized: AdapterNormalizedResult) -> list[AdapterConformanceCheck]:
        rules = normalized.data.get("rules")
        marker = rules[0] if isinstance(rules, list) and len(rules) == 1 else None
        strings = marker.get("strings") if isinstance(marker, dict) else None
        string = strings[0] if isinstance(strings, list) and len(strings) == 1 else None
        metadata = marker.get("meta") if isinstance(marker, dict) else None
        return [
            AdapterConformanceCheck(
                name="fixture-rule",
                ok=(
                    isinstance(marker, dict)
                    and marker.get("identifier") == "wha_native_marker"
                    and marker.get("namespace") == "default"
                    and marker.get("tags") == ["conformance"]
                ),
                detail=f"returned_rules={normalized.data.get('returned_rule_matches', 0)}",
            ),
            AdapterConformanceCheck(
                name="fixture-rule-metadata",
                ok=metadata == [["purpose", "White Hat Agent typed YARA-X conformance"]],
                detail=f"metadata_entries={len(metadata) if isinstance(metadata, list) else 0}",
            ),
            AdapterConformanceCheck(
                name="fixture-string-match",
                ok=(
                    isinstance(string, dict)
                    and string.get("identifier") == "$marker"
                    and string.get("offset") == 192
                    and string.get("match") == "WHA_NATIVE_CODE_MAP_MARKER"
                ),
                detail=f"returned_strings={normalized.data.get('returned_string_matches', 0)}",
            ),
            AdapterConformanceCheck(
                name="fixture-rule-identity",
                ok=normalized.data.get("rule_source_sha256") == YARA_X_CONFORMANCE_RULE_SHA256,
                detail=str(normalized.data.get("rule_source_sha256", "")),
            ),
        ]


class FridaExecutableRuntimeMapDriver:
    adapter_id = "frida"
    operation_id = "frida.executable-runtime-map"
    driver_id = "whitehat.frida-inject-runtime-map"
    driver_version = FRIDA_DRIVER_VERSION
    output_marker = "WHA_FRIDA_RUNTIME_MAP_V1 "
    collection_limits: ClassVar[dict[str, int]] = {
        "modules": 1024,
        "imports": 4096,
        "exports": 4096,
        "dependencies": 1024,
    }

    def _executable(self, entrypoints: list[str]) -> Path:
        executable = next(
            (
                Path(path).resolve()
                for path in entrypoints
                if re.fullmatch(
                    r"frida-inject(?:-[0-9][A-Za-z0-9._-]*)?(?:\.exe)?",
                    Path(path).name,
                    flags=re.IGNORECASE,
                )
            ),
            None,
        )
        if executable is None or not executable.is_file():
            raise AdapterExecutionError(
                "Frida runtime map requires an observed standalone frida-inject entrypoint"
            )
        return executable

    def tool_payload_digest(self, entrypoints: list[str]) -> str:
        script = _frida_runtime_map_script_bytes()
        return stable_digest(
            {
                "executable_sha256": _hash_file(self._executable(entrypoints)),
                "observation_script_sha256": hashlib.sha256(script).hexdigest(),
                "output_contract": "frida-runtime-module-map-v1",
            }
        )

    def prepare(
        self,
        status: AdapterStatus,
        operation: AdapterOperationPayload,
        limits: OperationResourceLimits,
        assets: dict[str, Path],
    ) -> TrustedInvocation:
        del assets
        if not isinstance(operation, FridaExecutableRuntimeMapPayload):
            raise AdapterExecutionError("Frida driver received a different operation payload")
        if limits.max_processes < 8:
            raise AdapterExecutionError("Frida runtime map requires a process limit of at least 8")
        if limits.memory_mib < 1024:
            raise AdapterExecutionError("Frida runtime map requires at least 1024 MiB of address space")
        return TrustedInvocation(
            argv=(
                "/opt/tool/frida-inject",
                "--file=/input/artifact",
                "--script=/input/runtime-map.js",
                "--runtime=qjs",
                "--eternalize",
            ),
            mounts=(SandboxMount(self._executable(status.entrypoints), "/opt/tool/frida-inject"),),
            inline_files=(
                SandboxInlineFile(
                    "/input/runtime-map.js",
                    _frida_runtime_map_script_bytes(),
                ),
            ),
            executable_input=True,
        )

    def normalize(
        self,
        process: SupervisedProcessResult,
        artifact_sha256: str,
        limits: OperationResourceLimits,
        operation: AdapterOperationPayload | None = None,
    ) -> AdapterNormalizedResult:
        if not isinstance(operation, FridaExecutableRuntimeMapPayload):
            raise AdapterExecutionError("Frida normalization requires its exact operation payload")
        raw = _read_marked_json(
            process.stdout_path,
            limits.max_output_bytes,
            marker=self.output_marker,
        )
        required = {
            "schema_version",
            "producer",
            "execution_phase",
            "cleanup_strategy",
            "process",
            "main_module",
            "modules",
            "imports",
            "exports",
            "dependencies",
            "collection_errors",
        }
        if set(raw) != required:
            raise AdapterExecutionError("Frida result has an unexpected outer schema")
        if (
            raw.get("schema_version") != "1.0"
            or raw.get("producer") != "frida-inject"
            or raw.get("execution_phase") != "spawned-before-main"
            or raw.get("cleanup_strategy") != "eternalize-then-pid-namespace-teardown"
        ):
            raise AdapterExecutionError("Frida result has an invalid producer contract")

        process_record = _normalize_frida_process(raw["process"])
        main_module = _normalize_frida_module(raw["main_module"])
        normalizers = {
            "modules": _normalize_frida_module,
            "imports": _normalize_frida_import,
            "exports": _normalize_frida_export,
            "dependencies": _normalize_frida_dependency,
        }
        remaining = limits.max_records
        collections: dict[str, JsonValue] = {}
        producer_truncated = False
        broker_truncated = False
        raw_module_items: list[dict[str, JsonValue]] = []
        for name, normalizer in normalizers.items():
            total, items, collection_truncated = _normalize_frida_collection(
                raw[name],
                name=name,
                maximum_items=self.collection_limits[name],
                item_normalizer=normalizer,
            )
            if name == "modules":
                raw_module_items = items
            selected = items[:remaining]
            remaining -= len(selected)
            limited = len(selected) != len(items)
            producer_truncated = producer_truncated or collection_truncated
            broker_truncated = broker_truncated or limited
            collections[name] = {
                "total": total,
                "observed": len(items),
                "returned": len(selected),
                "producer_truncated": collection_truncated,
                "broker_truncated": limited,
                "items": selected,
            }

        if raw_module_items and not any(
            item.get("base") == main_module["base"] and item.get("name") == main_module["name"]
            for item in raw_module_items
        ):
            raise AdapterExecutionError("Frida module list does not contain the main module")
        collection_errors = _normalize_frida_collection_errors(raw["collection_errors"])
        truncated = producer_truncated or broker_truncated or bool(collection_errors)
        records_returned = sum(
            int(collection["returned"]) for collection in collections.values() if isinstance(collection, dict)
        )
        data: dict[str, JsonValue] = {
            "engine": "frida-inject",
            "execution_phase": "spawned-before-main",
            "cleanup_strategy": raw["cleanup_strategy"],
            "observation_script_sha256": FRIDA_RUNTIME_MAP_SCRIPT_SHA256,
            "record_limit": limits.max_records,
            "record_limit_reached": broker_truncated,
            "process": process_record,
            "main_module": main_module,
            "collections": collections,
            "collection_errors": collection_errors,
        }
        return AdapterNormalizedResult(
            operation_id=self.operation_id,
            artifact_sha256=artifact_sha256,
            records_returned=records_returned,
            truncated=truncated,
            data=data,
        )

    def fixture_checks(self, normalized: AdapterNormalizedResult) -> list[AdapterConformanceCheck]:
        process = normalized.data.get("process")
        main = normalized.data.get("main_module")
        collections = normalized.data.get("collections")
        modules = collections.get("modules") if isinstance(collections, dict) else None
        module_items = modules.get("items") if isinstance(modules, dict) else None
        return [
            AdapterConformanceCheck(
                name="fixture-process",
                ok=(
                    isinstance(process, dict)
                    and process.get("platform") == "linux"
                    and process.get("arch") == "x64"
                    and process.get("pointer_size") == 8
                ),
                detail=f"platform={process.get('platform') if isinstance(process, dict) else None}",
            ),
            AdapterConformanceCheck(
                name="fixture-main-module",
                ok=(
                    isinstance(main, dict)
                    and main.get("path") == "/input/artifact"
                    and isinstance(main.get("base"), str)
                ),
                detail=f"path={main.get('path') if isinstance(main, dict) else None}",
            ),
            AdapterConformanceCheck(
                name="fixture-module-list",
                ok=(
                    isinstance(module_items, list)
                    and isinstance(main, dict)
                    and any(
                        isinstance(item, dict)
                        and item.get("base") == main.get("base")
                        and item.get("name") == main.get("name")
                        for item in module_items
                    )
                ),
                detail=f"returned_modules={len(module_items) if isinstance(module_items, list) else 0}",
            ),
            AdapterConformanceCheck(
                name="fixture-cleanup-and-errors",
                ok=(
                    normalized.data.get("cleanup_strategy") == "eternalize-then-pid-namespace-teardown"
                    and normalized.data.get("collection_errors") == []
                ),
                detail=f"truncated={normalized.truncated}",
            ),
        ]


_TSHARK_REQUIRED_FIELDS = (
    "frame.number",
    "frame.time_epoch",
    "frame.len",
    "frame.cap_len",
    "frame.protocols",
)
_TSHARK_FIELD_SPECS = (
    ("eth.src", "link_source", "str"),
    ("eth.dst", "link_destination", "str"),
    ("ip.src", "ipv4_source", "str"),
    ("ip.dst", "ipv4_destination", "str"),
    ("ipv6.src", "ipv6_source", "str"),
    ("ipv6.dst", "ipv6_destination", "str"),
    ("arp.opcode", "arp_opcode", "int"),
    ("arp.src.proto_ipv4", "arp_ipv4_source", "str"),
    ("arp.dst.proto_ipv4", "arp_ipv4_destination", "str"),
    ("tcp.srcport", "tcp_source_port", "int"),
    ("tcp.dstport", "tcp_destination_port", "int"),
    ("tcp.stream", "tcp_stream", "int"),
    ("tcp.flags", "tcp_flags", "str"),
    ("tcp.seq", "tcp_sequence", "int"),
    ("tcp.ack", "tcp_acknowledgment", "int"),
    ("tcp.len", "tcp_payload_bytes", "int"),
    ("udp.srcport", "udp_source_port", "int"),
    ("udp.dstport", "udp_destination_port", "int"),
    ("udp.stream", "udp_stream", "int"),
    ("udp.length", "udp_datagram_bytes", "int"),
    ("icmp.type", "icmp_type", "int"),
    ("icmp.code", "icmp_code", "int"),
    ("icmpv6.type", "icmpv6_type", "int"),
    ("icmpv6.code", "icmpv6_code", "int"),
    ("tcp.analysis.retransmission", "tcp_retransmission", "presence"),
    ("tcp.analysis.fast_retransmission", "tcp_fast_retransmission", "presence"),
    ("tcp.analysis.out_of_order", "tcp_out_of_order", "presence"),
    ("tcp.analysis.lost_segment", "tcp_lost_segment", "presence"),
    ("tcp.analysis.duplicate_ack", "tcp_duplicate_ack", "presence"),
    ("tcp.analysis.zero_window", "tcp_zero_window", "presence"),
    ("tcp.analysis.window_full", "tcp_window_full", "presence"),
    ("tcp.analysis.keep_alive", "tcp_keep_alive", "presence"),
    ("tcp.analysis.ack_rtt", "tcp_ack_rtt", "str"),
    ("dns.id", "dns_transaction_id", "str"),
    ("dns.flags.response", "dns_is_response", "bool"),
    ("dns.qry.name", "dns_query_names", "str"),
    ("dns.qry.type", "dns_query_types", "int"),
    ("dns.a", "dns_ipv4_answers", "str"),
    ("dns.aaaa", "dns_ipv6_answers", "str"),
    ("dns.flags.rcode", "dns_response_codes", "int"),
    ("http.request.method", "http_request_methods", "str"),
    ("http.host", "http_hosts", "str"),
    ("http.request.uri", "http_request_uris", "str"),
    ("http.response.code", "http_response_codes", "int"),
    ("http.content_type", "http_content_types", "str"),
    ("tls.handshake.extensions_server_name", "tls_server_names", "str"),
    ("tls.record.version", "tls_record_versions", "str"),
    ("tls.handshake.type", "tls_handshake_types", "int"),
    ("tls.handshake.version", "tls_handshake_versions", "str"),
    ("tls.handshake.ciphersuite", "tls_cipher_suites", "str"),
    ("tls.handshake.extensions_alpn_str", "tls_alpn_protocols", "str"),
    ("quic.long.packet_type", "quic_long_packet_types", "int"),
    ("quic.version", "quic_versions", "str"),
    ("quic.dcid", "quic_destination_connection_ids", "str"),
    ("quic.scid", "quic_source_connection_ids", "str"),
    ("websocket.opcode", "websocket_opcodes", "int"),
    ("websocket.payload_length", "websocket_payload_length_code", "int"),
    ("websocket.payload_length_ext_16", "websocket_payload_bytes_16", "int"),
    ("websocket.payload_length_ext_64", "websocket_payload_bytes_64", "int"),
)
_TSHARK_SELECTED_FIELDS = (*_TSHARK_REQUIRED_FIELDS, *(item[0] for item in _TSHARK_FIELD_SPECS))


class TsharkPacketCaptureMapDriver:
    adapter_id = "tshark"
    operation_id = "tshark.packet-capture-map"
    driver_id = "whitehat.tshark-json-fields"
    driver_version = TSHARK_DRIVER_VERSION

    def _executable(self, entrypoints: list[str]) -> Path:
        executable = next(
            (
                Path(path).resolve()
                for path in entrypoints
                if Path(path).name.casefold() in {"tshark", "tshark.exe"}
            ),
            None,
        )
        if executable is None or not executable.is_file():
            raise AdapterExecutionError("TShark operation requires an observed tshark entrypoint")
        return executable

    def tool_payload_digest(self, entrypoints: list[str]) -> str:
        return stable_digest(
            {
                "executable_sha256": _hash_file(self._executable(entrypoints)),
                "selected_fields": list(_TSHARK_SELECTED_FIELDS),
                "output_contract": "packet-protocol-map-v1",
            }
        )

    def prepare(
        self,
        status: AdapterStatus,
        operation: AdapterOperationPayload,
        limits: OperationResourceLimits,
        assets: dict[str, Path],
    ) -> TrustedInvocation:
        del assets
        if not isinstance(operation, TsharkPacketCaptureMapPayload):
            raise AdapterExecutionError("TShark driver received a different operation payload")
        argv = [
            "/opt/tool/tshark",
            "-r",
            "/input/artifact",
            "-n",
            "-Q",
            "-c",
            str(limits.max_records),
            "-T",
            "json",
            "--no-duplicate-keys",
            "--temp-dir",
            "/tmp",
        ]
        for field in _TSHARK_SELECTED_FIELDS:
            argv.extend(("-e", field))
        return TrustedInvocation(
            argv=tuple(argv),
            mounts=(SandboxMount(self._executable(status.entrypoints), "/opt/tool/tshark"),),
        )

    def normalize(
        self,
        process: SupervisedProcessResult,
        artifact_sha256: str,
        limits: OperationResourceLimits,
        operation: AdapterOperationPayload | None = None,
    ) -> AdapterNormalizedResult:
        if not isinstance(operation, TsharkPacketCaptureMapPayload):
            raise AdapterExecutionError("TShark normalization requires its exact operation payload")
        raw = _read_json(process.stdout_path, limits.max_output_bytes)
        if not isinstance(raw, list) or len(raw) > limits.max_records:
            raise AdapterExecutionError("TShark result has an invalid packet collection")

        packets: list[dict[str, JsonValue]] = []
        previous_number = 0
        protocol_counts: dict[str, int] = {}
        for item in raw:
            packet = _normalize_tshark_packet(item)
            number = int(packet["number"])
            if number <= previous_number:
                raise AdapterExecutionError("TShark result has duplicate or unordered frame numbers")
            previous_number = number
            packets.append(packet)
            for protocol in packet["protocols"]:
                name = str(protocol)
                protocol_counts[name] = protocol_counts.get(name, 0) + 1

        limit_reached = len(packets) == limits.max_records
        data: dict[str, JsonValue] = {
            "decoder": "tshark",
            "packet_limit": limits.max_records,
            "packet_limit_reached": limit_reached,
            "returned_packets": len(packets),
            "first_timestamp_epoch": packets[0]["timestamp_epoch"] if packets else None,
            "last_timestamp_epoch": packets[-1]["timestamp_epoch"] if packets else None,
            "total_wire_bytes": sum(int(packet["wire_bytes"]) for packet in packets),
            "total_captured_bytes": sum(int(packet["captured_bytes"]) for packet in packets),
            "protocol_counts": dict(sorted(protocol_counts.items())),
            "stream_endpoint_basis": "unambiguous single-layer TCP and UDP fields",
            "streams": _tshark_stream_summaries(packets),
            "packets": packets,
        }
        return AdapterNormalizedResult(
            operation_id=self.operation_id,
            artifact_sha256=artifact_sha256,
            records_returned=len(packets),
            truncated=limit_reached,
            data=data,
        )

    def fixture_checks(self, normalized: AdapterNormalizedResult) -> list[AdapterConformanceCheck]:
        packets = normalized.data.get("packets")
        packet_items = packets if isinstance(packets, list) else []
        fields = [item.get("fields", {}) for item in packet_items if isinstance(item, dict)]
        streams = normalized.data.get("streams")
        stream_items = streams if isinstance(streams, list) else []
        return [
            AdapterConformanceCheck(
                name="fixture-packets-and-protocols",
                ok=(
                    normalized.data.get("returned_packets") == 7
                    and normalized.data.get("protocol_counts", {}).get("dns") == 2
                    and normalized.data.get("protocol_counts", {}).get("http") == 2
                ),
                detail=f"returned_packets={normalized.data.get('returned_packets', 0)}",
            ),
            AdapterConformanceCheck(
                name="fixture-dns",
                ok=any(
                    isinstance(item, dict)
                    and item.get("dns_query_names") == ["fixture.test"]
                    and item.get("dns_ipv4_answers") == ["203.0.113.7"]
                    for item in fields
                ),
                detail="fixture.test resolves to its documentation address",
            ),
            AdapterConformanceCheck(
                name="fixture-http",
                ok=(
                    any(
                        isinstance(item, dict)
                        and item.get("http_request_methods") == ["GET"]
                        and item.get("http_hosts") == ["fixture.test"]
                        and item.get("http_request_uris") == ["/status?fixture=1"]
                        for item in fields
                    )
                    and any(
                        isinstance(item, dict) and item.get("http_response_codes") == [200] for item in fields
                    )
                ),
                detail="fixed request and response metadata decoded",
            ),
            AdapterConformanceCheck(
                name="fixture-streams",
                ok=(
                    len(stream_items) == 2
                    and {item.get("transport") for item in stream_items if isinstance(item, dict)}
                    == {"tcp", "udp"}
                ),
                detail=f"returned_streams={len(stream_items)}",
            ),
        ]


def _ghidra_entrypoint(entrypoints: list[str]) -> Path:
    entrypoint = next(
        (Path(path).resolve() for path in entrypoints if Path(path).name == "analyzeHeadless"),
        None,
    )
    if entrypoint is None or not entrypoint.is_file():
        raise AdapterExecutionError("Ghidra operation requires an observed analyzeHeadless entrypoint")
    return entrypoint


def _ghidra_root(entrypoints: list[str]) -> Path:
    return _ghidra_entrypoint(entrypoints).parent.parent


def _ghidra_tool_payload_digest(entrypoints: list[str], script_payload: bytes) -> str:
    root = _ghidra_root(entrypoints)
    operation_files = [
        root / "ghidraRun",
        root / "support/analyzeHeadless",
        root / "Ghidra/application.properties",
        root / "Ghidra/Framework/Generic/lib/Generic.jar",
        root / "Ghidra/Framework/Project/lib/Project.jar",
        root / "Ghidra/Framework/SoftwareModeling/lib/SoftwareModeling.jar",
        root / "Ghidra/Features/Base/lib/Base.jar",
        root / "Ghidra/Features/Decompiler/lib/Decompiler.jar",
        root / "Ghidra/Processors/x86/data/languages/x86-64.sla",
        root / "Ghidra/Processors/x86/data/languages/x86.ldefs",
    ]
    provider_digest = _hash_file_set(root, operation_files)
    java_digest, java_config_digest = _system_java_payload_digests(entrypoints)
    return stable_digest(
        {
            "provider_payload_sha256": provider_digest,
            "java_payload_sha256": java_digest,
            "java_config_sha256": java_config_digest,
            "driver_asset_sha256": hashlib.sha256(script_payload).hexdigest(),
        }
    )


class GhidraBinarySummaryDriver:
    adapter_id = "ghidra"
    operation_id = "ghidra.binary-summary"
    driver_id = "whitehat.ghidra-headless-summary"
    driver_version = DRIVER_VERSION

    def _root(self, entrypoints: list[str]) -> Path:
        return _ghidra_root(entrypoints)

    def tool_payload_digest(self, entrypoints: list[str]) -> str:
        return _ghidra_tool_payload_digest(entrypoints, _ghidra_script_bytes())

    def prepare(
        self,
        status: AdapterStatus,
        operation: AdapterOperationPayload,
        limits: OperationResourceLimits,
        assets: dict[str, Path],
    ) -> TrustedInvocation:
        del operation
        script = assets.get("ghidra_script")
        if script is None:
            raise AdapterExecutionError("bundled Ghidra summary script is unavailable")
        analysis_timeout = max(1, min(limits.wall_seconds - 5, limits.cpu_seconds, 600))
        return TrustedInvocation(
            argv=(
                "/opt/tool/support/analyzeHeadless",
                "/work",
                "wha-project",
                "-import",
                "/input/artifact",
                "-scriptPath",
                "/opt/wha-assets",
                "-postScript",
                "WhaBinarySummary.java",
                "/work/summary.json",
                str(limits.max_records),
                "-analysisTimeoutPerFile",
                str(analysis_timeout),
                "-max-cpu",
                "1",
                "-deleteProject",
            ),
            mounts=(
                SandboxMount(self._root(status.entrypoints), "/opt/tool"),
                *_system_java_mounts(status.entrypoints),
                SandboxMount(script, "/opt/wha-assets/WhaBinarySummary.java"),
            ),
            result_relative_path="summary.json",
        )

    def normalize(
        self,
        process: SupervisedProcessResult,
        artifact_sha256: str,
        limits: OperationResourceLimits,
        operation: AdapterOperationPayload | None = None,
    ) -> AdapterNormalizedResult:
        del operation
        if process.result_path is None or not process.result_path.is_file():
            raise AdapterExecutionError("Ghidra summary output is missing")
        payload = _read_json(process.result_path, limits.max_output_bytes)
        if not isinstance(payload, dict) or payload.get("schema_version") != "1.0":
            raise AdapterExecutionError("Ghidra summary output has an unexpected schema")
        functions = payload.get("functions") if isinstance(payload.get("functions"), dict) else {}
        externals = (
            payload.get("external_symbols") if isinstance(payload.get("external_symbols"), dict) else {}
        )
        memory = payload.get("memory_blocks") if isinstance(payload.get("memory_blocks"), dict) else {}
        for label, value in (
            ("functions", functions),
            ("external_symbols", externals),
            ("memory_blocks", memory),
        ):
            items = value.get("items") if isinstance(value.get("items"), list) else []
            if len(items) > limits.max_records:
                raise AdapterExecutionError(f"Ghidra {label} exceeds the record limit")
        returned = sum(int(value.get("returned", 0)) for value in (functions, externals, memory))
        if returned > limits.max_records:
            raise AdapterExecutionError("Ghidra aggregate output exceeds the record limit")
        data: dict[str, JsonValue] = {
            "program": _json_value(payload.get("program", {})),
            "memory_blocks": _json_value(memory),
            "functions": _json_value(functions),
            "external_symbols": _json_value(externals),
        }
        return AdapterNormalizedResult(
            operation_id=self.operation_id,
            artifact_sha256=artifact_sha256,
            records_returned=returned,
            truncated=any(bool(value.get("truncated")) for value in (functions, externals, memory)),
            data=data,
        )

    def fixture_checks(self, normalized: AdapterNormalizedResult) -> list[AdapterConformanceCheck]:
        program = normalized.data.get("program", {})
        functions = normalized.data.get("functions", {})
        items = functions.get("items", []) if isinstance(functions, dict) else []
        return [
            AdapterConformanceCheck(
                name="fixture-format",
                ok=isinstance(program, dict) and "ELF" in str(program.get("format", "")),
                detail=str(program.get("format", "")) if isinstance(program, dict) else "missing",
            ),
            AdapterConformanceCheck(
                name="fixture-language",
                ok=isinstance(program, dict) and str(program.get("language", "")).startswith("x86:LE:64"),
                detail=str(program.get("language", "")) if isinstance(program, dict) else "missing",
            ),
            AdapterConformanceCheck(
                name="fixture-function",
                ok=bool(items),
                detail=f"returned_functions={len(items)}",
            ),
        ]


class GhidraNativeCodeMapDriver:
    adapter_id = "ghidra"
    operation_id = "ghidra.native-code-map"
    driver_id = "whitehat.ghidra-native-code-map"
    driver_version = GHIDRA_NATIVE_MAP_DRIVER_VERSION

    def tool_payload_digest(self, entrypoints: list[str]) -> str:
        return _ghidra_tool_payload_digest(entrypoints, _ghidra_native_map_script_bytes())

    def prepare(
        self,
        status: AdapterStatus,
        operation: AdapterOperationPayload,
        limits: OperationResourceLimits,
        assets: dict[str, Path],
    ) -> TrustedInvocation:
        if not isinstance(operation, GhidraNativeCodeMapPayload):
            raise AdapterExecutionError("Ghidra native-code-map driver received a different payload")
        script = assets.get("ghidra_native_map_script")
        if script is None:
            raise AdapterExecutionError("bundled Ghidra native-code-map script is unavailable")
        analysis_timeout = max(1, min(limits.wall_seconds - 5, limits.cpu_seconds, 900))
        decompile_timeout = max(1, min(30, analysis_timeout, limits.cpu_seconds))
        json_character_limit = max(1024, min(16_000_000, limits.max_output_bytes // 8))
        return TrustedInvocation(
            argv=(
                "/opt/tool/support/analyzeHeadless",
                "/work",
                "wha-project",
                "-import",
                "/input/artifact",
                "-scriptPath",
                "/opt/wha-assets",
                "-postScript",
                "WhaNativeCodeMap.java",
                "/work/native-code-map.json",
                str(min(limits.max_records, 25_000)),
                str(json_character_limit),
                str(decompile_timeout),
                "-analysisTimeoutPerFile",
                str(analysis_timeout),
                "-max-cpu",
                "1",
                "-deleteProject",
            ),
            mounts=(
                SandboxMount(_ghidra_root(status.entrypoints), "/opt/tool"),
                *_system_java_mounts(status.entrypoints),
                SandboxMount(script, "/opt/wha-assets/WhaNativeCodeMap.java"),
            ),
            result_relative_path="native-code-map.json",
        )

    def normalize(
        self,
        process: SupervisedProcessResult,
        artifact_sha256: str,
        limits: OperationResourceLimits,
        operation: AdapterOperationPayload | None = None,
    ) -> AdapterNormalizedResult:
        del operation
        if process.result_path is None or not process.result_path.is_file():
            raise AdapterExecutionError("Ghidra native code map output is missing")
        payload = _read_json(process.result_path, limits.max_output_bytes)
        if not isinstance(payload, dict) or payload.get("schema_version") != "1.0":
            raise AdapterExecutionError("Ghidra native code map has an unexpected schema")
        expected_top_level = {
            "schema_version",
            "program",
            "analysis",
            "functions",
            "call_edges",
            "strings",
            "string_xrefs",
        }
        if set(payload) != expected_top_level:
            raise AdapterExecutionError("Ghidra native code map top-level schema drifted")
        program = payload.get("program")
        analysis = payload.get("analysis")
        if not isinstance(program, dict) or not isinstance(analysis, dict):
            raise AdapterExecutionError("Ghidra native code map metadata is malformed")
        expected_program_fields = {"name", "format", "language", "compiler_spec", "image_base"}
        if set(program) != expected_program_fields or not all(
            isinstance(program.get(field), str) for field in expected_program_fields
        ):
            raise AdapterExecutionError("Ghidra native code map program metadata is malformed")
        expected_analysis_fields = {
            "decompile_failures",
            "code_truncated_functions",
            "decompiled_characters",
        }
        if set(analysis) != expected_analysis_fields or not all(
            type(analysis.get(field)) is int and int(analysis[field]) >= 0
            for field in expected_analysis_fields
        ):
            raise AdapterExecutionError("Ghidra native code map analysis counters are malformed")

        sections: dict[str, dict[str, JsonValue]] = {}
        aggregate = 0
        truncated = False
        record_fields = {
            "functions": {
                "name",
                "namespace",
                "entry",
                "signature",
                "body_addresses",
                "external",
                "thunk",
                "decompile_status",
                "decompiler_message",
                "code_truncated",
                "code",
            },
            "call_edges": {
                "from_entry",
                "from_name",
                "callsite",
                "to_address",
                "to_entry",
                "to_name",
                "reference_type",
                "external",
            },
            "strings": {"address", "data_type", "byte_length", "value_truncated", "value"},
            "string_xrefs": {
                "from_address",
                "to_address",
                "reference_type",
                "operand_index",
                "source_function_entry",
                "source_function_name",
            },
        }
        required_string_fields = {
            "functions": {
                "name",
                "namespace",
                "entry",
                "signature",
                "decompile_status",
                "decompiler_message",
                "code",
            },
            "call_edges": {
                "from_entry",
                "from_name",
                "callsite",
                "to_address",
                "to_entry",
                "to_name",
                "reference_type",
            },
            "strings": {"address", "data_type", "value"},
            "string_xrefs": {
                "from_address",
                "to_address",
                "reference_type",
                "source_function_entry",
                "source_function_name",
            },
        }
        for label, expected_fields in record_fields.items():
            section = payload.get(label)
            if not isinstance(section, dict):
                raise AdapterExecutionError(f"Ghidra {label} section is malformed")
            expected_section_fields = {"returned", "truncated", "items"}
            if label == "functions":
                expected_section_fields.add("total")
            if set(section) != expected_section_fields:
                raise AdapterExecutionError(f"Ghidra {label} section schema drifted")
            items = section.get("items")
            returned = section.get("returned")
            section_truncated = section.get("truncated")
            if (
                not isinstance(items, list)
                or type(returned) is not int
                or returned < 0
                or returned != len(items)
                or type(section_truncated) is not bool
            ):
                raise AdapterExecutionError(f"Ghidra {label} section counters are malformed")
            if label == "functions":
                total = section.get("total")
                if type(total) is not int or total < returned:
                    raise AdapterExecutionError("Ghidra function total is malformed")
            for item in items:
                if (
                    not isinstance(item, dict)
                    or set(item) != expected_fields
                    or not all(isinstance(item.get(field), str) for field in required_string_fields[label])
                ):
                    raise AdapterExecutionError(f"Ghidra {label} contains a malformed record")
            sections[label] = _json_value(section)
            aggregate += returned
            truncated = truncated or section_truncated
        if aggregate > limits.max_records:
            raise AdapterExecutionError("Ghidra native code map exceeds the aggregate record limit")

        function_items = sections["functions"]["items"]
        function_entries: set[str] = set()
        failed_functions = 0
        code_truncated_functions = 0
        decompiled_characters = 0
        for function in function_items:
            assert isinstance(function, dict)
            if function.get("decompile_status") not in {
                "completed",
                "failed",
                "skipped-external",
            }:
                raise AdapterExecutionError("Ghidra function has an unknown decompile status")
            if (
                type(function.get("body_addresses")) is not int
                or int(function["body_addresses"]) < 0
                or type(function.get("external")) is not bool
                or type(function.get("thunk")) is not bool
                or type(function.get("code_truncated")) is not bool
                or len(str(function["code"])) > 64_000
                or len(str(function["decompiler_message"])) > 512
            ):
                raise AdapterExecutionError("Ghidra function record exceeds its fixed schema")
            entry = str(function["entry"])
            if not entry or entry in function_entries:
                raise AdapterExecutionError("Ghidra function entries are empty or duplicated")
            function_entries.add(entry)
            failed_functions += int(function["decompile_status"] == "failed")
            code_truncated_functions += int(bool(function["code_truncated"]))
            decompiled_characters += len(str(function["code"]))
        if (
            int(analysis["decompile_failures"]) != failed_functions
            or int(analysis["code_truncated_functions"]) != code_truncated_functions
            or int(analysis["decompiled_characters"]) != decompiled_characters
        ):
            raise AdapterExecutionError("Ghidra analysis counters do not match returned functions")
        if int(sections["functions"]["total"]) > len(function_items) and not bool(
            sections["functions"]["truncated"]
        ):
            raise AdapterExecutionError("Ghidra function truncation state is inconsistent")

        string_addresses: set[str] = set()
        for string_record in sections["strings"]["items"]:
            assert isinstance(string_record, dict)
            if (
                type(string_record.get("byte_length")) is not int
                or int(string_record["byte_length"]) < 0
                or type(string_record.get("value_truncated")) is not bool
                or len(str(string_record["value"])) > 4096
            ):
                raise AdapterExecutionError("Ghidra string record exceeds its fixed schema")
            address = str(string_record["address"])
            if not address or address in string_addresses:
                raise AdapterExecutionError("Ghidra string addresses are empty or duplicated")
            string_addresses.add(address)
        for edge in sections["call_edges"]["items"]:
            assert isinstance(edge, dict)
            if type(edge.get("external")) is not bool or edge.get("from_entry") not in function_entries:
                raise AdapterExecutionError("Ghidra call edge has an invalid external flag")
        for xref in sections["string_xrefs"]["items"]:
            assert isinstance(xref, dict)
            if type(xref.get("operand_index")) is not int or xref.get("to_address") not in string_addresses:
                raise AdapterExecutionError("Ghidra string xref has an invalid operand index")

        data: dict[str, JsonValue] = {
            "program": _json_value(program),
            "analysis": _json_value(analysis),
            **sections,
        }
        return AdapterNormalizedResult(
            operation_id=self.operation_id,
            artifact_sha256=artifact_sha256,
            records_returned=aggregate,
            truncated=truncated,
            data=data,
        )

    def fixture_checks(self, normalized: AdapterNormalizedResult) -> list[AdapterConformanceCheck]:
        program = normalized.data.get("program", {})
        function_section = normalized.data.get("functions", {})
        call_section = normalized.data.get("call_edges", {})
        string_section = normalized.data.get("strings", {})
        xref_section = normalized.data.get("string_xrefs", {})
        functions = function_section.get("items", []) if isinstance(function_section, dict) else []
        calls = call_section.get("items", []) if isinstance(call_section, dict) else []
        strings = string_section.get("items", []) if isinstance(string_section, dict) else []
        xrefs = xref_section.get("items", []) if isinstance(xref_section, dict) else []
        marker_function = next(
            (item for item in functions if isinstance(item, dict) and item.get("name") == "wha_marker"),
            {},
        )
        return [
            AdapterConformanceCheck(
                name="fixture-format",
                ok=isinstance(program, dict) and "ELF" in str(program.get("format", "")),
                detail=str(program.get("format", "")) if isinstance(program, dict) else "missing",
            ),
            AdapterConformanceCheck(
                name="fixture-decompiled-marker",
                ok="WHA_NATIVE_CODE_MAP_MARKER" in str(marker_function.get("code", "")),
                detail=f"returned_functions={len(functions)}",
            ),
            AdapterConformanceCheck(
                name="fixture-call-edge",
                ok=any(
                    isinstance(item, dict)
                    and item.get("from_name") == "wha_marker_length"
                    and item.get("to_name") == "wha_marker"
                    for item in calls
                ),
                detail=f"returned_call_edges={len(calls)}",
            ),
            AdapterConformanceCheck(
                name="fixture-defined-string",
                ok=any(
                    isinstance(item, dict) and item.get("value") == "WHA_NATIVE_CODE_MAP_MARKER"
                    for item in strings
                ),
                detail=f"returned_strings={len(strings)}",
            ),
            AdapterConformanceCheck(
                name="fixture-string-xref",
                ok=any(
                    isinstance(item, dict) and item.get("source_function_name") == "wha_marker"
                    for item in xrefs
                ),
                detail=f"returned_string_xrefs={len(xrefs)}",
            ),
        ]


class JadxAndroidStaticMapDriver:
    adapter_id = "jadx"
    operation_id = "jadx.android-static-map"
    driver_id = "whitehat.jadx-json-static-map"
    driver_version = JADX_DRIVER_VERSION

    def _entrypoint(self, entrypoints: list[str]) -> Path:
        entrypoint = next(
            (Path(path).resolve() for path in entrypoints if Path(path).name == "jadx"),
            None,
        )
        if entrypoint is None or not entrypoint.is_file():
            raise AdapterExecutionError("JADX operation requires an observed jadx entrypoint")
        return entrypoint

    def _root(self, entrypoints: list[str]) -> Path:
        root = self._entrypoint(entrypoints).parent.parent
        if not root.is_dir():
            raise AdapterExecutionError("JADX installation root is unavailable")
        return root

    def _payload_jar(self, root: Path) -> Path:
        matches = sorted(root.glob("lib/jadx-*-all.jar"))
        if len(matches) != 1:
            raise AdapterExecutionError("JADX operation requires exactly one CLI payload JAR")
        return matches[0]

    def tool_payload_digest(self, entrypoints: list[str]) -> str:
        root = self._root(entrypoints)
        provider_digest = _hash_file_set(
            root,
            [self._entrypoint(entrypoints), self._payload_jar(root)],
        )
        java_digest, java_config_digest = _system_java_payload_digests(entrypoints)
        return stable_digest(
            {
                "provider_payload_sha256": provider_digest,
                "java_payload_sha256": java_digest,
                "java_config_sha256": java_config_digest,
            }
        )

    def _mounts(self, entrypoints: list[str]) -> tuple[SandboxMount, ...]:
        return (
            SandboxMount(self._root(entrypoints), "/opt/tool"),
            *_system_java_mounts(entrypoints),
        )

    def version_invocation(self, status: AdapterStatus) -> TrustedInvocation:
        return TrustedInvocation(
            argv=("/opt/tool/bin/jadx", "--version"),
            mounts=self._mounts(status.entrypoints),
        )

    def prepare(
        self,
        status: AdapterStatus,
        operation: AdapterOperationPayload,
        limits: OperationResourceLimits,
        assets: dict[str, Path],
    ) -> TrustedInvocation:
        del limits, assets
        if not isinstance(operation, JadxAndroidStaticMapPayload):
            raise AdapterExecutionError("JADX driver received a different operation payload")
        return TrustedInvocation(
            argv=(
                "/usr/bin/env",
                "JADX_CONFIG_DIR=/work/jadx-state/config",
                "JADX_CACHE_DIR=/work/jadx-state/cache",
                "JADX_TMP_DIR=/work/jadx-state/tmp",
                "/opt/tool/bin/jadx",
                "--config",
                "none",
                "--mappings-mode",
                "ignore",
                "--deobf-cfg-file-mode",
                "ignore",
                "--output-format",
                "json",
                "--call-graph",
                "json",
                "--threads-count",
                "1",
                "--log-level",
                "error",
                "-d",
                "/work/jadx-output",
                "/input/artifact",
            ),
            mounts=self._mounts(status.entrypoints),
            result_relative_path="jadx-output",
        )

    def normalize(
        self,
        process: SupervisedProcessResult,
        artifact_sha256: str,
        limits: OperationResourceLimits,
        operation: AdapterOperationPayload | None = None,
    ) -> AdapterNormalizedResult:
        del operation
        if process.result_path is None:
            raise AdapterExecutionError("JADX output directory is missing")
        files = _regular_output_tree(
            process.result_path,
            max_files=limits.max_files,
            max_bytes=limits.max_output_bytes,
        )
        file_index = {relative: (path, byte_length) for relative, path, byte_length in files}
        mapping_path, _ = _required_output_file(file_index, "sources/mapping.json")
        graph_path, _ = _required_output_file(file_index, "callgraph.json")
        mapping = _read_json(mapping_path, limits.max_output_bytes)
        graph = _read_json(graph_path, limits.max_output_bytes)
        if not isinstance(mapping, dict) or not isinstance(mapping.get("classes"), list):
            raise AdapterExecutionError("JADX mapping output has an unexpected schema")
        if not isinstance(graph, dict):
            raise AdapterExecutionError("JADX call graph has an unexpected schema")
        nodes = graph.get("nodes")
        edges = graph.get("edges")
        if not isinstance(nodes, list) or not isinstance(edges, list):
            raise AdapterExecutionError("JADX call graph has no node and edge lists")
        if not all(isinstance(item, dict) for item in nodes) or not all(
            isinstance(item, dict) for item in edges
        ):
            raise AdapterExecutionError("JADX call graph contains a non-object record")

        remaining_records = limits.max_records
        byte_budget = max(0, limits.max_output_bytes * 7 // 10 - 4096)
        class_record_limit = max(1, limits.max_records * 2 // 3)
        class_byte_limit = byte_budget * 3 // 4
        used_bytes = 0
        class_items: list[JsonValue] = []
        referenced = {"sources/mapping.json", "callgraph.json"}
        class_mappings = mapping["classes"]
        for raw_mapping in class_mappings:
            if not isinstance(raw_mapping, dict):
                raise AdapterExecutionError("JADX mapping contains a non-object class record")
            relative = _jadx_class_output_path(raw_mapping.get("json"))
            if relative in referenced:
                raise AdapterExecutionError("JADX mapping contains a duplicate class output path")
            referenced.add(relative)
            class_path, class_bytes = _required_output_file(file_index, relative)
            document = _read_json(class_path, limits.max_output_bytes)
            if not isinstance(document, dict):
                raise AdapterExecutionError("JADX class output is not a JSON object")
            record: JsonValue = {
                "name": str(raw_mapping.get("name", "")),
                "path": relative,
                "sha256": _hash_file(class_path),
                "byte_length": class_bytes,
                "document": _json_value(document),
            }
            record_bytes = _json_record_cost(record)
            if (
                len(class_items) >= class_record_limit
                or remaining_records <= 0
                or used_bytes + record_bytes > class_byte_limit
            ):
                continue
            class_items.append(record)
            remaining_records -= 1
            used_bytes += record_bytes

        unexpected_sources = sorted(
            relative
            for relative in file_index
            if relative.startswith("sources/") and relative not in referenced
        )
        if unexpected_sources:
            raise AdapterExecutionError("JADX emitted an unindexed source JSON file")

        node_items, node_bytes = _bounded_json_records(
            nodes,
            max_records=remaining_records,
            max_bytes=max(0, byte_budget - used_bytes),
        )
        remaining_records -= len(node_items)
        used_bytes += node_bytes
        edge_items, edge_bytes = _bounded_json_records(
            edges,
            max_records=remaining_records,
            max_bytes=max(0, byte_budget - used_bytes),
        )
        remaining_records -= len(edge_items)
        used_bytes += edge_bytes

        resources: list[JsonValue] = []
        manifest_text_omitted = False
        resource_paths = [relative for relative in file_index if relative not in referenced]
        for relative in resource_paths:
            if remaining_records <= 0:
                break
            path, byte_length = file_index[relative]
            record = {
                "path": relative,
                "sha256": _hash_file(path),
                "byte_length": byte_length,
            }
            if relative.endswith("AndroidManifest.xml"):
                record["text_included"] = byte_length <= 1_048_576
                if byte_length <= 1_048_576:
                    record["text"] = path.read_text(encoding="utf-8")
                else:
                    manifest_text_omitted = True
            record_bytes = _json_record_cost(record)
            if used_bytes + record_bytes > byte_budget:
                continue
            resources.append(record)
            remaining_records -= 1
            used_bytes += record_bytes

        returned = len(class_items) + len(node_items) + len(edge_items) + len(resources)
        truncated = (
            len(class_items) < len(class_mappings)
            or len(node_items) < len(nodes)
            or len(edge_items) < len(edges)
            or len(resources) < len(resource_paths)
            or manifest_text_omitted
        )
        data: dict[str, JsonValue] = {
            "format": "jadx-json",
            "classes": {
                "total": len(class_mappings),
                "returned": len(class_items),
                "items": class_items,
            },
            "call_graph": {
                "nodes_total": len(nodes),
                "nodes": node_items,
                "edges_total": len(edges),
                "edges": edge_items,
            },
            "resources": {
                "total": len(resource_paths),
                "returned": len(resources),
                "items": resources,
            },
        }
        return AdapterNormalizedResult(
            operation_id=self.operation_id,
            artifact_sha256=artifact_sha256,
            records_returned=returned,
            truncated=truncated,
            data=data,
        )

    def fixture_checks(self, normalized: AdapterNormalizedResult) -> list[AdapterConformanceCheck]:
        classes = normalized.data.get("classes", {})
        class_items = classes.get("items", []) if isinstance(classes, dict) else []
        fixture_class = next(
            (
                item
                for item in class_items
                if isinstance(item, dict) and item.get("name") == "org.whitehat.fixture.MinimalAndroid"
            ),
            None,
        )
        document = fixture_class.get("document", {}) if isinstance(fixture_class, dict) else {}
        methods = document.get("methods", []) if isinstance(document, dict) else []
        marker_found = any(
            isinstance(method, dict)
            and method.get("name") == "marker"
            and "WHA_ANDROID_FIXTURE" in json.dumps(method, sort_keys=True)
            for method in methods
        )
        graph = normalized.data.get("call_graph", {})
        nodes = graph.get("nodes", []) if isinstance(graph, dict) else []
        edges = graph.get("edges", []) if isinstance(graph, dict) else []
        marker_ids = {
            item.get("id")
            for item in nodes
            if isinstance(item, dict) and ".marker()" in str(item.get("method", ""))
        }
        caller_ids = {
            item.get("id")
            for item in nodes
            if isinstance(item, dict) and ".markerLength()" in str(item.get("method", ""))
        }
        edge_found = any(
            isinstance(edge, dict)
            and edge.get("from") in caller_ids
            and edge.get("to") in marker_ids
            and edge.get("resolved") is True
            for edge in edges
        )
        return [
            AdapterConformanceCheck(
                name="fixture-class",
                ok=fixture_class is not None,
                detail=f"returned_classes={len(class_items)}",
            ),
            AdapterConformanceCheck(
                name="fixture-marker",
                ok=marker_found,
                detail="marker method contains the inert fixture constant",
            ),
            AdapterConformanceCheck(
                name="fixture-call-edge",
                ok=edge_found,
                detail="markerLength resolves to marker",
            ),
        ]


DRIVERS: dict[tuple[str, str], ProviderDriver] = {
    ("ghidra", "ghidra.binary-summary"): GhidraBinarySummaryDriver(),
    ("ghidra", "ghidra.native-code-map"): GhidraNativeCodeMapDriver(),
    ("capa", "capa.file-analyze"): CapaFileAnalyzeDriver(),
    ("llvm", "llvm.object-inspect"): LlvmObjectInspectDriver(),
    ("goresym", "goresym.symbol-map"): GoReSymSymbolMapDriver(),
    ("unblob", "unblob.extraction-map"): UnblobExtractionMapDriver(),
    ("jadx", "jadx.android-static-map"): JadxAndroidStaticMapDriver(),
    ("frida", "frida.executable-runtime-map"): FridaExecutableRuntimeMapDriver(),
    ("tshark", "tshark.packet-capture-map"): TsharkPacketCaptureMapDriver(),
    ("yara-x", "yara-x.file-scan"): YaraXFileScanDriver(),
}


def _driver_sandbox_profile_sha256(driver: ProviderDriver) -> str:
    return (
        OCI_SANDBOX_PROFILE_SHA256
        if isinstance(driver, UnblobExtractionMapDriver)
        else SANDBOX_PROFILE_SHA256
    )


def conformance_report_is_current(
    operation: AdapterOperationBinding,
    report: AdapterConformanceReport,
    entrypoints: list[str],
) -> bool:
    try:
        driver = _driver_for_operation(operation.operation_id)
        fixture = _conformance_fixture(operation.operation_id)
        tool_payload_sha256 = driver.tool_payload_digest(entrypoints)
        fixture_sha256 = _expected_conformance_fixture_sha256(fixture, driver, entrypoints)
    except (AdapterExecutionError, OSError, RuntimeError, ValueError):
        return False
    return (
        report.adapter_id == driver.adapter_id
        and report.driver_id == driver.driver_id
        and report.driver_version == driver.driver_version
        and report.sandbox_profile_sha256 == _driver_sandbox_profile_sha256(driver)
        and report.fixture_id == operation.conformance_suite_id == fixture.fixture_id
        and report.fixture_sha256 == fixture_sha256
        and report.tool_payload_sha256 == tool_payload_sha256
    )


class AdapterExecutionBroker:
    def __init__(
        self,
        manager: AdapterManager,
        fleet: FleetStore,
        evidence: EvidenceStore,
        *,
        supervisor: AdapterSandboxSupervisor | OfflineSandboxSupervisor | None = None,
    ) -> None:
        self.manager = manager
        self.fleet = fleet
        self.evidence = evidence
        self.supervisor = supervisor or AdapterSandboxSupervisor()

    def conform(self, adapter_id: str, operation_id: str) -> AdapterConformanceReport:
        manifest = self.manager.registry.get(adapter_id)
        operation = _operation(manifest.operations, operation_id)
        status = self.manager.status(adapter_id)
        if (
            not status.supported
            or not status.installed
            or not status.entrypoints
            or not status.observed_identity_sha256
        ):
            raise AdapterExecutionError(f"adapter cannot be observed safely: {adapter_id}")
        if manifest.probe is None:
            raise AdapterExecutionError(f"adapter has no fixed version probe: {adapter_id}")
        driver = _driver(adapter_id, operation_id)
        started_at = utc_now()
        started_monotonic = time.monotonic()
        checks: list[AdapterConformanceCheck] = []
        warnings: list[str] = []
        tool_digest = driver.tool_payload_digest(status.entrypoints)
        tool_version = "unobserved"
        fixture = _conformance_fixture(operation_id)
        expected_fixture_digest = _expected_conformance_fixture_sha256(
            fixture,
            driver,
            status.entrypoints,
        )
        requirement_paths, requirement_identity_sha256 = self.manager._requirement_observations(
            manifest,
            status.platform,
        )
        with tempfile.TemporaryDirectory(prefix="wha-adapter-conformance-") as temporary:
            temp_root = Path(temporary)
            fixture_path = temp_root / fixture.filename
            fixture_digest = _materialize_conformance_fixture(
                fixture,
                fixture_path,
                driver,
                status.entrypoints,
            )
            if manifest.probe.version_file:
                version, check = _probe_file_version(
                    _probe_entrypoint(manifest.probe, status),
                    manifest.probe,
                    name="tool-version",
                )
                tool_version = version or "unobserved"
                checks.append(AdapterConformanceCheck(name=check.name, ok=check.ok, detail=check.detail))
            else:
                version_invocation = (
                    driver.version_invocation(status)
                    if isinstance(driver, JadxAndroidStaticMapDriver)
                    else None
                )
                tool_version, check, probe_warnings = self._contained_version_probe(
                    manifest.probe,
                    _probe_entrypoint(manifest.probe, status),
                    fixture_path,
                    temp_root / "tool-version",
                    operation.limits,
                    name="tool-version",
                    invocation=version_invocation,
                )
                checks.append(check)
                warnings.extend(probe_warnings)
            for index, (requirement, dependency, dependency_identity) in enumerate(
                zip(
                    manifest.requirements,
                    requirement_paths,
                    requirement_identity_sha256,
                    strict=True,
                ),
                start=1,
            ):
                name = f"requirement-{index}-version"
                if dependency is None:
                    checks.append(AdapterConformanceCheck(name=name, ok=False, detail="executable not found"))
                    continue
                if dependency_identity is None:
                    checks.append(
                        AdapterConformanceCheck(
                            name=name,
                            ok=False,
                            detail="identity could not be observed",
                        )
                    )
                    continue
                if requirement.version_file:
                    _, check = _probe_file_version(
                        Path(dependency),
                        requirement,
                        name=name,
                    )
                    checks.append(AdapterConformanceCheck(name=check.name, ok=check.ok, detail=check.detail))
                    continue
                _, check, probe_warnings = self._contained_version_probe(
                    requirement,
                    Path(dependency),
                    fixture_path,
                    temp_root / name,
                    operation.limits,
                    name=name,
                )
                checks.append(check)
                warnings.extend(probe_warnings)
            checks.append(
                AdapterConformanceCheck(
                    name="fixture-digest",
                    ok=fixture_digest == expected_fixture_digest,
                    detail=fixture_digest,
                )
            )
            if all(check.ok for check in checks):
                fixture_work = temp_root / "fixture-run"
                fixture_work.mkdir(mode=0o700)
                with self._assets() as assets:
                    invocation = driver.prepare(
                        status,
                        _fixture_operation(operation_id),
                        operation.limits,
                        assets,
                    )
                    process = self.supervisor.run(
                        invocation,
                        fixture_path,
                        fixture_work,
                        operation.limits,
                    )
                checks.append(
                    AdapterConformanceCheck(
                        name="sandbox-process",
                        ok=process.outcome == AdapterExecutionOutcome.SUCCEEDED,
                        detail=_conformance_process_detail(process),
                    )
                )
                warnings.extend(process.warnings)
                if process.outcome == AdapterExecutionOutcome.SUCCEEDED:
                    try:
                        normalized = driver.normalize(
                            process,
                            fixture_digest,
                            operation.limits,
                            _fixture_operation(operation_id),
                        )
                        checks.extend(driver.fixture_checks(normalized))
                    except (AdapterExecutionError, OSError, UnicodeError, ValueError) as exc:
                        checks.append(
                            AdapterConformanceCheck(
                                name="normalized-output",
                                ok=False,
                                detail=type(exc).__name__,
                            )
                        )
            else:
                warnings.append("fixture execution skipped because a fixed preflight check failed")
        report = AdapterConformanceReport(
            adapter_id=adapter_id,
            operation_id=operation.operation_id,
            operation_version=operation.operation_version,
            manifest_digest=manifest.digest(),
            operation_contract_digest=operation.digest(),
            observed_identity_sha256=status.observed_identity_sha256,
            requirement_identity_sha256=requirement_identity_sha256,
            tool_payload_sha256=tool_digest,
            tool_version=tool_version,
            driver_id=driver.driver_id,
            driver_version=driver.driver_version,
            sandbox_profile_sha256=_driver_sandbox_profile_sha256(driver),
            fixture_id=fixture.fixture_id,
            fixture_sha256=fixture_digest,
            started_at=started_at,
            finished_at=started_at + timedelta(seconds=time.monotonic() - started_monotonic),
            passed=all(check.ok for check in checks),
            checks=checks,
            warnings=list(dict.fromkeys(warnings)),
        )
        self.manager.save_conformance_report(report, entrypoints=status.entrypoints)
        return report

    def _contained_version_probe(
        self,
        probe: ProbeDefinition,
        executable: Path,
        fixture_path: Path,
        work_dir: Path,
        operation_limits: OperationResourceLimits,
        *,
        name: str,
        invocation: TrustedInvocation | None = None,
    ) -> tuple[str, AdapterConformanceCheck, list[str]]:
        work_dir.mkdir(mode=0o700)
        limits = OperationResourceLimits(
            max_input_bytes=operation_limits.max_input_bytes,
            max_output_bytes=operation_limits.max_output_bytes,
            max_files=min(operation_limits.max_files, 16),
            max_records=1,
            wall_seconds=max(1, min(operation_limits.wall_seconds, math.ceil(probe.timeout_seconds))),
            cpu_seconds=max(1, min(operation_limits.cpu_seconds, math.ceil(probe.timeout_seconds))),
            memory_mib=operation_limits.memory_mib,
            max_processes=min(operation_limits.max_processes, 8),
        )
        executable = executable.resolve(strict=True)
        system_roots = tuple(
            path.resolve()
            for path in (Path("/usr"), Path("/bin"), Path("/lib"), Path("/lib64"))
            if path.exists()
        )
        system_visible = any(root == executable or root in executable.parents for root in system_roots)
        sandbox_executable = str(executable) if system_visible else "/opt/probe/executable"
        selected_invocation = invocation or TrustedInvocation(
            argv=(sandbox_executable, *probe.version_args),
            mounts=(() if system_visible else (SandboxMount(executable, "/opt/probe/executable"),)),
        )
        process = self.supervisor.run(selected_invocation, fixture_path, work_dir, limits)
        output = "\n".join(
            value
            for value in (
                _read_probe_text(process.stdout_path),
                _read_probe_text(process.stderr_path),
            )
            if value
        )
        match = re.search(probe.version_pattern or "", output)
        version = (
            match.group("version")
            if match and "version" in match.groupdict()
            else (match.group(1) if match and match.groups() else (match.group(0) if match else None))
        )
        ok = (
            process.outcome == AdapterExecutionOutcome.SUCCEEDED
            and process.return_code == 0
            and version is not None
            and _version_matches_probe(version, probe)
        )
        detail = (
            f"outcome={process.outcome.value}; exit={process.return_code}; version={version or 'unmatched'}"
        )
        if probe.minimum_version:
            detail += f"; minimum={probe.minimum_version}"
        return (
            version or "unobserved",
            AdapterConformanceCheck(name=name, ok=ok, detail=detail),
            list(process.warnings),
        )

    def execute(self, request: AdapterExecutionRequest) -> AdapterExecutionResult:
        task = self.fleet.assert_active_lease(
            request.task_id,
            request.agent_id,
            request.lease_token.get_secret_value(),
        )
        driver = _driver_for_operation(request.operation.operation_id)
        adapter_id = driver.adapter_id
        manifest = self.manager.registry.get(adapter_id)
        operation = _operation(manifest.operations, request.operation.operation_id)
        operation_payload = request.operation.model_dump(mode="json")
        manifest_variable_bytes = sum(
            len(value.encode("utf-8"))
            for value in (
                task.campaign_id,
                task.task_id,
                task.intent_id,
                task.scope_decision_id,
                adapter_id,
                operation.operation_id,
                operation.operation_version,
                *request.input_evidence_ids,
            )
        ) + len(json.dumps(operation_payload, ensure_ascii=True, separators=(",", ":")).encode())
        if manifest_variable_bytes + MINIMUM_EVIDENCE_IMPORT_BYTES > self.evidence.max_import_bytes:
            raise AdapterExecutionError("evidence import limit is too small for bounded execution metadata")
        if not set(operation.capabilities).issubset(task.required_capabilities):
            raise AdapterExecutionError("operation capabilities are outside the leased task contract")
        if EXECUTION_CLASS_RANK[operation.execution_class] > EXECUTION_CLASS_RANK[task.execution_class]:
            raise AdapterExecutionError("operation execution class exceeds the leased task contract")
        status = self.manager.status(adapter_id)
        if not status.healthy or not status.version or not status.observed_identity_sha256:
            raise AdapterExecutionError(f"adapter is not healthy: {adapter_id}")
        if operation.operation_id not in status.conformant_operations:
            raise AdapterExecutionError("operation has no current passing conformance report")
        reports = [
            report
            for report in self.manager.conformance_reports(adapter_id)
            if report.passed and report.operation_id == operation.operation_id
        ]
        if len(reports) != 1:
            raise AdapterExecutionError("operation conformance identity is missing or ambiguous")
        report = reports[0]
        current_tool_digest = driver.tool_payload_digest(status.entrypoints)
        if current_tool_digest != report.tool_payload_sha256:
            raise AdapterExecutionError("tool payload drifted after conformance")
        effective_limits = _effective_limits(
            operation.limits,
            request.limits,
            max_output_bytes=self.evidence.max_import_bytes,
        )
        self.fleet.heartbeat(
            request.task_id,
            request.agent_id,
            request.lease_token.get_secret_value(),
            extend_seconds=min(86_400, max(60, effective_limits.wall_seconds + 60)),
        )
        evidence_id = request.input_evidence_ids[0]
        started_at = utc_now()
        started_monotonic = time.monotonic()
        execution_id = stable_id(
            "adapter-execution",
            {"request_digest": request.digest(), "started_at": started_at.isoformat()},
        )
        captures: list[AdapterCapture] = []
        evidence_ids: list[str] = []
        warnings: list[str] = []
        normalized: AdapterNormalizedResult | None = None
        normalized_bytes: bytes | None = None
        with tempfile.TemporaryDirectory(prefix="wha-adapter-execution-") as temporary:
            temp_root = Path(temporary)
            input_record, input_path = self.evidence.snapshot_local_file(
                evidence_id,
                campaign_id=task.campaign_id,
                task_id=task.task_id,
                destination=temp_root / "input.artifact",
                max_bytes=effective_limits.max_input_bytes,
            )
            if input_record.descriptor.target != task.target:
                raise AdapterExecutionError("input evidence target differs from the leased task")
            if input_record.descriptor.evidence_type not in operation.input_types:
                raise AdapterExecutionError("input evidence type is outside the operation contract")
            with self._assets() as assets:
                invocation = driver.prepare(status, request.operation, effective_limits, assets)
                process = self.supervisor.run(invocation, input_path, temp_root, effective_limits)
            self.fleet.assert_active_lease(
                request.task_id,
                request.agent_id,
                request.lease_token.get_secret_value(),
            )
            outcome = process.outcome
            warnings.extend(process.warnings)
            if outcome == AdapterExecutionOutcome.SUCCEEDED:
                try:
                    normalized = driver.normalize(
                        process,
                        input_record.content_sha256,
                        effective_limits,
                        request.operation,
                    )
                except (AdapterExecutionError, OSError, UnicodeError, ValueError) as exc:
                    outcome = AdapterExecutionOutcome.INVALID_OUTPUT
                    warnings.append(f"normalization failed: {type(exc).__name__}")
            if normalized is not None:
                normalized_bytes = (
                    json.dumps(normalized.model_dump(mode="json"), indent=2, sort_keys=True) + "\n"
                ).encode()
                if (
                    normalized.records_returned > effective_limits.max_records
                    or len(normalized_bytes) > effective_limits.max_output_bytes
                ):
                    outcome = AdapterExecutionOutcome.INVALID_OUTPUT
                    normalized = None
                    normalized_bytes = None
                    warnings.append("normalized output exceeded its record or byte contract")
            provenance = {
                "execution_id": execution_id,
                "adapter_id": adapter_id,
                "operation_id": operation.operation_id,
                "operation_version": operation.operation_version,
                "manifest_digest": manifest.digest(),
                "operation_contract_digest": operation.digest(),
                "tool_payload_sha256": current_tool_digest,
                "conformance_report_digest": report.digest(),
                "sandbox_profile_sha256": _driver_sandbox_profile_sha256(driver),
                "input_evidence_id": evidence_id,
                "input_content_sha256": input_record.content_sha256,
                "outcome": outcome.value,
            }
            for name, path, media_type in (
                ("stdout", process.stdout_path, "application/octet-stream"),
                ("stderr", process.stderr_path, "application/octet-stream"),
            ):
                capture, registered = self._capture(
                    path,
                    name=name,
                    media_type=media_type,
                    evidence_type="adapter/execution-output",
                    task=task,
                    provenance=provenance,
                    complete=process.output_complete,
                )
                captures.append(capture)
                if registered:
                    evidence_ids.append(registered.evidence_id)
            if process.result_path is not None:
                capture, registered = self._capture(
                    process.result_path,
                    name="provider-result",
                    media_type="application/json",
                    evidence_type="adapter/execution-output",
                    task=task,
                    provenance=provenance,
                    complete=process.output_complete,
                )
                captures.append(capture)
                if registered:
                    evidence_ids.append(registered.evidence_id)
            if normalized is not None and normalized_bytes is not None:
                normalized_path = temp_root / "normalized.json"
                normalized_path.write_bytes(normalized_bytes)
                capture, registered = self._capture(
                    normalized_path,
                    name="normalized",
                    media_type="application/json",
                    evidence_type=operation.output_types[0],
                    task=task,
                    provenance=provenance,
                    complete=True,
                )
                captures.append(capture)
                if registered:
                    evidence_ids.append(registered.evidence_id)
            finished_at = started_at + timedelta(seconds=time.monotonic() - started_monotonic)
            result = AdapterExecutionResult(
                execution_id=execution_id,
                request_digest=request.digest(),
                campaign_id=task.campaign_id,
                task_id=task.task_id,
                target=task.target,
                intent_id=task.intent_id,
                scope_decision_id=task.scope_decision_id,
                adapter_id=adapter_id,
                operation_id=operation.operation_id,
                operation_version=operation.operation_version,
                manifest_digest=manifest.digest(),
                operation_contract_digest=operation.digest(),
                observed_identity_sha256=status.observed_identity_sha256,
                tool_payload_sha256=current_tool_digest,
                conformance_report_digest=report.digest(),
                sandbox_profile_sha256=_driver_sandbox_profile_sha256(driver),
                input_evidence_ids=request.input_evidence_ids,
                input_content_sha256=[input_record.content_sha256],
                effective_limits=effective_limits,
                outcome=outcome,
                exit_code=(
                    process.return_code
                    if process.return_code is not None and process.return_code >= 0
                    else None
                ),
                signal=process.signal_number,
                normalized=normalized if outcome == AdapterExecutionOutcome.SUCCEEDED else None,
                captures=captures,
                evidence_ids=evidence_ids,
                warnings=warnings,
                started_at=started_at,
                finished_at=finished_at,
            )
            manifest_path = temp_root / "execution-manifest.json"
            manifest_bytes = (
                json.dumps(
                    AdapterExecutionManifest.from_result(
                        result,
                        operation_payload=operation_payload,
                    ).model_dump(mode="json"),
                    indent=2,
                    sort_keys=True,
                )
                + "\n"
            ).encode()
            if len(manifest_bytes) > self.evidence.max_import_bytes:
                raise AdapterExecutionError("bounded execution manifest exceeds the evidence limit")
            manifest_path.write_bytes(manifest_bytes)
            capture, registered = self._capture(
                manifest_path,
                name="execution-manifest",
                media_type="application/json",
                evidence_type="adapter/execution-manifest",
                task=task,
                provenance=provenance,
                complete=True,
            )
            captures.append(capture)
            if registered:
                evidence_ids.append(registered.evidence_id)
            result.captures = captures
            result.evidence_ids = evidence_ids
            return result

    def _capture(
        self,
        path: Path,
        *,
        name: str,
        media_type: str,
        evidence_type: str,
        task,
        provenance: dict[str, JsonValue],
        complete: bool,
    ) -> tuple[AdapterCapture, EvidenceRecord | None]:
        if path.is_symlink() or not path.is_file():
            empty_digest = hashlib.sha256(b"").hexdigest()
            return (
                AdapterCapture(
                    name=name,
                    media_type=media_type,
                    byte_length=0,
                    content_sha256=empty_digest,
                    complete=False,
                ),
                None,
            )
        digest = _hash_file(path)
        descriptor = EvidenceDescriptor(
            campaign_id=task.campaign_id,
            task_id=task.task_id,
            target=task.target,
            evidence_type=evidence_type,
            title=f"{task.task_id} adapter {name}",
            description=f"Bounded {name} capture from a typed offline adapter operation.",
            producer="white-hat-agent.adapter-execution-broker",
            provenance={**provenance, "capture": name, "complete": complete},
        )
        record = self.evidence.import_file(path, descriptor, media_type=media_type)
        return (
            AdapterCapture(
                name=name,
                media_type=media_type,
                byte_length=record.byte_length,
                content_sha256=digest,
                complete=complete,
                evidence_id=record.evidence_id,
            ),
            record,
        )

    def _assets(self):
        stack = ExitStack()
        resource_root = importlib.resources.files("white_hat_agent").joinpath("builtin_adapter_fixtures")
        script = stack.enter_context(
            importlib.resources.as_file(resource_root.joinpath("WhaBinarySummary.java"))
        )
        native_map_script = stack.enter_context(
            importlib.resources.as_file(resource_root.joinpath("WhaNativeCodeMap.java"))
        )
        return _AssetContext(
            stack,
            {
                "ghidra_script": script,
                "ghidra_native_map_script": native_map_script,
            },
        )


class _AssetContext:
    def __init__(self, stack: ExitStack, assets: dict[str, Path]) -> None:
        self.stack = stack
        self.assets = assets

    def __enter__(self) -> dict[str, Path]:
        return self.assets

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.stack.close()


def _probe_entrypoint(probe: ProbeDefinition, status: AdapterStatus) -> Path:
    names = {
        Path(name).name.casefold()
        for key in (status.platform, status.platform.split("-", 1)[0], "any")
        for name in probe.executable_names.get(key, [])
    }
    matches = []
    for value in status.entrypoints:
        path = Path(value)
        candidate = path.name.casefold()
        candidate_stem = candidate.removesuffix(".exe")
        if path.is_file() and any(
            candidate == name or candidate_stem.startswith(name.removesuffix(".exe") + "-") for name in names
        ):
            matches.append(path.resolve())
    if len(matches) != 1:
        raise AdapterExecutionError("version probe does not map to exactly one observed entrypoint")
    return matches[0]


def _read_probe_text(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        return ""
    return path.read_bytes()[:16_384].decode("utf-8", errors="replace")


def _conformance_process_detail(process: SupervisedProcessResult) -> str:
    detail = f"outcome={process.outcome.value}; exit={process.return_code}"
    if process.outcome == AdapterExecutionOutcome.SUCCEEDED:
        return detail
    diagnostic = process.stderr_path.read_bytes()[:2048].decode("utf-8", errors="replace")
    diagnostic = " ".join(diagnostic.split())
    if diagnostic:
        detail += f"; stderr={diagnostic[:1024]}"
    return detail


def _operation(operations: list[AdapterOperationBinding], operation_id: str) -> AdapterOperationBinding:
    matches = [operation for operation in operations if operation.operation_id == operation_id]
    if len(matches) != 1:
        raise AdapterExecutionError(f"adapter operation is not defined exactly once: {operation_id}")
    return matches[0]


def _driver(adapter_id: str, operation_id: str) -> ProviderDriver:
    try:
        return DRIVERS[(adapter_id, operation_id)]
    except KeyError as exc:
        raise AdapterExecutionError(f"no reviewed provider driver: {adapter_id}/{operation_id}") from exc


def _driver_for_operation(operation_id: str) -> ProviderDriver:
    matches = [driver for (_, candidate), driver in DRIVERS.items() if candidate == operation_id]
    if len(matches) != 1:
        raise AdapterExecutionError(f"operation does not map to exactly one reviewed driver: {operation_id}")
    return matches[0]


def _fixture_operation(operation_id: str) -> AdapterOperationPayload:
    if operation_id == "ghidra.binary-summary":
        return GhidraBinarySummaryPayload(operation_id=operation_id)
    if operation_id == "ghidra.native-code-map":
        return GhidraNativeCodeMapPayload(operation_id=operation_id)
    if operation_id == "capa.file-analyze":
        return CapaFileAnalyzePayload(operation_id=operation_id, operating_system="linux")
    if operation_id == "llvm.object-inspect":
        return LlvmObjectInspectPayload(operation_id=operation_id)
    if operation_id == "goresym.symbol-map":
        return GoReSymSymbolMapPayload(operation_id=operation_id)
    if operation_id == "unblob.extraction-map":
        return UnblobExtractionMapPayload(operation_id=operation_id)
    if operation_id == "jadx.android-static-map":
        return JadxAndroidStaticMapPayload(operation_id=operation_id)
    if operation_id == "frida.executable-runtime-map":
        return FridaExecutableRuntimeMapPayload(operation_id=operation_id)
    if operation_id == "tshark.packet-capture-map":
        return TsharkPacketCaptureMapPayload(operation_id=operation_id)
    if operation_id == "yara-x.file-scan":
        return YaraXFileScanPayload(
            operation_id=operation_id,
            rule_source=_yara_x_conformance_rule(),
        )
    raise AdapterExecutionError(f"operation has no fixed conformance fixture: {operation_id}")


def _conformance_fixture(operation_id: str) -> ConformanceFixture:
    if operation_id in {
        "ghidra.binary-summary",
        "capa.file-analyze",
        "llvm.object-inspect",
    }:
        return ELF_FIXTURE
    if operation_id == "ghidra.native-code-map":
        return GHIDRA_NATIVE_MAP_FIXTURE
    if operation_id == "jadx.android-static-map":
        return JADX_FIXTURE
    if operation_id == "frida.executable-runtime-map":
        return FRIDA_RUNTIME_MAP_FIXTURE
    if operation_id == "tshark.packet-capture-map":
        return TSHARK_FIXTURE
    if operation_id == "yara-x.file-scan":
        return YARA_X_FIXTURE
    if operation_id == "goresym.symbol-map":
        return GORESYM_SELF_FIXTURE
    if operation_id == "unblob.extraction-map":
        return UNBLOB_FIXTURE
    raise AdapterExecutionError(f"operation has no fixed conformance fixture: {operation_id}")


def _fixture_payload(fixture: ConformanceFixture) -> bytes:
    if fixture.source != "package" or fixture.resource_name is None or fixture.sha256 is None:
        raise AdapterExecutionError("conformance fixture is not a packaged payload")
    resource = importlib.resources.files("white_hat_agent").joinpath(
        f"builtin_adapter_fixtures/{fixture.resource_name}"
    )
    encoded = b"".join(resource.read_bytes().split())
    payload = base64.b64decode(encoded, validate=True)
    if hashlib.sha256(payload).hexdigest() != fixture.sha256:
        raise AdapterExecutionError("bundled adapter fixture digest mismatch")
    return payload


def _expected_conformance_fixture_sha256(
    fixture: ConformanceFixture,
    driver: ProviderDriver,
    entrypoints: list[str],
) -> str:
    if fixture.source == "package":
        if fixture.sha256 is None:
            raise AdapterExecutionError("packaged conformance fixture has no digest")
        return fixture.sha256
    if fixture.source == "tool-entrypoint" and isinstance(driver, GoReSymSymbolMapDriver):
        return _hash_file(driver._executable(entrypoints))
    raise AdapterExecutionError("driver does not support a tool-entrypoint conformance fixture")


def _materialize_conformance_fixture(
    fixture: ConformanceFixture,
    destination: Path,
    driver: ProviderDriver,
    entrypoints: list[str],
) -> str:
    if fixture.source == "package":
        destination.write_bytes(_fixture_payload(fixture))
    elif fixture.source == "tool-entrypoint" and isinstance(driver, GoReSymSymbolMapDriver):
        shutil.copyfile(driver._executable(entrypoints), destination)
    else:
        raise AdapterExecutionError("driver cannot materialize the conformance fixture")
    return _hash_file(destination)


def _fixture_bytes() -> bytes:
    return _fixture_payload(ELF_FIXTURE)


def _jadx_fixture_bytes() -> bytes:
    return _fixture_payload(JADX_FIXTURE)


def _ghidra_native_map_fixture_bytes() -> bytes:
    return _fixture_payload(GHIDRA_NATIVE_MAP_FIXTURE)


def _tshark_fixture_bytes() -> bytes:
    return _fixture_payload(TSHARK_FIXTURE)


def _frida_fixture_bytes() -> bytes:
    return _fixture_payload(FRIDA_RUNTIME_MAP_FIXTURE)


def _unblob_fixture_bytes() -> bytes:
    return _fixture_payload(UNBLOB_FIXTURE)


def _ghidra_script_bytes() -> bytes:
    resource = importlib.resources.files("white_hat_agent").joinpath(
        "builtin_adapter_fixtures/WhaBinarySummary.java"
    )
    payload = resource.read_bytes()
    if hashlib.sha256(payload).hexdigest() != GHIDRA_SCRIPT_SHA256:
        raise AdapterExecutionError("bundled Ghidra script digest mismatch")
    return payload


def _ghidra_native_map_script_bytes() -> bytes:
    resource = importlib.resources.files("white_hat_agent").joinpath(
        "builtin_adapter_fixtures/WhaNativeCodeMap.java"
    )
    payload = resource.read_bytes()
    if hashlib.sha256(payload).hexdigest() != GHIDRA_NATIVE_MAP_SCRIPT_SHA256:
        raise AdapterExecutionError("bundled Ghidra native-code-map script digest mismatch")
    return payload


def _frida_runtime_map_script_bytes() -> bytes:
    resource = importlib.resources.files("white_hat_agent").joinpath(
        "builtin_adapter_fixtures/WhaRuntimeModuleMap.js"
    )
    payload = resource.read_bytes()
    if hashlib.sha256(payload).hexdigest() != FRIDA_RUNTIME_MAP_SCRIPT_SHA256:
        raise AdapterExecutionError("bundled Frida observation script digest mismatch")
    return payload


def _yara_x_conformance_rule() -> str:
    resource = importlib.resources.files("white_hat_agent").joinpath(
        "builtin_adapter_fixtures/yara_x_marker.yar"
    )
    payload = resource.read_bytes()
    if hashlib.sha256(payload).hexdigest() != YARA_X_CONFORMANCE_RULE_SHA256:
        raise AdapterExecutionError("packaged YARA-X conformance rule digest does not match")
    return payload.decode("utf-8")


def _effective_limits(
    contract: OperationResourceLimits,
    overrides: AdapterLimitOverrides,
    *,
    max_output_bytes: int | None = None,
) -> OperationResourceLimits:
    values = contract.model_dump()
    for field, requested in overrides.model_dump().items():
        if requested is None:
            continue
        if requested > values[field]:
            raise AdapterExecutionError(f"requested {field} exceeds the operation contract")
        values[field] = requested
    if max_output_bytes is not None:
        values["max_output_bytes"] = min(values["max_output_bytes"], max_output_bytes)
    return OperationResourceLimits.model_validate(values)


def _apply_resource_limits(limits: OperationResourceLimits) -> None:
    if resource is None:  # pragma: no cover - supervisor rejects non-Linux hosts first
        raise AdapterExecutionError("POSIX resource limits are unavailable")
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (limits.cpu_seconds, limits.cpu_seconds + 1))
    max_address_space = limits.memory_mib * 1024 * 1024
    resource.setrlimit(resource.RLIMIT_AS, (max_address_space, max_address_space))
    resource.setrlimit(resource.RLIMIT_FSIZE, (limits.max_output_bytes, limits.max_output_bytes))
    max_open_files = min(limits.max_files + 32, 4096)
    resource.setrlimit(resource.RLIMIT_NOFILE, (max_open_files, max_open_files))


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        _kill_process_group(process)


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)


def _tree_usage(
    root: Path,
    *,
    stop_after_bytes: int,
    stop_after_entries: int,
) -> tuple[int, int]:
    entries = 0
    byte_length = 0
    for current, directories, names in os.walk(root, followlinks=False):
        retained_directories: list[str] = []
        for name in directories:
            entries += 1
            path = Path(current) / name
            with suppress(OSError):
                if stat.S_ISDIR(path.lstat().st_mode):
                    retained_directories.append(name)
            if entries > stop_after_entries:
                return entries, byte_length
        directories[:] = retained_directories
        for name in names:
            path = Path(current) / name
            entries += 1
            with suppress(OSError):
                stat_result = path.lstat()
                if stat.S_ISREG(stat_result.st_mode):
                    byte_length += stat_result.st_size
            if entries > stop_after_entries or byte_length > stop_after_bytes:
                return entries, byte_length
    return entries, byte_length


def _descendant_process_count(root_pid: int) -> int:
    pending = [root_pid]
    observed: set[int] = set()
    while pending:
        pid = pending.pop()
        if pid in observed:
            continue
        observed.add(pid)
        for children_path in Path(f"/proc/{pid}/task").glob("*/children"):
            with suppress(OSError, UnicodeError, ValueError):
                pending.extend(int(value) for value in children_path.read_text().split())
    return len(observed)


def _read_json(path: Path, max_bytes: int) -> JsonValue:
    if path.is_symlink() or not path.is_file():
        raise AdapterExecutionError("adapter JSON output is not a regular file")
    if path.stat().st_size > max_bytes:
        raise AdapterExecutionError("adapter JSON output exceeds the byte limit")
    return json.loads(path.read_text(encoding="utf-8"))


def _read_marked_json(path: Path, max_bytes: int, *, marker: str) -> dict[str, object]:
    if path.is_symlink() or not path.is_file():
        raise AdapterExecutionError("adapter marked JSON output is not a regular file")
    if path.stat().st_size > max_bytes:
        raise AdapterExecutionError("adapter marked JSON output exceeds the byte limit")
    matches = [
        line.removeprefix(marker)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.startswith(marker)
    ]
    if len(matches) != 1:
        raise AdapterExecutionError("adapter output must contain exactly one marked JSON record")
    try:
        value = json.loads(matches[0])
    except json.JSONDecodeError as exc:
        raise AdapterExecutionError("adapter marked JSON record is invalid") from exc
    if not isinstance(value, dict):
        raise AdapterExecutionError("adapter marked JSON record is not an object")
    return value


def _frida_text(
    value: object,
    field: str,
    *,
    max_length: int,
    nullable: bool = False,
) -> str | None:
    if value is None and nullable:
        return None
    if (
        not isinstance(value, str)
        or not value
        or len(value) > max_length
        or "\x00" in value
        or "\r" in value
        or "\n" in value
    ):
        raise AdapterExecutionError(f"Frida result has an invalid {field}")
    return value


def _frida_pointer(value: object, field: str, *, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str) or re.fullmatch(r"0x[0-9a-fA-F]{1,16}", value) is None:
        raise AdapterExecutionError(f"Frida result has an invalid {field}")
    return value.casefold()


def _frida_integer(value: object, field: str, *, maximum: int = (1 << 63) - 1) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise AdapterExecutionError(f"Frida result has an invalid {field}")
    return value


def _normalize_frida_process(value: object) -> dict[str, JsonValue]:
    required = {"arch", "platform", "pointer_size", "page_size", "code_signing_policy"}
    if not isinstance(value, dict) or set(value) != required:
        raise AdapterExecutionError("Frida result has an unexpected process schema")
    arch = _frida_text(value["arch"], "process architecture", max_length=16)
    platform = _frida_text(value["platform"], "process platform", max_length=16)
    policy = _frida_text(value["code_signing_policy"], "code-signing policy", max_length=16)
    if arch not in {"ia32", "x64", "arm", "arm64"}:
        raise AdapterExecutionError("Frida result has an unknown process architecture")
    if platform not in {"windows", "darwin", "linux", "freebsd", "qnx", "barebone"}:
        raise AdapterExecutionError("Frida result has an unknown process platform")
    if policy not in {"optional", "required"}:
        raise AdapterExecutionError("Frida result has an unknown code-signing policy")
    pointer_size = _frida_integer(value["pointer_size"], "pointer size", maximum=16)
    if pointer_size not in {4, 8}:
        raise AdapterExecutionError("Frida result has an unsupported pointer size")
    page_size = _frida_integer(value["page_size"], "page size", maximum=1_048_576)
    if page_size < 256 or page_size & (page_size - 1):
        raise AdapterExecutionError("Frida result has an invalid page size")
    return {
        "arch": arch,
        "platform": platform,
        "pointer_size": pointer_size,
        "page_size": page_size,
        "code_signing_policy": policy,
    }


def _normalize_frida_module(value: object) -> dict[str, JsonValue]:
    if not isinstance(value, dict) or set(value) != {"name", "path", "base", "size"}:
        raise AdapterExecutionError("Frida result has an unexpected module schema")
    return {
        "name": _frida_text(value["name"], "module name", max_length=1024),
        "path": _frida_text(value["path"], "module path", max_length=4096),
        "base": _frida_pointer(value["base"], "module base"),
        "size": _frida_integer(value["size"], "module size", maximum=(1 << 63) - 1),
    }


def _normalize_frida_import(value: object) -> dict[str, JsonValue]:
    if not isinstance(value, dict) or set(value) != {"type", "name", "module", "address", "slot"}:
        raise AdapterExecutionError("Frida result has an unexpected import schema")
    return {
        "type": _frida_text(value["type"], "import type", max_length=64),
        "name": _frida_text(value["name"], "import name", max_length=4096),
        "module": _frida_text(value["module"], "import module", max_length=4096, nullable=True),
        "address": _frida_pointer(value["address"], "import address", nullable=True),
        "slot": _frida_pointer(value["slot"], "import slot", nullable=True),
    }


def _normalize_frida_export(value: object) -> dict[str, JsonValue]:
    if not isinstance(value, dict) or set(value) != {
        "type",
        "name",
        "address",
        "offset_from_main",
    }:
        raise AdapterExecutionError("Frida result has an unexpected export schema")
    return {
        "type": _frida_text(value["type"], "export type", max_length=64),
        "name": _frida_text(value["name"], "export name", max_length=4096),
        "address": _frida_pointer(value["address"], "export address"),
        "offset_from_main": _frida_pointer(value["offset_from_main"], "export offset"),
    }


def _normalize_frida_dependency(value: object) -> dict[str, JsonValue]:
    if not isinstance(value, dict) or set(value) != {"name", "type"}:
        raise AdapterExecutionError("Frida result has an unexpected dependency schema")
    return {
        "name": _frida_text(value["name"], "dependency name", max_length=4096),
        "type": _frida_text(value["type"], "dependency type", max_length=64),
    }


def _normalize_frida_collection(
    value: object,
    *,
    name: str,
    maximum_items: int,
    item_normalizer: Callable[[object], dict[str, JsonValue]],
) -> tuple[int, list[dict[str, JsonValue]], bool]:
    if not isinstance(value, dict) or set(value) != {"total", "returned", "truncated", "items"}:
        raise AdapterExecutionError(f"Frida result has an unexpected {name} collection schema")
    total = _frida_integer(value["total"], f"{name} total", maximum=10_000_000)
    returned = _frida_integer(value["returned"], f"{name} returned", maximum=maximum_items)
    truncated = value["truncated"]
    items = value["items"]
    if not isinstance(truncated, bool) or not isinstance(items, list):
        raise AdapterExecutionError(f"Frida result has an invalid {name} collection")
    if len(items) != returned or returned > total or truncated != (returned < total):
        raise AdapterExecutionError(f"Frida result has inconsistent {name} counts")
    return total, [item_normalizer(item) for item in items], truncated


def _normalize_frida_collection_errors(value: object) -> list[JsonValue]:
    if not isinstance(value, list) or len(value) > 4:
        raise AdapterExecutionError("Frida result has an invalid collection error list")
    records: list[JsonValue] = []
    observed: set[str] = set()
    for item in value:
        if not isinstance(item, dict) or set(item) != {"collection", "error"}:
            raise AdapterExecutionError("Frida result has an invalid collection error")
        collection = _frida_text(item["collection"], "error collection", max_length=32)
        error = _frida_text(item["error"], "collection error", max_length=2048)
        if collection not in {"modules", "imports", "exports", "dependencies"}:
            raise AdapterExecutionError("Frida result names an unknown failed collection")
        if collection in observed:
            raise AdapterExecutionError("Frida result repeats a collection error")
        observed.add(collection)
        records.append({"collection": collection, "error": error})
    return records


def _tshark_values(layers: dict[str, object], field: str) -> list[str]:
    raw = layers.get(field)
    if not isinstance(raw, list) or not raw or len(raw) > 256:
        raise AdapterExecutionError(f"TShark result has invalid values for {field}")
    values: list[str] = []
    for value in raw:
        if not isinstance(value, str) or len(value) > 65_536 or "\x00" in value:
            raise AdapterExecutionError(f"TShark result has an invalid value for {field}")
        values.append(value)
    return values


def _tshark_integer(value: str, field: str, *, maximum: int = (1 << 64) - 1) -> int:
    if re.fullmatch(r"[0-9]+", value) is None:
        raise AdapterExecutionError(f"TShark result has a non-decimal {field}")
    parsed = int(value)
    if parsed > maximum:
        raise AdapterExecutionError(f"TShark result has an out-of-range {field}")
    return parsed


def _normalize_tshark_packet(value: object) -> dict[str, JsonValue]:
    if not isinstance(value, dict) or "_source" not in value:
        raise AdapterExecutionError("TShark result has an invalid packet object")
    if not set(value).issubset({"_index", "_type", "_score", "_source"}):
        raise AdapterExecutionError("TShark result has unexpected packet metadata")
    if "_index" in value and (not isinstance(value["_index"], str) or len(value["_index"]) > 256):
        raise AdapterExecutionError("TShark result has invalid index metadata")
    if value.get("_type", "doc") != "doc" or value.get("_score") is not None:
        raise AdapterExecutionError("TShark result has invalid document metadata")
    source = value["_source"]
    if not isinstance(source, dict) or set(source) != {"layers"}:
        raise AdapterExecutionError("TShark result has an invalid packet source")
    layers = source["layers"]
    if not isinstance(layers, dict):
        raise AdapterExecutionError("TShark result has invalid packet layers")
    if not set(_TSHARK_REQUIRED_FIELDS).issubset(layers):
        raise AdapterExecutionError("TShark result is missing required frame fields")
    if not set(layers).issubset(_TSHARK_SELECTED_FIELDS):
        raise AdapterExecutionError("TShark result contains an unselected field")
    for field in layers:
        _tshark_values(layers, field)

    number_values = _tshark_values(layers, "frame.number")
    time_values = _tshark_values(layers, "frame.time_epoch")
    wire_values = _tshark_values(layers, "frame.len")
    captured_values = _tshark_values(layers, "frame.cap_len")
    protocol_values = _tshark_values(layers, "frame.protocols")
    required_values = (
        number_values,
        time_values,
        wire_values,
        captured_values,
        protocol_values,
    )
    if any(len(items) != 1 for items in required_values):
        raise AdapterExecutionError("TShark result repeats a required frame field")
    timestamp = time_values[0]
    if re.fullmatch(r"-?[0-9]{1,20}(?:\.[0-9]{1,12})?", timestamp) is None:
        raise AdapterExecutionError("TShark result has an invalid frame timestamp")
    protocols = protocol_values[0].split(":")
    if (
        not protocols
        or len(protocols) > 128
        or any(re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", item) is None for item in protocols)
    ):
        raise AdapterExecutionError("TShark result has an invalid protocol chain")

    fields: dict[str, JsonValue] = {}
    for source_name, output_name, field_type in _TSHARK_FIELD_SPECS:
        if source_name not in layers:
            continue
        raw_values = _tshark_values(layers, source_name)
        if field_type == "presence":
            fields[output_name] = True
        elif field_type == "int":
            fields[output_name] = [_tshark_integer(item, source_name) for item in raw_values]
        elif field_type == "bool":
            if any(item not in {"True", "False", "1", "0"} for item in raw_values):
                raise AdapterExecutionError(f"TShark result has a non-boolean {source_name}")
            fields[output_name] = [item in {"True", "1"} for item in raw_values]
        else:
            fields[output_name] = raw_values

    return {
        "number": _tshark_integer(number_values[0], "frame number", maximum=(1 << 32) - 1),
        "timestamp_epoch": timestamp,
        "wire_bytes": _tshark_integer(wire_values[0], "wire length", maximum=(1 << 32) - 1),
        "captured_bytes": _tshark_integer(captured_values[0], "captured length", maximum=(1 << 32) - 1),
        "protocols": protocols,
        "fields": fields,
    }


def _tshark_single_field(fields: dict[str, JsonValue], name: str) -> JsonValue | None:
    value = fields.get(name)
    return value[0] if isinstance(value, list) and len(value) == 1 else None


def _tshark_stream_summaries(packets: list[dict[str, JsonValue]]) -> list[JsonValue]:
    state: dict[tuple[str, int], dict[str, object]] = {}
    for packet in packets:
        fields = packet.get("fields")
        if not isinstance(fields, dict):
            continue
        selected: tuple[str, int, str, str] | None = None
        for transport in ("tcp", "udp"):
            stream = _tshark_single_field(fields, f"{transport}_stream")
            if isinstance(stream, int):
                selected = (
                    transport,
                    stream,
                    f"{transport}_source_port",
                    f"{transport}_destination_port",
                )
                break
        if selected is None:
            continue
        transport, stream, source_port_name, destination_port_name = selected
        key = (transport, stream)
        item = state.setdefault(
            key,
            {"packet_count": 0, "wire_bytes": 0, "endpoints": set()},
        )
        item["packet_count"] = int(item["packet_count"]) + 1
        item["wire_bytes"] = int(item["wire_bytes"]) + int(packet["wire_bytes"])
        source_address = _tshark_single_field(fields, "ipv4_source") or _tshark_single_field(
            fields, "ipv6_source"
        )
        destination_address = _tshark_single_field(fields, "ipv4_destination") or _tshark_single_field(
            fields, "ipv6_destination"
        )
        source_port = _tshark_single_field(fields, source_port_name)
        destination_port = _tshark_single_field(fields, destination_port_name)
        endpoints = item["endpoints"]
        if not isinstance(endpoints, set):
            raise AdapterExecutionError("TShark stream state is invalid")
        if isinstance(source_address, str) and isinstance(source_port, int):
            endpoints.add((source_address, source_port))
        if isinstance(destination_address, str) and isinstance(destination_port, int):
            endpoints.add((destination_address, destination_port))

    summaries: list[JsonValue] = []
    for (transport, stream), item in sorted(state.items()):
        endpoints = item["endpoints"]
        if not isinstance(endpoints, set):
            raise AdapterExecutionError("TShark stream state is invalid")
        summaries.append(
            {
                "transport": transport,
                "stream_id": stream,
                "packet_count": int(item["packet_count"]),
                "wire_bytes": int(item["wire_bytes"]),
                "endpoints": [
                    {"address": str(address), "port": int(port)} for address, port in sorted(endpoints)
                ],
            }
        )
    return summaries


def _read_single_ndjson(path: Path, max_bytes: int) -> dict[str, JsonValue]:
    if path.is_symlink() or not path.is_file():
        raise AdapterExecutionError("adapter NDJSON output is not a regular file")
    if path.stat().st_size > max_bytes:
        raise AdapterExecutionError("adapter NDJSON output exceeds the byte limit")
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if len(lines) != 1:
        raise AdapterExecutionError("adapter NDJSON output must contain exactly one record")
    value = json.loads(lines[0])
    if not isinstance(value, dict):
        raise AdapterExecutionError("adapter NDJSON record is not an object")
    return value


def _yara_string(value: object, field: str, *, max_length: int, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not value and not allow_empty) or len(value) > max_length:
        raise AdapterExecutionError(f"YARA-X result has an invalid {field}")
    return value


def _normalize_yara_rule(value: object) -> dict[str, JsonValue]:
    if not isinstance(value, dict) or set(value) != {
        "identifier",
        "namespace",
        "meta",
        "tags",
        "strings",
    }:
        raise AdapterExecutionError("YARA-X result has an unexpected rule schema")
    identifier = _yara_string(value["identifier"], "rule identifier", max_length=256)
    namespace = _yara_string(value["namespace"], "rule namespace", max_length=256)

    raw_meta = value["meta"]
    if not isinstance(raw_meta, list) or len(raw_meta) > 64:
        raise AdapterExecutionError("YARA-X result has invalid rule metadata")
    metadata: list[JsonValue] = []
    meta_keys: set[str] = set()
    for entry in raw_meta:
        if not isinstance(entry, list) or len(entry) != 2:
            raise AdapterExecutionError("YARA-X result has an invalid metadata entry")
        key = _yara_string(entry[0], "metadata key", max_length=256)
        meta_value = entry[1]
        if isinstance(meta_value, str):
            meta_value = _yara_string(
                meta_value,
                "metadata value",
                max_length=4096,
                allow_empty=True,
            )
        elif not isinstance(meta_value, (bool, int, float)) or (
            isinstance(meta_value, float) and not math.isfinite(meta_value)
        ):
            raise AdapterExecutionError("YARA-X result has an invalid metadata value")
        if key in meta_keys:
            raise AdapterExecutionError("YARA-X result has duplicate metadata keys")
        meta_keys.add(key)
        metadata.append([key, meta_value])
    metadata.sort(key=lambda entry: str(entry[0]))

    raw_tags = value["tags"]
    if not isinstance(raw_tags, list) or len(raw_tags) > 64:
        raise AdapterExecutionError("YARA-X result has invalid rule tags")
    tags = [_yara_string(tag, "tag", max_length=256) for tag in raw_tags]
    if len(tags) != len(set(tags)):
        raise AdapterExecutionError("YARA-X result has duplicate rule tags")
    tags.sort()

    raw_strings = value["strings"]
    if not isinstance(raw_strings, list):
        raise AdapterExecutionError("YARA-X result has invalid string matches")
    strings: list[dict[str, JsonValue]] = []
    string_identities: set[tuple[object, ...]] = set()
    for item in raw_strings:
        if not isinstance(item, dict):
            raise AdapterExecutionError("YARA-X result has an invalid string match")
        required = {"identifier", "offset", "match"}
        allowed = required | {"xor_key", "plaintext"}
        if not required.issubset(item) or not set(item).issubset(allowed):
            raise AdapterExecutionError("YARA-X result has an unexpected string schema")
        match_identifier = _yara_string(item["identifier"], "string identifier", max_length=256)
        offset = item["offset"]
        if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
            raise AdapterExecutionError("YARA-X result has an invalid string offset")
        match_text = _yara_string(
            item["match"],
            "matched text",
            max_length=512,
            allow_empty=True,
        )
        normalized: dict[str, JsonValue] = {
            "identifier": match_identifier,
            "offset": offset,
            "match": match_text,
        }
        xor_key = item.get("xor_key")
        plaintext = item.get("plaintext")
        if xor_key is not None:
            if isinstance(xor_key, bool) or not isinstance(xor_key, int) or not 0 <= xor_key <= 255:
                raise AdapterExecutionError("YARA-X result has an invalid XOR key")
            normalized["xor_key"] = xor_key
            normalized["plaintext"] = _yara_string(
                plaintext,
                "XOR plaintext",
                max_length=512,
                allow_empty=True,
            )
        elif "plaintext" in item:
            raise AdapterExecutionError("YARA-X result has plaintext without an XOR key")
        identity = (
            normalized["identifier"],
            normalized["offset"],
            normalized["match"],
            normalized.get("xor_key"),
            normalized.get("plaintext"),
        )
        if identity in string_identities:
            raise AdapterExecutionError("YARA-X result has duplicate string matches")
        string_identities.add(identity)
        strings.append(normalized)
    strings.sort(key=lambda item: (int(item["offset"]), str(item["identifier"]), str(item["match"])))
    return {
        "identifier": identifier,
        "namespace": namespace,
        "meta": metadata,
        "tags": tags,
        "strings": strings,
    }


def _regular_output_tree(
    root: Path,
    *,
    max_files: int,
    max_bytes: int,
) -> list[tuple[str, Path, int]]:
    if root.is_symlink() or not root.is_dir():
        raise AdapterExecutionError("adapter output is not a regular directory")
    resolved_root = root.resolve(strict=True)
    pending = [resolved_root]
    entries = 0
    byte_length = 0
    files: list[tuple[str, Path, int]] = []
    while pending:
        current = pending.pop()
        with os.scandir(current) as directory:
            children = sorted(directory, key=lambda entry: entry.name, reverse=True)
        for entry in children:
            entries += 1
            if entries > max_files:
                raise AdapterExecutionError("adapter output exceeds the file limit")
            path = Path(entry.path)
            metadata = entry.stat(follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode):
                raise AdapterExecutionError("adapter output contains a symbolic link")
            if stat.S_ISDIR(metadata.st_mode):
                pending.append(path)
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise AdapterExecutionError("adapter output contains a special file")
            resolved = path.resolve(strict=True)
            if resolved_root not in resolved.parents:
                raise AdapterExecutionError("adapter output escaped its result directory")
            byte_length += metadata.st_size
            if byte_length > max_bytes:
                raise AdapterExecutionError("adapter output exceeds the byte limit")
            files.append((resolved.relative_to(resolved_root).as_posix(), resolved, metadata.st_size))
    return sorted(files, key=lambda item: item[0])


def _required_output_file(
    files: dict[str, tuple[Path, int]],
    relative: str,
) -> tuple[Path, int]:
    try:
        return files[relative]
    except KeyError as exc:
        raise AdapterExecutionError(f"adapter output is missing required file: {relative}") from exc


def _jadx_class_output_path(value: object) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise AdapterExecutionError("JADX class mapping has an invalid JSON path")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or path.suffix != ".json":
        raise AdapterExecutionError("JADX class mapping has an unsafe JSON path")
    if path.as_posix() != value:
        raise AdapterExecutionError("JADX class mapping path is not canonical")
    return f"sources/{path.as_posix()}"


def _json_record_cost(value: JsonValue) -> int:
    return len(json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode()) + 256


_GORESYM_TOP_LEVEL_FIELDS = {
    "Version",
    "BuildId",
    "Arch",
    "OS",
    "TabMeta",
    "ModuleMeta",
    "Types",
    "Interfaces",
    "BuildInfo",
    "Files",
    "UserFunctions",
    "StdFunctions",
    "Strings",
}


def _goresym_text(
    value: object,
    field: str,
    *,
    max_length: int,
    allow_empty: bool = False,
    allow_newlines: bool = False,
) -> str:
    if (
        not isinstance(value, str)
        or (not value and not allow_empty)
        or len(value) > max_length
        or "\x00" in value
        or (not allow_newlines and ("\r" in value or "\n" in value))
    ):
        raise AdapterExecutionError(f"GoReSym result has an invalid {field}")
    return value


def _goresym_uint(value: object, field: str, *, maximum: int = (1 << 64) - 1) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise AdapterExecutionError(f"GoReSym result has an invalid {field}")
    return value


def _goresym_truncate(value: str, limit: int) -> tuple[str, bool]:
    return value[:limit], len(value) > limit


def _goresym_list(value: object, field: str) -> list[object]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise AdapterExecutionError(f"GoReSym result has an invalid {field} collection")
    return value


def _normalize_goresym_module(value: object, *, replacement_allowed: bool = True) -> dict[str, JsonValue]:
    expected = {"Path", "Version", "Sum", "Replace"}
    if not isinstance(value, dict) or set(value) != expected:
        raise AdapterExecutionError("GoReSym result has an unexpected module schema")
    replacement = value["Replace"]
    if replacement is not None and not replacement_allowed:
        raise AdapterExecutionError("GoReSym result has a nested module replacement")
    normalized: dict[str, JsonValue] = {
        "path": _goresym_text(value["Path"], "module path", max_length=4096, allow_empty=True),
        "version": _goresym_text(value["Version"], "module version", max_length=4096, allow_empty=True),
        "sum": _goresym_text(value["Sum"], "module sum", max_length=4096, allow_empty=True),
        "replacement": None,
    }
    if replacement is not None:
        normalized["replacement"] = _normalize_goresym_module(
            replacement,
            replacement_allowed=False,
        )
    return normalized


def _normalize_goresym_slice(value: object, field: str) -> dict[str, JsonValue]:
    if not isinstance(value, dict) or set(value) != {"Data", "Len", "Capacity"}:
        raise AdapterExecutionError(f"GoReSym result has an unexpected {field} schema")
    return {
        "data": _goresym_uint(value["Data"], f"{field} data"),
        "length": _goresym_uint(value["Len"], f"{field} length"),
        "capacity": _goresym_uint(value["Capacity"], f"{field} capacity"),
    }


def _normalize_goresym_tab_metadata(value: object) -> dict[str, JsonValue]:
    expected = {"VA", "Version", "Endianess", "CpuQuantum", "CpuQuantumStr", "PointerSize"}
    if not isinstance(value, dict) or set(value) != expected:
        raise AdapterExecutionError("GoReSym result has an unexpected pclntab schema")
    endianness = _goresym_text(value["Endianess"], "pclntab endianness", max_length=32)
    if endianness not in {"LittleEndian", "BigEndian"}:
        raise AdapterExecutionError("GoReSym result has an unknown pclntab endianness")
    pointer_size = _goresym_uint(value["PointerSize"], "pclntab pointer size", maximum=16)
    if pointer_size not in {4, 8}:
        raise AdapterExecutionError("GoReSym result has an unsupported pointer size")
    return {
        "address": _goresym_uint(value["VA"], "pclntab address"),
        "version": _goresym_text(value["Version"], "pclntab version", max_length=64),
        "endianness": endianness,
        "cpu_quantum": _goresym_uint(value["CpuQuantum"], "pclntab CPU quantum", maximum=16),
        "cpu_quantum_name": _goresym_text(value["CpuQuantumStr"], "pclntab CPU quantum name", max_length=128),
        "pointer_size": pointer_size,
    }


def _normalize_goresym_module_metadata(value: object) -> dict[str, JsonValue]:
    expected = {"VA", "TextVA", "Types", "ETypes", "Typelinks", "ITablinks", "LegacyTypes"}
    if not isinstance(value, dict) or set(value) != expected:
        raise AdapterExecutionError("GoReSym result has an unexpected moduledata schema")
    return {
        "address": _goresym_uint(value["VA"], "moduledata address"),
        "text_address": _goresym_uint(value["TextVA"], "moduledata text address"),
        "types_address": _goresym_uint(value["Types"], "moduledata types address"),
        "types_end_address": _goresym_uint(value["ETypes"], "moduledata types end address"),
        "type_links": _normalize_goresym_slice(value["Typelinks"], "type links"),
        "interface_links": _normalize_goresym_slice(value["ITablinks"], "interface links"),
        "legacy_types": _normalize_goresym_slice(value["LegacyTypes"], "legacy types"),
    }


def _normalize_goresym_type(value: object) -> tuple[JsonValue, bool]:
    required = {"VA", "Str", "CStr", "Kind"}
    allowed = required | {"Reconstructed", "CReconstructed"}
    if not isinstance(value, dict) or not required.issubset(value) or not set(value).issubset(allowed):
        raise AdapterExecutionError("GoReSym result has an unexpected type schema")
    record: dict[str, JsonValue] = {
        "address": _goresym_uint(value["VA"], "type address"),
        "name": _goresym_text(value["Str"], "type name", max_length=65_536),
        "c_name": _goresym_text(value["CStr"], "C type name", max_length=65_536, allow_empty=True),
        "kind": _goresym_text(value["Kind"], "type kind", max_length=128),
    }
    truncated = False
    for source, destination in (
        ("Reconstructed", "definition"),
        ("CReconstructed", "c_definition"),
    ):
        if source not in value:
            continue
        raw = _goresym_text(
            value[source],
            destination,
            max_length=1_048_576,
            allow_empty=True,
            allow_newlines=True,
        )
        bounded, shortened = _goresym_truncate(raw, 16_384)
        record[destination] = bounded
        record[f"{destination}_truncated"] = shortened
        truncated |= shortened
    return record, truncated


def _normalize_goresym_function(value: object) -> tuple[JsonValue, bool]:
    if not isinstance(value, dict) or set(value) != {"Start", "End", "PackageName", "FullName"}:
        raise AdapterExecutionError("GoReSym result has an unexpected function schema")
    start = _goresym_uint(value["Start"], "function start")
    end = _goresym_uint(value["End"], "function end")
    if end < start:
        raise AdapterExecutionError("GoReSym result has an inverted function range")
    package = _goresym_text(value["PackageName"], "function package", max_length=65_536, allow_empty=True)
    full_name = _goresym_text(value["FullName"], "function name", max_length=65_536)
    bounded_package, package_truncated = _goresym_truncate(package, 4096)
    bounded_name, name_truncated = _goresym_truncate(full_name, 4096)
    return (
        {
            "start": start,
            "end": end,
            "package": bounded_package,
            "package_truncated": package_truncated,
            "full_name": bounded_name,
            "full_name_truncated": name_truncated,
        },
        package_truncated or name_truncated,
    )


def _normalize_goresym_file(value: object) -> tuple[JsonValue, bool]:
    path = _goresym_text(value, "source path", max_length=65_536)
    bounded, truncated = _goresym_truncate(path, 8192)
    return {"path": bounded, "path_truncated": truncated}, truncated


def _normalize_goresym_string(value: object) -> tuple[JsonValue, bool]:
    if not isinstance(value, dict) or set(value) != {"Str", "Start"}:
        raise AdapterExecutionError("GoReSym result has an unexpected string schema")
    raw = _goresym_text(
        value["Str"],
        "recovered string",
        max_length=1_048_576,
        allow_empty=True,
        allow_newlines=True,
    )
    bounded, truncated = _goresym_truncate(raw, 4096)
    return (
        {
            "start": _goresym_uint(value["Start"], "string start"),
            "value": bounded,
            "value_truncated": truncated,
        },
        truncated,
    )


def _normalize_goresym_dependency(value: object) -> tuple[JsonValue, bool]:
    return _normalize_goresym_module(value), False


def _normalize_goresym_setting(value: object) -> tuple[JsonValue, bool]:
    if not isinstance(value, dict) or set(value) != {"Key", "Value"}:
        raise AdapterExecutionError("GoReSym result has an unexpected build-setting schema")
    key = _goresym_text(value["Key"], "build-setting key", max_length=4096)
    raw = _goresym_text(
        value["Value"],
        "build-setting value",
        max_length=1_048_576,
        allow_empty=True,
    )
    bounded, truncated = _goresym_truncate(raw, 16_384)
    return {"key": key, "value": bounded, "value_truncated": truncated}, truncated


def _normalize_goresym_collections(
    collections: list[tuple[str, list[object], Callable[[object], tuple[JsonValue, bool]]]],
    limits: OperationResourceLimits,
) -> tuple[dict[str, JsonValue], int, bool]:
    sections: dict[str, dict[str, JsonValue]] = {
        name: {"total": len(values), "returned": 0, "truncated": False, "items": []}
        for name, values, _ in collections
    }
    record_budget = limits.max_records
    reserved_bytes = min(262_144, max(4096, limits.max_output_bytes // 4))
    byte_budget = max(0, limits.max_output_bytes - reserved_bytes)
    used_bytes = 0
    any_item_truncated = {name: False for name, _, _ in collections}
    quota = record_budget // len(collections)

    def retain(
        name: str,
        values: list[object],
        normalizer: Callable[[object], tuple[JsonValue, bool]],
        start: int,
        stop: int,
    ) -> None:
        nonlocal record_budget, used_bytes
        items = sections[name]["items"]
        if not isinstance(items, list):
            raise AdapterExecutionError("GoReSym normalization state is invalid")
        for raw in values[start:stop]:
            normalized, item_truncated = normalizer(raw)
            any_item_truncated[name] |= item_truncated
            cost = _json_record_cost(normalized)
            if record_budget < 1 or used_bytes + cost > byte_budget:
                continue
            items.append(normalized)
            record_budget -= 1
            used_bytes += cost

    for name, values, normalizer in collections:
        retain(name, values, normalizer, 0, min(len(values), quota))
    for name, values, normalizer in collections:
        retain(name, values, normalizer, min(len(values), quota), len(values))

    returned = 0
    truncated = False
    result: dict[str, JsonValue] = {}
    for name, values, _ in collections:
        section = sections[name]
        items = section["items"]
        if not isinstance(items, list):
            raise AdapterExecutionError("GoReSym normalization state is invalid")
        section_truncated = len(items) < len(values) or any_item_truncated[name]
        section["returned"] = len(items)
        section["truncated"] = section_truncated
        returned += len(items)
        truncated |= section_truncated
        result[name] = section
    return result, returned, truncated


def _normalize_goresym_payload(
    payload: JsonValue,
    limits: OperationResourceLimits,
) -> tuple[dict[str, JsonValue], int, bool]:
    if not isinstance(payload, dict) or set(payload) != _GORESYM_TOP_LEVEL_FIELDS:
        raise AdapterExecutionError("GoReSym emitted an unexpected JSON document")
    build_info = payload["BuildInfo"]
    if not isinstance(build_info, dict) or set(build_info) != {
        "GoVersion",
        "Path",
        "Main",
        "Deps",
        "Settings",
    }:
        raise AdapterExecutionError("GoReSym result has an unexpected build-info schema")
    build: dict[str, JsonValue] = {
        "go_version": _goresym_text(payload["Version"], "Go version", max_length=128),
        "build_id": _goresym_text(payload["BuildId"], "Go build ID", max_length=4096, allow_empty=True),
        "architecture": _goresym_text(payload["Arch"], "architecture", max_length=64),
        "operating_system": _goresym_text(payload["OS"], "operating system", max_length=64),
        "pclntab": _normalize_goresym_tab_metadata(payload["TabMeta"]),
        "moduledata": _normalize_goresym_module_metadata(payload["ModuleMeta"]),
        "build_info": {
            "go_version": _goresym_text(
                build_info["GoVersion"], "build-info Go version", max_length=128, allow_empty=True
            ),
            "path": _goresym_text(build_info["Path"], "build-info path", max_length=4096, allow_empty=True),
            "main": _normalize_goresym_module(build_info["Main"]),
        },
    }
    raw_collections = [
        (
            "user_functions",
            _goresym_list(payload["UserFunctions"], "user functions"),
            _normalize_goresym_function,
        ),
        (
            "standard_functions",
            _goresym_list(payload["StdFunctions"], "standard functions"),
            _normalize_goresym_function,
        ),
        ("types", _goresym_list(payload["Types"], "types"), _normalize_goresym_type),
        ("interfaces", _goresym_list(payload["Interfaces"], "interfaces"), _normalize_goresym_type),
        ("files", _goresym_list(payload["Files"], "files"), _normalize_goresym_file),
        ("strings", _goresym_list(payload["Strings"], "strings"), _normalize_goresym_string),
        (
            "dependencies",
            _goresym_list(build_info["Deps"], "dependencies"),
            _normalize_goresym_dependency,
        ),
        (
            "build_settings",
            _goresym_list(build_info["Settings"], "build settings"),
            _normalize_goresym_setting,
        ),
    ]
    collections, returned, truncated = _normalize_goresym_collections(raw_collections, limits)
    return {"build": build, **collections}, returned, truncated


def _bounded_json_records(
    values: list[object],
    *,
    max_records: int,
    max_bytes: int,
) -> tuple[list[JsonValue], int]:
    records: list[JsonValue] = []
    used_bytes = 0
    for value in values:
        record = _json_value(value)
        record_bytes = _json_record_cost(record)
        if len(records) >= max_records or used_bytes + record_bytes > max_bytes:
            continue
        records.append(record)
        used_bytes += record_bytes
    return records, used_bytes


def _system_java_home(entrypoints: list[str] | tuple[str, ...] = ()) -> Path:
    java = next(
        (Path(value) for value in entrypoints if Path(value).name.casefold() in {"java", "java.exe"}),
        None,
    )
    if java is None:
        resolved = shutil.which("java")
        java = Path(resolved) if resolved else None
    if java is None or not java.exists():
        raise AdapterExecutionError("typed Java operation requires an observed Java runtime")
    java_home = java.resolve(strict=True).parent.parent
    if not java_home.is_dir():
        raise AdapterExecutionError("Java home is unavailable")
    return java_home


def _system_java_config_roots(java_home: Path) -> tuple[Path, ...]:
    config = java_home / "conf"
    candidates = [config] if config.is_symlink() else list(config.rglob("*"))
    roots: set[Path] = set()
    for candidate in candidates:
        if not candidate.is_symlink():
            continue
        target = candidate.resolve(strict=True)
        try:
            relative = target.relative_to("/etc")
        except ValueError:
            continue
        if not relative.parts:
            raise AdapterExecutionError("system Java configuration resolves to an unsafe root")
        root = Path("/etc") / relative.parts[0]
        if root.is_symlink() or not root.is_dir():
            raise AdapterExecutionError("system Java configuration is unavailable")
        roots.add(root.resolve(strict=True))
    return tuple(sorted(roots))


def _system_java_mounts(
    entrypoints: list[str] | tuple[str, ...] = (),
) -> tuple[SandboxMount, ...]:
    java_home = _system_java_home(entrypoints)
    return (
        SandboxMount(java_home, "/opt/java"),
        *(SandboxMount(root, root.as_posix()) for root in _system_java_config_roots(java_home)),
    )


def _system_java_payload_digests(
    entrypoints: list[str] | tuple[str, ...] = (),
) -> tuple[str, str]:
    java_home = _system_java_home(entrypoints)
    java_executable = next(
        (path for path in (java_home / "bin/java", java_home / "bin/java.exe") if path.is_file()),
        None,
    )
    if java_executable is None:
        raise AdapterExecutionError("Java executable is unavailable beneath the observed home")
    core_payloads = [java_home / "release", java_executable, java_home / "lib/modules"]
    if any(not path.is_file() for path in core_payloads):
        raise AdapterExecutionError("Java runtime is missing a required content-identity payload")
    native_candidates = [
        java_home / "lib/libjava.so",
        java_home / "lib/libjli.so",
        java_home / "lib/server/libjvm.so",
        java_home / "lib/libjava.dylib",
        java_home / "lib/libjli.dylib",
        java_home / "lib/server/libjvm.dylib",
        java_home / "bin/java.dll",
        java_home / "bin/jli.dll",
        java_home / "bin/server/jvm.dll",
    ]
    java_digest = _hash_file_set(
        java_home,
        [*core_payloads, *[path for path in native_candidates if path.is_file()]],
    )
    config_roots = _system_java_config_roots(java_home)
    config_payloads = [
        {
            "destination": root.as_posix(),
            "sha256": _hash_file_set(
                root,
                sorted(path for path in root.rglob("*") if path.is_file()),
            ),
        }
        for root in config_roots
    ]
    config_digest = (
        str(config_payloads[0]["sha256"]) if len(config_payloads) == 1 else stable_digest(config_payloads)
    )
    return java_digest, config_digest


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1_048_576):
            digest.update(chunk)
    return digest.hexdigest()


def _hash_file_set(root: Path, paths: list[Path]) -> str:
    root = root.resolve(strict=True)
    digest = hashlib.sha256()
    digest.update(b"white-hat-agent-operation-payload\0\x01")
    for path in paths:
        resolved = path.resolve(strict=True)
        if root != resolved and root not in resolved.parents:
            raise AdapterExecutionError("operation payload file escaped the tool root")
        if path.is_symlink() or not resolved.is_file():
            raise AdapterExecutionError("operation payload contains a link or non-file")
        relative = resolved.relative_to(root).as_posix().encode()
        file_digest = bytes.fromhex(_hash_file(resolved))
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(resolved.stat().st_size.to_bytes(8, "big"))
        digest.update(file_digest)
    return digest.hexdigest()


def _unblob_task_path(value: object) -> str:
    if value == "/data/input/artifact":
        return "input"
    if not isinstance(value, str) or not value.startswith("/data/output/extracted/"):
        raise AdapterExecutionError("unblob reported a path outside its fixed mounts")
    relative = value.removeprefix("/data/output/extracted/")
    path = PurePosixPath(relative)
    if (
        not relative
        or len(relative.encode("utf-8")) > 4_096
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise AdapterExecutionError("unblob reported an unsafe extracted path")
    return path.as_posix()


def _unblob_stat_record(
    stat_report: dict[str, object],
    hash_report: dict[str, object] | None,
    magic_report: dict[str, object] | None,
    depth: int,
) -> dict[str, JsonValue]:
    flags = {
        "directory": stat_report.get("is_dir"),
        "file": stat_report.get("is_file"),
        "link": stat_report.get("is_link"),
    }
    if any(not isinstance(value, bool) for value in flags.values()) or sum(flags.values()) != 1:
        raise AdapterExecutionError("unblob StatReport has an invalid file type")
    kind = next(name for name, selected in flags.items() if selected)
    size = stat_report.get("size")
    if isinstance(size, bool) or not isinstance(size, int) or not 0 <= size <= 2_147_483_648:
        raise AdapterExecutionError("unblob StatReport has an invalid size")
    record: dict[str, JsonValue] = {
        "path": _unblob_task_path(stat_report.get("path")),
        "kind": kind,
        "size": size,
        "depth": depth,
    }
    if kind == "file":
        sha256 = hash_report.get("sha256") if hash_report is not None else None
        if not isinstance(sha256, str) or re.fullmatch(r"[0-9a-f]{64}", sha256) is None:
            raise AdapterExecutionError("unblob file task has no valid SHA-256 report")
        record["sha256"] = sha256
    if kind == "link":
        target = stat_report.get("link_target")
        if not isinstance(target, str) or len(target.encode("utf-8")) > 4_096 or "\x00" in target:
            raise AdapterExecutionError("unblob link task has an invalid target")
        record["link_target"] = target
    if magic_report is not None:
        magic = magic_report.get("magic")
        mime_type = magic_report.get("mime_type")
        if (
            not isinstance(magic, str)
            or len(magic.encode("utf-8")) > 2_048
            or not isinstance(mime_type, str)
            or len(mime_type.encode("utf-8")) > 256
        ):
            raise AdapterExecutionError("unblob magic report is invalid or unbounded")
        record["magic"] = magic
        record["mime_type"] = mime_type
    return record


def _unblob_output_entries(
    root: Path,
    limits: OperationResourceLimits,
) -> dict[str, dict[str, JsonValue]]:
    if not root.exists():
        return {}
    if root.is_symlink() or not root.is_dir():
        raise AdapterExecutionError("unblob extraction root is not a regular directory")
    entries: dict[str, dict[str, JsonValue]] = {}
    for current, directories, names in os.walk(root, followlinks=False):
        retained: list[str] = []
        for name in directories:
            path = Path(current) / name
            relative = path.relative_to(root).as_posix()
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                target = os.readlink(path)
                entries[relative] = {
                    "path": relative,
                    "kind": "link",
                    "size": metadata.st_size,
                    "link_target": target,
                }
            elif stat.S_ISDIR(metadata.st_mode):
                entries[relative] = {
                    "path": relative,
                    "kind": "directory",
                    "size": metadata.st_size,
                }
                retained.append(name)
            else:
                raise AdapterExecutionError("unblob output tree contains a special directory entry")
        directories[:] = retained
        for name in names:
            path = Path(current) / name
            relative = path.relative_to(root).as_posix()
            metadata = path.lstat()
            if stat.S_ISREG(metadata.st_mode):
                entries[relative] = {
                    "path": relative,
                    "kind": "file",
                    "size": metadata.st_size,
                    "sha256": _hash_file(path),
                }
            elif stat.S_ISLNK(metadata.st_mode):
                entries[relative] = {
                    "path": relative,
                    "kind": "link",
                    "size": metadata.st_size,
                    "link_target": os.readlink(path),
                }
            else:
                raise AdapterExecutionError("unblob output tree contains a special file")
        if len(entries) > limits.max_files:
            raise AdapterExecutionError("unblob output tree exceeds the file contract")
    if any(len(path.encode("utf-8")) > 4_096 for path in entries):
        raise AdapterExecutionError("unblob output tree contains an unbounded path")
    return entries


def _unblob_records_match(
    reported: dict[str, JsonValue],
    actual: dict[str, JsonValue],
) -> bool:
    if reported.get("kind") != actual.get("kind"):
        return False
    if reported.get("kind") == "directory":
        return True
    if reported.get("size") != actual.get("size"):
        return False
    if reported.get("kind") == "file":
        return reported.get("sha256") == actual.get("sha256")
    return reported.get("link_target") == actual.get("link_target")


def _unblob_chunk_record(report: dict[str, object], task_path: str) -> dict[str, JsonValue]:
    handler = report.get("handler_name")
    start_offset = report.get("start_offset")
    end_offset = report.get("end_offset")
    size = report.get("size")
    encrypted = report.get("is_encrypted")
    extraction_reports = report.get("extraction_reports")
    if (
        not isinstance(handler, str)
        or re.fullmatch(r"[A-Za-z0-9_.+-]{1,128}", handler) is None
        or any(
            isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 2**63 - 1
            for value in (start_offset, end_offset, size)
        )
        or end_offset - start_offset != size
        or not isinstance(encrypted, bool)
        or not isinstance(extraction_reports, list)
        or len(extraction_reports) > 64
    ):
        raise AdapterExecutionError("unblob ChunkReport is invalid or unbounded")
    return {
        "path": task_path,
        "handler": handler,
        "start_offset": start_offset,
        "end_offset": end_offset,
        "size": size,
        "encrypted": encrypted,
        "extraction_reports": len(extraction_reports),
    }


def _llvm_records(value: object, wrapper: str, limit: int) -> tuple[list[JsonValue], bool]:
    if not isinstance(value, list):
        return [], False
    records: list[JsonValue] = []
    for item in value[:limit]:
        if isinstance(item, dict) and isinstance(item.get(wrapper), dict):
            records.append(_json_value(item[wrapper]))
    return records, len(value) > len(records)


def _nested_name(value: dict[str, JsonValue]) -> str:
    name = value.get("Name")
    if isinstance(name, dict):
        return str(name.get("Name", ""))
    return str(name or "")


def _feature_count_summary(value: object) -> JsonValue:
    if not isinstance(value, dict):
        return {}
    functions = value.get("functions") if isinstance(value.get("functions"), list) else []
    return {
        "file": int(value.get("file", 0)),
        "functions_total": len(functions),
    }


def _json_value(value: object) -> JsonValue:
    return json.loads(json.dumps(value, ensure_ascii=True))
