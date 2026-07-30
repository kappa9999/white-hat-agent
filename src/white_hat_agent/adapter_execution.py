from __future__ import annotations

import base64
import hashlib
import importlib.resources
import json
import math
import os
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time
from contextlib import ExitStack, suppress
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Annotated, Literal, Protocol, Self

from pydantic import AwareDatetime, Field, JsonValue, SecretStr, model_validator

from .adapter_registry import (
    AdapterConformanceCheck,
    AdapterConformanceReport,
    AdapterManager,
    AdapterOperationBinding,
    AdapterStatus,
    OperationResourceLimits,
    ProbeDefinition,
    _probe_file_version,
    _requirement_observations,
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


class CapaFileAnalyzePayload(StrictModel):
    operation_id: Literal["capa.file-analyze"]
    operating_system: Literal["auto", "linux", "macos", "windows"] = "auto"


class LlvmObjectInspectPayload(StrictModel):
    operation_id: Literal["llvm.object-inspect"]


class JadxAndroidStaticMapPayload(StrictModel):
    operation_id: Literal["jadx.android-static-map"]


AdapterOperationPayload = Annotated[
    GhidraBinarySummaryPayload
    | CapaFileAnalyzePayload
    | LlvmObjectInspectPayload
    | JadxAndroidStaticMapPayload,
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
    effective_limits: OperationResourceLimits
    exit_code: int | None = None
    signal: int | None = None

    @classmethod
    def from_result(cls, result: AdapterExecutionResult) -> Self:
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
            effective_limits=result.effective_limits,
            exit_code=result.exit_code,
            signal=result.signal,
        )


@dataclass(frozen=True)
class SandboxMount:
    source: Path
    destination: str


@dataclass(frozen=True)
class TrustedInvocation:
    argv: tuple[str, ...]
    mounts: tuple[SandboxMount, ...]
    result_relative_path: str | None = None


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


@dataclass(frozen=True)
class ConformanceFixture:
    fixture_id: str
    filename: str
    resource_name: str
    sha256: str


ELF_FIXTURE = ConformanceFixture(
    fixture_id="minimal-elf64-x86-64-v1",
    filename="fixture.elf",
    resource_name="minimal_elf64.b64",
    sha256="daf49381748b12d617a3c645f9932ade03d7c0cac6b804da1bd35ae80cf37cad",
)
JADX_FIXTURE = ConformanceFixture(
    fixture_id="minimal-dex35-v1",
    filename="fixture.dex",
    resource_name="minimal_android_dex.b64",
    sha256="865d09fc9bc4a407c2bab2516dd2576a63d410d036f30c21b6a28b8b875ec847",
)
# Backward-compatible public constants for the original shared ELF fixture.
FIXTURE_ID = ELF_FIXTURE.fixture_id
FIXTURE_SHA256 = ELF_FIXTURE.sha256
GHIDRA_SCRIPT_SHA256 = "87e15c8b2368cc739e4cca74ca306c1cbbddef9cc673626737de7dbc6317a5a9"
DRIVER_VERSION = "1.2.0"
JADX_DRIVER_VERSION = "1.0.0"
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
    ) -> TrustedInvocation: ...

    def normalize(
        self,
        process: SupervisedProcessResult,
        artifact_sha256: str,
        limits: OperationResourceLimits,
    ) -> AdapterNormalizedResult: ...

    def fixture_checks(self, normalized: AdapterNormalizedResult) -> list[AdapterConformanceCheck]: ...


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
        command = self._command(invocation, input_path, tool_work_dir)
        started = time.monotonic()
        limited = False
        timed_out = False
        warnings: list[str] = []
        with stdout_path.open("wb") as stdout_handle, stderr_path.open("wb") as stderr_handle:
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
            if parent not in created and parent not in {"/", "/usr", "/bin", "/lib", "/lib64", "/etc"}:
                command.extend(("--dir", parent))
                created.add(parent)
            command.extend(("--ro-bind", str(source), mount.destination))
        command.extend(("--", *invocation.argv))
        return command


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
    ) -> AdapterNormalizedResult:
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
    ) -> AdapterNormalizedResult:
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


class GhidraBinarySummaryDriver:
    adapter_id = "ghidra"
    operation_id = "ghidra.binary-summary"
    driver_id = "whitehat.ghidra-headless-summary"
    driver_version = DRIVER_VERSION

    def _entrypoint(self, entrypoints: list[str]) -> Path:
        entrypoint = next(
            (Path(path).resolve() for path in entrypoints if Path(path).name == "analyzeHeadless"),
            None,
        )
        if entrypoint is None or not entrypoint.is_file():
            raise AdapterExecutionError("Ghidra operation requires an observed analyzeHeadless entrypoint")
        return entrypoint

    def _root(self, entrypoints: list[str]) -> Path:
        return self._entrypoint(entrypoints).parent.parent

    def tool_payload_digest(self, entrypoints: list[str]) -> str:
        root = self._root(entrypoints)
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
        java_digest, java_config_digest = _system_java_payload_digests()
        script_digest = hashlib.sha256(_ghidra_script_bytes()).hexdigest()
        return stable_digest(
            {
                "provider_payload_sha256": provider_digest,
                "java_payload_sha256": java_digest,
                "java_config_sha256": java_config_digest,
                "driver_asset_sha256": script_digest,
            }
        )

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
                *_system_java_mounts(),
                SandboxMount(script, "/opt/wha-assets/WhaBinarySummary.java"),
            ),
            result_relative_path="summary.json",
        )

    def normalize(
        self,
        process: SupervisedProcessResult,
        artifact_sha256: str,
        limits: OperationResourceLimits,
    ) -> AdapterNormalizedResult:
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
        java_digest, java_config_digest = _system_java_payload_digests()
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
            *_system_java_mounts(),
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
    ) -> AdapterNormalizedResult:
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
    ("capa", "capa.file-analyze"): CapaFileAnalyzeDriver(),
    ("llvm", "llvm.object-inspect"): LlvmObjectInspectDriver(),
    ("jadx", "jadx.android-static-map"): JadxAndroidStaticMapDriver(),
}


def conformance_report_is_current(
    operation: AdapterOperationBinding,
    report: AdapterConformanceReport,
    entrypoints: list[str],
) -> bool:
    try:
        driver = _driver_for_operation(operation.operation_id)
        fixture = _conformance_fixture(operation.operation_id)
        tool_payload_sha256 = driver.tool_payload_digest(entrypoints)
    except (AdapterExecutionError, OSError, RuntimeError, ValueError):
        return False
    return (
        report.adapter_id == driver.adapter_id
        and report.driver_id == driver.driver_id
        and report.driver_version == driver.driver_version
        and report.sandbox_profile_sha256 == SANDBOX_PROFILE_SHA256
        and report.fixture_id == operation.conformance_suite_id == fixture.fixture_id
        and report.fixture_sha256 == fixture.sha256
        and report.tool_payload_sha256 == tool_payload_sha256
    )


class AdapterExecutionBroker:
    def __init__(
        self,
        manager: AdapterManager,
        fleet: FleetStore,
        evidence: EvidenceStore,
        *,
        supervisor: OfflineSandboxSupervisor | None = None,
    ) -> None:
        self.manager = manager
        self.fleet = fleet
        self.evidence = evidence
        self.supervisor = supervisor or OfflineSandboxSupervisor()

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
        checks: list[AdapterConformanceCheck] = []
        warnings: list[str] = []
        tool_digest = driver.tool_payload_digest(status.entrypoints)
        tool_version = "unobserved"
        fixture = _conformance_fixture(operation_id)
        requirement_paths, requirement_identity_sha256 = _requirement_observations(
            manifest,
            status.platform,
        )
        with tempfile.TemporaryDirectory(prefix="wha-adapter-conformance-") as temporary:
            temp_root = Path(temporary)
            fixture_path = temp_root / fixture.filename
            fixture_path.write_bytes(_fixture_payload(fixture))
            fixture_digest = _hash_file(fixture_path)
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
                    ok=fixture_digest == fixture.sha256,
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
                        detail=f"outcome={process.outcome.value}; exit={process.return_code}",
                    )
                )
                warnings.extend(process.warnings)
                if process.outcome == AdapterExecutionOutcome.SUCCEEDED:
                    try:
                        normalized = driver.normalize(process, fixture_digest, operation.limits)
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
            sandbox_profile_sha256=SANDBOX_PROFILE_SHA256,
            fixture_id=fixture.fixture_id,
            fixture_sha256=fixture.sha256,
            started_at=started_at,
            finished_at=utc_now(),
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
        )
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
                    normalized = driver.normalize(process, input_record.content_sha256, effective_limits)
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
                "sandbox_profile_sha256": SANDBOX_PROFILE_SHA256,
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
            finished_at = utc_now()
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
                sandbox_profile_sha256=SANDBOX_PROFILE_SHA256,
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
                    AdapterExecutionManifest.from_result(result).model_dump(mode="json"),
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
        return _AssetContext(stack, {"ghidra_script": script})


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
    matches = [
        Path(path).resolve()
        for path in status.entrypoints
        if Path(path).name.casefold() in names and Path(path).is_file()
    ]
    if len(matches) != 1:
        raise AdapterExecutionError("version probe does not map to exactly one observed entrypoint")
    return matches[0]


def _read_probe_text(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        return ""
    return path.read_bytes()[:16_384].decode("utf-8", errors="replace")


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
    if operation_id == "capa.file-analyze":
        return CapaFileAnalyzePayload(operation_id=operation_id, operating_system="linux")
    if operation_id == "llvm.object-inspect":
        return LlvmObjectInspectPayload(operation_id=operation_id)
    if operation_id == "jadx.android-static-map":
        return JadxAndroidStaticMapPayload(operation_id=operation_id)
    raise AdapterExecutionError(f"operation has no fixed conformance fixture: {operation_id}")


def _conformance_fixture(operation_id: str) -> ConformanceFixture:
    if operation_id in {
        "ghidra.binary-summary",
        "capa.file-analyze",
        "llvm.object-inspect",
    }:
        return ELF_FIXTURE
    if operation_id == "jadx.android-static-map":
        return JADX_FIXTURE
    raise AdapterExecutionError(f"operation has no fixed conformance fixture: {operation_id}")


def _fixture_payload(fixture: ConformanceFixture) -> bytes:
    resource = importlib.resources.files("white_hat_agent").joinpath(
        f"builtin_adapter_fixtures/{fixture.resource_name}"
    )
    encoded = b"".join(resource.read_bytes().split())
    payload = base64.b64decode(encoded, validate=True)
    if hashlib.sha256(payload).hexdigest() != fixture.sha256:
        raise AdapterExecutionError("bundled adapter fixture digest mismatch")
    return payload


def _fixture_bytes() -> bytes:
    return _fixture_payload(ELF_FIXTURE)


def _jadx_fixture_bytes() -> bytes:
    return _fixture_payload(JADX_FIXTURE)


def _ghidra_script_bytes() -> bytes:
    resource = importlib.resources.files("white_hat_agent").joinpath(
        "builtin_adapter_fixtures/WhaBinarySummary.java"
    )
    payload = resource.read_bytes()
    if hashlib.sha256(payload).hexdigest() != GHIDRA_SCRIPT_SHA256:
        raise AdapterExecutionError("bundled Ghidra script digest mismatch")
    return payload


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


def _system_java_home() -> Path:
    java = Path("/usr/bin/java")
    if not java.exists():
        raise AdapterExecutionError("typed Java operation requires system Java")
    java_home = java.resolve(strict=True).parent.parent
    if not java_home.is_dir():
        raise AdapterExecutionError("system Java home is unavailable")
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


def _system_java_mounts() -> tuple[SandboxMount, ...]:
    java_home = _system_java_home()
    return (
        SandboxMount(java_home, "/opt/java"),
        *(SandboxMount(root, root.as_posix()) for root in _system_java_config_roots(java_home)),
    )


def _system_java_payload_digests() -> tuple[str, str]:
    java_home = _system_java_home()
    java_digest = _hash_file_set(
        java_home,
        [
            java_home / "release",
            java_home / "bin/java",
            java_home / "lib/modules",
            java_home / "lib/libjava.so",
            java_home / "lib/libjli.so",
            java_home / "lib/server/libjvm.so",
        ],
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
