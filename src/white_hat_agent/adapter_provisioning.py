from __future__ import annotations

import hashlib
import json
import lzma
import os
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import zipfile
from collections.abc import Mapping
from datetime import date
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Literal, Self
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, quote, unquote, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
from xml.etree import ElementTree

from pydantic import AwareDatetime, Field, field_validator, model_validator

from .adapter_registry import (
    AdapterManager,
    AdapterManifest,
    AdapterRegistryError,
    AdoptiumProvisioner,
    GitCheckoutProvisioner,
    GitHubReleaseProvisioner,
    InstalledAdapterRecord,
    MitreCweProvisioner,
    content_tree_digest,
    current_platform,
    platform_values,
    version_key,
)
from .knowledge.models import Slug
from .models import Sha256, StrictModel, stable_digest, utc_now

_USER_AGENT = "white-hat-agent-adapter-provisioner/1 (+https://github.com/kappa9999/white-hat-agent)"
_MAX_RELEASE_METADATA_BYTES = 4_194_304
_MAX_ARCHIVE_ENTRIES = 100_000
_CWE_VERSION_URL = "https://cwe-api.mitre.org/api/v1/cwe/version"
_CWE_CATALOG_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
_CWE_CATALOG_NAME = "cwec_latest.xml.zip"
_CWE_XML_NAMESPACE = "http://cwe.mitre.org/cwe-7"


class ProvisionAction(StrEnum):
    NONE = "none"
    INSTALL = "install"
    UPDATE = "update"


class ResolvedArtifact(StrictModel):
    name: str = Field(min_length=1)
    url: str = Field(pattern=r"^https://")
    size: int = Field(ge=1)
    sha256: Sha256

    @field_validator("name")
    @classmethod
    def safe_file_name(cls, value: str) -> str:
        if value in {".", ".."} or "/" in value or "\\" in value or ":" in value:
            raise ValueError("release artifact name must be a portable file name")
        return value


class CweCatalogIdentity(StrictModel):
    content_date: date
    total_weaknesses: int = Field(ge=1, le=100_000)
    total_categories: int = Field(ge=1, le=100_000)
    total_views: int = Field(ge=1, le=100_000)


class AdapterProvisionPlan(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    adapter_id: Slug
    manifest_digest: Sha256
    platform: str
    method: Literal["github-release", "adoptium-api", "git-checkout", "mitre-cwe"]
    action: ProvisionAction
    current_version: str | None = None
    target_version: str = Field(min_length=1)
    revision: str = Field(min_length=1)
    source_urls: list[str] = Field(min_length=1)
    artifacts: list[ResolvedArtifact] = Field(default_factory=list)
    entrypoints: list[str] = Field(default_factory=list)
    strip_single_directory: bool = False
    max_download_bytes: int = Field(default=1, ge=1, le=2_147_483_648)
    max_install_bytes: int = Field(default=1, ge=1, le=8_589_934_592)
    cwe_identity: CweCatalogIdentity | None = None
    created_at: AwareDatetime
    blockers: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def valid_plan(self) -> Self:
        if self.method in {"github-release", "adoptium-api", "mitre-cwe"} and not self.artifacts:
            raise ValueError("release plans require resolved artifacts")
        if self.method == "git-checkout" and self.artifacts:
            raise ValueError("git checkout plans do not accept release artifacts")
        if (self.method == "mitre-cwe") != (self.cwe_identity is not None):
            raise ValueError("only MITRE CWE plans require a CWE catalog identity")
        return self

    def digest(self) -> str:
        return stable_digest(self)


class AdapterProvisionResult(StrictModel):
    adapter_id: Slug
    plan_digest: Sha256
    action: ProvisionAction
    changed: bool
    installed: InstalledAdapterRecord | None = None


class AdapterProvisioner:
    def __init__(self, manager: AdapterManager) -> None:
        self.manager = manager

    def plan(self, adapter_id: str) -> AdapterProvisionPlan:
        manifest = self.manager.registry.get(adapter_id)
        definition = manifest.provisioner
        if definition is None:
            raise AdapterRegistryError(f"adapter has no trusted provisioner: {adapter_id}")
        platform = current_platform()
        status = self.manager.status(adapter_id)
        if not status.supported:
            raise AdapterRegistryError(f"adapter does not support current platform: {platform}")
        if isinstance(definition, GitHubReleaseProvisioner):
            requirement_blockers = _provision_requirement_blockers(manifest, status.blockers)
            return self._plan_github(
                manifest,
                definition,
                platform,
                status.version,
                requirement_blockers,
            )
        if isinstance(definition, AdoptiumProvisioner):
            return self._plan_adoptium(
                manifest,
                definition,
                platform,
                status.version,
            )
        if isinstance(definition, GitCheckoutProvisioner):
            return self._plan_git(manifest, definition, platform, status.revision)
        if isinstance(definition, MitreCweProvisioner):
            return self._plan_cwe(manifest, definition, platform, status.version)
        raise AssertionError(f"unsupported provisioner: {type(definition).__name__}")

    def provision(self, plan: AdapterProvisionPlan) -> AdapterProvisionResult:
        manifest = self.manager.registry.get(plan.adapter_id)
        self._validate_plan(plan, manifest)
        if plan.blockers:
            raise AdapterRegistryError("provision plan has blockers: " + "; ".join(plan.blockers))
        if plan.action == ProvisionAction.NONE:
            record = self.manager._installed_record(manifest)
            return AdapterProvisionResult(
                adapter_id=plan.adapter_id,
                plan_digest=plan.digest(),
                action=plan.action,
                changed=False,
                installed=record,
            )
        if plan.method in {"github-release", "adoptium-api", "mitre-cwe"}:
            record = self._provision_archive(plan, manifest)
        else:
            record = self._provision_git(plan, manifest)
        return AdapterProvisionResult(
            adapter_id=plan.adapter_id,
            plan_digest=plan.digest(),
            action=plan.action,
            changed=True,
            installed=record,
        )

    def _plan_github(
        self,
        manifest: AdapterManifest,
        definition: GitHubReleaseProvisioner,
        platform: str,
        current_version: str | None,
        requirement_blockers: list[str],
    ) -> AdapterProvisionPlan:
        patterns = platform_values(definition.asset_patterns, platform)
        if not patterns:
            raise AdapterRegistryError(f"no release asset pattern for {manifest.adapter_id} on {platform}")
        api_url = f"https://api.github.com/repos/{definition.repository}/releases/latest"
        release = _get_json(api_url)
        tag = _required_string(release.get("tag_name"), "release tag")
        assets = release.get("assets")
        if not isinstance(assets, list) or len(assets) > 1_000:
            raise AdapterRegistryError("GitHub release assets are missing or unbounded")
        resolved: list[ResolvedArtifact] = []
        for pattern in patterns:
            matches = [asset for asset in assets if _asset_name_matches(asset, pattern)]
            if len(matches) != 1:
                raise AdapterRegistryError(
                    f"release pattern must match exactly one asset: {pattern!r}; matches={len(matches)}"
                )
            resolved.append(_resolved_asset(matches[0], definition.repository))
        if len({item.name for item in resolved}) != len(resolved):
            raise AdapterRegistryError("release patterns resolved duplicate assets")
        total_size = sum(item.size for item in resolved)
        if total_size > definition.max_download_bytes:
            raise AdapterRegistryError(
                f"release assets total {total_size} bytes; maximum is {definition.max_download_bytes}"
            )
        target_version = _release_version(tag)
        action = ProvisionAction.INSTALL
        if current_version:
            action = (
                ProvisionAction.NONE
                if version_key(current_version) >= version_key(target_version)
                else ProvisionAction.UPDATE
            )
        entrypoints = _resolved_release_entrypoints(definition, platform, target_version)
        return AdapterProvisionPlan(
            adapter_id=manifest.adapter_id,
            manifest_digest=manifest.digest(),
            platform=platform,
            method="github-release",
            action=action,
            current_version=current_version,
            target_version=target_version,
            revision=tag,
            source_urls=[api_url, *[item.url for item in resolved]],
            artifacts=resolved,
            entrypoints=entrypoints,
            strip_single_directory=definition.strip_single_directory,
            max_download_bytes=definition.max_download_bytes,
            max_install_bytes=definition.max_install_bytes,
            created_at=utc_now(),
            blockers=requirement_blockers,
        )

    def _plan_git(
        self,
        manifest: AdapterManifest,
        definition: GitCheckoutProvisioner,
        platform: str,
        current_revision: str | None,
    ) -> AdapterProvisionPlan:
        owner_repo = definition.repository.removeprefix("https://github.com/").removesuffix(".git")
        encoded_ref = quote(definition.ref, safe="")
        api_url = f"https://api.github.com/repos/{owner_repo}/commits/{encoded_ref}"
        payload = _get_json(api_url)
        revision = _required_string(payload.get("sha"), "commit sha").lower()
        if re.fullmatch(r"[0-9a-f]{40}", revision) is None:
            raise AdapterRegistryError("GitHub commit API returned an invalid SHA-1 identity")
        action = (
            ProvisionAction.NONE
            if current_revision == revision
            else (ProvisionAction.UPDATE if current_revision else ProvisionAction.INSTALL)
        )
        return AdapterProvisionPlan(
            adapter_id=manifest.adapter_id,
            manifest_digest=manifest.digest(),
            platform=platform,
            method="git-checkout",
            action=action,
            current_version=current_revision[:12] if current_revision else None,
            target_version=revision[:12],
            revision=revision,
            source_urls=[definition.repository, api_url],
            max_download_bytes=definition.max_checkout_bytes,
            max_install_bytes=definition.max_checkout_bytes,
            created_at=utc_now(),
        )

    def _plan_adoptium(
        self,
        manifest: AdapterManifest,
        definition: AdoptiumProvisioner,
        platform: str,
        current_version: str | None,
    ) -> AdapterProvisionPlan:
        api_url = _adoptium_api_url(definition, platform)
        payload = _get_adoptium_json(api_url)
        if len(payload) != 1:
            raise AdapterRegistryError(
                f"Adoptium API must resolve exactly one package; matches={len(payload)}"
            )
        release = payload[0]
        revision = _required_string(release.get("release_name"), "Adoptium release name")
        artifact = _resolved_adoptium_artifact(release, definition, platform)
        if artifact.size > definition.max_download_bytes:
            raise AdapterRegistryError(
                f"Adoptium package is {artifact.size} bytes; maximum is {definition.max_download_bytes}"
            )
        target_version = _adoptium_version(revision)
        if version_key(target_version)[0] != definition.feature_version:
            raise AdapterRegistryError("Adoptium API returned a different feature version")
        action = ProvisionAction.INSTALL
        if current_version:
            action = (
                ProvisionAction.NONE
                if version_key(current_version) >= version_key(target_version)
                else ProvisionAction.UPDATE
            )
        entrypoints = _resolved_release_entrypoints(definition, platform, target_version)
        return AdapterProvisionPlan(
            adapter_id=manifest.adapter_id,
            manifest_digest=manifest.digest(),
            platform=platform,
            method="adoptium-api",
            action=action,
            current_version=current_version,
            target_version=target_version,
            revision=revision,
            source_urls=[api_url, artifact.url],
            artifacts=[artifact],
            entrypoints=entrypoints,
            strip_single_directory=definition.strip_single_directory,
            max_download_bytes=definition.max_download_bytes,
            max_install_bytes=definition.max_install_bytes,
            created_at=utc_now(),
        )

    def _plan_cwe(
        self,
        manifest: AdapterManifest,
        definition: MitreCweProvisioner,
        platform: str,
        current_version: str | None,
    ) -> AdapterProvisionPlan:
        release = _get_cwe_version_json(_CWE_VERSION_URL)
        target_version = _required_cwe_version(release.get("ContentVersion"))
        identity = CweCatalogIdentity(
            content_date=_required_cwe_date(release.get("ContentDate")),
            total_weaknesses=_required_cwe_count(release.get("TotalWeaknesses"), "weaknesses"),
            total_categories=_required_cwe_count(release.get("TotalCategories"), "categories"),
            total_views=_required_cwe_count(release.get("TotalViews"), "views"),
        )
        artifact = _resolve_cwe_artifact(definition.max_download_bytes)
        action = ProvisionAction.INSTALL
        if current_version:
            action = (
                ProvisionAction.NONE
                if version_key(current_version) >= version_key(target_version)
                else ProvisionAction.UPDATE
            )
        return AdapterProvisionPlan(
            adapter_id=manifest.adapter_id,
            manifest_digest=manifest.digest(),
            platform=platform,
            method="mitre-cwe",
            action=action,
            current_version=current_version,
            target_version=target_version,
            revision=f"cwe-{target_version}@{identity.content_date.isoformat()}",
            source_urls=[_CWE_VERSION_URL, _CWE_CATALOG_URL],
            artifacts=[artifact],
            strip_single_directory=False,
            max_download_bytes=definition.max_download_bytes,
            max_install_bytes=definition.max_install_bytes,
            cwe_identity=identity,
            created_at=utc_now(),
        )

    def _validate_plan(self, plan: AdapterProvisionPlan, manifest: AdapterManifest) -> None:
        if plan.manifest_digest != manifest.digest():
            raise AdapterRegistryError("provision plan does not match the current adapter manifest")
        if plan.platform != current_platform():
            raise AdapterRegistryError("provision plan platform does not match the current host")
        definition = manifest.provisioner
        if definition is None or plan.method != definition.kind:
            raise AdapterRegistryError("provision plan method does not match the adapter manifest")
        current = self.manager.status(plan.adapter_id)
        if isinstance(definition, GitHubReleaseProvisioner):
            if plan.target_version != _release_version(plan.revision):
                raise AdapterRegistryError("provision plan version does not match its release revision")
            patterns = platform_values(definition.asset_patterns, plan.platform) or []
            if len(plan.artifacts) != len(patterns) or any(
                re.fullmatch(pattern, artifact.name) is None
                for pattern, artifact in zip(patterns, plan.artifacts, strict=True)
            ):
                raise AdapterRegistryError("provision plan artifacts do not match the adapter manifest")
            if len({artifact.name for artifact in plan.artifacts}) != len(plan.artifacts):
                raise AdapterRegistryError("provision plan contains duplicate release artifacts")
            if sum(artifact.size for artifact in plan.artifacts) > definition.max_download_bytes:
                raise AdapterRegistryError("provision plan exceeds the manifest download bound")
            expected_entries = _resolved_release_entrypoints(
                definition,
                plan.platform,
                plan.target_version,
            )
            if plan.entrypoints != expected_entries:
                raise AdapterRegistryError("provision plan entrypoints do not match the adapter manifest")
            if plan.strip_single_directory != definition.strip_single_directory:
                raise AdapterRegistryError("provision plan extraction layout does not match the manifest")
            if plan.max_download_bytes != definition.max_download_bytes:
                raise AdapterRegistryError("provision plan download bound does not match the manifest")
            if plan.max_install_bytes != definition.max_install_bytes:
                raise AdapterRegistryError("provision plan install bound does not match the manifest")
            for artifact in plan.artifacts:
                _validate_release_asset_url(artifact.url, definition.repository)
                parsed_path = urlsplit(artifact.url).path
                release_prefix = f"/{definition.repository}/releases/download/"
                release_path = parsed_path.removeprefix(release_prefix)
                encoded_revision, separator, encoded_name = release_path.partition("/")
                if (
                    not separator
                    or unquote(encoded_revision) != plan.revision
                    or unquote(encoded_name) != artifact.name
                ):
                    raise AdapterRegistryError("provision plan artifact identity does not match its URL")
            api_url = f"https://api.github.com/repos/{definition.repository}/releases/latest"
            if plan.source_urls != [api_url, *[artifact.url for artifact in plan.artifacts]]:
                raise AdapterRegistryError("provision plan sources do not match the resolved artifacts")
        elif isinstance(definition, AdoptiumProvisioner):
            if len(plan.artifacts) != 1:
                raise AdapterRegistryError("Adoptium plans require exactly one package")
            if plan.target_version != _adoptium_version(plan.revision):
                raise AdapterRegistryError("Adoptium plan version does not match its release")
            if version_key(plan.target_version)[0] != definition.feature_version:
                raise AdapterRegistryError("Adoptium plan has a different feature version")
            expected_entries = _resolved_release_entrypoints(
                definition,
                plan.platform,
                plan.target_version,
            )
            if plan.entrypoints != expected_entries:
                raise AdapterRegistryError("Adoptium plan entrypoints do not match the manifest")
            if plan.strip_single_directory != definition.strip_single_directory:
                raise AdapterRegistryError("Adoptium plan extraction layout does not match the manifest")
            if (
                plan.max_download_bytes != definition.max_download_bytes
                or plan.max_install_bytes != definition.max_install_bytes
                or plan.artifacts[0].size > definition.max_download_bytes
            ):
                raise AdapterRegistryError("Adoptium plan exceeds the manifest bounds")
            _validate_release_asset_url(
                plan.artifacts[0].url,
                "adoptium/temurin21-binaries",
            )
            release_path = urlsplit(plan.artifacts[0].url).path.removeprefix(
                "/adoptium/temurin21-binaries/releases/download/"
            )
            encoded_revision, separator, encoded_name = release_path.partition("/")
            if (
                not separator
                or unquote(encoded_revision) != plan.revision
                or unquote(encoded_name) != plan.artifacts[0].name
            ):
                raise AdapterRegistryError("Adoptium package URL does not match its release")
            api_url = _adoptium_api_url(definition, plan.platform)
            if plan.source_urls != [api_url, plan.artifacts[0].url]:
                raise AdapterRegistryError("Adoptium plan sources do not match the manifest")
        elif isinstance(definition, GitCheckoutProvisioner):
            owner_repo = definition.repository.removeprefix("https://github.com/").removesuffix(".git")
            encoded_ref = quote(definition.ref, safe="")
            api_url = f"https://api.github.com/repos/{owner_repo}/commits/{encoded_ref}"
            if plan.source_urls != [definition.repository, api_url]:
                raise AdapterRegistryError("provision plan repository does not match the manifest")
            if re.fullmatch(r"[0-9a-f]{40}", plan.revision) is None:
                raise AdapterRegistryError("provision plan has an invalid git revision")
            if plan.target_version != plan.revision[:12]:
                raise AdapterRegistryError("provision plan version does not match its git revision")
            if (
                plan.max_download_bytes != definition.max_checkout_bytes
                or plan.max_install_bytes != definition.max_checkout_bytes
            ):
                raise AdapterRegistryError("provision plan checkout bounds do not match the manifest")
        elif isinstance(definition, MitreCweProvisioner):
            if plan.cwe_identity is None or len(plan.artifacts) != 1:
                raise AdapterRegistryError("MITRE CWE plans require one catalog and its identity")
            expected_revision = f"cwe-{plan.target_version}@{plan.cwe_identity.content_date.isoformat()}"
            if plan.revision != expected_revision:
                raise AdapterRegistryError("MITRE CWE plan version does not match its catalog identity")
            artifact = plan.artifacts[0]
            if artifact.name != _CWE_CATALOG_NAME or artifact.url != _CWE_CATALOG_URL:
                raise AdapterRegistryError("MITRE CWE plan does not reference the canonical catalog")
            if (
                artifact.size > definition.max_download_bytes
                or plan.max_download_bytes != definition.max_download_bytes
                or plan.max_install_bytes != definition.max_install_bytes
            ):
                raise AdapterRegistryError("MITRE CWE plan exceeds the manifest bounds")
            if plan.entrypoints or plan.strip_single_directory:
                raise AdapterRegistryError("MITRE CWE plan has an invalid extraction layout")
            if plan.source_urls != [_CWE_VERSION_URL, _CWE_CATALOG_URL]:
                raise AdapterRegistryError("MITRE CWE plan sources do not match the canonical catalog")
        expected_current = current.revision if plan.method == "git-checkout" else current.version
        serialized_current = (
            expected_current[:12] if plan.method == "git-checkout" and expected_current else expected_current
        )
        if plan.current_version != serialized_current:
            raise AdapterRegistryError("provision plan is stale for the current adapter state")
        expected_action = ProvisionAction.INSTALL
        if expected_current:
            if plan.method == "git-checkout":
                expected_action = (
                    ProvisionAction.NONE if expected_current == plan.revision else ProvisionAction.UPDATE
                )
            else:
                expected_action = (
                    ProvisionAction.NONE
                    if version_key(expected_current) >= version_key(plan.target_version)
                    else ProvisionAction.UPDATE
                )
        if plan.action != expected_action:
            raise AdapterRegistryError("provision plan action is stale for the current adapter state")
        expected_blockers = _provision_requirement_blockers(manifest, current.blockers)
        if plan.blockers != expected_blockers:
            raise AdapterRegistryError("provision plan blockers are stale for the current host")

    def _provision_archive(
        self,
        plan: AdapterProvisionPlan,
        manifest: AdapterManifest,
    ) -> InstalledAdapterRecord:
        temporary_root = self._temporary_adapter_root(plan.adapter_id)
        try:
            downloads = temporary_root / "downloads"
            content = temporary_root / "content"
            downloads.mkdir()
            content.mkdir()
            downloaded: list[Path] = []
            for artifact in plan.artifacts:
                destination = downloads / artifact.name
                if plan.method == "mitre-cwe":
                    _download_cwe_artifact(
                        artifact,
                        destination,
                        max_bytes=plan.max_download_bytes,
                    )
                else:
                    _download_artifact(artifact, destination, max_bytes=plan.max_download_bytes)
                downloaded.append(destination)
            _materialize_assets(
                downloaded,
                content,
                strip_single_directory=plan.strip_single_directory,
                max_install_bytes=plan.max_install_bytes,
            )
            if plan.method == "mitre-cwe":
                if plan.cwe_identity is None:
                    raise AdapterRegistryError("MITRE CWE plan is missing its catalog identity")
                _validate_cwe_snapshot(
                    content,
                    version=plan.target_version,
                    identity=plan.cwe_identity,
                )
            for relative in plan.entrypoints:
                entrypoint = content / relative
                if not entrypoint.is_file() or entrypoint.is_symlink():
                    raise AdapterRegistryError(f"release is missing declared entrypoint: {relative}")
                if os.name != "nt":
                    entrypoint.chmod(entrypoint.stat().st_mode | stat.S_IXUSR)
            shutil.rmtree(downloads)
            record = InstalledAdapterRecord(
                adapter_id=plan.adapter_id,
                manifest_digest=manifest.digest(),
                version=plan.target_version,
                revision=plan.revision,
                source_urls=plan.source_urls,
                artifact_sha256=[item.sha256 for item in plan.artifacts],
                content_sha256=content_tree_digest(
                    content,
                    max_bytes=plan.max_install_bytes,
                ),
                entrypoints=plan.entrypoints,
                installed_at=utc_now(),
            )
            (temporary_root / "installed.json").write_text(
                record.model_dump_json(indent=2) + "\n", encoding="utf-8"
            )
            self._activate(temporary_root, plan.adapter_id)
            return record
        except BaseException:
            shutil.rmtree(temporary_root, ignore_errors=True)
            raise

    def _provision_git(
        self,
        plan: AdapterProvisionPlan,
        manifest: AdapterManifest,
    ) -> InstalledAdapterRecord:
        git = shutil.which("git")
        if not git:
            raise AdapterRegistryError("git is required to provision this adapter")
        temporary_root = self._temporary_adapter_root(plan.adapter_id)
        content = temporary_root / "content"
        environment = {
            **{key: value for key, value in os.environ.items() if not key.startswith("GIT_")},
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
        }
        common = [
            git,
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "protocol.file.allow=never",
            "-c",
            "http.followRedirects=false",
        ]
        try:
            content.mkdir()
            _run_git([*common, "init", "--quiet", str(content)], environment)
            _run_git(
                [*common, "-C", str(content), "remote", "add", "origin", plan.source_urls[0]],
                environment,
            )
            _run_git(
                [
                    *common,
                    "-C",
                    str(content),
                    "fetch",
                    "--quiet",
                    "--depth=1",
                    "--no-tags",
                    "origin",
                    plan.revision,
                ],
                environment,
            )
            _run_git(
                [*common, "-C", str(content), "checkout", "--quiet", "--detach", "FETCH_HEAD"],
                environment,
            )
            observed = _run_git([*common, "-C", str(content), "rev-parse", "HEAD"], environment).strip()
            if observed != plan.revision:
                raise AdapterRegistryError("git checkout identity does not match the provision plan")
            checkout_bytes = _tree_size(content)
            if checkout_bytes > plan.max_install_bytes:
                raise AdapterRegistryError(
                    f"git checkout is {checkout_bytes} bytes; maximum is {plan.max_install_bytes}"
                )
            shutil.rmtree(content / ".git")
            record = InstalledAdapterRecord(
                adapter_id=plan.adapter_id,
                manifest_digest=manifest.digest(),
                version=plan.target_version,
                revision=plan.revision,
                source_urls=plan.source_urls,
                content_sha256=content_tree_digest(
                    content,
                    max_bytes=plan.max_install_bytes,
                ),
                installed_at=utc_now(),
            )
            (temporary_root / "installed.json").write_text(
                record.model_dump_json(indent=2) + "\n", encoding="utf-8"
            )
            self._activate(temporary_root, plan.adapter_id)
            return record
        except BaseException:
            shutil.rmtree(temporary_root, ignore_errors=True)
            raise

    def _temporary_adapter_root(self, adapter_id: str) -> Path:
        self.manager.managed_root.mkdir(parents=True, exist_ok=True)
        return Path(tempfile.mkdtemp(prefix=f".{adapter_id}-", dir=self.manager.managed_root))

    def _activate(self, temporary_root: Path, adapter_id: str) -> None:
        destination = self.manager.managed_root / adapter_id
        backup = self.manager.managed_root / f".{adapter_id}.previous"
        if backup.exists():
            shutil.rmtree(backup)
        try:
            if destination.exists():
                os.replace(destination, backup)
            os.replace(temporary_root, destination)
        except BaseException:
            if not destination.exists() and backup.exists():
                os.replace(backup, destination)
            raise
        shutil.rmtree(backup, ignore_errors=True)


def _get_json(url: str) -> dict[str, object]:
    _validate_github_api_url(url)
    headers = {"Accept": "application/vnd.github+json", "User-Agent": _USER_AGENT}
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = Request(url, headers=headers, method="GET")
    try:
        with build_opener(_GitHubApiRedirectHandler()).open(request, timeout=30) as response:
            content_length = response.headers.get("Content-Length")
            if content_length and int(content_length) > _MAX_RELEASE_METADATA_BYTES:
                raise AdapterRegistryError("GitHub API response exceeds metadata byte limit")
            body = response.read(_MAX_RELEASE_METADATA_BYTES + 1)
    except (HTTPError, URLError, OSError, ValueError) as exc:
        raise AdapterRegistryError(f"GitHub API request failed: {type(exc).__name__}") from exc
    if len(body) > _MAX_RELEASE_METADATA_BYTES:
        raise AdapterRegistryError("GitHub API response exceeds metadata byte limit")
    try:
        payload = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AdapterRegistryError("GitHub API returned invalid JSON") from exc
    if not isinstance(payload, dict):
        raise AdapterRegistryError("GitHub API response must be an object")
    return payload


def _get_adoptium_json(url: str) -> list[dict[str, object]]:
    _validate_adoptium_api_url(url)
    request = Request(
        url,
        headers={"Accept": "application/json", "User-Agent": _USER_AGENT},
        method="GET",
    )
    try:
        with build_opener(_AdoptiumApiRedirectHandler()).open(request, timeout=30) as response:
            content_length = response.headers.get("Content-Length")
            if content_length and int(content_length) > _MAX_RELEASE_METADATA_BYTES:
                raise AdapterRegistryError("Adoptium API response exceeds metadata byte limit")
            body = response.read(_MAX_RELEASE_METADATA_BYTES + 1)
    except (HTTPError, URLError, OSError, ValueError) as exc:
        raise AdapterRegistryError(f"Adoptium API request failed: {type(exc).__name__}") from exc
    if len(body) > _MAX_RELEASE_METADATA_BYTES:
        raise AdapterRegistryError("Adoptium API response exceeds metadata byte limit")
    try:
        payload = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AdapterRegistryError("Adoptium API returned invalid JSON") from exc
    if (
        not isinstance(payload, list)
        or len(payload) > 10
        or any(not isinstance(item, dict) for item in payload)
    ):
        raise AdapterRegistryError("Adoptium API response must be a bounded object list")
    return payload


def _get_cwe_version_json(url: str) -> dict[str, object]:
    _validate_cwe_url(url, expected=_CWE_VERSION_URL)
    request = Request(
        url,
        headers={"Accept": "application/json", "User-Agent": _USER_AGENT},
        method="GET",
    )
    try:
        with build_opener(_CweRedirectHandler()).open(request, timeout=30) as response:
            content_length = response.headers.get("Content-Length")
            if content_length and int(content_length) > _MAX_RELEASE_METADATA_BYTES:
                raise AdapterRegistryError("MITRE CWE version response exceeds metadata byte limit")
            body = response.read(_MAX_RELEASE_METADATA_BYTES + 1)
    except (HTTPError, URLError, OSError, ValueError) as exc:
        raise AdapterRegistryError(f"MITRE CWE version request failed: {type(exc).__name__}") from exc
    if len(body) > _MAX_RELEASE_METADATA_BYTES:
        raise AdapterRegistryError("MITRE CWE version response exceeds metadata byte limit")
    try:
        payload = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AdapterRegistryError("MITRE CWE version endpoint returned invalid JSON") from exc
    if not isinstance(payload, dict):
        raise AdapterRegistryError("MITRE CWE version response must be an object")
    return payload


def _resolve_cwe_artifact(max_bytes: int) -> ResolvedArtifact:
    size, digest = _stream_cwe_catalog(max_bytes=max_bytes)
    return ResolvedArtifact(
        name=_CWE_CATALOG_NAME,
        url=_CWE_CATALOG_URL,
        size=size,
        sha256=digest,
    )


def _download_cwe_artifact(
    artifact: ResolvedArtifact,
    destination: Path,
    *,
    max_bytes: int,
) -> None:
    if artifact.name != _CWE_CATALOG_NAME or artifact.url != _CWE_CATALOG_URL:
        raise AdapterRegistryError("MITRE CWE artifact is not the canonical catalog")
    try:
        size, digest = _stream_cwe_catalog(max_bytes=max_bytes, destination=destination)
    except BaseException:
        destination.unlink(missing_ok=True)
        raise
    if size != artifact.size:
        destination.unlink(missing_ok=True)
        raise AdapterRegistryError("MITRE CWE catalog size changed after planning")
    if digest != artifact.sha256:
        destination.unlink(missing_ok=True)
        raise AdapterRegistryError("MITRE CWE catalog digest changed after planning")


def _stream_cwe_catalog(
    *,
    max_bytes: int,
    destination: Path | None = None,
) -> tuple[int, str]:
    _validate_cwe_url(_CWE_CATALOG_URL, expected=_CWE_CATALOG_URL)
    request = Request(
        _CWE_CATALOG_URL,
        headers={"Accept": "application/zip", "User-Agent": _USER_AGENT},
        method="GET",
    )
    digest = hashlib.sha256()
    received = 0
    output = None
    try:
        if destination is not None:
            output = destination.open("xb")
        with build_opener(_CweRedirectHandler()).open(request, timeout=60) as response:
            content_length = response.headers.get("Content-Length")
            if content_length:
                declared = int(content_length)
                if declared < 1 or declared > max_bytes:
                    raise AdapterRegistryError("MITRE CWE catalog exceeds its download byte limit")
            while chunk := response.read(1_048_576):
                received += len(chunk)
                if received > max_bytes:
                    raise AdapterRegistryError("MITRE CWE catalog exceeds its download byte limit")
                digest.update(chunk)
                if output is not None:
                    output.write(chunk)
        if received < 1:
            raise AdapterRegistryError("MITRE CWE catalog download was empty")
        if output is not None:
            output.flush()
            os.fsync(output.fileno())
    except (HTTPError, URLError, OSError, ValueError) as exc:
        raise AdapterRegistryError(f"MITRE CWE catalog request failed: {type(exc).__name__}") from exc
    finally:
        if output is not None:
            output.close()
    return received, digest.hexdigest()


def _validate_cwe_snapshot(
    content: Path,
    *,
    version: str,
    identity: CweCatalogIdentity,
) -> None:
    expected = content / f"cwec_v{version}.xml"
    files = [path for path in content.rglob("*") if path.is_file()]
    if files != [expected] or expected.is_symlink():
        raise AdapterRegistryError("MITRE CWE archive must contain exactly its versioned XML catalog")
    namespace = f"{{{_CWE_XML_NAMESPACE}}}"
    expected_tags = {
        f"{namespace}Weakness": "Weakness",
        f"{namespace}Category": "Category",
        f"{namespace}View": "View",
    }
    counts = {name: 0 for name in expected_tags.values()}
    try:
        events = ElementTree.iterparse(expected, events=("start", "end"))
        _, root = next(events)
        root_tag = root.tag
        root_attributes = dict(root.attrib)
        for event, element in events:
            if event == "start":
                record_type = expected_tags.get(element.tag)
                if record_type is not None:
                    counts[record_type] += 1
            else:
                element.clear()
    except (ElementTree.ParseError, OSError, StopIteration) as exc:
        raise AdapterRegistryError("MITRE CWE catalog XML is invalid") from exc
    if root_tag != f"{namespace}Weakness_Catalog" or root_attributes.get("Name") != "CWE":
        raise AdapterRegistryError("MITRE CWE catalog has an unexpected XML identity")
    if (
        root_attributes.get("Version") != version
        or root_attributes.get("Date") != identity.content_date.isoformat()
    ):
        raise AdapterRegistryError("MITRE CWE catalog version does not match its plan")
    expected_counts = {
        "Weakness": identity.total_weaknesses,
        "Category": identity.total_categories,
        "View": identity.total_views,
    }
    if counts != expected_counts:
        raise AdapterRegistryError(
            "MITRE CWE catalog counts do not match its version endpoint: "
            f"observed={counts}; expected={expected_counts}"
        )


def _required_cwe_version(value: object) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9]+\.[0-9]+(?:\.[0-9]+)?", value) is None:
        raise AdapterRegistryError("MITRE CWE version endpoint returned an invalid content version")
    return value


def _required_cwe_date(value: object) -> date:
    if not isinstance(value, str) or re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value) is None:
        raise AdapterRegistryError("MITRE CWE version endpoint returned an invalid content date")
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise AdapterRegistryError("MITRE CWE version endpoint returned an invalid content date") from exc


def _required_cwe_count(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1 or value > 100_000:
        raise AdapterRegistryError(f"MITRE CWE version endpoint returned an invalid {label} count")
    return value


def _asset_name_matches(asset: object, pattern: str) -> bool:
    return (
        isinstance(asset, dict)
        and isinstance(asset.get("name"), str)
        and re.fullmatch(pattern, asset["name"]) is not None
    )


def _resolved_asset(asset: object, repository: str) -> ResolvedArtifact:
    if not isinstance(asset, dict):
        raise AdapterRegistryError("GitHub release asset must be an object")
    name = _required_string(asset.get("name"), "asset name")
    url = _required_string(asset.get("browser_download_url"), "asset URL")
    _validate_release_asset_url(url, repository)
    size = asset.get("size")
    if isinstance(size, bool) or not isinstance(size, int) or size < 1:
        raise AdapterRegistryError("GitHub release asset has invalid size")
    digest = _required_string(asset.get("digest"), "asset digest")
    if re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
        raise AdapterRegistryError("GitHub release asset lacks a SHA-256 digest")
    return ResolvedArtifact(name=name, url=url, size=size, sha256=digest.removeprefix("sha256:"))


def _resolved_adoptium_artifact(
    release: dict[str, object],
    definition: AdoptiumProvisioner,
    platform: str,
) -> ResolvedArtifact:
    os_name, architecture = _adoptium_coordinates(platform)
    binary = release.get("binary")
    if not isinstance(binary, dict):
        raise AdapterRegistryError("Adoptium release is missing binary metadata")
    expected = {
        "architecture": architecture,
        "os": os_name,
        "image_type": definition.image_type,
        "jvm_impl": definition.jvm_impl,
    }
    if any(binary.get(key) != value for key, value in expected.items()):
        raise AdapterRegistryError("Adoptium binary metadata does not match the requested runtime")
    package = binary.get("package")
    if not isinstance(package, dict):
        raise AdapterRegistryError("Adoptium release is missing package metadata")
    name = _required_string(package.get("name"), "Adoptium package name")
    url = _required_string(package.get("link"), "Adoptium package URL")
    _validate_release_asset_url(url, "adoptium/temurin21-binaries")
    if unquote(urlsplit(url).path.rsplit("/", 1)[-1]) != name:
        raise AdapterRegistryError("Adoptium package name does not match its URL")
    size = package.get("size")
    if isinstance(size, bool) or not isinstance(size, int) or size < 1:
        raise AdapterRegistryError("Adoptium package has invalid size")
    digest = _required_string(package.get("checksum"), "Adoptium package checksum").lower()
    if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise AdapterRegistryError("Adoptium package lacks a valid SHA-256 checksum")
    return ResolvedArtifact(name=name, url=url, size=size, sha256=digest)


def _download_artifact(artifact: ResolvedArtifact, destination: Path, *, max_bytes: int) -> None:
    _validate_release_asset_url(artifact.url, None)
    request = Request(artifact.url, headers={"User-Agent": _USER_AGENT}, method="GET")
    opener = build_opener(_ReleaseAssetRedirectHandler())
    digest = hashlib.sha256()
    received = 0
    try:
        with opener.open(request, timeout=60) as response, destination.open("xb") as handle:
            while chunk := response.read(1_048_576):
                received += len(chunk)
                if received > max_bytes or received > artifact.size:
                    raise AdapterRegistryError("release asset exceeds its declared byte bound")
                digest.update(chunk)
                handle.write(chunk)
            handle.flush()
            os.fsync(handle.fileno())
    except (HTTPError, URLError, OSError) as exc:
        destination.unlink(missing_ok=True)
        raise AdapterRegistryError(f"release asset download failed: {type(exc).__name__}") from exc
    if received != artifact.size:
        destination.unlink(missing_ok=True)
        raise AdapterRegistryError("release asset size does not match GitHub metadata")
    if digest.hexdigest() != artifact.sha256:
        destination.unlink(missing_ok=True)
        raise AdapterRegistryError("release asset SHA-256 does not match GitHub metadata")


def _materialize_assets(
    assets: list[Path],
    destination: Path,
    *,
    strip_single_directory: bool,
    max_install_bytes: int,
) -> None:
    extracted = 0
    entries = 0
    for asset in assets:
        lower = asset.name.casefold()
        if lower.endswith(".zip"):
            with zipfile.ZipFile(asset) as archive:
                for item in archive.infolist():
                    entries += 1
                    extracted += item.file_size
                    _check_archive_bounds(entries, extracted, max_install_bytes)
                    _extract_zip_item(archive, item, destination)
        elif lower.endswith((".tar.gz", ".tgz", ".tar.xz", ".txz", ".tar")):
            with tarfile.open(asset, mode="r:*") as archive:
                for item in archive:
                    entries += 1
                    extracted += max(item.size, 0)
                    _check_archive_bounds(entries, extracted, max_install_bytes)
                    _extract_tar_item(archive, item, destination)
        elif lower.endswith(".xz"):
            entries += 1
            _check_archive_bounds(entries, extracted, max_install_bytes)
            output_name = asset.name[:-3]
            relative = _safe_archive_path(output_name)
            if relative is None or len(relative.parts) != 1:
                raise AdapterRegistryError("compressed release asset has an unsafe output name")
            target = destination / relative.name
            if target.exists():
                raise AdapterRegistryError(f"release assets collide at {relative.name}")
            try:
                with lzma.open(asset, mode="rb") as source, target.open("xb") as output:
                    while chunk := source.read(1_048_576):
                        extracted += len(chunk)
                        _check_archive_bounds(entries, extracted, max_install_bytes)
                        output.write(chunk)
            except (lzma.LZMAError, OSError) as exc:
                target.unlink(missing_ok=True)
                raise AdapterRegistryError(
                    f"compressed release asset could not be materialized: {type(exc).__name__}"
                ) from exc
        else:
            entries += 1
            extracted += asset.stat().st_size
            _check_archive_bounds(entries, extracted, max_install_bytes)
            target = destination / asset.name
            if target.exists():
                raise AdapterRegistryError(f"release assets collide at {asset.name}")
            shutil.copyfile(asset, target)
    if strip_single_directory:
        children = list(destination.iterdir())
        if len(children) == 1 and children[0].is_dir() and not children[0].is_symlink():
            root = children[0]
            temporary = destination.parent / ".stripped"
            os.replace(root, temporary)
            destination.rmdir()
            os.replace(temporary, destination)


def _extract_zip_item(archive: zipfile.ZipFile, item: zipfile.ZipInfo, destination: Path) -> None:
    relative = _safe_archive_path(item.filename)
    if relative is None:
        return
    mode = (item.external_attr >> 16) & 0xFFFF
    if stat.S_ISLNK(mode):
        raise AdapterRegistryError("release archive contains a symbolic link")
    target = destination.joinpath(*relative.parts)
    if item.is_dir():
        target.mkdir(parents=True, exist_ok=True)
        return
    if target.exists():
        raise AdapterRegistryError(f"release archive contains duplicate path: {relative}")
    target.parent.mkdir(parents=True, exist_ok=True)
    with archive.open(item) as source, target.open("xb") as output:
        shutil.copyfileobj(source, output, length=1_048_576)
    if mode:
        target.chmod(mode & 0o777)


def _extract_tar_item(archive: tarfile.TarFile, item: tarfile.TarInfo, destination: Path) -> None:
    relative = _safe_archive_path(item.name)
    if relative is None:
        return
    if item.issym() or item.islnk() or item.isdev() or item.isfifo():
        raise AdapterRegistryError("release archive contains a link or special file")
    target = destination.joinpath(*relative.parts)
    if item.isdir():
        target.mkdir(parents=True, exist_ok=True)
        return
    if not item.isfile():
        return
    if target.exists():
        raise AdapterRegistryError(f"release archive contains duplicate path: {relative}")
    source = archive.extractfile(item)
    if source is None:
        raise AdapterRegistryError(f"release archive cannot read file: {relative}")
    target.parent.mkdir(parents=True, exist_ok=True)
    with source, target.open("xb") as output:
        shutil.copyfileobj(source, output, length=1_048_576)
    target.chmod(item.mode & 0o777)


def _safe_archive_path(value: str) -> PurePosixPath | None:
    normalized = value.replace("\\", "/")
    if normalized in {"", "."}:
        return None
    path = PurePosixPath(normalized)
    if path.is_absolute() or ".." in path.parts or any(":" in part for part in path.parts):
        raise AdapterRegistryError("release archive path escapes the install root")
    return path


def _check_archive_bounds(entries: int, extracted: int, maximum: int) -> None:
    if entries > _MAX_ARCHIVE_ENTRIES:
        raise AdapterRegistryError("release archive exceeds entry-count limit")
    if extracted > maximum:
        raise AdapterRegistryError("release archive exceeds extracted-byte limit")


def _run_git(command: list[str], environment: Mapping[str, str]) -> str:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=300,
            env=environment,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise AdapterRegistryError(f"git command failed: {type(exc).__name__}") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()[:2_000]
        raise AdapterRegistryError(f"git command failed with exit {result.returncode}: {detail}")
    return result.stdout


def _tree_size(root: Path) -> int:
    total = 0
    for entries, path in enumerate(root.rglob("*"), start=1):
        if entries > _MAX_ARCHIVE_ENTRIES:
            raise AdapterRegistryError("git checkout exceeds entry-count limit")
        if path.is_symlink():
            raise AdapterRegistryError("git checkout contains a symbolic link")
        if path.is_file():
            total += path.stat().st_size
    return total


def _required_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AdapterRegistryError(f"GitHub response is missing {label}")
    return value.strip()


def _provision_requirement_blockers(
    manifest: AdapterManifest,
    blockers: list[str],
) -> list[str]:
    retained: list[str] = []
    for blocker in blockers:
        match = re.fullmatch(r"runtime requirement ([0-9]+)(?: .*)?", blocker)
        if match is None:
            continue
        index = int(match.group(1)) - 1
        if index < 0 or index >= len(manifest.requirements):
            retained.append(blocker)
            continue
        if manifest.requirements[index].managed_adapter_id is None:
            retained.append(blocker)
    return retained


def _adoptium_coordinates(platform: str) -> tuple[str, str]:
    try:
        return {
            "linux-x86_64": ("linux", "x64"),
            "linux-arm64": ("linux", "aarch64"),
            "macos-x86_64": ("mac", "x64"),
            "macos-arm64": ("mac", "aarch64"),
            "windows-x86_64": ("windows", "x64"),
            "windows-arm64": ("windows", "aarch64"),
        }[platform]
    except KeyError as exc:
        raise AdapterRegistryError(f"Adoptium does not support current platform: {platform}") from exc


def _adoptium_api_url(definition: AdoptiumProvisioner, platform: str) -> str:
    os_name, architecture = _adoptium_coordinates(platform)
    query = urlencode(
        {
            "architecture": architecture,
            "heap_size": "normal",
            "image_type": definition.image_type,
            "os": os_name,
            "vendor": definition.vendor,
        }
    )
    return (
        f"https://api.adoptium.net/v3/assets/latest/{definition.feature_version}/"
        f"{definition.jvm_impl}?{query}"
    )


def _resolved_release_entrypoints(
    definition: GitHubReleaseProvisioner | AdoptiumProvisioner,
    platform: str,
    target_version: str,
) -> list[str]:
    templates = platform_values(definition.entrypoints, platform) or []
    if (
        any("{version}" in value for value in templates)
        and re.fullmatch(
            r"[0-9]+(?:\.[0-9]+)+",
            target_version,
        )
        is None
    ):
        raise AdapterRegistryError("release version cannot be used in an entrypoint path")
    resolved = [value.replace("{version}", target_version) for value in templates]
    for value in resolved:
        path = Path(value)
        if path.is_absolute() or ".." in path.parts:
            raise AdapterRegistryError("resolved adapter entrypoint escapes the install root")
    return resolved


def _release_version(tag: str) -> str:
    match = re.search(r"\d+(?:\.\d+)+", tag)
    return match.group(0) if match else tag


def _adoptium_version(release_name: str) -> str:
    match = re.fullmatch(r"jdk-(?P<version>[0-9]+(?:\.[0-9]+)*(?:\+[0-9]+)?)", release_name)
    if match is None:
        raise AdapterRegistryError("Adoptium release has an unexpected version identity")
    return match.group("version")


def _validate_github_api_url(url: str) -> None:
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "api.github.com"
        or parsed.username
        or parsed.password
        or parsed.fragment
        or parsed.query
        or re.fullmatch(
            r"/repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/(?:releases/latest|commits/[^/]+)",
            parsed.path,
        )
        is None
    ):
        raise AdapterRegistryError("URL is outside the bounded GitHub API surface")


def _validate_adoptium_api_url(url: str) -> None:
    parsed = urlsplit(url)
    query = parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "api.adoptium.net"
        or parsed.username
        or parsed.password
        or parsed.fragment
        or re.fullmatch(r"/v3/assets/latest/[0-9]{2}/hotspot", parsed.path) is None
        or set(query) != {"architecture", "heap_size", "image_type", "os", "vendor"}
        or query.get("architecture") not in (["x64"], ["aarch64"])
        or query.get("heap_size") != ["normal"]
        or query.get("image_type") != ["jdk"]
        or query.get("os") not in (["linux"], ["mac"], ["windows"])
        or query.get("vendor") != ["eclipse"]
    ):
        raise AdapterRegistryError("URL is outside the bounded Adoptium API surface")


def _validate_cwe_url(url: str, *, expected: str) -> None:
    parsed = urlsplit(url)
    if (
        url != expected
        or parsed.scheme != "https"
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise AdapterRegistryError("URL is outside the bounded MITRE CWE surface")


def _validate_release_asset_url(url: str, repository: str | None) -> None:
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "github.com"
        or parsed.username
        or parsed.password
        or parsed.fragment
        or parsed.query
    ):
        raise AdapterRegistryError("release asset URL is not an allowed GitHub URL")
    expected = f"/{repository}/releases/download/" if repository else "/"
    if repository and not parsed.path.startswith(expected):
        raise AdapterRegistryError("release asset URL does not match the declared repository")
    if "/releases/download/" not in parsed.path:
        raise AdapterRegistryError("release asset URL is outside GitHub releases")


class _GitHubApiRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise AdapterRegistryError("GitHub API redirects require adapter manifest review")


class _AdoptiumApiRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise AdapterRegistryError("Adoptium API redirects require adapter manifest review")


class _CweRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise AdapterRegistryError("MITRE CWE redirects require adapter manifest review")


class _ReleaseAssetRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urlsplit(newurl)
        host = (parsed.hostname or "").casefold()
        if (
            parsed.scheme != "https"
            or parsed.username
            or parsed.password
            or parsed.fragment
            or not host.endswith(".githubusercontent.com")
        ):
            raise AdapterRegistryError("release asset redirected outside GitHub content hosting")
        return super().redirect_request(req, fp, code, msg, headers, newurl)
