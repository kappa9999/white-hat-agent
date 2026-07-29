from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
import shutil
import stat
import tarfile
import tempfile
import tomllib
import uuid
import zipfile
from email.parser import BytesParser
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO

CYCLONEDX_SCHEMA = "http://cyclonedx.org/schema/bom-1.6.schema.json"
CYCLONEDX_SPEC = "1.6"
STATIC_CANDIDATE_FILES = frozenset({"SHA256SUMS", "reproducibility.json"})
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
NORMALIZED_PAX_FIELDS = frozenset({"atime", "ctime", "gid", "gname", "mtime", "uid", "uname"})


class ArtifactError(ValueError):
    pass


def _require_regular_file(path: Path) -> None:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError as error:
        raise ArtifactError(f"required release file is missing: {path}") from error
    if not stat.S_ISREG(mode):
        raise ArtifactError(f"release path must be a regular file: {path}")


def digest(path: Path) -> str:
    _require_regular_file(path)
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _directory_files(directory: Path) -> dict[str, Path]:
    try:
        mode = directory.lstat().st_mode
    except FileNotFoundError as error:
        raise ArtifactError(f"release directory does not exist: {directory}") from error
    if not stat.S_ISDIR(mode):
        raise ArtifactError(f"release directory must be a real directory, not a link or file: {directory}")

    files: dict[str, Path] = {}
    for entry in directory.iterdir():
        _require_regular_file(entry)
        if entry.name in files:
            raise ArtifactError(f"duplicate release file name: {entry.name}")
        files[entry.name] = entry
    return files


def distribution_files(directory: Path) -> list[Path]:
    files = _directory_files(directory)
    wheels = sorted(path for name, path in files.items() if name.endswith(".whl"))
    sdists = sorted(path for name, path in files.items() if name.endswith(".tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        raise ArtifactError(f"expected one wheel and one sdist in {directory}; found {wheels=} {sdists=}")
    return [wheels[0], sdists[0]]


def _safe_archive_name(name: str) -> None:
    path = PurePosixPath(name)
    if not name or "\\" in name or path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ArtifactError(f"sdist contains an unsafe member path: {name!r}")


def _normalized_tar_member(member: tarfile.TarInfo, epoch: int) -> tarfile.TarInfo:
    _safe_archive_name(member.name)
    if not (member.isfile() or member.isdir()):
        raise ArtifactError(f"sdist member must be a regular file or directory: {member.name}")
    if member.mode < 0 or member.mode > 0o7777:
        raise ArtifactError(f"sdist member has an invalid mode: {member.name}")

    normalized = tarfile.TarInfo(member.name)
    normalized.type = member.type
    normalized.mode = member.mode
    normalized.size = member.size if member.isfile() else 0
    normalized.mtime = epoch
    normalized.uid = 0
    normalized.gid = 0
    normalized.uname = ""
    normalized.gname = ""
    normalized.pax_headers = {
        key: value for key, value in member.pax_headers.items() if key not in NORMALIZED_PAX_FIELDS
    }
    return normalized


def normalize_sdist(path: Path, epoch: int) -> None:
    """Rewrite one locally built sdist into a deterministic, extraction-safe tar.gz."""
    _require_regular_file(path)
    if epoch < 0 or epoch > 0xFFFFFFFF:
        raise ArtifactError("SOURCE_DATE_EPOCH must fit the gzip timestamp field")

    members: list[tarfile.TarInfo]
    with tarfile.open(path, "r:gz") as source:
        members = source.getmembers()
        names: set[str] = set()
        for member in members:
            _safe_archive_name(member.name)
            if member.name in names:
                raise ArtifactError(f"sdist contains a duplicate member: {member.name}")
            names.add(member.name)

        original_mode = stat.S_IMODE(path.stat().st_mode)
        temporary_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(prefix=f".{path.name}.", dir=path.parent, delete=False) as raw:
                temporary_path = Path(raw.name)
                with (
                    gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=epoch) as compressed,
                    tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as target,
                ):
                    for member in sorted(members, key=lambda item: item.name):
                        normalized = _normalized_tar_member(member, epoch)
                        payload: BinaryIO | None = source.extractfile(member) if member.isfile() else None
                        if member.isfile() and payload is None:
                            raise ArtifactError(f"could not read sdist member: {member.name}")
                        try:
                            target.addfile(normalized, payload)
                        finally:
                            if payload is not None:
                                payload.close()
                raw.flush()
                os.fsync(raw.fileno())
            os.chmod(temporary_path, original_mode)
            os.replace(temporary_path, path)
            temporary_path = None
        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)


def normalize_distribution_sdist(directory: Path, epoch: int) -> Path:
    sdist = next(path for path in distribution_files(directory) if path.name.endswith(".tar.gz"))
    normalize_sdist(sdist, epoch)
    return sdist


def compare_builds(first_dir: Path, second_dir: Path, report_path: Path) -> dict[str, Any]:
    first_artifacts = distribution_files(first_dir)
    second_artifacts = distribution_files(second_dir)
    if [path.name for path in first_artifacts] != [path.name for path in second_artifacts]:
        raise ArtifactError("isolated builds produced different artifact names")

    artifacts: list[dict[str, str]] = []
    for first, second in zip(first_artifacts, second_artifacts, strict=True):
        first_digest = digest(first)
        second_digest = digest(second)
        if first_digest != second_digest:
            raise ArtifactError(f"isolated builds are not byte-for-byte reproducible: {first.name}")
        artifacts.append(
            {
                "first_sha256": first_digest,
                "name": first.name,
                "second_sha256": second_digest,
                "status": "byte-for-byte",
            }
        )

    report = {
        "artifacts": artifacts,
        "candidate_build": "first",
        "reproducibility": "byte-for-byte",
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    _write_json(report_path, report)
    return report


def _metadata_bytes(path: Path) -> bytes:
    if path.suffix == ".whl":
        with zipfile.ZipFile(path) as archive:
            names = [name for name in archive.namelist() if name.endswith(".dist-info/METADATA")]
            if len(names) != 1:
                raise ArtifactError(f"expected one wheel METADATA file in {path.name}")
            return archive.read(names[0])
    with tarfile.open(path, "r:gz") as archive:
        members = [
            member
            for member in archive.getmembers()
            if member.name.endswith("/PKG-INFO") and member.name.count("/") == 1
        ]
        if len(members) != 1:
            raise ArtifactError(f"expected one top-level PKG-INFO file in {path.name}")
        extracted = archive.extractfile(members[0])
        if extracted is None:
            raise ArtifactError(f"could not read PKG-INFO from {path.name}")
        return extracted.read()


def package_metadata(path: Path) -> tuple[str, str, list[str]]:
    metadata = BytesParser().parsebytes(_metadata_bytes(path))
    name = metadata.get("Name")
    version = metadata.get("Version")
    if not name or not version:
        raise ArtifactError(f"distribution metadata is missing Name or Version in {path.name}")
    return name, version, metadata.get_all("Requires-Dist", [])


def _normalized_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _component_dependencies(requirements: list[str]) -> tuple[list[dict[str, Any]], list[str]]:
    components: list[dict[str, Any]] = []
    refs: list[str] = []
    for requirement in sorted(set(requirements)):
        match = re.match(r"^\s*([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)", requirement)
        if match is None:
            raise ArtifactError(f"invalid Requires-Dist value: {requirement!r}")
        name = match.group(1)
        bom_ref = f"pkg:pypi/{_normalized_name(name)}"
        if bom_ref in refs:
            raise ArtifactError(f"duplicate normalized dependency name in metadata: {name}")
        refs.append(bom_ref)
        components.append(
            {
                "bom-ref": bom_ref,
                "name": name,
                "properties": [{"name": "python:requires-dist", "value": requirement}],
                "purl": bom_ref,
                "type": "library",
            }
        )
    return components, refs


def _bom(
    *, name: str, version: str, artifact: str, artifact_digest: str, requirements: list[str]
) -> dict[str, Any]:
    components, dependency_refs = _component_dependencies(requirements)
    subject_ref = f"release-artifact:{artifact}"
    return {
        "$schema": CYCLONEDX_SCHEMA,
        "bomFormat": "CycloneDX",
        "components": components,
        "dependencies": [{"dependsOn": dependency_refs, "ref": subject_ref}],
        "metadata": {
            "component": {
                "bom-ref": subject_ref,
                "hashes": [{"alg": "SHA-256", "content": artifact_digest}],
                "name": name,
                "properties": [
                    {"name": "release:artifact", "value": artifact},
                    {"name": "release:tag", "value": f"v{version}"},
                ],
                "purl": f"pkg:pypi/{_normalized_name(name)}@{version}",
                "type": "application",
                "version": version,
            }
        },
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, artifact_digest)}",
        "specVersion": CYCLONEDX_SPEC,
        "version": 1,
    }


def _read_project(root: Path) -> tuple[str, str]:
    with (root / "pyproject.toml").open("rb") as stream:
        project = tomllib.load(stream)["project"]
    return project["name"], project["version"]


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _expected_distribution_names(name: str, version: str) -> set[str]:
    distribution = name.replace("-", "_")
    return {f"{distribution}-{version}-py3-none-any.whl", f"{distribution}-{version}.tar.gz"}


def generate_candidate(
    *, root: Path, dist_dir: Path, output_dir: Path, reproducibility_report: Path, tag: str
) -> None:
    if output_dir.exists():
        if _directory_files(output_dir):
            raise ArtifactError(f"candidate output directory is not empty: {output_dir}")
    else:
        output_dir.mkdir(parents=True)

    artifacts = distribution_files(dist_dir)
    project_name, project_version = _read_project(root)
    if tag != f"v{project_version}":
        raise ArtifactError(f"candidate tag {tag!r} does not match project version {project_version!r}")
    if {path.name for path in artifacts} != _expected_distribution_names(project_name, project_version):
        raise ArtifactError("distribution file names do not match the project name and version")

    for source in artifacts:
        candidate = output_dir / source.name
        shutil.copyfile(source, candidate)
        metadata_name, metadata_version, requirements = package_metadata(candidate)
        if metadata_name != project_name or metadata_version != project_version:
            raise ArtifactError(f"metadata mismatch in {source.name}: {(metadata_name, metadata_version)!r}")
        kind = "wheel" if candidate.suffix == ".whl" else "sdist"
        _write_json(
            output_dir / f"{project_name}-{project_version}-{kind}.cdx.json",
            _bom(
                name=project_name,
                version=project_version,
                artifact=candidate.name,
                artifact_digest=digest(candidate),
                requirements=requirements,
            ),
        )

    shutil.copyfile(reproducibility_report, output_dir / "reproducibility.json")
    checksum_lines = [
        f"{digest(path)}  {path.name}"
        for path in sorted(output_dir.iterdir(), key=lambda candidate: candidate.name)
        if path.name != "SHA256SUMS"
    ]
    (output_dir / "SHA256SUMS").write_text("\n".join(checksum_lines) + "\n", encoding="utf-8")
    verify_candidate(output_dir)


def _load(path: Path) -> dict[str, Any]:
    _require_regular_file(path)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ArtifactError(f"invalid JSON in {path}") from error
    if not isinstance(value, dict):
        raise ArtifactError(f"expected an object in {path}")
    return value


def _safe_file_name(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or not value or value in {".", ".."} or "/" in value or "\\" in value:
        raise ArtifactError(f"{label} must be a safe candidate file name, found {value!r}")
    return value


def _sha256(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise ArtifactError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _parse_checksums(path: Path) -> dict[str, str]:
    lines = path.read_text(encoding="utf-8").splitlines()
    checksums: dict[str, str] = {}
    names: list[str] = []
    for line in lines:
        parts = line.split("  ", 1)
        if len(parts) != 2:
            raise ArtifactError("SHA256SUMS must use lowercase '<digest>  <name>' records")
        checksum = _sha256(parts[0], label="SHA256SUMS record")
        name = _safe_file_name(parts[1], label="SHA256SUMS name")
        if name == "SHA256SUMS" or name in checksums:
            raise ArtifactError(f"invalid or duplicate SHA256SUMS name: {name}")
        checksums[name] = checksum
        names.append(name)
    if names != sorted(names):
        raise ArtifactError("SHA256SUMS records must be sorted by file name")
    return checksums


def _verify_reproducibility(report: dict[str, Any], expected: dict[str, str]) -> None:
    if set(report) != {"artifacts", "candidate_build", "reproducibility"}:
        raise ArtifactError("reproducibility report has unexpected fields")
    entries = report.get("artifacts")
    if not isinstance(entries, list) or len(entries) != len(expected):
        raise ArtifactError("reproducibility report must describe every release artifact exactly once")
    if report.get("candidate_build") != "first" or report.get("reproducibility") != "byte-for-byte":
        raise ArtifactError("release artifacts must be byte-for-byte reproducible")

    seen: set[str] = set()
    for item in entries:
        if not isinstance(item, dict) or set(item) != {"first_sha256", "name", "second_sha256", "status"}:
            raise ArtifactError("reproducibility artifact entry has unexpected fields")
        name = _safe_file_name(item.get("name"), label="reproducibility artifact name")
        first = _sha256(item.get("first_sha256"), label=f"first build of {name}")
        second = _sha256(item.get("second_sha256"), label=f"second build of {name}")
        if name in seen or name not in expected:
            raise ArtifactError(f"unexpected or duplicate reproducibility artifact: {name}")
        if item.get("status") != "byte-for-byte" or first != second or first != expected[name]:
            raise ArtifactError(f"reproducibility evidence does not match candidate artifact: {name}")
        seen.add(name)
    if seen != set(expected):
        raise ArtifactError("reproducibility report does not cover the candidate artifacts")


def verify_candidate(candidate_dir: Path) -> dict[str, Any]:
    files = _directory_files(candidate_dir)
    missing_static = sorted(STATIC_CANDIDATE_FILES - files.keys())
    if missing_static:
        raise ArtifactError(f"candidate is missing required files: {', '.join(missing_static)}")

    artifacts = distribution_files(candidate_dir)
    metadata_records = [package_metadata(path) for path in artifacts]
    package_names = {record[0] for record in metadata_records}
    package_versions = {record[1] for record in metadata_records}
    if len(package_names) != 1 or len(package_versions) != 1:
        raise ArtifactError("wheel and sdist package identities do not agree")
    package_name = next(iter(package_names))
    version = next(iter(package_versions))
    if {path.name for path in artifacts} != _expected_distribution_names(package_name, version):
        raise ArtifactError("candidate distribution file names do not match package metadata")

    artifact_digests = {path.name: digest(path) for path in artifacts}
    expected_names = (
        set(artifact_digests)
        | STATIC_CANDIDATE_FILES
        | {
            f"{package_name}-{version}-sdist.cdx.json",
            f"{package_name}-{version}-wheel.cdx.json",
        }
    )
    if set(files) != expected_names:
        missing = sorted(expected_names - files.keys())
        extra = sorted(files.keys() - expected_names)
        raise ArtifactError(f"candidate file allowlist mismatch: {missing=} {extra=}")

    expected_checksums = {name: digest(path) for name, path in files.items() if name != "SHA256SUMS"}
    if _parse_checksums(candidate_dir / "SHA256SUMS") != expected_checksums:
        raise ArtifactError("SHA256SUMS must cover every candidate file except itself")
    _verify_reproducibility(_load(candidate_dir / "reproducibility.json"), artifact_digests)

    for artifact, metadata in zip(artifacts, metadata_records, strict=True):
        kind = "wheel" if artifact.suffix == ".whl" else "sdist"
        expected_sbom = _bom(
            name=package_name,
            version=version,
            artifact=artifact.name,
            artifact_digest=artifact_digests[artifact.name],
            requirements=metadata[2],
        )
        if _load(candidate_dir / f"{package_name}-{version}-{kind}.cdx.json") != expected_sbom:
            raise ArtifactError(f"{kind} SBOM does not exactly match artifact metadata")

    all_digests = {name: digest(path) for name, path in files.items()}
    return {
        "artifacts": artifact_digests,
        "files": all_digests,
        "tag": f"v{version}",
        "version": version,
    }


def verify_release_assets(candidate_dir: Path, release: dict[str, Any]) -> dict[str, Any]:
    candidate = verify_candidate(candidate_dir)
    expected_tag = candidate["tag"]
    if release.get("tag_name") != expected_tag:
        raise ArtifactError("GitHub release tag does not match the candidate version")

    assets = release.get("assets")
    if not isinstance(assets, list):
        raise ArtifactError("GitHub release response must contain an assets list")
    remote: dict[str, dict[str, Any]] = {}
    for asset in assets:
        if not isinstance(asset, dict):
            raise ArtifactError("GitHub release assets must be objects")
        name = _safe_file_name(asset.get("name"), label="GitHub release asset name")
        if name in remote:
            raise ArtifactError(f"duplicate GitHub release asset: {name}")
        if asset.get("state") not in (None, "uploaded"):
            raise ArtifactError(f"GitHub release asset is not fully uploaded: {name}")
        size = asset.get("size")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise ArtifactError(f"GitHub release asset has an invalid size: {name}")
        remote[name] = asset

    files = _directory_files(candidate_dir)
    if set(remote) != set(files):
        missing = sorted(files.keys() - remote.keys())
        extra = sorted(remote.keys() - files.keys())
        raise ArtifactError(f"GitHub release asset allowlist mismatch: {missing=} {extra=}")
    for name, path in files.items():
        asset = remote[name]
        if asset["size"] != path.stat().st_size:
            raise ArtifactError(f"GitHub release asset size does not match candidate: {name}")
        if asset.get("digest") != f"sha256:{candidate['files'][name]}":
            raise ArtifactError(f"GitHub release asset digest does not match candidate: {name}")
    return {"assets": candidate["files"], "tag": expected_tag, "version": candidate["version"]}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Normalize, compare, assemble, and verify release artifacts."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    normalize = subparsers.add_parser("normalize-sdist")
    normalize.add_argument("--dist", type=Path, required=True)
    normalize.add_argument("--epoch", type=int, required=True)

    compare = subparsers.add_parser("compare")
    compare.add_argument("--first", type=Path, required=True)
    compare.add_argument("--second", type=Path, required=True)
    compare.add_argument("--report", type=Path, required=True)

    generate = subparsers.add_parser("generate")
    generate.add_argument("--root", type=Path, default=Path.cwd())
    generate.add_argument("--dist", type=Path, required=True)
    generate.add_argument("--output", type=Path, required=True)
    generate.add_argument("--reproducibility-report", type=Path, required=True)
    generate.add_argument("--tag", required=True)

    verify = subparsers.add_parser("verify")
    verify.add_argument("--candidate", type=Path, required=True)

    verify_release = subparsers.add_parser(
        "verify-release-assets",
        help="Verify a GitHub Releases API response against an exact local candidate.",
    )
    verify_release.add_argument("--candidate", type=Path, required=True)
    verify_release.add_argument("--release-json", type=Path, required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.command == "normalize-sdist":
        print(normalize_distribution_sdist(args.dist, args.epoch))
    elif args.command == "compare":
        print(json.dumps(compare_builds(args.first, args.second, args.report), sort_keys=True))
    elif args.command == "generate":
        generate_candidate(
            root=args.root.resolve(),
            dist_dir=args.dist,
            output_dir=args.output,
            reproducibility_report=args.reproducibility_report,
            tag=args.tag,
        )
        print(json.dumps(verify_candidate(args.output), sort_keys=True))
    elif args.command == "verify":
        print(json.dumps(verify_candidate(args.candidate), sort_keys=True))
    else:
        print(json.dumps(verify_release_assets(args.candidate, _load(args.release_json)), sort_keys=True))


if __name__ == "__main__":
    main()
