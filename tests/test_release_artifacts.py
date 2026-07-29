from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from verify_release_artifacts import (
    ArtifactError,
    compare_builds,
    generate_candidate,
    normalize_sdist,
    verify_candidate,
    verify_release_assets,
)
from verify_release_artifacts import main as release_artifacts_main

METADATA = b"""Metadata-Version: 2.4
Name: white-hat-agent
Version: 0.3.0
Requires-Dist: pydantic<3,>=2.11

"""


def write_wheel(path: Path, *, module: bytes = b'__version__ = "0.3.0"\n') -> None:
    timestamp = (2026, 7, 29, 12, 0, 0)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, payload in (
            ("white_hat_agent-0.3.0.dist-info/METADATA", METADATA),
            ("white_hat_agent/__init__.py", module),
        ):
            member = zipfile.ZipInfo(name, timestamp)
            member.create_system = 3
            member.external_attr = 0o100644 << 16
            archive.writestr(member, payload)


def write_sdist(
    path: Path,
    *,
    timestamp: int,
    module: bytes = b'__version__ = "0.3.0"\n',
    member_name: str | None = None,
    pax_comment: str = "preserved",
) -> None:
    with (
        path.open("wb") as raw,
        gzip.GzipFile(fileobj=raw, mode="wb", mtime=timestamp) as compressed,
        tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive,
    ):
        entries = (
            (member_name or "white_hat_agent-0.3.0/PKG-INFO", METADATA),
            ("white_hat_agent-0.3.0/src/white_hat_agent/__init__.py", module),
        )
        for name, payload in entries:
            member = tarfile.TarInfo(name)
            member.mode = 0o644
            member.size = len(payload)
            member.mtime = timestamp
            member.pax_headers = {"comment": pax_comment, "mtime": f"{timestamp}.5"}
            archive.addfile(member, io.BytesIO(payload))


def write_build(directory: Path, *, timestamp: int, changed: bool = False) -> None:
    directory.mkdir()
    module = b"changed\n" if changed else b'__version__ = "0.3.0"\n'
    write_wheel(directory / "white_hat_agent-0.3.0-py3-none-any.whl", module=module)
    write_sdist(directory / "white_hat_agent-0.3.0.tar.gz", timestamp=timestamp, module=module)


def write_project(root: Path) -> None:
    (root / "pyproject.toml").write_text(
        """[project]
name = "white-hat-agent"
version = "0.3.0"
dependencies = ["pydantic>=2.11,<3"]
"""
    )


def write_reproducibility_report(dist: Path, report: Path) -> None:
    artifacts = []
    for artifact in sorted(dist.iterdir()):
        artifact_digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        artifacts.append(
            {
                "first_sha256": artifact_digest,
                "name": artifact.name,
                "second_sha256": artifact_digest,
                "status": "byte-for-byte",
            }
        )
    report.write_text(
        json.dumps(
            {
                "artifacts": artifacts,
                "candidate_build": "first",
                "reproducibility": "byte-for-byte",
            }
        )
    )


def write_candidate(root: Path) -> Path:
    write_project(root)
    dist = root / "dist"
    write_build(dist, timestamp=1)
    report = root / "reproducibility.json"
    write_reproducibility_report(dist, report)
    candidate = root / "candidate"
    generate_candidate(
        root=root,
        dist_dir=dist,
        output_dir=candidate,
        reproducibility_report=report,
        tag="v0.3.0",
    )
    return candidate


def refresh_checksums(candidate: Path) -> None:
    lines = [
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}"
        for path in sorted(candidate.iterdir())
        if path.name != "SHA256SUMS"
    ]
    (candidate / "SHA256SUMS").write_text("\n".join(lines) + "\n")


def github_release(candidate: Path) -> dict[str, object]:
    assets = [
        {
            "digest": f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}",
            "name": path.name,
            "size": path.stat().st_size,
            "state": "uploaded",
        }
        for path in sorted(candidate.iterdir())
    ]
    return {"assets": assets, "tag_name": "v0.3.0"}


def test_normalized_sdists_and_isolated_builds_are_byte_exact(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    write_build(first, timestamp=1)
    write_build(second, timestamp=2)

    normalize_sdist(first / "white_hat_agent-0.3.0.tar.gz", 100)
    normalize_sdist(second / "white_hat_agent-0.3.0.tar.gz", 100)
    report = compare_builds(first, second, tmp_path / "reproducibility.json")

    assert report["reproducibility"] == "byte-for-byte"
    assert {item["status"] for item in report["artifacts"]} == {"byte-for-byte"}
    with tarfile.open(first / "white_hat_agent-0.3.0.tar.gz", "r:gz") as archive:
        assert all(member.mtime == 100 for member in archive.getmembers())
        assert all(member.uid == member.gid == 0 for member in archive.getmembers())
        assert {member.pax_headers.get("comment") for member in archive.getmembers()} == {"preserved"}


def test_normalize_sdist_rejects_unsafe_or_nonregular_members(tmp_path: Path) -> None:
    unsafe = tmp_path / "unsafe.tar.gz"
    write_sdist(unsafe, timestamp=1, member_name="../escape")
    with pytest.raises(ArtifactError, match="unsafe member path"):
        normalize_sdist(unsafe, 100)

    linked = tmp_path / "linked.tar.gz"
    with tarfile.open(linked, "w:gz") as archive:
        member = tarfile.TarInfo("white_hat_agent-0.3.0/link")
        member.type = tarfile.SYMTYPE
        member.linkname = "/tmp/target"
        archive.addfile(member)
    with pytest.raises(ArtifactError, match="regular file or directory"):
        normalize_sdist(linked, 100)


def test_compare_builds_rejects_any_byte_drift(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    write_build(first, timestamp=1)
    write_build(second, timestamp=1, changed=True)

    with pytest.raises(ArtifactError, match="byte-for-byte"):
        compare_builds(first, second, tmp_path / "reproducibility.json")


def test_generate_and_verify_minimal_candidate(tmp_path: Path) -> None:
    candidate = write_candidate(tmp_path)
    result = verify_candidate(candidate)

    assert result["version"] == "0.3.0"
    assert set(result["artifacts"]) == {
        "white_hat_agent-0.3.0-py3-none-any.whl",
        "white_hat_agent-0.3.0.tar.gz",
    }
    assert {path.name for path in candidate.iterdir()} == {
        "SHA256SUMS",
        "reproducibility.json",
        "white-hat-agent-0.3.0-sdist.cdx.json",
        "white-hat-agent-0.3.0-wheel.cdx.json",
        "white_hat_agent-0.3.0-py3-none-any.whl",
        "white_hat_agent-0.3.0.tar.gz",
    }
    sbom = json.loads((candidate / "white-hat-agent-0.3.0-wheel.cdx.json").read_text())
    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["components"][0]["properties"] == [
        {"name": "python:requires-dist", "value": "pydantic<3,>=2.11"}
    ]
    checksum_names = {line.split("  ", 1)[1] for line in (candidate / "SHA256SUMS").read_text().splitlines()}
    assert checksum_names == {path.name for path in candidate.iterdir()} - {"SHA256SUMS"}


@pytest.mark.parametrize("target", ["artifact", "sbom", "reproducibility"])
def test_verify_candidate_rejects_tampering(tmp_path: Path, target: str) -> None:
    candidate = write_candidate(tmp_path)
    if target == "artifact":
        path = next(candidate.glob("*.whl"))
        path.write_bytes(path.read_bytes() + b"tampered")
    elif target == "sbom":
        path = candidate / "white-hat-agent-0.3.0-wheel.cdx.json"
        sbom = json.loads(path.read_text())
        sbom["components"] = []
        path.write_text(json.dumps(sbom))
        refresh_checksums(candidate)
    else:
        path = candidate / "reproducibility.json"
        report = json.loads(path.read_text())
        report["artifacts"][0]["second_sha256"] = "0" * 64
        path.write_text(json.dumps(report))
        refresh_checksums(candidate)

    with pytest.raises(ArtifactError):
        verify_candidate(candidate)


def test_verify_candidate_rejects_extra_or_nonregular_entries(tmp_path: Path) -> None:
    candidate = write_candidate(tmp_path)
    (candidate / "unexpected.txt").write_text("must never be published")
    with pytest.raises(ArtifactError, match="allowlist"):
        verify_candidate(candidate)

    (candidate / "unexpected.txt").unlink()
    target = tmp_path / "outside.txt"
    target.write_text("outside")
    os.symlink(target, candidate / "unexpected")
    with pytest.raises(ArtifactError, match="regular file"):
        verify_candidate(candidate)


def test_verify_release_assets_accepts_exact_api_response(tmp_path: Path) -> None:
    candidate = write_candidate(tmp_path)
    result = verify_release_assets(candidate, github_release(candidate))
    assert result["tag"] == "v0.3.0"
    assert result["assets"].keys() == {path.name for path in candidate.iterdir()}


def test_verify_release_assets_cli_consumes_github_api_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    candidate = write_candidate(tmp_path)
    response = tmp_path / "release.json"
    response.write_text(json.dumps(github_release(candidate)))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "verify_release_artifacts.py",
            "verify-release-assets",
            "--candidate",
            str(candidate),
            "--release-json",
            str(response),
        ],
    )
    release_artifacts_main()
    assert json.loads(capsys.readouterr().out)["tag"] == "v0.3.0"


@pytest.mark.parametrize(
    ("mutation", "match"),
    [
        ("missing", "allowlist"),
        ("extra", "allowlist"),
        ("size", "size"),
        ("digest", "digest"),
        ("state", "not fully uploaded"),
        ("tag", "tag"),
    ],
)
def test_verify_release_assets_rejects_remote_drift(tmp_path: Path, mutation: str, match: str) -> None:
    candidate = write_candidate(tmp_path)
    release = github_release(candidate)
    assets = release["assets"]
    assert isinstance(assets, list)
    if mutation == "missing":
        assets.pop()
    elif mutation == "extra":
        assets.append({"digest": f"sha256:{'0' * 64}", "name": "extra", "size": 0, "state": "uploaded"})
    elif mutation == "size":
        assets[0]["size"] += 1
    elif mutation == "digest":
        assets[0]["digest"] = f"sha256:{'0' * 64}"
    elif mutation == "state":
        assets[0]["state"] = "new"
    else:
        release["tag_name"] = "v9.9.9"

    with pytest.raises(ArtifactError, match=match):
        verify_release_assets(candidate, release)
