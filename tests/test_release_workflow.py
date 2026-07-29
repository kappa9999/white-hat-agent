from __future__ import annotations

import re
from pathlib import Path

import yaml

WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/release.yml"
SHA_PIN = re.compile(r"^[^@]+@[0-9a-f]{40}$")


def load_workflow() -> dict[str, object]:
    return yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)


def job_step(workflow: dict[str, object], job: str, name: str) -> dict[str, object]:
    steps = workflow["jobs"][job]["steps"]
    return next(step for step in steps if step.get("name") == name)


def test_release_workflow_confines_write_permissions_to_provenance_and_publication() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    forbidden = (
        "packages: write",
        "pypa/gh-action-pypi-publish",
        "softprops/action-gh-release",
    )

    assert not any(value in text for value in forbidden)
    workflow = load_workflow()
    assert workflow["permissions"] == {}
    assert set(workflow["on"]) == {"push", "workflow_dispatch"}
    assert workflow["on"]["push"]["tags"] == ["v*.*.*"]
    assert workflow["jobs"]["attest"]["permissions"] == {
        "artifact-metadata": "write",
        "attestations": "write",
        "contents": "read",
        "id-token": "write",
    }
    assert workflow["jobs"]["attest"]["environment"] == "release-provenance"
    assert workflow["jobs"]["publish"]["permissions"] == {"contents": "write"}
    assert workflow["jobs"]["publish"]["environment"] == "github-release"
    read_only = set(workflow["jobs"]) - {"attest", "publish"}
    assert all(workflow["jobs"][name]["permissions"] == {"contents": "read"} for name in read_only)


def test_release_workflow_actions_are_sha_pinned() -> None:
    workflow = load_workflow()
    uses = [step["uses"] for job in workflow["jobs"].values() for step in job["steps"] if "uses" in step]

    assert uses
    assert all(SHA_PIN.fullmatch(value) for value in uses)
    assert "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1" in uses
    assert "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c" in uses
    assert "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a" in uses
    assert "actions/attest@f7c74d28b9d84cb8768d0b8ca14a4bac6ef463e6" in uses


def test_release_workflow_uses_two_isolated_builds_and_exact_candidate_smoke() -> None:
    workflow = load_workflow()

    assert workflow["jobs"]["build"]["strategy"]["matrix"]["copy"] == ["1", "2"]
    build_script = job_step(workflow, "build", "Build wheel and sdist")["run"]
    assert "uv build --no-cache" in build_script
    assert "verify_release_artifacts.py normalize-sdist" in build_script
    assert '--epoch "$SOURCE_DATE_EPOCH"' in build_script

    generate_script = job_step(workflow, "assemble", "Generate checksums and SBOMs")["run"]
    assert '--tag "$TAG"' in generate_script
    assert not any(
        obsolete in generate_script
        for obsolete in ("--commit", "--repository", "--workflow-ref", "--invocation-id")
    )

    smoke_steps = workflow["jobs"]["smoke"]["steps"]
    assert any(step.get("name") == "Download exact assembled candidate" for step in smoke_steps)
    assert any("scripts/release_smoke.py" in step.get("run", "") for step in smoke_steps)
    attest_steps = workflow["jobs"]["attest"]["steps"]
    assert any(step.get("name") == "Verify published attestations" for step in attest_steps)
    provenance_steps = [step for step in attest_steps if "subject-checksums" in step.get("with", {})]
    assert len(provenance_steps) == 1
    assert provenance_steps[0]["with"]["subject-checksums"] == ".release/candidate/SHA256SUMS"
    checksum_steps = [
        step
        for step in attest_steps
        if step.get("with", {}).get("subject-path") == ".release/candidate/SHA256SUMS"
    ]
    assert len(checksum_steps) == 1

    sbom_steps = {
        step["name"]: step["with"]
        for step in attest_steps
        if step.get("name") in {"Attest wheel SBOM", "Attest sdist SBOM"}
    }
    assert sbom_steps == {
        "Attest wheel SBOM": {
            "subject-path": (
                ".release/candidate/white_hat_agent-${{ needs.gate.outputs.version }}-py3-none-any.whl"
            ),
            "sbom-path": (
                ".release/candidate/white-hat-agent-${{ needs.gate.outputs.version }}-wheel.cdx.json"
            ),
        },
        "Attest sdist SBOM": {
            "subject-path": ".release/candidate/white_hat_agent-${{ needs.gate.outputs.version }}.tar.gz",
            "sbom-path": (
                ".release/candidate/white-hat-agent-${{ needs.gate.outputs.version }}-sdist.cdx.json"
            ),
        },
    }
    assert all("*" not in value for inputs in sbom_steps.values() for value in inputs.values())

    attestation_verification = job_step(workflow, "attest", "Verify published attestations")["run"]
    assert '--signer-workflow "$GITHUB_REPOSITORY/.github/workflows/release.yml"' in attestation_verification
    assert '--source-ref "refs/tags/${TAG}"' in attestation_verification
    assert '--source-digest "$COMMIT"' in attestation_verification
    assert "--deny-self-hosted-runners" in attestation_verification

    publish_steps = workflow["jobs"]["publish"]["steps"]
    publish_script = "\n".join(step.get("run", "") for step in publish_steps)
    assert "gh release create" in publish_script
    assert "--draft" in publish_script
    assert "gh release upload" in publish_script
    assert "verify-release-assets" in publish_script
    assert "gh release edit" not in publish_script
    assert "--method PATCH" in publish_script
    assert "-F draft=false" in publish_script
    assert ".release/candidate/*" not in publish_script
    assert ".immutable == true" in publish_script
    assert "provenance.intoto.json" not in WORKFLOW.read_text(encoding="utf-8")


def test_release_workflow_pins_and_reverifies_the_exact_draft_by_database_id() -> None:
    workflow = load_workflow()
    create = job_step(workflow, "publish", "Create draft and upload the exact candidate allowlist")["run"]
    draft_verify = job_step(workflow, "publish", "Verify GitHub-computed draft asset digests")["run"]
    publish = job_step(workflow, "publish", "Revalidate tag and publish the verified draft")["run"]
    final = job_step(workflow, "publish", "Verify published immutability and asset identity")["run"]

    assert "select(.tag_name == $tag and .draft == true)" in create
    assert '> "$RUNNER_TEMP/release-id.txt"' in create
    assert "releases/${release_id}" in draft_verify
    assert "releases/tags/${TAG}" not in draft_verify
    assert ".id == $release_id" in draft_verify
    assert "verify-release-assets" in draft_verify

    prepublish_verify = publish.index("verify-release-assets")
    publish_by_id = publish.index("--method PATCH")
    assert "releases/${release_id}" in publish
    assert "releases/tags/${TAG}" not in publish
    assert ".id == $release_id" in publish
    assert ".draft == true" in publish
    assert prepublish_verify < publish_by_id
    assert "-F draft=false" in publish

    immutable_check = final.index(".immutable == true")
    final_asset_check = final.index("verify-release-assets")
    final_ref_check = final.index("verify_release_ref.py")
    assert "releases/${release_id}" in final
    assert "releases/tags/${TAG}" not in final
    assert ".id == $release_id" in final
    assert immutable_check < final_asset_check < final_ref_check
