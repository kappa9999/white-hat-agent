from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from release_gate import (
    ReleaseGateError,
    ruleset_applies,
    validate_local_release,
    validate_remote_release,
    validate_tag_binding,
)


def write_release_files(root: Path, version: str = "0.3.0") -> tuple[Path, Path]:
    pyproject = root / "pyproject.toml"
    pyproject.write_text(f'[project]\nname = "white-hat-agent"\nversion = "{version}"\n')
    changelog = root / "CHANGELOG.md"
    changelog.write_text(f"# Changelog\n\n## [{version}] - 2026-07-29\n\nRelease.\n")
    return pyproject, changelog


def protected_ruleset() -> dict[str, object]:
    return {
        "conditions": {"ref_name": {"exclude": [], "include": ["refs/tags/v*"]}},
        "enforcement": "active",
        "bypass_actors": [{"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"}],
        "rules": [
            {"type": "creation"},
            {"type": "deletion"},
            {"type": "required_signatures"},
            {"type": "update"},
        ],
        "target": "tag",
    }


def validate_rulesets(rulesets: list[dict[str, object]]) -> str:
    return validate_remote_release(
        tag="v0.3.0",
        commit="a" * 40,
        tag_ref={"ref": "refs/tags/v0.3.0", "object": {"sha": "b" * 40, "type": "tag"}},
        annotated_tag={
            "tag": "v0.3.0",
            "object": {"sha": "a" * 40, "type": "commit"},
            "sha": "b" * 40,
            "verification": {"reason": "valid", "verified": True},
        },
        default_branch_ref={
            "ref": "refs/heads/main",
            "object": {"sha": "a" * 40, "type": "commit"},
        },
        rulesets=rulesets,
        existing_release=None,
    )


def test_local_gate_accepts_consistent_tag(tmp_path: Path) -> None:
    pyproject, changelog = write_release_files(tmp_path)

    version = validate_local_release(
        pyproject=pyproject,
        changelog=changelog,
        tag="v0.3.0",
        ref="refs/tags/v0.3.0",
        ref_type="tag",
        event_name="workflow_dispatch",
    )

    assert version == "0.3.0"


@pytest.mark.parametrize(
    ("tag", "ref", "ref_type"),
    [
        ("v0.3.1", "refs/tags/v0.3.1", "tag"),
        ("v0.3.0", "refs/heads/main", "branch"),
        ("0.3.0", "refs/tags/0.3.0", "tag"),
    ],
)
def test_local_gate_rejects_version_or_ref_mismatch(
    tmp_path: Path, tag: str, ref: str, ref_type: str
) -> None:
    pyproject, changelog = write_release_files(tmp_path)

    with pytest.raises(ReleaseGateError):
        validate_local_release(
            pyproject=pyproject,
            changelog=changelog,
            tag=tag,
            ref=ref,
            ref_type=ref_type,
            event_name="push",
        )


def test_local_gate_requires_latest_changelog_entry(tmp_path: Path) -> None:
    pyproject, changelog = write_release_files(tmp_path)
    changelog.write_text("# Changelog\n\n## [0.2.0] - 2026-07-29\n\nOld.\n\n## [0.3.0] - 2026-07-28\n")

    with pytest.raises(ReleaseGateError, match="latest changelog"):
        validate_local_release(
            pyproject=pyproject,
            changelog=changelog,
            tag="v0.3.0",
            ref="refs/tags/v0.3.0",
            ref_type="tag",
            event_name="push",
        )


def test_ruleset_matching_honors_exclusions() -> None:
    ruleset = protected_ruleset()
    ruleset["conditions"] = {"ref_name": {"exclude": ["refs/tags/v0.2.*"], "include": ["refs/tags/v*"]}}

    assert ruleset_applies(ruleset, "refs/tags/v0.3.0")
    assert not ruleset_applies(ruleset, "refs/tags/v0.2.9")


def test_remote_gate_accepts_signed_annotated_protected_tag() -> None:
    inactive = protected_ruleset()
    inactive["enforcement"] = "disabled"

    assert validate_rulesets([inactive, protected_ruleset()]) == "b" * 40


@pytest.mark.parametrize(
    ("tag_type", "verified", "rulesets", "existing_release", "match"),
    [
        ("commit", True, [protected_ruleset()], None, "annotated"),
        ("tag", False, [protected_ruleset()], None, "signature"),
        ("tag", True, [], None, "exactly one active tag ruleset; found 0"),
        ("tag", True, [protected_ruleset()], {"id": 1}, "already exists"),
    ],
)
def test_remote_gate_fails_closed(
    tag_type: str,
    verified: bool,
    rulesets: list[dict[str, object]],
    existing_release: dict[str, int] | None,
    match: str,
) -> None:
    with pytest.raises(ReleaseGateError, match=match):
        validate_remote_release(
            tag="v0.3.0",
            commit="a" * 40,
            tag_ref={
                "ref": "refs/tags/v0.3.0",
                "object": {"sha": "b" * 40, "type": tag_type},
            },
            annotated_tag={
                "tag": "v0.3.0",
                "object": {"sha": "a" * 40, "type": "commit"},
                "sha": "b" * 40,
                "verification": {"reason": "valid" if verified else "unsigned", "verified": verified},
            },
            default_branch_ref={
                "ref": "refs/heads/main",
                "object": {"sha": "a" * 40, "type": "commit"},
            },
            rulesets=rulesets,
            existing_release=existing_release,
        )


def test_remote_gate_rejects_non_main_commit() -> None:
    common = {
        "tag": "v0.3.0",
        "commit": "a" * 40,
        "tag_ref": {
            "ref": "refs/tags/v0.3.0",
            "object": {"sha": "b" * 40, "type": "tag"},
        },
        "annotated_tag": {
            "tag": "v0.3.0",
            "object": {"sha": "a" * 40, "type": "commit"},
            "sha": "b" * 40,
            "verification": {"reason": "valid", "verified": True},
        },
        "existing_release": None,
    }

    with pytest.raises(ReleaseGateError, match="main branch head"):
        validate_remote_release(
            **common,
            default_branch_ref={
                "ref": "refs/heads/main",
                "object": {"sha": "c" * 40, "type": "commit"},
            },
            rulesets=[protected_ruleset()],
        )


def test_remote_gate_rejects_split_protections() -> None:
    creation = protected_ruleset()
    creation["rules"] = [{"type": "creation"}, {"type": "deletion"}]
    updates = protected_ruleset()
    updates["rules"] = [{"type": "required_signatures"}, {"type": "update"}]

    with pytest.raises(ReleaseGateError, match="exactly one active tag ruleset; found 2"):
        validate_rulesets([creation, updates])


def test_remote_gate_rejects_missing_protection_in_sole_ruleset() -> None:
    ruleset = protected_ruleset()
    ruleset["rules"] = [rule for rule in ruleset["rules"] if rule["type"] != "update"]

    with pytest.raises(ReleaseGateError, match="missing required protections: update"):
        validate_rulesets([ruleset])


@pytest.mark.parametrize(
    ("bypass_actors", "match"),
    [
        ([], "exactly one bypass actor; found 0"),
        (
            [
                {"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"},
                {"actor_id": 7, "actor_type": "Team", "bypass_mode": "always"},
            ],
            "exactly one bypass actor; found 2",
        ),
        (
            [{"actor_id": 4, "actor_type": "RepositoryRole", "bypass_mode": "always"}],
            "must be RepositoryRole actor_id 5 in always mode",
        ),
        (
            [{"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "pull_request"}],
            "must be RepositoryRole actor_id 5 in always mode",
        ),
    ],
)
def test_remote_gate_requires_exact_maintainer_bypass(
    bypass_actors: list[dict[str, object]], match: str
) -> None:
    ruleset = protected_ruleset()
    ruleset["bypass_actors"] = bypass_actors

    with pytest.raises(ReleaseGateError, match=match):
        validate_rulesets([ruleset])


def test_tag_binding_detects_name_and_object_changes() -> None:
    tag_ref = {
        "ref": "refs/tags/v0.3.0",
        "object": {"sha": "b" * 40, "type": "tag"},
    }
    annotated = {
        "tag": "v0.3.0",
        "object": {"sha": "a" * 40, "type": "commit"},
        "sha": "b" * 40,
        "verification": {"reason": "valid", "verified": True},
    }

    assert (
        validate_tag_binding(
            tag="v0.3.0",
            commit="a" * 40,
            tag_ref=tag_ref,
            annotated_tag=annotated,
            expected_tag_object_sha="b" * 40,
        )
        == "b" * 40
    )
    with pytest.raises(ReleaseGateError, match="changed"):
        validate_tag_binding(
            tag="v0.3.0",
            commit="a" * 40,
            tag_ref=tag_ref,
            annotated_tag=annotated,
            expected_tag_object_sha="c" * 40,
        )
    with pytest.raises(ReleaseGateError, match="name"):
        validate_tag_binding(
            tag="v0.3.0",
            commit="a" * 40,
            tag_ref=tag_ref,
            annotated_tag={**annotated, "tag": "v9.9.9"},
        )
