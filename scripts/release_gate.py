from __future__ import annotations

import argparse
import fnmatch
import json
import re
import subprocess
import tomllib
from pathlib import Path
from typing import Any

SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
CHANGELOG_RELEASE = re.compile(r"^## \[(?P<version>[^]]+)] - (?P<date>\d{4}-\d{2}-\d{2})$", re.MULTILINE)
REQUIRED_TAG_RULES = frozenset({"creation", "deletion", "required_signatures", "update"})


class ReleaseGateError(ValueError):
    pass


def load_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def project_version(pyproject: Path) -> str:
    with pyproject.open("rb") as stream:
        version = tomllib.load(stream).get("project", {}).get("version")
    if not isinstance(version, str) or not SEMVER.fullmatch(version):
        raise ReleaseGateError(f"project.version must be a stable semantic version, found {version!r}")
    return version


def validate_local_release(
    *,
    pyproject: Path,
    changelog: Path,
    tag: str,
    ref: str,
    ref_type: str,
    event_name: str,
) -> str:
    version = project_version(pyproject)
    expected_tag = f"v{version}"
    if tag != expected_tag:
        raise ReleaseGateError(f"tag {tag!r} does not match project version {version!r}")
    if ref_type != "tag" or ref != f"refs/tags/{tag}":
        raise ReleaseGateError(f"release must run from exact tag refs/tags/{tag}; found {ref_type=} {ref=}")
    if event_name not in {"push", "workflow_dispatch"}:
        raise ReleaseGateError(f"unexpected release event: {event_name!r}")

    releases = list(CHANGELOG_RELEASE.finditer(changelog.read_text(encoding="utf-8")))
    if not releases:
        raise ReleaseGateError("CHANGELOG.md has no dated release entries")
    first_version = releases[0].group("version")
    if first_version != version:
        raise ReleaseGateError(
            f"latest changelog release {first_version!r} does not match project version {version!r}"
        )
    if sum(match.group("version") == version for match in releases) != 1:
        raise ReleaseGateError(f"CHANGELOG.md must contain exactly one dated entry for {version}")
    return version


def _pattern_matches(pattern: str, ref: str) -> bool:
    if pattern == "~ALL":
        return True
    if pattern == "~DEFAULT_BRANCH":
        return False
    return fnmatch.fnmatchcase(ref, pattern)


def ruleset_applies(ruleset: dict[str, Any], ref: str) -> bool:
    if ruleset.get("target") != "tag" or ruleset.get("enforcement") != "active":
        return False
    ref_condition = ruleset.get("conditions", {}).get("ref_name", {})
    included = ref_condition.get("include", [])
    excluded = ref_condition.get("exclude", [])
    return any(_pattern_matches(pattern, ref) for pattern in included) and not any(
        _pattern_matches(pattern, ref) for pattern in excluded
    )


def validate_tag_binding(
    *,
    tag: str,
    commit: str,
    tag_ref: dict[str, Any],
    annotated_tag: dict[str, Any],
    expected_tag_object_sha: str | None = None,
) -> str:
    expected_ref = f"refs/tags/{tag}"
    if tag_ref.get("ref") != expected_ref:
        raise ReleaseGateError(f"remote ref does not resolve to {expected_ref}")
    object_data = tag_ref.get("object", {})
    if object_data.get("type") != "tag" or not object_data.get("sha"):
        raise ReleaseGateError("release ref must be an annotated tag; lightweight tags are rejected")
    tag_object_sha = object_data["sha"]
    if expected_tag_object_sha is not None and tag_object_sha != expected_tag_object_sha:
        raise ReleaseGateError("release tag object changed after the initial gate")
    if annotated_tag.get("tag") != tag:
        raise ReleaseGateError("annotated tag name does not match the release tag")
    if annotated_tag.get("sha") != object_data["sha"]:
        raise ReleaseGateError("annotated tag object does not match the remote tag ref")
    target = annotated_tag.get("object", {})
    if target.get("type") != "commit" or target.get("sha") != commit:
        raise ReleaseGateError("annotated tag does not point directly to the workflow commit")
    verification = annotated_tag.get("verification", {})
    if verification.get("verified") is not True or verification.get("reason") != "valid":
        raise ReleaseGateError(
            f"annotated tag signature is not valid: {verification.get('reason', 'unknown')}"
        )
    return tag_object_sha


def validate_remote_release(
    *,
    tag: str,
    commit: str,
    tag_ref: dict[str, Any],
    annotated_tag: dict[str, Any],
    default_branch_ref: dict[str, Any],
    rulesets: list[dict[str, Any]],
    existing_release: dict[str, Any] | None,
) -> str:
    expected_ref = f"refs/tags/{tag}"
    tag_object_sha = validate_tag_binding(
        tag=tag,
        commit=commit,
        tag_ref=tag_ref,
        annotated_tag=annotated_tag,
    )
    default_object = default_branch_ref.get("object", {})
    if (
        default_branch_ref.get("ref") != "refs/heads/main"
        or default_object.get("type") != "commit"
        or default_object.get("sha") != commit
    ):
        raise ReleaseGateError("release commit must be the current protected main branch head")
    if existing_release:
        raise ReleaseGateError(f"a release already exists for {tag}; immutable candidates cannot be replaced")

    applicable = [ruleset for ruleset in rulesets if ruleset_applies(ruleset, expected_ref)]
    if len(applicable) != 1:
        raise ReleaseGateError(
            f"release tag must be covered by exactly one active tag ruleset; found {len(applicable)}"
        )

    ruleset = applicable[0]
    rules = ruleset.get("rules")
    if not isinstance(rules, list) or any(
        not isinstance(rule, dict) or not isinstance(rule.get("type"), str) for rule in rules
    ):
        raise ReleaseGateError("the applicable tag ruleset has an invalid rules list")
    missing = sorted(REQUIRED_TAG_RULES - {rule["type"] for rule in rules})
    if missing:
        raise ReleaseGateError(
            "the applicable tag ruleset is missing required protections: " + ", ".join(missing)
        )

    # GitHub intentionally omits bypass_actors unless the API caller has write
    # access to the ruleset. The least-privilege Actions token cannot see it;
    # maintainer preflight validates the setting with an admin-scoped token.
    if "bypass_actors" not in ruleset:
        return tag_object_sha

    bypass_actors = ruleset["bypass_actors"]
    if not isinstance(bypass_actors, list):
        raise ReleaseGateError("the applicable tag ruleset has an invalid bypass_actors list")
    if len(bypass_actors) != 1:
        raise ReleaseGateError(
            f"the applicable tag ruleset must have exactly one bypass actor; found {len(bypass_actors)}"
        )
    actor = bypass_actors[0]
    if not isinstance(actor, dict) or (
        actor.get("actor_type"),
        actor.get("actor_id"),
        actor.get("bypass_mode"),
    ) != ("RepositoryRole", 5, "always"):
        raise ReleaseGateError(
            "the applicable tag ruleset bypass must be RepositoryRole actor_id 5 in always mode"
        )
    return tag_object_sha


def validate_generated_assets(root: Path, paths: list[str]) -> None:
    diff = subprocess.run(
        ["git", "diff", "--exit-code", "--", *paths],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    status = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=all", "--", *paths],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    if diff.returncode != 0 or status.stdout.strip():
        details = "\n".join(part.strip() for part in (diff.stdout, status.stdout) if part.strip())
        raise ReleaseGateError(f"generated release assets are dirty:\n{details}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Fail closed unless a release tag is trusted and consistent."
    )
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--tag", required=True)
    parser.add_argument("--ref", required=True)
    parser.add_argument("--ref-type", required=True)
    parser.add_argument("--event-name", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--tag-ref-json", type=Path, required=True)
    parser.add_argument("--annotated-tag-json", type=Path, required=True)
    parser.add_argument("--default-branch-ref-json", type=Path, required=True)
    parser.add_argument("--rulesets-json", type=Path, required=True)
    parser.add_argument("--existing-release-json", type=Path, required=True)
    parser.add_argument("--generated-path", action="append", default=[])
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    root = args.root.resolve()
    version = validate_local_release(
        pyproject=root / "pyproject.toml",
        changelog=root / "CHANGELOG.md",
        tag=args.tag,
        ref=args.ref,
        ref_type=args.ref_type,
        event_name=args.event_name,
    )
    validate_generated_assets(root, args.generated_path)
    tag_object_sha = validate_remote_release(
        tag=args.tag,
        commit=args.commit,
        tag_ref=load_json(args.tag_ref_json),
        annotated_tag=load_json(args.annotated_tag_json),
        default_branch_ref=load_json(args.default_branch_ref_json),
        rulesets=load_json(args.rulesets_json),
        existing_release=load_json(args.existing_release_json) or None,
    )
    print(
        json.dumps(
            {
                "commit": args.commit,
                "tag": args.tag,
                "tag_object_sha": tag_object_sha,
                "version": version,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
