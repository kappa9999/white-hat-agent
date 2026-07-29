from __future__ import annotations

import argparse
import json
from pathlib import Path

from release_gate import load_json, validate_tag_binding


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Revalidate an immutable release tag binding after the initial gate."
    )
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--expected-tag-object-sha", required=True)
    parser.add_argument("--tag-ref-json", type=Path, required=True)
    parser.add_argument("--annotated-tag-json", type=Path, required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    tag_object_sha = validate_tag_binding(
        tag=args.tag,
        commit=args.commit,
        tag_ref=load_json(args.tag_ref_json),
        annotated_tag=load_json(args.annotated_tag_json),
        expected_tag_object_sha=args.expected_tag_object_sha,
    )
    print(json.dumps({"commit": args.commit, "tag": args.tag, "tag_object_sha": tag_object_sha}))


if __name__ == "__main__":
    main()
