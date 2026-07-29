from __future__ import annotations

import argparse
from pathlib import Path

from white_hat_agent.intelligence.artifacts import stage_run_artifact


def main() -> int:
    parser = argparse.ArgumentParser(description="Stage exact snapshots referenced by one intelligence run")
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--reports", type=Path, required=True)
    parser.add_argument("--before", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    path = stage_run_artifact(args.workspace, args.reports, args.before, args.out)
    print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
