from __future__ import annotations

import filecmp
from pathlib import Path


def compare_trees(public: Path, bundled: Path) -> list[str]:
    public_files = {path.relative_to(public) for path in public.rglob("*") if path.is_file()}
    bundled_files = {path.relative_to(bundled) for path in bundled.rglob("*") if path.is_file()}
    issues = [f"only public: {path}" for path in sorted(public_files - bundled_files)]
    issues.extend(f"only bundled: {path}" for path in sorted(bundled_files - public_files))
    for relative in sorted(public_files.intersection(bundled_files)):
        if not filecmp.cmp(public / relative, bundled / relative, shallow=False):
            issues.append(f"content differs: {relative}")
    return issues


if __name__ == "__main__":
    root = Path(__file__).resolve().parents[1]
    issues = [
        *compare_trees(root / "adapters", root / "src/white_hat_agent/builtin_adapters"),
        *compare_trees(root / "corpus" / "playbooks", root / "src/white_hat_agent/builtin_corpus"),
        *compare_trees(root / "capabilities", root / "src/white_hat_agent/builtin_capabilities"),
    ]
    if issues:
        raise SystemExit("built-in asset drift:\n" + "\n".join(issues))
    print("built-in assets match public sources")
