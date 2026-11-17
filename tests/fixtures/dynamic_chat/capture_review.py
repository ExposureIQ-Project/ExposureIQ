"""Write read-only Git/snapshot diffs and protected-file evidence for review."""

from __future__ import annotations

import difflib
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).parent
BEFORE = Path("/tmp/opencode/s5-dynamic-before-zoio7mii")
TIER1 = Path("/tmp/opencode/s5-dynamic-tier1-hz_j4pug")
TIER2 = Path("/tmp/opencode/s5-dynamic-tier2-957tif5q")
UNSAVED_BASELINE = {"tests/test_stage5_evidence.py":
                    "Inherited before this task, but absent from the pre-task source snapshot. Its exact Tier 1 delta is unavailable, not reconstructed or counted as a new file."}


def git(*args):
    result = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, check=True)
    return result.stdout


def content(root, name):
    path = root / name
    return path.read_text(encoding="utf-8") if path.is_file() else ""


def main():
    original = json.loads((BEFORE / "manifest.json").read_text(encoding="utf-8"))
    first = json.loads((TIER1 / "manifest.json").read_text(encoding="utf-8"))
    second = json.loads((TIER2 / "manifest.json").read_text(encoding="utf-8"))
    for snapshot, catalog in ((BEFORE / "before", original), (TIER1 / "sources", first), (TIER2 / "sources", second)):
        for name, expected in catalog["files"].items():
            assert hashlib.sha256((snapshot / name).read_bytes()).hexdigest() == expected, name
    paths = set(original["files"]) | set(first["files"]) | set(second["files"]) | {
        "exposureiq/viewer/browser.py", "exposureiq/viewer/session.py", "tests/test_report_open.py"}
    paths = sorted(name for name in paths if name.startswith("exposureiq/") or
                   name.startswith("tests/") and (name.count("/") == 1 or name.endswith("source-provenance.json")))
    groups = []
    for tier, left, right in ((1, BEFORE / "before", TIER1 / "sources"),
                               (2, TIER1 / "sources", TIER2 / "sources"),
                               (3, TIER2 / "sources", ROOT)):
        patches, files = [], []
        for name in paths:
            if tier == 1 and name in UNSAVED_BASELINE:
                continue
            old, new = content(left, name), content(right, name)
            if old == new:
                continue
            lines = list(difflib.unified_diff(old.splitlines(keepends=True), new.splitlines(keepends=True),
                                             fromfile="a/" + name if old else "/dev/null", tofile="b/" + name if new else "/dev/null"))
            patches += ["diff --git a/" + name + " b/" + name + "\n", *lines]
            files.append({"file": name, "added": sum(line.startswith("+") and not line.startswith("+++") for line in lines),
                          "removed": sum(line.startswith("-") and not line.startswith("---") for line in lines)})
        filename = f"tier{tier}-source.patch"
        (OUT / filename).write_text("".join(patches), encoding="utf-8")
        groups.append({"tier": tier, "diff": filename, "files": files, "source_files": len(files),
                       "added": sum(item["added"] for item in files), "removed": sum(item["removed"] for item in files)})

    protected = {name: {"sha256": hashlib.sha256((ROOT / name).read_bytes()).hexdigest(), "unchanged":
                       hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == expected} for name, expected in original["protected"].items()}
    assert all(item["unchanged"] for item in protected.values())
    assert not git("diff", "--name-only", "--", ".github")
    assert not git("ls-files", "--others", "--exclude-standard", "--", ".github", "**/AGENTS.md")
    assert not git("diff", "--cached", "--name-only")
    status_path = OUT / "git-status.txt"
    status_path.touch(exist_ok=True)
    status = git("status", "--short", "--branch", "--untracked-files=all")
    status_path.write_text(status, encoding="utf-8")
    (OUT / "git-diff-stat.txt").write_text(git("diff", "--stat"), encoding="utf-8")
    (OUT / "git-working-tree.patch").write_text(git("diff"), encoding="utf-8")
    git("diff", "--check")
    # Failed pytest tracebacks can contain a temporary viewer URL. Redact only
    # those no-longer-active session fragments, retaining failures/counts.
    review_path = OUT / "review.json"
    previous = json.loads(review_path.read_text(encoding="utf-8")) if review_path.is_file() else {}
    redacted = set(previous.get("redacted_test_traces", []))
    for path in OUT.glob("*.txt"):
        raw = path.read_text(encoding="utf-8")
        safe = re.sub(r"(?<=#)[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])", "[session-redacted]", raw)
        if safe != raw:
            path.write_text(safe, encoding="utf-8")
            redacted.add(path.name)
    result = {"branch": git("branch", "--show-current").strip(), "staged": 0,
              "tracked_modified": sum(line.startswith(" M ") for line in status.splitlines()),
              "untracked": sum(line.startswith("?? ") for line in status.splitlines()), "protected": protected,
              "github_changed": False, "groups": groups, "redacted_test_traces": sorted(redacted),
              "unavailable_baseline": UNSAVED_BASELINE,
              "meaning": "Tier diffs compare preserved pre-task and green-tier snapshots. The ordinary Git diff also includes inherited tracked Stage 5 work; it omits untracked packages. No staging/commit/push/gh command ran."}
    (OUT / "review.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    lines = ["# Actual task-only source diffs", "", result["meaning"], "", "| Tier | Source/test files | Added lines | Removed lines | Full diff |", "| --- | ---: | ---: | ---: | --- |"]
    for group in groups:
        lines.append(f"| {group['tier']} | {group['source_files']} | {group['added']} | {group['removed']} | [{group['diff']}]({group['diff']}) |")
    lines += ["", "New acceptance scripts, synthetic transcripts, screenshots and documentation are listed by the full [Git status](git-status.txt); they are not hidden inside source-diff counts.", "", "## Changed source/test files"]
    for group in groups:
        lines += ["", f"### Tier {group['tier']}", ""]
        lines += [f"- `{item['file']}` (+{item['added']}/−{item['removed']})" for item in group["files"]]
    lines += ["", "## Unavailable pre-task delta", ""]
    lines += [f"- `{name}`: {reason} See [changed-tests.md](changed-tests.md) and the [current source](../../test_stage5_evidence.py)." for name, reason in UNSAVED_BASELINE.items()]
    lines += ["", "## Protected boundaries", "", "All four protected files match their pre-task hashes; `.github` has no tracked change. Nothing is staged. The existing virtual environment was reused; no dependency installation or pyproject edit was made in this task.", ""]
    (OUT / "diffs.md").write_text("\n".join(lines), encoding="utf-8")
    for group in groups:
        print(f"Tier {group['tier']}: {group['source_files']} source/test files; +{group['added']}/-{group['removed']} lines.")
    print("Protected files unchanged; Git diff --check passed; nothing staged.")


if __name__ == "__main__":
    main()
