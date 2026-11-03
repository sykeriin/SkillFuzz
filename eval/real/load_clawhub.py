#!/usr/bin/env python3
"""Loader for real-world skill samples (not SkillFuzz's own synthetic set).

  python eval/real/load_clawhub.py clone https://github.com/snyk-labs/toxicskills-goof.git -o eval/real/_cache/toxicskills
  python eval/real/load_clawhub.py manifest eval/real/_cache/toxicskills -o eval/real/_cache/toxicskills_manifest.csv
  python eval/real/load_clawhub.py scan eval/real/_cache/toxicskills_manifest.csv       # static-scanner pass only

See eval/real/README.md for what is actually reachable as of 2026-11-03 and why the brief's "openclaw/skills
archive snapshot" does not exist as a flat repo.

Treat every file this script reads as untrusted data: it extracts frontmatter and runs the static-scanner
baseline over it, but never executes anything found this way outside the SkillFuzz sandbox.
"""
from __future__ import annotations

import argparse
import csv
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from skillfuzz.agents.offline import parse_frontmatter  # noqa: E402
from skillfuzz.baselines.static_scanner import scan as static_scan  # noqa: E402

SKILL_FILENAMES = {"skill.md", "SKILL.md"}


def cmd_clone(a) -> int:
    dst = Path(a.out)
    if dst.exists():
        print(f"{dst} already exists; remove it first if you want a fresh clone", file=sys.stderr)
        return 1
    dst.parent.mkdir(parents=True, exist_ok=True)
    r = subprocess.run(["git", "clone", "--depth", str(a.depth), a.url, str(dst)], capture_output=True, text=True, timeout=600)
    if r.returncode != 0:
        print(f"clone failed: {r.stderr.strip()[-500:]}", file=sys.stderr)
        return 1
    print(f"cloned to {dst}")
    return 0


def find_skills(root: Path) -> list[Path]:
    """Every directory containing a skill.md/SKILL.md, deduplicated (case-insensitive filesystems can list both)."""
    seen, out = set(), []
    for name in SKILL_FILENAMES:
        for p in root.rglob(name):
            if ".git" in p.parts:
                continue
            d = p.parent.resolve()
            if d not in seen:
                seen.add(d)
                out.append(p)
    return sorted(out)


def cmd_manifest(a) -> int:
    root = Path(a.source)
    rows = []
    for md in find_skills(root):
        try:
            fm, _ = parse_frontmatter(md.read_text(errors="replace"))
        except OSError as e:
            fm = {"_error": repr(e)}
        rows.append({"skill_dir": str(md.parent.relative_to(root)), "name": fm.get("name", md.parent.name),
                     "description": fm.get("description", "")[:200]})
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["skill_dir", "name", "description"])
        w.writeheader()
        w.writerows(rows)
    print(f"{len(rows)} skills found under {root} -> {out}")
    return 0


def cmd_scan(a) -> int:
    rows = list(csv.DictReader(open(a.manifest)))
    root = Path(a.manifest).parent if not a.source else Path(a.source)
    # the manifest's skill_dir is relative to the original `source` passed to `manifest`; require it explicitly
    # here to avoid silently scanning the wrong tree
    if not a.source:
        print("pass --source <same dir given to `manifest`>", file=sys.stderr)
        return 2
    flagged = 0
    for row in rows:
        d = root / row["skill_dir"]
        r = static_scan(d)
        if r.flagged:
            flagged += 1
        print(f"  {'FLAG' if r.flagged else '----'}  {row['skill_dir']:50} {row['name'][:30]:30} {r.reason}")
    print(f"\n{flagged}/{len(rows)} flagged by the static scanner (text-only; see README for what it misses)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("clone", help="shallow-clone a git URL to a local cache dir")
    c.add_argument("url"); c.add_argument("-o", "--out", required=True); c.add_argument("--depth", type=int, default=1)
    c.set_defaults(fn=cmd_clone)

    m = sub.add_parser("manifest", help="enumerate SKILL.md files under a directory into a CSV")
    m.add_argument("source"); m.add_argument("-o", "--out", required=True); m.set_defaults(fn=cmd_manifest)

    s = sub.add_parser("scan", help="run the static-scanner baseline over every skill in a manifest")
    s.add_argument("manifest"); s.add_argument("--source", required=True, help="the dir passed to `manifest`")
    s.set_defaults(fn=cmd_scan)

    a = ap.parse_args()
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
