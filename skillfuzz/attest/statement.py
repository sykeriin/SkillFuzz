"""in-toto Statement v1 with a SkillFuzz behaviour predicate."""
from __future__ import annotations

import datetime as dt
import subprocess
from pathlib import Path

from ..models import Fingerprint
from ..util import tree_digest

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://skillfuzz.dev/attestation/behavior/v0.1"
TOOL_VERSION = "0.1.0"


def git_commit(skill_dir: str | Path) -> str | None:
    try:
        r = subprocess.run(["git", "-C", str(skill_dir), "rev-parse", "HEAD"], capture_output=True, text=True, timeout=10)
        return r.stdout.strip() if r.returncode == 0 else None
    except Exception:
        return None


def build_statement(skill_dir: str | Path, fp: Fingerprint, fuzz_config: dict | None = None) -> dict:
    skill_dir = Path(skill_dir)
    digest = tree_digest(skill_dir)
    if fp.skill_digest and fp.skill_digest != digest:
        raise ValueError("fingerprint was produced from different skill contents than the tree being attested "
                         f"({fp.skill_digest[:19]}... vs {digest[:19]}...). Re-run `skillfuzz fuzz`.")
    subject = {"name": skill_dir.resolve().name, "digest": {"sha256": digest.split(":", 1)[1]}}
    commit = git_commit(skill_dir)
    if commit:
        subject["annotations"] = {"git_commit": commit}
    return {
        "_type": STATEMENT_TYPE,
        "subject": [subject],
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "fingerprint": fp.model_dump(),
            "fuzz": fuzz_config or fp.meta,
            "tool": {"name": "skillfuzz", "version": TOOL_VERSION},
            "created": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        },
    }
