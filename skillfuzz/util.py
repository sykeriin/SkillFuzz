from __future__ import annotations

import hashlib
import os
from pathlib import Path

_TWO_PART_TLDS = {"co.uk", "com.au", "co.in", "co.jp", "com.br"}


def registrable(host: str) -> str:
    host = host.strip().lower().rstrip(".")
    parts = host.split(".")
    if len(parts) <= 2 or host.replace(".", "").isdigit():
        return host
    if ".".join(parts[-2:]) in _TWO_PART_TLDS:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def tree_digest(root: str | Path) -> str:
    """sha256 over sorted (relative path, file hash) pairs. Ignores .git and fuzz artefacts."""
    root = Path(root)
    h = hashlib.sha256()
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root)
        if any(part in {".git", "__pycache__", ".skillfuzz"} for part in rel.parts) or not p.is_file():
            continue
        h.update(str(rel).encode() + b"\0")
        h.update(hashlib.sha256(p.read_bytes()).digest())
    return "sha256:" + h.hexdigest()


def env_bool(name: str) -> bool:
    return os.environ.get(name, "").lower() in {"1", "true", "yes"}
