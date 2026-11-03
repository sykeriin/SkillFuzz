"""Installer hook: fetch -> verify -> diff against the installed/pinned version -> install or refuse."""
from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

from ..models import Fingerprint
from .verify import INVALID, Verification, find_attestation, verify_skill
from . import dsse
import json


def _fetch(source: str, workdir: Path) -> Path:
    if Path(source).is_dir():
        dst = workdir / Path(source).resolve().name
        shutil.copytree(source, dst, ignore=shutil.ignore_patterns(".git", "__pycache__"))
        return dst
    if source.startswith(("http://", "https://", "git@", "ssh://", "file://")) or source.endswith(".git"):
        dst = workdir / Path(source.rstrip("/")).stem
        r = subprocess.run(["git", "clone", "--depth", "1", source, str(dst)], capture_output=True, text=True, timeout=300)
        if r.returncode != 0:
            raise RuntimeError(f"git clone failed: {r.stderr.strip()[-300:]}")
        shutil.rmtree(dst / ".git", ignore_errors=True)
        return dst
    raise RuntimeError(f"source is neither a directory nor a git URL: {source}")


def installed_fingerprint(dest: Path, pubkey: str | Path) -> Fingerprint | None:
    """Fingerprint of the currently installed version, trusted only if its own attestation verifies."""
    att = find_attestation(dest)
    if att is None:
        return None
    try:
        st = dsse.verify(json.loads(att.read_text()), pubkey)
        return Fingerprint.model_validate(st["predicate"]["fingerprint"])
    except Exception:
        return None


def install(source: str, dest: str | Path, pubkey: str | Path, attestation: str | Path | None = None,
            previous: Fingerprint | None = None, allow_growth: bool = False, check_only: bool = False) -> Verification:
    """Verify `source`; unless `check_only` (or refused), copy it to `dest`.

    The reference for "growth" is, in order: an explicit `previous`, then the verified attestation of what is already
    installed at `dest`. With neither (first install) only taint and run-time instruction fetches can block.
    `allow_growth` overrides undeclared growth only; a tainted flow is never overridable.
    """
    dest = Path(dest)
    with tempfile.TemporaryDirectory(prefix="skf-install-") as td:
        try:
            staged = _fetch(source, Path(td))
        except RuntimeError as e:
            return Verification(INVALID, str(e))
        if previous is None and dest.exists():
            previous = installed_fingerprint(dest, pubkey)
        if attestation and not Path(attestation).is_absolute():
            attestation = Path(attestation).resolve()
        v = verify_skill(staged, pubkey, attestation, previous, allow_growth)
        if v.ok and not check_only:
            if dest.exists():
                shutil.rmtree(dest)
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(staged, dest)
            if attestation and not (dest / ".skillfuzz" / "attestation.json").exists():
                (dest / ".skillfuzz").mkdir(exist_ok=True)
                shutil.copy(attestation, dest / ".skillfuzz" / "attestation.json")
        return v
