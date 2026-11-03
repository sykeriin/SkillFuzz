"""Verify an attestation against a skill tree and apply the version-diff policy."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from ..fingerprint.diff import DiffReport, diff
from ..fingerprint.manifest import Manifest
from ..models import Fingerprint
from ..util import tree_digest
from . import dsse
from .statement import PREDICATE_TYPE

DEFAULT_ATTESTATION = Path(".skillfuzz") / "attestation.json"

# exit codes shared by `skillfuzz verify` and `skillfuzz install`
OK, GROWTH, MALICIOUS, INVALID = 0, 1, 2, 3


@dataclass
class Verification:
    exit_code: int
    reason: str
    fingerprint: Fingerprint | None = None
    report: DiffReport | None = None

    @property
    def ok(self) -> bool:
        return self.exit_code == OK


def find_attestation(skill_dir: Path, explicit: str | Path | None = None) -> Path | None:
    p = Path(explicit) if explicit else Path(skill_dir) / DEFAULT_ATTESTATION
    return p if p.exists() else None


def verify_skill(skill_dir: str | Path, pubkey: str | Path, attestation: str | Path | None = None,
                 previous: Fingerprint | None = None, allow_growth: bool = False) -> Verification:
    skill_dir = Path(skill_dir)
    att = find_attestation(skill_dir, attestation)
    if att is None:
        return Verification(INVALID, "no attestation found (expected .skillfuzz/attestation.json)")
    try:
        statement = dsse.verify(json.loads(att.read_text()), pubkey)
    except (dsse.AttestationError, json.JSONDecodeError) as e:
        return Verification(INVALID, f"attestation rejected: {e}")
    if statement.get("predicateType") != PREDICATE_TYPE:
        return Verification(INVALID, f"unexpected predicateType {statement.get('predicateType')!r}")
    subj = (statement.get("subject") or [{}])[0].get("digest", {}).get("sha256")
    actual = tree_digest(skill_dir).split(":", 1)[1]
    if subj != actual:
        return Verification(INVALID, "skill contents do not match the attested digest "
                                     f"(attested {str(subj)[:12]}..., actual {actual[:12]}...): the skill changed after attestation")
    try:
        fp = Fingerprint.model_validate(statement["predicate"]["fingerprint"])
    except Exception as e:
        return Verification(INVALID, f"unreadable fingerprint in attestation: {e}")
    report = diff(previous, fp, Manifest.load(skill_dir))
    if report.verdict == "malicious":
        return Verification(MALICIOUS, "attested behaviour includes honeytoken exfiltration", fp, report)
    if report.verdict == "undeclared_growth" and not allow_growth:
        return Verification(GROWTH, "undeclared capability growth since the pinned version", fp, report)
    return Verification(OK, "signature, digest and behaviour policy OK", fp, report)
