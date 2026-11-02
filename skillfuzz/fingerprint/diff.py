"""Version differ. Flags capability growth that the manifest does not declare; any tainted flow is malicious."""
from __future__ import annotations

from dataclasses import dataclass, field

from ..models import Fingerprint
from .manifest import Manifest

SEVERITY = {"taint": "critical", "remote_fetch": "high", "host": "high", "secret": "high",
            "tool": "medium", "exec": "medium", "file_write": "medium", "file_read": "low"}
BLOCKING = {"critical", "high", "medium"}


@dataclass
class Finding:
    kind: str
    item: str
    severity: str
    declared: bool
    detail: str = ""


@dataclass
class DiffReport:
    verdict: str                                  # ok | undeclared_growth | malicious
    findings: list[Finding] = field(default_factory=list)
    removed: dict[str, list[str]] = field(default_factory=dict)

    @property
    def exit_code(self) -> int:
        return {"ok": 0, "undeclared_growth": 1, "malicious": 2}[self.verdict]

    def render(self) -> str:
        lines = [f"verdict: {self.verdict}"]
        for f in self.findings:
            tag = "declared" if f.declared else "UNDECLARED"
            lines.append(f"  [{f.severity:8}] {f.kind:12} {f.item}  ({tag}) {f.detail}")
        for k, v in self.removed.items():
            if v:
                lines.append(f"  [removed ] {k}: {', '.join(v)}")
        return "\n".join(lines)


def _declared(kind: str, item: str, m: Manifest | None) -> bool:
    if m is None:
        return False
    if kind == "host":
        return m.allows_host(item)
    return item in {"secret": m.secrets, "tool": m.tools, "exec": m.exec, "file_write": m.file_writes,
                    "file_read": m.file_reads}.get(kind, [])


def diff(old: Fingerprint | None, new: Fingerprint, manifest: Manifest | None = None) -> DiffReport:
    base = old or Fingerprint(skill=new.skill, skill_digest="")
    # first attestation with no manifest: nothing to compare against, so only taint can fail it
    first_no_manifest = old is None and manifest is None
    findings: list[Finding] = []
    for f in new.tainted_flows:
        findings.append(Finding("taint", f"{f.secret_class} -> {f.sink}", "critical", False,
                                f"via {f.channel} {f.detail}".strip()))
    if new.remote_instruction_fetch and not (manifest and manifest.remote_instruction_fetch):
        findings.append(Finding("remote_fetch", "instructions fetched at run time", "high", False,
                                "pin by content hash or declare it"))
    groups = [("host", new.hosts, base.hosts), ("secret", new.secret_classes, base.secret_classes),
              ("tool", new.tools, base.tools), ("exec", new.exec_binaries, base.exec_binaries),
              ("file_write", new.file_writes, base.file_writes), ("file_read", new.file_reads, base.file_reads)]
    for kind, now, before in groups:
        for item in sorted(set(now) - set(before)):
            findings.append(Finding(kind, item, SEVERITY[kind], _declared(kind, item, manifest)))
    removed = {kind: sorted(set(before) - set(now)) for kind, now, before in groups}
    if any(f.kind == "taint" for f in findings):
        verdict = "malicious"
    elif first_no_manifest:
        # nothing to compare against, so only hazards that are bad regardless of baseline can fail it
        verdict = "undeclared_growth" if any(f.kind == "remote_fetch" for f in findings) else "ok"
    elif any(f.severity in BLOCKING and not f.declared for f in findings):
        verdict = "undeclared_growth"
    else:
        verdict = "ok"
    if first_no_manifest:
        for f in findings:
            f.detail = (f.detail + " baseline (no previous version, no manifest)").strip()
    return DiffReport(verdict, findings, removed)
