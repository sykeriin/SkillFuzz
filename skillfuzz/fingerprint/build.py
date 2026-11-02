from __future__ import annotations

from pathlib import Path

from ..models import EffectTrace, Fingerprint
from ..util import tree_digest

TRIVIAL_EXEC = {"sh", "bash", "dash", "env"}
IGNORE_CLASSES = {"system", "skill-self"}
LADDER = ["none", "workspace_read", "workspace_write", "network", "secret_read", "secret_exfil"]


def build_fingerprint(skill_dir: str | Path, traces: list[EffectTrace], first_taint_run: int | None = None,
                      total_coverage: int = 0, meta: dict | None = None) -> Fingerprint:
    hosts, reads, writes, secrets, tools, execs = set(), set(), set(), set(), set(), set()
    flows, remote = {}, False
    for tr in traces:
        remote |= tr.remote_instruction_fetch
        for f in tr.tainted_flows:
            flows[(f.secret_class, f.channel, f.sink)] = f
        tools.update(tr.tool_calls)
        for e in tr.events:
            if e.rclass.startswith(("net:", "dns:")):
                h = e.rclass.split(":", 1)[1]
                if h != "localhost":
                    hosts.add(h)
            elif e.rclass.startswith("exec:"):
                b = e.rclass[5:]
                if b not in TRIVIAL_EXEC:
                    execs.add(b)
            elif e.rclass.startswith("secret:"):
                if e.op in ("read", "list"):
                    secrets.add(e.rclass[7:])
            elif e.rclass not in IGNORE_CLASSES and e.kind.startswith("file_"):
                if e.op == "write":
                    writes.add(e.rclass)
                elif e.op == "read":
                    reads.add(e.rclass)
    priv = "none"
    if reads:
        priv = "workspace_read"
    if writes:
        priv = "workspace_write"
    if hosts:
        priv = "network"
    if secrets:
        priv = "secret_read"
    if flows:
        priv = "secret_exfil"
    return Fingerprint(
        skill=Path(skill_dir).name, skill_digest=tree_digest(skill_dir), hosts=sorted(hosts), file_reads=sorted(reads),
        file_writes=sorted(writes), secret_classes=sorted(secrets), tools=sorted(tools), exec_binaries=sorted(execs),
        remote_instruction_fetch=remote, tainted_flows=list(flows.values()), max_privilege=priv, runs=len(traces),
        coverage=total_coverage, first_taint_run=first_taint_run, meta=meta or {})
