"""Shared schemas. Everything that crosses a process or file boundary is defined here."""
from __future__ import annotations

import hashlib
import json
from typing import Any

from pydantic import BaseModel, Field


class FuzzInput(BaseModel):
    """One point in the (task, persona, environment) search space."""

    task: str
    persona: str = "developer"          # developer | finance | admin
    env_vars: dict[str, str] = Field(default_factory=dict)
    clock: str | None = None            # ISO date (YYYY-MM-DD) the sandbox clock is moved to
    os_profile: str = "linux"           # linux | macos (affects uname shim + OSTYPE)
    locale: str = "en_US.UTF-8"
    git_remote: str = "git@github.com:example-user/demo-project.git"
    cwd_kind: str = "repo"              # repo | empty

    def key(self) -> str:
        blob = json.dumps(self.model_dump(), sort_keys=True)
        return hashlib.sha256(blob.encode()).hexdigest()[:12]

    def describe(self) -> str:
        bits = [f"task={self.task!r}", f"persona={self.persona}"]
        if self.env_vars:
            bits.append("env=" + ",".join(f"{k}={v}" for k, v in sorted(self.env_vars.items())))
        if self.clock:
            bits.append(f"clock={self.clock}")
        if self.os_profile != "linux":
            bits.append(f"os={self.os_profile}")
        if not self.locale.startswith("en_US"):
            bits.append(f"locale={self.locale}")
        if "example-user" not in self.git_remote:
            bits.append(f"remote={self.git_remote}")
        return " ".join(bits)


class Event(BaseModel):
    """A normalised effect. `actor` is who did it, `rclass` what kind of resource, `op` what was done."""

    kind: str                           # file_read file_write exec connect dns http tool_call
    actor: str                          # "agent" or a process basename (python3, curl, bash...)
    rclass: str                         # secret:aws, workspace, home, tmp, net:<host>, dns:<host>, exec:<bin> ...
    op: str                             # read write exec connect resolve send call
    detail: str = ""
    ts: float = 0.0

    def triple(self) -> str:
        return f"{self.actor}|{self.rclass}|{self.op}"


class TaintedFlow(BaseModel):
    secret_class: str
    channel: str                        # http_body | http_url | dns | tls_unreadable | file
    sink: str                           # host or file path
    detail: str = ""


class EffectTrace(BaseModel):
    fuzz_input: FuzzInput
    run_id: str
    events: list[Event] = Field(default_factory=list)
    tainted_flows: list[TaintedFlow] = Field(default_factory=list)
    exposures: list[str] = Field(default_factory=list)       # secret markers visible in agent output (informational)
    tool_calls: list[str] = Field(default_factory=list)
    script_coverage: list[str] = Field(default_factory=list)  # "file:line" and "file:a->b" arcs from coverage.py
    remote_instruction_fetch: bool = False
    exit_code: int | None = None
    timed_out: bool = False
    duration_s: float = 0.0
    error: str | None = None

    def coverage_set(self) -> set[str]:
        cov = {e.triple() for e in self.events}
        cov.update(f"script|{c}" for c in self.script_coverage)
        cov.update(f"taint|{t.secret_class}|{t.channel}" for t in self.tainted_flows)
        return cov


class Fingerprint(BaseModel):
    """Union of observed capabilities over all fuzz runs of one skill version."""

    skill: str
    skill_digest: str
    hosts: list[str] = Field(default_factory=list)
    file_reads: list[str] = Field(default_factory=list)       # resource classes, never raw paths
    file_writes: list[str] = Field(default_factory=list)
    secret_classes: list[str] = Field(default_factory=list)   # secrets read
    tools: list[str] = Field(default_factory=list)            # agent tool names used
    exec_binaries: list[str] = Field(default_factory=list)
    remote_instruction_fetch: bool = False
    tainted_flows: list[TaintedFlow] = Field(default_factory=list)
    max_privilege: str = "none"
    runs: int = 0
    coverage: int = 0
    first_taint_run: int | None = None
    meta: dict[str, Any] = Field(default_factory=dict)
