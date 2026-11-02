"""Declared-capabilities manifest (like Android permissions). `skillfuzz.toml` in the skill root:

    [capabilities]
    network = ["api.github.com"]         # host or parent domain
    secrets = ["dotenv"]                 # secret classes the skill may read
    exec = ["git", "python3"]
    file_writes = ["workspace"]
    tools = ["bash", "read_file"]
    remote_instruction_fetch = false
"""
from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Manifest:
    network: list[str] = field(default_factory=list)
    secrets: list[str] = field(default_factory=list)
    exec: list[str] = field(default_factory=list)
    file_writes: list[str] = field(default_factory=list)
    file_reads: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    remote_instruction_fetch: bool = False

    def allows_host(self, host: str) -> bool:
        h = host.lower()
        return any(h == d.lower() or h.endswith("." + d.lower()) for d in self.network)

    @classmethod
    def load(cls, path: str | Path) -> "Manifest | None":
        p = Path(path)
        if p.is_dir():
            p = p / "skillfuzz.toml"
        if not p.exists():
            return None
        caps = tomllib.loads(p.read_text()).get("capabilities", {})
        return cls(**{k: caps[k] for k in cls.__dataclass_fields__ if k in caps})
