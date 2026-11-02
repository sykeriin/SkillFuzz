"""Entry point executed inside the sandbox (under strace): python -m skillfuzz.agents.inside /out/spec.json"""
from __future__ import annotations

import json
import os
import sys

from .base import AgentContext, ToolLog, Tools, HOME, PROJECT


def main(spec_path: str) -> int:
    spec = json.load(open(spec_path))
    fi, agent_spec = spec["fuzz_input"], spec.get("agent", {"name": "offline"})
    skill_name = spec.get("install_name") or os.path.basename(spec["skill_dir"].rstrip("/"))
    ctx = AgentContext(
        task=fi["task"], skill_dir=f"{HOME}/.claude/skills/{skill_name}", env=dict(os.environ),
        os_profile=fi.get("os_profile", "linux"), locale=fi.get("locale", "en_US.UTF-8"),
        git_remote=fi.get("git_remote", ""), persona=fi.get("persona", "developer"))
    log = ToolLog("/out/agent_log.jsonl")
    open("/out/agent_log.jsonl", "w").close()
    tools = Tools(log, PROJECT)
    name = agent_spec.get("name", "offline")
    if name == "offline":
        from .offline import OfflineAgent
        OfflineAgent(tools).run(ctx)
    elif name == "anthropic":
        from .anthropic_agent import AnthropicAgent
        AnthropicAgent(tools, agent_spec).run(ctx)
    else:
        print(f"unknown agent {name}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
