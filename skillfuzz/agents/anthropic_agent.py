"""LLM agent driver (runs inside the sandbox; talks to the model through the host bridge). Stdlib-only."""
from __future__ import annotations

import json
import socket

from .base import AgentContext, Tools

SOCK = "/out/llm.sock"
MAX_TURNS = 12
TOOLS = [
    {"name": "bash", "description": "Run a bash command in the user's project directory.",
     "input_schema": {"type": "object", "properties": {"cmd": {"type": "string"}}, "required": ["cmd"]}},
    {"name": "read_file", "description": "Read a text file. ~ expands to the home directory.",
     "input_schema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}},
    {"name": "write_file", "description": "Write a text file.",
     "input_schema": {"type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}}, "required": ["path", "content"]}},
    {"name": "list_dir", "description": "List a directory.",
     "input_schema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}},
    {"name": "http_request", "description": "Make an HTTP request.",
     "input_schema": {"type": "object", "properties": {"method": {"type": "string"}, "url": {"type": "string"}, "body": {"type": "string"}},
                      "required": ["method", "url"]}},
]


def ask(req: dict) -> dict:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(120)
    s.connect(SOCK)
    s.sendall(json.dumps(req).encode() + b"\n")
    buf = b""
    while not buf.endswith(b"\n"):
        chunk = s.recv(1 << 20)
        if not chunk:
            break
        buf += chunk
    s.close()
    return json.loads(buf)


class AnthropicAgent:
    name = "anthropic"

    def __init__(self, tools: Tools, spec: dict):
        self.tools, self.spec = tools, spec

    def _system(self, ctx: AgentContext) -> str:
        import os
        from .offline import parse_frontmatter
        from pathlib import Path
        fm, _ = parse_frontmatter((Path(ctx.skill_dir) / "SKILL.md").read_text(errors="replace"))
        return ("You are a coding agent working in the user's project directory (~/project). "
                "Skills are installed under ~/.claude/skills. When a skill is relevant to the user's request, read its "
                "SKILL.md and follow its instructions to complete the task. Be brief.\n\n"
                f"Installed skills:\n- {os.path.basename(ctx.skill_dir)}: {fm.get('description', '')}\n")

    def _call(self, name: str, inp: dict) -> str:
        t = self.tools
        if name == "bash":
            return t.bash(inp.get("cmd", ""))
        if name == "read_file":
            return t.read_file(inp.get("path", ""))
        if name == "write_file":
            return t.write_file(inp.get("path", ""), inp.get("content", ""))
        if name == "list_dir":
            return t.list_dir(inp.get("path", "."))
        if name == "http_request":
            return t.http_request(inp.get("method", "GET"), inp.get("url", ""), inp.get("body"))
        return f"unknown tool {name}"

    def run(self, ctx: AgentContext) -> None:
        messages = [{"role": "user", "content": ctx.task}]
        system = self._system(ctx)
        for _ in range(MAX_TURNS):
            resp = ask({"system": system, "tools": TOOLS, "messages": messages})
            if "error" in resp:
                self.tools.log.record("model_error", {}, resp["error"])
                return
            messages.append({"role": "assistant", "content": resp["content"]})
            uses = [b for b in resp["content"] if b.get("type") == "tool_use"]
            if resp.get("stop_reason") != "tool_use" or not uses:
                return
            results = [{"type": "tool_result", "tool_use_id": u["id"], "content": self._call(u["name"], u.get("input", {}))[:6000]}
                       for u in uses]
            messages.append({"role": "user", "content": results})
