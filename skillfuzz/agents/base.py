"""Stdlib-only (it runs inside the sandbox). Tools every agent driver uses, with every call logged."""
from __future__ import annotations

import datetime as dt
import json
import os
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

HOME = os.environ.get("HOME", "/home/agent")
PROJECT = f"{HOME}/project"
MAX_OUT = 4000


@dataclass
class AgentContext:
    task: str
    skill_dir: str
    env: dict = field(default_factory=dict)
    os_profile: str = "linux"
    locale: str = "en_US.UTF-8"
    git_remote: str = ""
    persona: str = "developer"
    today: dt.date = field(default_factory=dt.date.today)   # honours the LD_PRELOAD clock shift


class ToolLog:
    def __init__(self, path: str):
        self.path = path

    def record(self, tool: str, args: dict, output: str) -> None:
        with open(self.path, "a") as f:
            f.write(json.dumps({"tool": tool, "args": args, "output": output[:MAX_OUT], "ts": time.time()}) + "\n")


class Tools:
    def __init__(self, log: ToolLog, cwd: str = PROJECT):
        self.log, self.cwd = log, cwd if os.path.isdir(cwd) else HOME

    @staticmethod
    def expand(p: str) -> str:
        p = os.path.expanduser(p.strip())
        return p

    def bash(self, cmd: str, timeout: int = 20) -> str:
        try:
            r = subprocess.run(["bash", "-c", cmd], cwd=self.cwd, capture_output=True, text=True, timeout=timeout)
            out = (r.stdout + r.stderr)
        except subprocess.TimeoutExpired as e:
            out = f"[timeout] {(e.stdout or b'')[:500]!r}"
        except Exception as e:
            out = f"[error] {e!r}"
        self.log.record("bash", {"cmd": cmd}, out)
        return out

    def python(self, code: str, timeout: int = 20) -> str:
        p = "/tmp/_skf_block.py"
        Path(p).write_text(code)
        try:
            r = subprocess.run(["python3", p], cwd=self.cwd, capture_output=True, text=True, timeout=timeout)
            out = r.stdout + r.stderr
        except Exception as e:
            out = f"[error] {e!r}"
        self.log.record("bash", {"cmd": "python3 <block>\n" + code[:300]}, out)
        return out

    def read_file(self, path: str) -> str:
        p = self.expand(path)
        if not os.path.isabs(p):
            p = os.path.join(self.cwd, p)
        try:
            data = Path(p).read_text(errors="replace")
        except Exception as e:
            data = f"[error] {e!r}"
        self.log.record("read_file", {"path": path}, data)
        return data

    def write_file(self, path: str, content: str) -> str:
        p = self.expand(path)
        if not os.path.isabs(p):
            p = os.path.join(self.cwd, p)
        try:
            Path(p).parent.mkdir(parents=True, exist_ok=True)
            Path(p).write_text(content)
            out = "ok"
        except Exception as e:
            out = f"[error] {e!r}"
        self.log.record("write_file", {"path": path, "bytes": len(content)}, out)
        return out

    def list_dir(self, path: str = ".") -> str:
        p = self.expand(path)
        if not os.path.isabs(p):
            p = os.path.join(self.cwd, p)
        try:
            out = "\n".join(sorted(os.listdir(p)))
        except Exception as e:
            out = f"[error] {e!r}"
        self.log.record("list_dir", {"path": path}, out)
        return out

    def http_request(self, method: str, url: str, body: str | bytes | None = None) -> str:
        data = body.encode() if isinstance(body, str) else body
        req = urllib.request.Request(url, data=data, method=method.upper(),
                                     headers={"User-Agent": "agent-http/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                out = f"{r.status} " + r.read(2000).decode(errors="replace")
        except urllib.error.HTTPError as e:
            out = f"{e.code} {e.reason}"
        except Exception as e:
            out = f"[error] {e!r}"
        self.log.record("http_request", {"method": method, "url": url, "bytes": len(data or b"")}, out)
        return out
