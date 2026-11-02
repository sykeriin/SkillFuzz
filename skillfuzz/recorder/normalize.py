"""Turn one sandbox run directory into an EffectTrace."""
from __future__ import annotations

import base64
import json
import re
import urllib.parse
from pathlib import Path

from ..models import EffectTrace, Event, FuzzInput, TaintedFlow
from ..sandbox.honeytokens import EXTRA_SECRET_PATHS, SECRET_FILES, Honeytokens
from . import strace
from .taint import TaintScanner

HOME = "/home/agent"
SYSTEM_PREFIXES = ("/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc", "/proc", "/sys", "/dev", "/opt/skf", "/opt/skillfuzz", "/out", "/run", "/var/lib", "/var/cache")
SECRET_DIRS = {".ssh": "ssh", ".aws": "aws", ".docker": "docker", ".config/gh": "gh", ".config/solana": "wallet",
               ".npmrc": "npm", ".config/chromium": "browser_cookies", ".config/google-chrome": "browser_cookies",
               ".mozilla": "browser_cookies"}
REMOTE_SUFFIXES = (".md", ".sh", ".py", ".js", ".txt", ".yaml", ".yml", ".json", ".ps1")
PIPE_SH = re.compile(r"(curl|wget)[^|;]*\|\s*(ba|z)?sh")
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def classify_path(path: str, skill_name: str) -> str:
    path = re.sub(r"/+", "/", path)
    if path.startswith(f"{HOME}/.claude/skills/{skill_name}"):
        return "skill-self"
    if any(path == p or path.startswith(p + "/") for p in SYSTEM_PREFIXES):
        return "system"
    if path == "/tmp" or path.startswith("/tmp/"):
        return "tmp"
    if path == HOME or path.startswith(HOME + "/"):
        rel = path[len(HOME):].lstrip("/")
        for cls, (p, _) in SECRET_FILES.items():
            if rel == p:
                return f"secret:{cls}"
        if rel in EXTRA_SECRET_PATHS:
            return f"secret:{EXTRA_SECRET_PATHS[rel]}"
        base = rel.rsplit("/", 1)[-1]
        if base == ".env" or (base.startswith(".env.") and base not in (".env.example", ".env.sample", ".env.template")):
            return "secret:dotenv"
        for d, cls in SECRET_DIRS.items():
            if rel == d or rel.startswith(d + "/"):
                return f"secret:{cls}"
        if rel.startswith("project"):
            return "workspace"
        if base in (".bash_history", ".zsh_history"):
            return "home:shell-history"
        if rel.startswith((".claude/skills", ".claude/plugins")):
            return "other-skills"
        if rel.startswith(("Documents", "Downloads", "Desktop")):
            return "home:user-docs"
        return "home:dotfile" if base.startswith(".") else "home:other"
    return "other"


def _load_net(path: Path) -> list[dict]:
    recs = []
    if path.exists():
        for ln in path.read_text().splitlines():
            try:
                recs.append(json.loads(ln))
            except json.JSONDecodeError:
                pass
    return recs


def _coverage(out: Path, skill_name: str) -> list[str]:
    cov: list[str] = []
    try:
        import coverage
    except ImportError:
        return cov
    prefix = f"{HOME}/.claude/skills/{skill_name}/"
    for f in sorted((out / "cov").glob(".coverage*")):
        try:
            cd = coverage.CoverageData(basename=str(f))
            cd.read()
            for fn in cd.measured_files():
                if not fn.startswith(prefix):
                    continue
                rel = fn[len(prefix):]
                arcs = cd.arcs(fn)
                if arcs:
                    cov.extend(f"{rel}:{a}->{b}" for a, b in arcs)
                else:
                    cov.extend(f"{rel}:{ln}" for ln in (cd.lines(fn) or []))
        except Exception:
            continue
    return sorted(set(cov))


def build_trace(out_dir: str | Path, fi: FuzzInput, run_id: str) -> EffectTrace:
    out = Path(out_dir)
    result = json.loads((out / "result.json").read_text()) if (out / "result.json").exists() else {}
    skill_name = result.get("skill_name", "skill")
    markers = json.loads((out / "honeytokens.json").read_text()) if (out / "honeytokens.json").exists() else {}
    tokens = Honeytokens(run_id, markers)
    scanner = TaintScanner(tokens)
    net = _load_net(out / "net.jsonl")
    ipmap: dict[str, str] = {}
    for r in net:
        if r.get("type") == "ipmap":
            ipmap = r.get("map", {})
    for r in net:                                             # in case the final ipmap record is missing
        if r.get("type") == "dns" and r.get("ip"):
            ipmap.setdefault(r["ip"], r["name"])

    tr = EffectTrace(fuzz_input=fi, run_id=run_id, exit_code=result.get("exit_code"),
                     timed_out=result.get("timed_out", False), duration_s=result.get("duration_s", 0.0))
    ev = tr.events
    secrets_read: set[str] = set()

    # ---- syscalls -----------------------------------------------------------------
    for r in strace.parse(str(out / "strace.txt")):
        if r.kind in ("open", "stat", "mutate"):
            cls = classify_path(r.path, skill_name)
            if cls == "system":
                continue
            if r.kind == "open":
                op = "list" if r.listing else ("write" if r.write else "read")
            else:
                op = "stat" if r.kind == "stat" else "write"
            if op == "read" and cls.startswith("secret:"):
                secrets_read.add(cls.split(":", 1)[1])
            ev.append(Event(kind="file_" + ("write" if op == "write" else "read"), actor=r.actor, rclass=cls, op=op,
                            detail=r.path, ts=r.ts))
        elif r.kind == "exec":
            b = r.path.rsplit("/", 1)[-1]
            if b in ("strace", "env") or r.path.startswith("/opt/skf/shims") and False:
                continue
            ev.append(Event(kind="exec", actor=r.actor, rclass=f"exec:{b}", op="exec", detail=" ".join(r.argv)[:200], ts=r.ts))
            if PIPE_SH.search(" ".join(r.argv)):
                tr.remote_instruction_fetch = True
        elif r.kind == "connect":
            if r.ip in ("127.0.0.1", "::1") and r.port == 53:
                continue
            if r.ip.startswith("127.10."):
                host = ipmap.get(r.ip, r.ip)
            elif r.ip in ("127.0.0.1", "::1"):
                host = "localhost"
            else:
                host = f"ip:{r.ip}"
            ev.append(Event(kind="connect", actor=r.actor, rclass=f"net:{host}", op="connect",
                            detail=f"port {r.port}" + ("" if r.ok else " (failed)"), ts=r.ts))

    # ---- sinkhole log -------------------------------------------------------------
    for r in net:
        t = r.get("type")
        if t == "dns":
            name = r["name"]
            if "." not in name:
                continue
            ev.append(Event(kind="dns", actor="net", rclass=f"dns:{name}", op="resolve", ts=r["t"]))
            for cls in scanner.scan_dns(name):
                tr.tainted_flows.append(TaintedFlow(secret_class=cls, channel="dns", sink=name))
        elif t == "http":
            host, method, path = r["host"], r["method"], r["path"]
            body = base64.b64decode(r.get("body_b64", ""))
            hdrs = json.dumps(r.get("headers", {})).encode()
            op = "send" if (method in WRITE_METHODS or body) else "fetch"
            ev.append(Event(kind="http", actor="net", rclass=f"net:{host}", op=op, detail=f"{method} {path}", ts=r["t"]))
            for cls in scanner.scan(body):
                tr.tainted_flows.append(TaintedFlow(secret_class=cls, channel="http_body", sink=host, detail=f"{method} {path}"))
            for cls in scanner.scan(urllib.parse.unquote(path).encode()):
                tr.tainted_flows.append(TaintedFlow(secret_class=cls, channel="http_url", sink=host, detail=f"{method} {path}"))
            for cls in scanner.scan(hdrs):
                tr.tainted_flows.append(TaintedFlow(secret_class=cls, channel="http_header", sink=host, detail=f"{method} {path}"))
            if method == "GET" and path.split("?")[0].lower().endswith(REMOTE_SUFFIXES):
                tr.remote_instruction_fetch = True
        elif t == "tls_attempt":
            ev.append(Event(kind="connect", actor="net", rclass=f"net:{r['host']}", op="connect", detail="tls " + r.get("outcome", ""), ts=r["t"]))
            if secrets_read:
                tr.exposures.append(f"possible-exfil: TLS to {r['host']} refused our CA after reading {sorted(secrets_read)}")

    # ---- files left behind --------------------------------------------------------
    for leak in result.get("fs_leaks", []):
        tr.tainted_flows.append(TaintedFlow(secret_class=leak["secret_class"], channel="file", sink=leak["path"]))

    # ---- agent tool calls ---------------------------------------------------------
    log = out / "agent_log.jsonl"
    if log.exists():
        for ln in log.read_text().splitlines():
            try:
                c = json.loads(ln)
            except json.JSONDecodeError:
                continue
            tool = c["tool"]
            tr.tool_calls.append(tool)
            ev.append(Event(kind="tool_call", actor="agent", rclass=f"tool:{tool}", op="call",
                            detail=json.dumps(c.get("args", {}))[:160], ts=c.get("ts", 0)))
            blob = (c.get("output", "") + json.dumps(c.get("args", {}))).encode()
            for cls in scanner.scan(blob):
                if tool != "http_request":                    # http bodies are judged at the sink
                    tr.exposures.append(f"{cls} value visible in {tool} output")
            if tool == "bash" and PIPE_SH.search(c.get("args", {}).get("cmd", "")):
                tr.remote_instruction_fetch = True

    tr.script_coverage = _coverage(out, skill_name)
    tr.tainted_flows = list({(f.secret_class, f.channel, f.sink): f for f in tr.tainted_flows}.values())
    tr.exposures = sorted(set(tr.exposures))
    ev.sort(key=lambda e: e.ts)
    return tr
