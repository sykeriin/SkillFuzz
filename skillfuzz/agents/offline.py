"""OfflineAgent - a deterministic stand-in for an LLM agent. Stdlib-only (runs inside the sandbox).

It does what a *compliant* agent would do with a skill:
  * activates the skill only if the task overlaps the skill's trigger words,
  * executes fenced bash/python blocks in the skill's instruction sections,
  * follows plain imperative lines ("read X", "upload X to URL", "fetch URL", "run `cmd`"),
  * honours conditional lines ("If the task mentions 'deploy', ...", "When CI=true, ...", "after 2027-01-15",
    "if the git remote contains acme-corp") using the facts in the AgentContext.

It is much weaker than a real LLM (no paraphrase understanding), which is why results with it demonstrate the
mechanism, not detection performance. Use the Anthropic driver for real measurements.
"""
from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass, field

from .base import AgentContext, Tools

STOP = set("""this that with from your their have will when then into only also each such using used uses use
the and for are not can any all out one two get set new may must more most other some than them these those
would could should about after before while where which what skill skills user users task tasks please make
need needs want wants help helps just like over under again very much many""".split())
RUN_HEADINGS = ("usage", "steps", "instructions", "workflow", "how to", "run", "procedure", "setup", "process", "quick start", "overview", "when")
COND_RE = re.compile(
    r"^\s*(?:[-*>]\s*|\d+\.\s*)?(?:\*\*)?(?:only\s+)?(?P<kw>if|when|whenever|once|in case|after)\b\s*(?P<cond>.*?)\s*(?:,|:|;| - | — |\bthen\b)\s*(?P<rest>.*)$",
    re.I)
NEG_RE = re.compile(r"\b(never|do not|don't|must not|should not|avoid)\b", re.I)
URL = r"<?(?P<url>https?://[^\s)>\"'`]+)"
SEND_RE = re.compile(r"\b(?:send|upload|post|submit|forward|transmit|exfiltrate|copy)\s+(?P<what>.+?)\s+(?:to|at)\s+" + URL, re.I)
FETCH_RE = re.compile(r"\b(?:fetch|download|retrieve|load|pull)\b[^.\n]*?" + URL, re.I)
READ_RE = re.compile(r"\b(?:read|cat|open|inspect)\s+(?:the\s+)?(?:file\s+)?`?(?P<path>(?:~|/|\.)[\w./~-]+)`?", re.I)
RUN_RE = re.compile(r"\brun\s+`(?P<cmd>[^`]+)`", re.I)
PATHISH = re.compile(r"(~/[\w./-]+|\.env\b|`[^`]+`)")
SEQUENCE_WORDS = ("finish", "done", "complete", "start", "begin", "ready", "asked", "needed", "request", "invoked", "activated", "user wants")


def words(s: str) -> set[str]:
    return {w.rstrip("s") for w in re.findall(r"[a-z]{4,}", s.lower())} - STOP


def parse_frontmatter(text: str) -> tuple[dict, str]:
    if text.startswith("---"):
        parts = text.split("---", 2)
        if len(parts) >= 3:
            fm = {}
            for ln in parts[1].splitlines():
                k, _, v = ln.partition(":")
                if v.strip():
                    fm[k.strip().lower()] = v.strip().strip("'\"")
            return fm, parts[2]
    return {}, text


@dataclass
class Item:
    kind: str                 # "code" | "text"
    content: str
    lang: str = ""
    cond: str | None = None


@dataclass
class Section:
    heading: str
    items: list[Item] = field(default_factory=list)


def parse_sections(body: str) -> list[Section]:
    sections = [Section("")]
    in_fence, lang, buf, block_cond, pending = False, "", [], None, None
    for line in body.splitlines():
        s = line.strip()
        if in_fence:
            if s.startswith("```"):
                sections[-1].items.append(Item("code", "\n".join(buf), lang, block_cond))
                in_fence, buf, pending = False, [], None
            else:
                buf.append(line)
            continue
        if s.startswith("```"):
            in_fence, lang, buf, block_cond = True, s[3:].strip().lower(), [], pending
            continue
        if re.match(r"^#{1,6}\s", s):
            sections.append(Section(s.lstrip("# ").strip()))
            pending = None
            continue
        if not s:
            continue
        s = re.sub(r"<!--|-->", "", s).strip()          # agents read HTML comments too
        if not s:
            continue
        m = COND_RE.match(s)
        if m:
            cond, rest = (m.group("kw") + " " + m.group("cond")).strip(), m.group("rest").strip()
            if rest:
                sections[-1].items.append(Item("text", rest, cond=cond))
            # a condition only carries over to the next fenced block if the line ends in "run:" style (or is bare)
            pending = cond if (not rest or rest.rstrip().endswith(":")) else None
        else:
            sections[-1].items.append(Item("text", s))
            pending = None
    return sections


def eval_cond(text: str, ctx: AgentContext) -> bool | None:
    t = text.lower()
    res: list[bool] = []
    for m in re.finditer(r"(?:mentions?|contains?|includes?|asks? (?:about|for)|says|references?|involves?)\s+[\"'“‘`]([^\"'”’`]+)[\"'”’`]", t):
        res.append(m.group(1) in ctx.task.lower())
    for m in re.finditer(r"\b([A-Z][A-Z0-9_]+)\s*(?:=|==|is set to|equals)\s*[\"']?([\w.-]+)", text):
        res.append(ctx.env.get(m.group(1), "").lower() == m.group(2).lower())
    for m in re.finditer(r"\$?\{?\b([A-Z][A-Z0-9_]+)\}?\s+(?:is set|is defined|exists|is non-?empty|is present)", text):
        res.append(bool(ctx.env.get(m.group(1))))
    if re.search(r"\b(?:in|inside|under)\s+(?:a\s+)?(?:ci|continuous integration)\b|ci (?:environment|pipeline|mode)", t):
        res.append(any(ctx.env.get(k) for k in ("CI", "GITHUB_ACTIONS", "JENKINS_URL", "GITLAB_CI")))
    if re.search(r"\bproduction\b|\bprod\b", t) and not re.search(r"mentions?", t):
        res.append(any("prod" in v.lower() for v in ctx.env.values()))
    for m in re.finditer(r"git remote[^,;:]*?(?:contains|matches|includes|is|points to|has)\s+[\"'`]?([\w.@:/-]+)", t):
        res.append(m.group(1) in ctx.git_remote.lower())
    for m in re.finditer(r"(on or after|after|since|from|before|until)\s+(\d{4}-\d{2}-\d{2})", t):
        try:
            d = dt.date.fromisoformat(m.group(2))
        except ValueError:
            continue
        res.append(ctx.today < d if m.group(1) in ("before", "until") else ctx.today >= d)
    for m in re.finditer(r"\b(monday|tuesday|wednesday|thursday|friday|saturday|sunday)\b", t):
        res.append(ctx.today.strftime("%A").lower() == m.group(1))
    if re.search(r"\b(macos|darwin|mac os)\b", t):
        res.append(ctx.os_profile == "macos")
    elif re.search(r"\blinux\b", t):
        res.append(ctx.os_profile == "linux")
    for m in re.finditer(r"\b([a-z]{2}_[A-Z]{2})\b", text):
        res.append(ctx.locale.startswith(m.group(1)))
    langs = {"german": "de", "french": "fr", "spanish": "es", "japanese": "ja"}
    for m in re.finditer(r"language is (german|french|spanish|japanese)", t):
        res.append(ctx.locale.startswith(langs[m.group(1)]))
    if res:
        return all(res)
    return None


class OfflineAgent:
    name = "offline"

    def __init__(self, tools: Tools):
        self.tools = tools

    def run(self, ctx: AgentContext) -> None:
        from pathlib import Path
        md = Path(ctx.skill_dir) / "SKILL.md"
        if not md.exists():
            return
        fm, body = parse_frontmatter(md.read_text(errors="replace"))
        trigger = words(" ".join([fm.get("name", ""), fm.get("description", ""), fm.get("triggers", ""), fm.get("when_to_use", "")]))
        if not (words(ctx.task) & trigger):
            return                                         # a real agent would not load this skill for this task
        task_words = words(ctx.task)
        for sec in parse_sections(body):
            h = sec.heading.lower()
            if sec.heading and not (any(k in h for k in RUN_HEADINGS) or (words(h) & task_words)):
                continue
            for it in sec.items:
                if it.cond is not None:
                    ok = eval_cond(it.cond, ctx)
                    if ok is None:
                        ok = any(w in it.cond.lower() for w in SEQUENCE_WORDS)
                    if not ok:
                        continue
                if it.kind == "code":
                    self._run_code(it)
                else:
                    self._follow(it.content, ctx)

    def _run_code(self, it: Item) -> None:
        code = "\n".join(re.sub(r"^\$\s+", "", ln) for ln in it.content.splitlines())
        if it.lang in ("bash", "sh", "shell", "zsh", "console"):
            self.tools.bash(code)
        elif it.lang in ("python", "python3", "py"):
            self.tools.python(code)

    def _follow(self, line: str, ctx: AgentContext) -> None:
        if NEG_RE.search(line):
            return
        m = SEND_RE.search(line)
        if m:
            what, url = m.group("what"), m.group("url").rstrip(".,;")
            chunks = []
            for tok in PATHISH.findall(what):
                tok = tok.strip("`")
                if tok.startswith(("~", "/", ".")) or "/" in tok or "." in tok:
                    chunks.append(self.tools.read_file(tok))
            self.tools.http_request("POST", url, "\n".join(chunks) if chunks else what)
            return
        m = FETCH_RE.search(line)
        if m:
            self.tools.http_request("GET", m.group("url").rstrip(".,;"))
            return
        m = RUN_RE.search(line)
        if m:
            self.tools.bash(m.group("cmd"))
            return
        m = READ_RE.search(line)
        if m:
            self.tools.read_file(m.group("path"))
