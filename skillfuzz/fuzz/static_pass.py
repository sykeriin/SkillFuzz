"""Static pre-pass ("concolic-lite"): read the skill and harvest the values its conditions compare against.

We do not solve constraints. We grep for the literals a trigger condition mentions - env var names and values,
dates, quoted keywords, git-remote fragments, locales, OS names - and hand them to the mutators as targeted values.
"""
from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass, field
from pathlib import Path

NOISE_ENV = {"HOME", "PATH", "USER", "PWD", "SHELL", "TERM", "TMPDIR", "LANG", "LC_ALL", "OLDPWD", "HOSTNAME", "EDITOR", "TZ", "LOGNAME", "IFS", "PS1", "SKF"}
TEXT_EXT = {".md", ".py", ".sh", ".bash", ".zsh", ".js", ".ts", ".json", ".yaml", ".yml", ".toml", ".txt", ""}
GENERIC_ENV = [("CI", "true"), ("GITHUB_ACTIONS", "true"), ("ENV", "production"), ("NODE_ENV", "production"),
               ("AWS_PROFILE", "prod"), ("ENVIRONMENT", "production"), ("DEPLOY_ENV", "prod")]
# NOTE: keep these disjoint from the strings the eval generators use as triggers, or the eval leaks the answer.
GENERIC_REMOTES = ["git@github.com:globex-industries/internal-app.git", "git@gitlab.corp.example.com:platform/api.git"]
GENERIC_LOCALES = ["de_DE.UTF-8", "ja_JP.UTF-8", "ru_RU.UTF-8"]
GENERIC_KEYWORDS = ["deploy", "release", "production", "publish", "backup", "credentials", "migrate"]
LANGS = {"german": "de_DE", "french": "fr_FR", "spanish": "es_ES", "japanese": "ja_JP", "russian": "ru_RU", "chinese": "zh_CN"}


@dataclass
class Dictionary:
    env: list[tuple[str, str]] = field(default_factory=list)          # targeted (name, value)
    generic_env: list[tuple[str, str]] = field(default_factory=list)
    dates: list[str] = field(default_factory=list)                    # ISO dates to move the clock to
    keywords: list[str] = field(default_factory=list)
    remotes: list[str] = field(default_factory=list)
    locales: list[str] = field(default_factory=list)
    os_hints: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)

    def targeted_size(self) -> int:
        return len(self.env) + len(self.dates) + len(self.keywords) + len(self.remotes) + len(self.locales) + len(self.os_hints)


def _read_texts(skill_dir: Path) -> list[str]:
    out = []
    for p in sorted(skill_dir.rglob("*")):
        if p.is_file() and p.suffix.lower() in TEXT_EXT and ".git" not in p.parts and p.stat().st_size < 300_000:
            try:
                out.append(p.read_text(errors="ignore"))
            except OSError:
                pass
    return out


def _uniq(xs):
    seen, out = set(), []
    for x in xs:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def analyse(skill_dir: str | Path, today: dt.date | None = None, with_generic: bool = True) -> Dictionary:
    skill_dir, today = Path(skill_dir), today or dt.date.today()
    texts = _read_texts(skill_dir)
    d = Dictionary()
    env, dates, kws, remotes, locales, oss, hosts = [], [], [], [], [], [], []
    for t in texts:
        for m in re.finditer(r"""os\.environ(?:\.get)?\s*[\[(]\s*["']([A-Z][A-Z0-9_]+)["']""", t):
            env.append((m.group(1), "true"))
        for m in re.finditer(r"""getenv\(\s*["']([A-Z][A-Z0-9_]+)["']""", t):
            env.append((m.group(1), "true"))
        for m in re.finditer(r"""\$\{?([A-Z][A-Z0-9_]{1,})\}?""", t):
            env.append((m.group(1), "true"))
        # name compared against a literal:  X == "prod", "$X" = "prod", X=true, X is set to 1
        for m in re.finditer(r"""\b([A-Z][A-Z0-9_]{1,})\}?"?\s*(?:==|=|-eq|is set to|equals)\s*["']?([\w.-]+)""", t):
            env.append((m.group(1), m.group(2)))
        # os.environ.get("NAME") == "val",  os.environ["NAME"] == "val",  [ "$NAME" = "val" ]
        for m in re.finditer(r"""["']\$?\{?([A-Z][A-Z0-9_]{1,})\}?["']\)?\]?\s*(?:==|=|!=)\s*["']([\w.-]+)["']""", t):
            env.append((m.group(1), m.group(2)))
        for m in re.finditer(r"\b(20\d{2})-(\d{2})-(\d{2})\b", t):
            dates.append(m.group(0))
        for m in re.finditer(r"\b(?:date|datetime)\(\s*(20\d{2}),\s*(\d{1,2}),\s*(\d{1,2})", t):
            dates.append(f"{m.group(1)}-{int(m.group(2)):02d}-{int(m.group(3)):02d}")
        for m in re.finditer(r"\.year\s*(?:>=|>|==)\s*(20\d{2})", t):
            dates.append(f"{m.group(1)}-01-01")
        for ln in t.splitlines():
            low = ln.lower()
            if re.search(r"\b(if|when|mention|contain|in task|in request|grep|lower\(\)|keyword|elif|while)\b", low):
                # quotes must pair with the same kind, and an apostrophe inside a word (user's) never opens one
                for _, q in re.findall(r"""(?<!\w)(["'`])([A-Za-z][\w -]{2,24})\1""", ln):
                    kws.append(q.strip().lower())
                for q in re.findall(r"“([A-Za-z][\w -]{2,24})”|‘([A-Za-z][\w -]{2,24})’", ln):
                    kws.append("".join(q).strip().lower())
            if re.search(r"remote|origin|git", low):
                for tok in re.findall(r"\b([\w-]+(?:\.[\w-]+)*\.(?:com|io|net|org|corp|internal|local))\b", ln):
                    remotes.append(tok)
                for tok in re.findall(r"\b([a-z0-9]+-(?:corp|inc|llc|labs|internal))\b", low):
                    remotes.append(tok)
        for m in re.finditer(r"\b([a-z]{2})_([A-Z]{2})\b", t):
            locales.append(f"{m.group(1)}_{m.group(2)}.UTF-8")
        for lang, code in LANGS.items():
            if re.search(rf"language is {lang}|{lang}", t, re.I):
                locales.append(code + ".UTF-8")
        if re.search(r"darwin|macos|mac os|OSTYPE|uname", t, re.I):
            oss.append("macos")
        for m in re.finditer(r"https?://([\w.-]+)", t):
            hosts.append(m.group(1).lower())
    d.env = _uniq((k, v) for k, v in env if k not in NOISE_ENV)
    # a name seen only as "true" also gets 1 and production
    extra = [(k, v) for k, _ in list(d.env) for v in ("1", "production")]
    d.env = _uniq(list(d.env) + extra)[:60]
    d.dates = _uniq(dates)
    d.keywords = _uniq(k for k in kws if k not in ("true", "false", "none"))[:40]
    d.remotes = _uniq(remotes)
    d.locales = _uniq(locales)
    d.os_hints = _uniq(oss)
    d.hosts = _uniq(hosts)
    if with_generic:
        d.generic_env = list(GENERIC_ENV)
        d.keywords = _uniq(d.keywords + GENERIC_KEYWORDS)
        d.remotes = _uniq(d.remotes + GENERIC_REMOTES)
        d.locales = _uniq(d.locales + GENERIC_LOCALES)
        d.dates = _uniq(d.dates + [(today + dt.timedelta(days=n)).isoformat() for n in (30, 90, 365, 730)])
    return d


def remote_url_for(token: str) -> str:
    if token.startswith(("git@", "http://", "https://", "ssh://")):
        return token
    if "." in token:
        return f"git@{token}:platform/app.git"
    return f"git@github.com:{token}/internal-app.git"


def clock_candidates(date_str: str) -> list[str]:
    """Static dates are usually thresholds ('after 2027-01-15'): try the day after, and the day itself."""
    try:
        d = dt.date.fromisoformat(date_str)
    except ValueError:
        return []
    return [(d + dt.timedelta(days=1)).isoformat(), d.isoformat()]


STATEFUL_RE = re.compile(r"(counter|\.count\b|run_count|invocation|times_run|launch_count|nth_run|usage_count)", re.I)


def is_stateful(skill_dir: str | Path) -> bool:
    """Heuristic: does the skill keep a counter/state between invocations? Only then do we pay for repeated runs."""
    return any(STATEFUL_RE.search(t) for t in _read_texts(Path(skill_dir)))
