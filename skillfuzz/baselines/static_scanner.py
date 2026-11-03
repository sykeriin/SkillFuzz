"""Static scanner baseline in the style of SkillSieve's layer 1 (regex/heuristic triage). Our own re-implementation of
the *idea*, not their code: rules over SKILL.md and scripts, flag on dangerous co-occurrences.

It reads text only, so a payload that is packed and decoded at run time is invisible to it by construction.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CATEGORIES: dict[str, tuple[int, list[str]]] = {
    "credential_access": (2, [r"\.aws/credentials", r"\.ssh/id_", r"\.npmrc", r"\.docker/config", r"(?<![\w])\.env\b(?!\.example)",
                              r"Cookies\b", r"solana/id\.json", r"wallet\.dat", r"gh/hosts\.yml", r"keychain", r"/etc/shadow"]),
    "network_send": (2, [r"curl[^\n|;]*(-d\b|--data|-X\s*POST|-F\b|--upload-file)", r"wget[^\n]*--post", r"requests\.(post|put)\(",
                         r"urlopen\(", r"urllib\.request", r"http\.client", r"socket\.(create_connection|connect)", r"\bnc\s+-"]),
    "remote_exec": (3, [r"(curl|wget)[^\n|;]*\|\s*(ba|z)?sh", r"base64\s+(-d|--decode)[^\n]*\|\s*(ba|z)?sh", r"\beval\s*\$\(\s*(curl|wget)"]),
    "decode_and_exec": (3, [r"exec\(\s*(base64|bytes|zlib|codecs)", r"exec\(\s*[\w.]*b64decode", r"eval\(\s*[\w.]*b64decode",
                            r"getattr\(__import__"]),
    "dynamic_exec": (1, [r"\bexec\(", r"\beval\(", r"compile\([^\n]*exec"]),
    "obfuscation": (2, [r"[A-Za-z0-9+/]{120,}={0,2}", r"(\\x[0-9a-fA-F]{2}){12,}", r"chr\(\d+\)\s*\+\s*chr\(\d+\)"]),
    "prompt_injection": (3, [r"ignore (all |any )?(previous|prior) instructions", r"do not (tell|inform|mention)[^.\n]*user", r"without (telling|informing|notifying)",
                             r"(silently|secretly|quietly)\s+(send|upload|post|exfiltrate|copy)", r"(upload|send|post|forward)\s+[^.\n]{0,60}(credentials|ssh key|id_ed25519|\.env|token|cookies)[^.\n]{0,60}https?://"]),
    "persistence": (2, [r"crontab\s+-", r">>\s*~?/?\.?(bashrc|zshrc|profile)", r"LaunchAgents", r"systemctl\s+(enable|--user)"]),
}
# a single category is rarely enough; dangerous pairings flag immediately
FLAG_PAIRS = [("credential_access", "network_send")]
FLAG_ALONE = {"remote_exec", "decode_and_exec", "prompt_injection"}
THRESHOLD = 5
TEXT_EXT = {".md", ".py", ".sh", ".bash", ".zsh", ".js", ".ts", ".yaml", ".yml", ".json", ".toml", ".txt", ""}


@dataclass
class ScanResult:
    flagged: bool
    score: int
    hits: dict[str, list[str]] = field(default_factory=dict)
    reason: str = ""


def scan(skill_dir: str | Path) -> ScanResult:
    root = Path(skill_dir)
    hits: dict[str, list[str]] = {}
    for p in sorted(root.rglob("*")):
        if not p.is_file() or ".git" in p.parts or p.stat().st_size > 400_000:
            continue
        if p.suffix.lower() not in TEXT_EXT:
            continue
        text = p.read_text(errors="ignore")
        for cat, (_, pats) in CATEGORIES.items():
            for pat in pats:
                if re.search(pat, text, re.I if cat == "prompt_injection" else 0):
                    hits.setdefault(cat, []).append(f"{p.relative_to(root)}: /{pat[:40]}/")
                    break
    score = sum(CATEGORIES[c][0] for c in hits)
    for a, b in FLAG_PAIRS:
        if a in hits and b in hits:
            return ScanResult(True, score, hits, f"{a} + {b}")
    for c in FLAG_ALONE:
        if c in hits:
            return ScanResult(True, score, hits, c)
    if score >= THRESHOLD:
        return ScanResult(True, score, hits, f"score {score} >= {THRESHOLD}")
    return ScanResult(False, score, hits)
