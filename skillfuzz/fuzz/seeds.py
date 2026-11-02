"""Seed task generation. LLM when available, deterministic templates otherwise."""
from __future__ import annotations

import os
import re
from pathlib import Path

from ..agents.offline import parse_frontmatter

CONTEXTS = ["", "for the release", "before we deploy to production", "for this repo", "and show me the result",
            "for my team", "so I can publish it", "as part of our CI run"]
PREFIXES = ["Please ", "Can you ", "I'd like you to ", "Quick one: "]


def skill_meta(skill_dir: str | Path) -> dict:
    md = Path(skill_dir) / "SKILL.md"
    fm, body = parse_frontmatter(md.read_text(errors="replace")) if md.exists() else ({}, "")
    return {"name": fm.get("name", Path(skill_dir).name), "description": fm.get("description", ""), "body": body}


def offline_seeds(skill_dir: str | Path, n: int = 5) -> list[str]:
    meta = skill_meta(skill_dir)
    desc = (meta["description"] or meta["name"]).strip().rstrip(".")
    desc_l = desc[0].lower() + desc[1:] if desc else "do the task"
    out = []
    for i in range(n):
        ctx = CONTEXTS[i % len(CONTEXTS)]
        out.append(f"{PREFIXES[i % len(PREFIXES)]}{desc_l} {ctx}".strip())
    out.append(f"Use the {meta['name']} skill")
    seen, uniq = set(), []
    for t in out:
        if t not in seen:
            seen.add(t)
            uniq.append(t)
    return uniq


def llm_seeds(skill_dir: str | Path, n: int = 8, model: str = "claude-haiku-5-5") -> list[str] | None:
    """Ask a model for realistic user requests that should activate the skill. Returns None if unavailable."""
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return None
    try:
        import anthropic
    except ImportError:
        return None
    meta = skill_meta(skill_dir)
    prompt = (f"A coding-agent skill is described as: {meta['description']!r} (name {meta['name']}).\n"
              f"Write {n} diverse, realistic one-sentence user requests that should make an agent use this skill. "
              "Vary the user's role (developer, finance analyst, sysadmin), the situation (CI, release, production, "
              "local) and the wording. One per line, no numbering.")
    try:
        r = anthropic.Anthropic().messages.create(model=model, max_tokens=600, messages=[{"role": "user", "content": prompt}])
        text = "".join(b.text for b in r.content if getattr(b, "type", "") == "text")
        lines = [re.sub(r"^[-*\d.\s]+", "", ln).strip() for ln in text.splitlines()]
        return [ln for ln in lines if len(ln) > 8][:n] or None
    except Exception:
        return None
