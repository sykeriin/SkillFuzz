"""Mutation operators over FuzzInput."""
from __future__ import annotations

import datetime as dt
import random

from ..models import FuzzInput
from .static_pass import Dictionary, clock_candidates, remote_url_for

PERSONAS = ["developer", "finance", "admin"]
PREFIXES = ["Please ", "Can you ", "I'd like you to ", "Quick one: ", "Hey, "]
SUFFIXES = ["", " right now", " and keep it short", " - it's urgent", " for the team"]


class Mutator:
    def __init__(self, d: Dictionary, rng: random.Random, use_static: bool = True):
        self.d, self.rng, self.use_static = d, rng, use_static
        self.ops = [self.persona, self.env_inject, self.clock, self.git_remote, self.locale, self.os_profile,
                    self.keyword, self.rephrase, self.cwd]
        self.weights = [1, 4, 3, 2, 2, 1, 4, 2, 1]

    # ---- single operators (each returns a mutated copy) ---------------------------------
    def persona(self, fi: FuzzInput) -> FuzzInput:
        return fi.model_copy(update={"persona": self.rng.choice([p for p in PERSONAS if p != fi.persona])})

    def env_inject(self, fi: FuzzInput) -> FuzzInput:
        pool = (self.d.env if self.use_static and self.d.env and self.rng.random() < 0.7 else []) or self.d.generic_env
        if not pool:
            return fi
        k, v = self.rng.choice(pool)
        env = dict(fi.env_vars)
        env[k] = v
        return fi.model_copy(update={"env_vars": env})

    def clock(self, fi: FuzzInput) -> FuzzInput:
        today = dt.date.today()
        cands = [(today + dt.timedelta(days=n)).isoformat() for n in (1, 30, 90, 365, 730)]
        if self.use_static:
            for ds in self.d.dates:
                cands += clock_candidates(ds)
        return fi.model_copy(update={"clock": self.rng.choice(cands)})

    def git_remote(self, fi: FuzzInput) -> FuzzInput:
        pool = [remote_url_for(t) for t in self.d.remotes] if self.use_static else [remote_url_for("globex-industries")]
        return fi.model_copy(update={"git_remote": self.rng.choice(pool or [fi.git_remote])})

    def locale(self, fi: FuzzInput) -> FuzzInput:
        return fi.model_copy(update={"locale": self.rng.choice(self.d.locales or ["de_DE.UTF-8"])})

    def os_profile(self, fi: FuzzInput) -> FuzzInput:
        return fi.model_copy(update={"os_profile": "macos" if fi.os_profile == "linux" else "linux"})

    def keyword(self, fi: FuzzInput) -> FuzzInput:
        kw = self.rng.choice(self.d.keywords if self.use_static else ["deploy", "release"]) if self.d.keywords else "deploy"
        base = fi.task if kw in fi.task.lower() else f"{fi.task} {self.rng.choice(['and', 'then', 'before I', 'for the'])} {kw}"
        return fi.model_copy(update={"task": base})

    def rephrase(self, fi: FuzzInput) -> FuzzInput:
        t = fi.task
        for p in PREFIXES:
            if t.startswith(p):
                t = t[len(p):]
        return fi.model_copy(update={"task": self.rng.choice(PREFIXES) + t + self.rng.choice(SUFFIXES)})

    def cwd(self, fi: FuzzInput) -> FuzzInput:
        return fi.model_copy(update={"cwd_kind": "empty" if fi.cwd_kind == "repo" else "repo"})

    def crossover(self, a: FuzzInput, b: FuzzInput) -> FuzzInput:
        return a.model_copy(update={"env_vars": {**a.env_vars, **b.env_vars}, "clock": a.clock or b.clock,
                                    "git_remote": self.rng.choice([a.git_remote, b.git_remote]),
                                    "locale": self.rng.choice([a.locale, b.locale])})

    # ---- composite ------------------------------------------------------------------------
    def mutate(self, fi: FuzzInput, corpus: list[FuzzInput]) -> FuzzInput:
        out = fi
        if len(corpus) > 1 and self.rng.random() < 0.15:
            out = self.crossover(out, self.rng.choice(corpus))
        for _ in range(self.rng.choice([1, 1, 2, 3])):
            out = self.rng.choices(self.ops, self.weights)[0](out)
        return out

    def sweep(self, base: FuzzInput) -> list[FuzzInput]:
        """Deterministic one-edit mutants built from the static dictionary: the targeted phase."""
        out: list[FuzzInput] = []
        for k, v in self.d.env:
            out.append(base.model_copy(update={"env_vars": {**base.env_vars, k: v}}))
        for ds in self.d.dates:
            for c in clock_candidates(ds)[:1]:
                out.append(base.model_copy(update={"clock": c}))
        for tok in self.d.remotes:
            out.append(base.model_copy(update={"git_remote": remote_url_for(tok)}))
        for loc in self.d.locales:
            out.append(base.model_copy(update={"locale": loc}))
        for kw in self.d.keywords:
            if kw not in base.task.lower():
                out.append(base.model_copy(update={"task": f"{base.task} and {kw}"}))
        if "macos" in self.d.os_hints:
            out.append(base.model_copy(update={"os_profile": "macos"}))
        return out
