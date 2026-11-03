"""The coverage-guided loop."""
from __future__ import annotations

import csv
import json
import random
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path

from ..fingerprint.build import build_fingerprint
from ..models import EffectTrace, Fingerprint, FuzzInput
from ..recorder.normalize import build_trace
from ..sandbox.namespace import NamespaceSandbox
from . import seeds as seedmod
from .mutators import Mutator
from .static_pass import analyse, is_stateful


STATEFUL_MIN_RUNS = 4          # a "3rd invocation" trigger needs at least 3 sequential runs; one spare


@dataclass
class FuzzConfig:
    max_runs: int = 60
    plateau: int = 15                 # stop after this many mutation runs without new coverage
    repeats: int = 1                  # run each input k times and union (use 2-3 with a real LLM agent)
    timeout: float = 60
    seed: int = 0
    stop_on_taint: bool = False
    agent: dict = field(default_factory=lambda: {"name": "offline"})
    llm_seeds: bool = False
    static_sweep: bool = True         # ablation switches
    use_static_dict: bool = True
    guided: bool = True               # False = parents chosen uniformly from seeds, no corpus growth
    script_coverage: bool = True      # False = effect-triple coverage only
    keep_raw: str = "interesting"     # all | interesting | none
    model_fn: object = None           # test hook: replaces the host-side LLM call for agent "anthropic"


@dataclass
class RunRecord:
    idx: int
    fi: FuzzInput
    new_cov: int
    total_cov: int
    tainted: bool
    seconds: float
    phase: str


@dataclass
class FuzzResult:
    fingerprint: Fingerprint
    records: list[RunRecord]
    traces: list[EffectTrace]
    corpus: list[FuzzInput]
    first_taint_run: int | None
    sandbox_seconds: float


class Fuzzer:
    def __init__(self, skill_dir: str | Path, out_dir: str | Path, cfg: FuzzConfig | None = None, sandbox=None):
        self.skill_dir, self.out_dir = Path(skill_dir).resolve(), Path(out_dir).resolve()
        self.cfg = cfg or FuzzConfig()
        self.sandbox = sandbox or NamespaceSandbox()
        self.rng = random.Random(self.cfg.seed)
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self._n = 0
        self.stateful = is_stateful(self.skill_dir)
        self.llm_usage: dict[str, int] = {}

    # ---- one input -> one merged trace ---------------------------------------------------------------
    def run_input(self, fi: FuzzInput) -> EffectTrace:
        merged: EffectTrace | None = None
        reps = max(self.cfg.repeats, STATEFUL_MIN_RUNS) if self.stateful else self.cfg.repeats
        state = (self.out_dir / "state" / fi.key()) if self.stateful else None
        if state is not None:
            shutil.rmtree(state, ignore_errors=True)       # every input starts from a clean slate; repeats share state
        for rep in range(reps):
            self._n += 1
            rdir = self.out_dir / "runs" / f"{self._n:04d}"
            if rdir.exists():
                shutil.rmtree(rdir)
            res = self.sandbox.run(self.skill_dir, fi, rdir, agent=self.cfg.agent, timeout=self.cfg.timeout,
                                   seed=self.cfg.seed + self._n, **({"model_fn": self.cfg.model_fn} if self.cfg.model_fn else {}),
                                   **({"state_dir": state} if state is not None else {}))
            for k, v in (res.get("llm_usage") or {}).items():
                self.llm_usage[k] = self.llm_usage.get(k, 0) + v
            tr = build_trace(rdir, fi, res["run_id"])
            tr._dir = rdir  # type: ignore[attr-defined]
            if merged is None:
                merged = tr
            else:
                merged.events += tr.events
                merged.tainted_flows += tr.tainted_flows
                merged.script_coverage = sorted(set(merged.script_coverage) | set(tr.script_coverage))
                merged.tool_calls += tr.tool_calls
                merged.exposures = sorted(set(merged.exposures) | set(tr.exposures))
                merged.remote_instruction_fetch |= tr.remote_instruction_fetch
                merged.duration_s += tr.duration_s
        assert merged is not None
        return merged

    def _cov(self, tr: EffectTrace) -> set[str]:
        cov = tr.coverage_set()
        if not self.cfg.script_coverage:
            cov = {c for c in cov if not c.startswith("script|")}
        return cov

    def _finish_run_dir(self, tr: EffectTrace, interesting: bool) -> None:
        rdir: Path = tr._dir  # type: ignore[attr-defined]
        (rdir / "trace.json").write_text(tr.model_dump_json(indent=1, exclude={"events"} if False else set()))
        if self.cfg.keep_raw == "all" or (self.cfg.keep_raw == "interesting" and interesting):
            return
        for name in ("strace.txt", "net.jsonl", "cov", "agent_log.jsonl"):
            p = rdir / name
            shutil.rmtree(p, ignore_errors=True) if p.is_dir() else p.unlink(missing_ok=True)

    # ---- main loop ---------------------------------------------------------------------------------
    def fuzz(self, initial_corpus: list[FuzzInput] | None = None, label: str = "") -> FuzzResult:
        cfg = self.cfg
        d = analyse(self.skill_dir, with_generic=True)
        if not cfg.use_static_dict:
            d.env, d.dates, d.keywords, d.remotes, d.locales, d.os_hints = [], [], [], [], [], []
            d.keywords = ["deploy", "release"]
        mut = Mutator(d, self.rng, use_static=cfg.use_static_dict)
        task_seeds = (seedmod.llm_seeds(self.skill_dir) if cfg.llm_seeds else None) or seedmod.offline_seeds(self.skill_dir)

        seen: set[str] = set()
        global_cov: set[str] = set()
        corpus: list[tuple[FuzzInput, float]] = []
        records: list[RunRecord] = []
        traces: list[EffectTrace] = []
        first_taint: int | None = None
        sb_seconds = 0.0
        seed_inputs: list[FuzzInput] = []

        def execute(fi: FuzzInput, phase: str, as_seed: bool = False) -> bool:
            nonlocal first_taint, sb_seconds
            seen.add(fi.key())
            t0 = time.time()
            tr = self.run_input(fi)
            sb_seconds += time.time() - t0
            cov = self._cov(tr)
            new = cov - global_cov
            global_cov.update(cov)
            tainted = bool(tr.tainted_flows)
            idx = len(records) + 1
            if tainted and first_taint is None:
                first_taint = idx
            records.append(RunRecord(idx, fi, len(new), len(global_cov), tainted, time.time() - t0, phase))
            traces.append(tr)
            keep = bool(new) or as_seed
            if keep and cfg.guided:
                corpus.append((fi, float(max(len(new), 1))))
            self._finish_run_dir(tr, interesting=bool(new) or tainted)
            return bool(new)

        # phase 0: regression replay of a previous version's corpus, then fresh seeds
        for fi in (initial_corpus or []):
            if fi.key() not in seen and len(records) < cfg.max_runs:
                execute(fi, "replay", as_seed=True)
        for t in task_seeds:
            fi = FuzzInput(task=t)
            if fi.key() not in seen and len(records) < cfg.max_runs:
                seed_inputs.append(fi)
                execute(fi, "seed", as_seed=True)
        if not seed_inputs:
            seed_inputs = [FuzzInput(task=task_seeds[0])]

        def stop() -> bool:
            return len(records) >= cfg.max_runs or (cfg.stop_on_taint and first_taint is not None)

        # phase 1: targeted sweep from the static dictionary, applied to the most productive seed
        since_gain = 0
        if cfg.static_sweep and cfg.use_static_dict and not stop():
            best = max(seed_inputs, key=lambda s: next((r.new_cov for r in records if r.fi.key() == s.key()), 0))
            for fi in mut.sweep(best):
                if stop():
                    break
                if fi.key() in seen:
                    continue
                since_gain = 0 if execute(fi, "sweep") else since_gain + 1
                if since_gain >= cfg.plateau:
                    break

        # phase 2: AFL-style havoc over the corpus
        since_gain = 0
        while not stop() and since_gain < cfg.plateau:
            if cfg.guided and corpus:
                parent = self.rng.choices([c[0] for c in corpus], [c[1] for c in corpus])[0]
                pool = [c[0] for c in corpus]
            else:
                parent = self.rng.choice(seed_inputs)
                pool = seed_inputs
            child = mut.mutate(parent, pool)
            tries = 0
            while child.key() in seen and tries < 20:
                child, tries = mut.mutate(parent, pool), tries + 1
            if child.key() in seen:
                break
            gained = execute(child, "havoc")
            since_gain = 0 if gained else since_gain + 1
            if cfg.guided:
                for i, (fi, e) in enumerate(corpus):          # energy decay on the parent
                    if fi.key() == parent.key():
                        corpus[i] = (fi, max(e * 0.9, 0.5))
                        break

        fp = build_fingerprint(self.skill_dir, traces, first_taint, len(global_cov),
                               meta={"label": label, "agent": cfg.agent, "seed": cfg.seed, "max_runs": cfg.max_runs,
                                     "plateau": cfg.plateau, "sandbox_seconds": round(sb_seconds, 1), "llm_usage": self.llm_usage,
                                     "first_taint_input": records[first_taint - 1].fi.describe() if first_taint else None,
                                     "stop_reason": "taint" if (cfg.stop_on_taint and first_taint) else
                                     ("budget" if len(records) >= cfg.max_runs else "plateau")})
        result = FuzzResult(fp, records, traces, [c[0] for c in corpus], first_taint, sb_seconds)
        self._write(result)
        return result

    def _write(self, r: FuzzResult) -> None:
        (self.out_dir / "fingerprint.json").write_text(r.fingerprint.model_dump_json(indent=2))
        (self.out_dir / "corpus.json").write_text(json.dumps([c.model_dump() for c in r.corpus], indent=1))
        with open(self.out_dir / "coverage_curve.csv", "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["run", "phase", "new_coverage", "total_coverage", "tainted", "seconds", "input"])
            for rec in r.records:
                w.writerow([rec.idx, rec.phase, rec.new_cov, rec.total_cov, int(rec.tainted), round(rec.seconds, 2), rec.fi.describe()])
